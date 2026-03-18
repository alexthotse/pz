//! Skill invocation tool: discover and run slash-command skills.
const std = @import("std");
const core_skill = @import("../skill.zig");
const tools = @import("../tools.zig");
const noop = @import("../../test/noop_sink.zig");

pub const Err = error{
    KindMismatch,
    InvalidArgs,
    OutOfMemory,
};

pub const Cache = struct {
    skills: ?[]core_skill.SkillInfo = null,
    home: ?[]const u8 = null,

    pub fn load(self: *Cache, alloc: std.mem.Allocator) ![]const core_skill.SkillInfo {
        if (self.skills == null) self.skills = try core_skill.discoverAndRead(alloc, self.home);
        return self.skills.?;
    }

    pub fn find(self: *Cache, alloc: std.mem.Allocator, name: []const u8) !?*const core_skill.SkillInfo {
        const skills = try self.load(alloc);
        return core_skill.findByDirName(skills, name);
    }

    pub fn deinit(self: *Cache, alloc: std.mem.Allocator) void {
        if (self.skills) |skills| {
            core_skill.freeSkills(alloc, skills);
            self.skills = null;
        }
    }
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64 = 0,
    cache: *Cache,
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,
    cache: *Cache,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
            .cache = opts.cache,
        };
    }

    pub fn run(self: Handler, call: tools.Call, _: tools.Sink) Err!tools.Result {
        if (call.kind != .skill) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .skill) return error.KindMismatch;

        const args = call.args.skill;
        if (args.name.len == 0) return error.InvalidArgs;

        const info = self.cache.find(self.alloc, args.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(call, .io, @errorName(err)),
        };
        const skill = info orelse return fail(call, .invalid_args, "skill not found");
        if (skill.meta.disable_model_invocation) {
            return fail(call, .invalid_args, "skill disables model invocation");
        }

        const text = render(self.alloc, skill.*, args.args) catch return error.OutOfMemory;
        defer self.alloc.free(text);
        return okWithResult(self, call, text);
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        shared.deinitResult(self.alloc, res);
    }
};

fn render(alloc: std.mem.Allocator, skill: core_skill.SkillInfo, args: []const u8) ![]u8 {
    if (args.len == 0) return alloc.dupe(u8, skill.meta.body);
    return std.fmt.allocPrint(alloc, "{s}\n\nUser: {s}", .{ skill.meta.body, args });
}

fn okWithResult(self: Handler, call: tools.Call, result: []const u8) Err!tools.Result {
    const slice = tools.truncate.apply(result, self.max_bytes);

    const data = self.alloc.dupe(u8, slice.chunk) catch return error.OutOfMemory;
    errdefer self.alloc.free(data);

    var meta_chunk: ?[]u8 = null;
    if (slice.meta) |meta| {
        meta_chunk = tools.truncate.metaJsonAlloc(self.alloc, .stdout, meta) catch return error.OutOfMemory;
    }
    errdefer if (meta_chunk) |chunk| self.alloc.free(chunk);

    const out_len: usize = 1 + @as(usize, @intFromBool(meta_chunk != null));
    const out = self.alloc.alloc(tools.Output, out_len) catch return error.OutOfMemory;
    errdefer self.alloc.free(out);

    out[0] = .{
        .call_id = call.id,
        .seq = 0,
        .at_ms = self.now_ms,
        .stream = .stdout,
        .chunk = data,
        .owned = true,
        .truncated = slice.truncated,
    };

    if (meta_chunk) |chunk| {
        out[1] = .{
            .call_id = call.id,
            .seq = 1,
            .at_ms = self.now_ms,
            .stream = .meta,
            .chunk = chunk,
            .owned = true,
            .truncated = false,
        };
    }

    return .{
        .call_id = call.id,
        .started_at_ms = self.now_ms,
        .ended_at_ms = self.now_ms,
        .out = out,
        .out_owned = true,
        .final = .{
            .ok = .{ .code = 0 },
        },
    };
}

const fail = shared.fail;

fn dupInfo(
    alloc: std.mem.Allocator,
    dir_name: []const u8,
    body: []const u8,
    disable_model_invocation: bool,
) !core_skill.SkillInfo {
    return .{
        .meta = .{
            .name = try alloc.dupe(u8, dir_name),
            .description = try alloc.dupe(u8, ""),
            .body = try alloc.dupe(u8, body),
            .disable_model_invocation = disable_model_invocation,
            .user_invocable = false,
        },
        .dir_name = try alloc.dupe(u8, dir_name),
        .source = .project,
    };
}

test "skill handler returns cached body with appended args" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const skills = try std.testing.allocator.alloc(core_skill.SkillInfo, 1);
    skills[0] = try dupInfo(std.testing.allocator, "review-plan", "Use critic", false);

    var cache = Cache{ .skills = skills };
    defer cache.deinit(std.testing.allocator);

    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 44,
        .cache = &cache,
    });
    const call: tools.Call = .{
        .id = "skill-1",
        .kind = .skill,
        .args = .{
            .skill = .{
                .name = "review-plan",
                .args = "focus on policy",
            },
        },
        .src = .model,
        .at_ms = 44,
    };

    const res = try h.run(call, noop.sink());
    defer h.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "final={s}\nout={s}\n", .{
        @tagName(res.final),
        res.out[0].chunk,
    });
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "final=ok
        \\out=Use critic
        \\
        \\User: focus on policy
        \\"
    ).expectEqual(snap);
}

test "skill handler blocks model-disabled skills" {
    const skills = try std.testing.allocator.alloc(core_skill.SkillInfo, 1);
    skills[0] = try dupInfo(std.testing.allocator, "sec", "Body", true);

    var cache = Cache{ .skills = skills };
    defer cache.deinit(std.testing.allocator);

    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 45,
        .cache = &cache,
    });
    const call: tools.Call = .{
        .id = "skill-2",
        .kind = .skill,
        .args = .{
            .skill = .{
                .name = "sec",
            },
        },
        .src = .model,
        .at_ms = 45,
    };

    const res = try h.run(call, noop.sink());
    switch (res.final) {
        .failed => |failed| try std.testing.expectEqualStrings("skill disables model invocation", failed.msg),
        else => return error.TestUnexpectedResult,
    }
}
