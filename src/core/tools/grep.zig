//! Grep tool: regex search across files with path guarding.
const std = @import("std");
const path_guard = @import("path_guard.zig");
const tools = @import("../tools.zig");
const shared = @import("shared.zig");
const noop = @import("../../test/noop_sink.zig");
const Acc = shared.Acc;

pub const Err = error{
    KindMismatch,
    InvalidArgs,
    NotFound,
    Denied,
    TooLarge,
    Io,
    OutOfMemory,
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64 = 0,
    pre_open: ?PreOpen = null,
};

const PreOpen = struct {
    ctx: *anyopaque,
    run: *const fn (*anyopaque, std.fs.Dir, []const u8) anyerror!void,
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,
    pre_open: ?PreOpen,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
            .pre_open = opts.pre_open,
        };
    }

    pub fn run(self: Handler, call: tools.Call, _: tools.Sink) Err!tools.Result {
        if (call.kind != .grep) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .grep) return error.KindMismatch;

        const args = call.args.grep;
        if (args.path.len == 0) return error.InvalidArgs;
        if (args.pattern.len == 0) return error.InvalidArgs;
        if (args.max_results == 0) return error.InvalidArgs;

        var root = path_guard.openDir(args.path, .{ .iterate = true }) catch |open_err| {
            return shared.mapFsErr(open_err);
        };
        defer root.close();

        var acc = Acc.init(self.alloc, self.max_bytes);
        defer acc.deinit();

        var hit_ct: u32 = 0;
        var path = std.ArrayList(u8).empty;
        defer path.deinit(self.alloc);
        try grepDir(self, root, &path, args, &hit_ct, &acc);

        const data = acc.takeOwned() catch return error.OutOfMemory;
        errdefer self.alloc.free(data);

        return shared.buildResult(self.alloc, call.id, self.now_ms, data, self.max_bytes, acc.full_bytes) catch return error.OutOfMemory;
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        shared.deinitResult(self.alloc, res);
    }
};

fn grepDir(
    self: Handler,
    dir: std.fs.Dir,
    path: *std.ArrayList(u8),
    args: tools.Call.GrepArgs,
    hit_ct: *u32,
    acc: *Acc,
) Err!void {
    var it = dir.iterate();
    while (try nextEnt(&it)) |ent| {
        if (hit_ct.* >= args.max_results) break;

        const base_len = path.items.len;
        if (base_len != 0) try path.append(self.alloc, '/');
        defer path.shrinkRetainingCapacity(base_len);
        try path.appendSlice(self.alloc, ent.name);

        switch (ent.kind) {
            .directory => {
                var child = dir.openDir(ent.name, .{
                    .iterate = true,
                    .access_sub_paths = true,
                    .no_follow = true,
                }) catch |open_err| return shared.mapFsErr(open_err);
                defer child.close();
                try grepDir(self, child, path, args, hit_ct, acc);
            },
            .file => try grepFile(self, dir, ent.name, path.items, args, hit_ct, acc),
            else => {}, // .sym_link, .named_pipe, .unix_domain_socket, .block_device, .character_device, .whiteout, .door skipped
        }
    }
}

fn grepFile(
    self: Handler,
    dir: std.fs.Dir,
    name: []const u8,
    rel_path: []const u8,
    args: tools.Call.GrepArgs,
    hit_ct: *u32,
    acc: *Acc,
) Err!void {
    if (self.pre_open) |hook| {
        hook.run(hook.ctx, dir, rel_path) catch |hook_err| return shared.mapFsErr(hook_err);
    }

    var file = path_guard.openFileInDir(dir, name, .{ .mode = .read_only }) catch |open_err| {
        return shared.mapFsErr(open_err);
    };
    defer file.close();

    const full = file.readToEndAlloc(self.alloc, self.max_bytes) catch |read_err| switch (read_err) {
        error.FileTooBig => return error.TooLarge,
        else => return shared.mapFsErr(read_err),
    };
    defer self.alloc.free(full);

    var line_no: u32 = 0;
    var it = std.mem.splitScalar(u8, full, '\n');
    while (hit_ct.* < args.max_results) {
        const raw_line = it.next() orelse break;
        line_no += 1;
        const line = trimLine(raw_line);
        if (!lineMatches(line, args.pattern, args.ignore_case)) continue;

        const row = std.fmt.allocPrint(self.alloc, "{s}:{d}:{s}\n", .{
            rel_path,
            line_no,
            line,
        }) catch return error.OutOfMemory;
        defer self.alloc.free(row);
        try acc.append(row);
        hit_ct.* += 1;
    }
}

fn nextEnt(it: *std.fs.Dir.Iterator) Err!?std.fs.Dir.Entry {
    return it.next() catch |next_err| shared.mapFsErr(next_err);
}

fn trimLine(raw: []const u8) []const u8 {
    if (raw.len == 0) return raw;
    if (raw[raw.len - 1] == '\r') return raw[0 .. raw.len - 1];
    return raw;
}

fn lineMatches(line: []const u8, pattern: []const u8, ignore_case: bool) bool {
    if (!ignore_case) return std.mem.indexOf(u8, line, pattern) != null;
    return containsAsciiFold(line, pattern);
}

fn containsAsciiFold(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > hay.len) return false;

    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (eqlAsciiFold(hay[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn eqlAsciiFold(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (asciiLower(x) != asciiLower(y)) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    if (ch >= 'A' and ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}



test "grep handler finds matching lines with file and line numbers" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        has_a: bool,
        has_b: bool,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("src");
    try tmp.dir.writeFile(.{ .sub_path = "src/a.txt", .data = "alpha\nbeta\n" });
    try tmp.dir.writeFile(.{ .sub_path = "src/b.txt", .data = "Beta\n" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "src");
    defer std.testing.allocator.free(root);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 9,
    });
    const call: tools.Call = .{
        .id = "g1",
        .kind = .grep,
        .args = .{
            .grep = .{
                .path = root,
                .pattern = "beta",
                .ignore_case = true,
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    try oh.snap(@src(),
        \\core.tools.grep.test.grep handler finds matching lines with file and line numbers.Snap
        \\  .has_a: bool = true
        \\  .has_b: bool = true
    ).expectEqual(Snap{
        .has_a = std.mem.indexOf(u8, res.out[0].chunk, "a.txt:2:beta\n") != null,
        .has_b = std.mem.indexOf(u8, res.out[0].chunk, "b.txt:1:Beta\n") != null,
    });
}

test "grep handler validates args and missing roots" {
    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 64,
    });

    const bad: tools.Call = .{
        .id = "g2",
        .kind = .grep,
        .args = .{
            .grep = .{ .path = ".", .pattern = "", .max_results = 1 },
        },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.InvalidArgs, handler.run(bad, sink));

    const missing: tools.Call = .{
        .id = "g3",
        .kind = .grep,
        .args = .{
            .grep = .{ .path = "no-such-dir-9477", .pattern = "x" },
        },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.NotFound, handler.run(missing, sink));
}

test "grep handler denies hardlinked leaf" {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("src");
    try tmp.dir.writeFile(.{ .sub_path = "src/base.txt", .data = "secret\n" });
    try std.posix.linkat(tmp.dir.fd, "src/base.txt", tmp.dir.fd, "src/alias.txt", 0);

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "src");
    defer std.testing.allocator.free(root);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    try std.testing.expectError(error.Denied, handler.run(.{
        .id = "g-link",
        .kind = .grep,
        .args = .{
            .grep = .{
                .path = root,
                .pattern = "secret",
            },
        },
        .src = .model,
        .at_ms = 0,
    }, sink));
}

test "grep handler keeps trusted dir after ancestor swap" {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    const Hook = struct {
        const Ctx = struct {
            root: std.fs.Dir,
            done: bool = false,
        };

        fn run(raw: *anyopaque, _: std.fs.Dir, rel_path: []const u8) !void {
            const ctx: *Ctx = @ptrCast(@alignCast(raw));
            if (ctx.done) return;
            if (!std.mem.eql(u8, rel_path, "sub/victim.txt")) return;
            ctx.done = true;
            try ctx.root.rename("sub", "gone");
            try ctx.root.rename("swap", "sub");
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("src/sub");
    try tmp.dir.makePath("src/swap");
    try tmp.dir.writeFile(.{ .sub_path = "src/sub/victim.txt", .data = "secret\n" });
    try tmp.dir.writeFile(.{ .sub_path = "src/swap/victim.txt", .data = "hacked\n" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "src");
    defer std.testing.allocator.free(root);

    const sink = noop.sink();

    var ctx = Hook.Ctx{ .root = try tmp.dir.openDir("src", .{ .access_sub_paths = true }) };
    defer ctx.root.close();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 256,
        .pre_open = .{ .ctx = &ctx, .run = Hook.run },
    });
    const res = try handler.run(.{
        .id = "g-race",
        .kind = .grep,
        .args = .{
            .grep = .{
                .path = root,
                .pattern = "secret",
            },
        },
        .src = .model,
        .at_ms = 0,
    }, sink);
    defer handler.deinitResult(res);

    try std.testing.expectEqualStrings("sub/victim.txt:1:secret\n", res.out[0].chunk);
}
