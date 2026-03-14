const std = @import("std");
const path_guard = @import("path_guard.zig");
const tools = @import("../tools.zig");
const tool_snap = @import("../../test/tool_snap.zig");

pub const Err = error{
    KindMismatch,
    InvalidArgs,
    NotFound,
    Denied,
    Io,
    OutOfMemory,
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64 = 0,
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
        };
    }

    pub fn run(self: Handler, call: tools.Call, _: tools.Sink) Err!tools.Result {
        if (call.kind != .find) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .find) return error.KindMismatch;

        const args = call.args.find;
        if (args.path.len == 0) return error.InvalidArgs;
        if (args.name.len == 0) return error.InvalidArgs;
        if (args.max_results == 0) return error.InvalidArgs;

        var root = path_guard.openDir(args.path, .{ .iterate = true }) catch |open_err| {
            return mapFsErr(open_err);
        };
        defer root.close();

        var matches = std.ArrayList([]u8).empty;
        defer {
            for (matches.items) |m| self.alloc.free(m);
            matches.deinit(self.alloc);
        }

        const collect_limit = satMul(@as(usize, args.max_results), 8);
        var path = std.ArrayList(u8).empty;
        defer path.deinit(self.alloc);
        try collectMatches(self, root, &path, args.name, collect_limit, &matches);

        std.sort.pdq([]u8, matches.items, {}, lessPath);

        var acc = Acc.init(self.alloc, self.max_bytes);
        defer acc.deinit();

        const emit_len = @min(matches.items.len, @as(usize, args.max_results));
        for (matches.items[0..emit_len]) |match_path| {
            try acc.append(match_path);
            try acc.append("\n");
        }

        const data = acc.takeOwned() catch return error.OutOfMemory;
        errdefer self.alloc.free(data);

        const meta = tools.truncate.metaFor(self.max_bytes, acc.full_bytes);
        var meta_chunk: ?[]u8 = null;
        if (meta) |m| {
            meta_chunk = tools.truncate.metaJsonAlloc(self.alloc, .stdout, m) catch return error.OutOfMemory;
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
            .truncated = meta != null,
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
            meta_chunk = null;
        }

        return .{
            .call_id = call.id,
            .started_at_ms = self.now_ms,
            .ended_at_ms = self.now_ms,
            .out = out,
            .out_owned = true,
            .final = .{ .ok = .{ .code = 0 } },
        };
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        if (!res.out_owned) return;
        for (res.out) |out| {
            if (out.owned) self.alloc.free(out.chunk);
        }
        self.alloc.free(res.out);
    }
};

fn lessPath(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn collectMatches(
    self: Handler,
    dir: std.fs.Dir,
    path: *std.ArrayList(u8),
    needle: []const u8,
    limit: usize,
    matches: *std.ArrayList([]u8),
) Err!void {
    var it = dir.iterate();
    while (try nextEnt(&it)) |ent| {
        if (matches.items.len >= limit) break;

        const base_len = path.items.len;
        if (base_len != 0) try path.append(self.alloc, '/');
        defer path.shrinkRetainingCapacity(base_len);
        try path.appendSlice(self.alloc, ent.name);

        if (std.mem.indexOf(u8, ent.name, needle) != null) {
            const dup = self.alloc.dupe(u8, path.items) catch return error.OutOfMemory;
            errdefer self.alloc.free(dup);
            matches.append(self.alloc, dup) catch return error.OutOfMemory;
            if (matches.items.len >= limit) break;
        }

        if (ent.kind != .directory) continue;

        var child = dir.openDir(ent.name, .{
            .iterate = true,
            .access_sub_paths = true,
            .no_follow = true,
        }) catch |open_err| return mapFsErr(open_err);
        defer child.close();
        try collectMatches(self, child, path, needle, limit, matches);
    }
}

fn nextEnt(it: *std.fs.Dir.Iterator) Err!?std.fs.Dir.Entry {
    return it.next() catch |next_err| mapFsErr(next_err);
}

const Acc = struct {
    alloc: std.mem.Allocator,
    limit: usize,
    buf: std.ArrayList(u8) = .empty,
    full_bytes: usize = 0,

    fn init(alloc: std.mem.Allocator, limit: usize) Acc {
        return .{
            .alloc = alloc,
            .limit = limit,
        };
    }

    fn deinit(self: *Acc) void {
        self.buf.deinit(self.alloc);
        self.* = undefined;
    }

    fn append(self: *Acc, data: []const u8) !void {
        self.full_bytes = satAdd(self.full_bytes, data.len);
        if (self.buf.items.len >= self.limit) return;

        const keep = @min(data.len, self.limit - self.buf.items.len);
        if (keep == 0) return;
        try self.buf.appendSlice(self.alloc, data[0..keep]);
    }

    fn takeOwned(self: *Acc) ![]u8 {
        const out = try self.buf.toOwnedSlice(self.alloc);
        self.buf = .empty;
        return out;
    }
};

fn satAdd(a: usize, b: usize) usize {
    const sum, const ov = @addWithOverflow(a, b);
    if (ov == 0) return sum;
    return std.math.maxInt(usize);
}

fn satMul(a: usize, b: usize) usize {
    const out, const ov = @mulWithOverflow(a, b);
    if (ov == 0) return out;
    return std.math.maxInt(usize);
}

fn mapFsErr(err: anyerror) Err {
    return switch (err) {
        error.FileNotFound => error.NotFound,
        error.AccessDenied, error.PermissionDenied, error.SymLinkLoop => error.Denied,
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

test "find handler lists matching paths in sorted order" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("src/lib");
    try tmp.dir.writeFile(.{ .sub_path = "src/a.zig", .data = "" });
    try tmp.dir.writeFile(.{ .sub_path = "src/lib/b.zig", .data = "" });
    try tmp.dir.writeFile(.{ .sub_path = "src/lib/c.txt", .data = "" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "src");
    defer std.testing.allocator.free(root);

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 7,
    });
    const call: tools.Call = .{
        .id = "f1",
        .kind = .find,
        .args = .{ .find = .{
            .path = root,
            .name = ".zig",
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const snap = try tool_snap.resultAlloc(std.testing.allocator, res);
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "call=f1
        \\start=7
        \\end=7
        \\out=1
        \\0=f1|7|stdout|false|a.zig
        \\lib/b.zig
        \\
        \\final=ok|0
        \\"
    ).expectEqual(snap);
}

test "find handler validates args and handles missing roots" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 64,
    });

    const bad: tools.Call = .{
        .id = "f2",
        .kind = .find,
        .args = .{ .find = .{ .path = ".", .name = "", .max_results = 1 } },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.InvalidArgs, handler.run(bad, sink));

    const missing: tools.Call = .{
        .id = "f3",
        .kind = .find,
        .args = .{ .find = .{ .path = "no-such-dir-8572", .name = "x" } },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.NotFound, handler.run(missing, sink));
}

test "find handler truncates on high hit count instead of erroring" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    // Create more files than max_results * 8
    try tmp.dir.makePath("d");
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        var name: [12]u8 = undefined;
        const n = std.fmt.bufPrint(&name, "d/f{d}.txt", .{i}) catch unreachable;
        try tmp.dir.writeFile(.{ .sub_path = n, .data = "" });
    }

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "d");
    defer std.testing.allocator.free(root);

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 0,
    });
    const call: tools.Call = .{
        .id = "f4",
        .kind = .find,
        .args = .{
            .find = .{
                .path = root,
                .name = ".txt",
                .max_results = 2, // collect_limit = 2 * 8 = 16 < 20 files
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    // Should succeed (truncated) instead of erroring
    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    // Should have 1 data chunk with at most max_results lines
    try std.testing.expect(res.out.len >= 1);
    const chunk = res.out[0].chunk;
    var lines: usize = 0;
    for (chunk) |c| {
        if (c == '\n') lines += 1;
    }
    try std.testing.expect(lines <= 2);
}
