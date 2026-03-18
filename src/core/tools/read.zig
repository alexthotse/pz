//! File read tool with path guarding and line-range support.
const std = @import("std");
const path_guard = @import("path_guard.zig");
const tools = @import("../tools.zig");
const shared = @import("shared.zig");
const tool_snap = @import("../../test/tool_snap.zig");
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
        if (call.kind != .read) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .read) return error.KindMismatch;

        const args = call.args.read;
        const from_line = args.from_line orelse 1;

        if (args.path.len == 0) return error.InvalidArgs;
        if (from_line == 0) return error.InvalidArgs;

        if (args.to_line) |to_line| {
            if (to_line == 0) return error.InvalidArgs;
            if (to_line < from_line) return error.InvalidArgs;
        }

        const selected = try readSelected(self, args.path, from_line, args.to_line);
        errdefer self.alloc.free(selected.chunk);

        return shared.buildResult(self.alloc, call.id, self.now_ms, selected.chunk, self.max_bytes, selected.full_bytes) catch return error.OutOfMemory;
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        shared.deinitResult(self.alloc, res);
    }
};

const Selected = struct {
    chunk: []u8,
    full_bytes: usize,
};

fn readSelected(self: Handler, path: []const u8, from_line: u32, to_line: ?u32) Err!Selected {
    var file = path_guard.openFile(path, .{ .mode = .read_only }) catch |open_err| {
        return shared.mapFsErr(open_err);
    };
    defer file.close();

    const last_line = to_line orelse std.math.maxInt(u32);
    var line_no: u32 = 1;
    var in_range = line_no >= from_line and line_no <= last_line;

    var acc = Acc.init(self.alloc, self.max_bytes);
    defer acc.deinit();

    var scratch: [4096]u8 = undefined;
    while (true) {
        const n = file.read(&scratch) catch |read_err| {
            return shared.mapFsErr(read_err);
        };
        if (n == 0) break;

        var i: usize = 0;
        while (i < n) : (i += 1) {
            const b = scratch[i];
            if (in_range) try acc.appendByte(b);

            if (b == '\n') {
                if (line_no == last_line) {
                    return .{
                        .chunk = acc.takeOwned() catch return error.OutOfMemory,
                        .full_bytes = acc.full_bytes,
                    };
                }
                line_no = shared.satAdd(u32, line_no, 1);
                in_range = line_no >= from_line and line_no <= last_line;
            }
        }
    }

    return .{
        .chunk = acc.takeOwned() catch return error.OutOfMemory,
        .full_bytes = acc.full_bytes,
    };
}



test "read handler returns selected lines with deterministic timestamps" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "in.txt", .data = "a\nb\nc\n" });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.txt");
    defer std.testing.allocator.free(path);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 55,
    });

    const call: tools.Call = .{
        .id = "c1",
        .kind = .read,
        .args = .{
            .read = .{
                .path = path,
                .from_line = 2,
                .to_line = 3,
            },
        },
        .src = .system,
        .at_ms = 5,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const snap = try tool_snap.resultAlloc(std.testing.allocator, res);
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "call=c1
        \\start=55
        \\end=55
        \\out=1
        \\0=c1|55|stdout|false|b
        \\c
        \\
        \\final=ok|0
        \\"
    ).expectEqual(snap);
}

test "read handler returns invalid args on reversed line range" {
    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });

    const call: tools.Call = .{
        .id = "c2",
        .kind = .read,
        .args = .{
            .read = .{
                .path = "ignored",
                .from_line = 3,
                .to_line = 2,
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.InvalidArgs, handler.run(call, sink));
}

test "read handler returns not found for missing file" {
    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });

    const call: tools.Call = .{
        .id = "c3",
        .kind = .read,
        .args = .{
            .read = .{
                .path = "this-file-should-not-exist-7b3908b0.txt",
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.NotFound, handler.run(call, sink));
}

test "read handler returns kind mismatch for wrong call kind" {
    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });

    const call: tools.Call = .{
        .id = "c4",
        .kind = .write,
        .args = .{
            .write = .{
                .path = "x",
                .text = "y",
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.KindMismatch, handler.run(call, sink));
}

test "read handler truncates oversized output instead of failing TooLarge" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        out_len: usize,
        chunk_len: usize,
        trunc: bool,
        is_meta: bool,
        has_trunc_meta: bool,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    var text = std.ArrayList(u8).empty;
    defer text.deinit(std.testing.allocator);
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        try text.appendSlice(std.testing.allocator, "line-data-1234567890\n");
    }

    try tmp.dir.writeFile(.{ .sub_path = "big.txt", .data = text.items });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "big.txt");
    defer std.testing.allocator.free(path);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
        .now_ms = 99,
    });
    const call: tools.Call = .{
        .id = "c-big",
        .kind = .read,
        .args = .{
            .read = .{ .path = path },
        },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    try oh.snap(@src(),
        \\core.tools.read.test.read handler truncates oversized output instead of failing TooLarge.Snap
        \\  .out_len: usize = 2
        \\  .chunk_len: usize = 128
        \\  .trunc: bool = true
        \\  .is_meta: bool = true
        \\  .has_trunc_meta: bool = true
    ).expectEqual(Snap{
        .out_len = res.out.len,
        .chunk_len = res.out[0].chunk.len,
        .trunc = res.out[0].truncated,
        .is_meta = res.out[1].stream == .meta,
        .has_trunc_meta = std.mem.indexOf(u8, res.out[1].chunk, "\"type\":\"trunc\"") != null,
    });
}

test "read handler can target a line in very large file without TooLarge" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        out_len: usize,
        chunk: []const u8,
        trunc: bool,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    var txt = std.ArrayList(u8).empty;
    defer txt.deinit(std.testing.allocator);
    var w = txt.writer(std.testing.allocator);
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        try w.print("line-{d}\n", .{i + 1});
    }
    try tmp.dir.writeFile(.{ .sub_path = "huge.txt", .data = txt.items });

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "huge.txt");
    defer std.testing.allocator.free(path);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 64,
    });

    const call: tools.Call = .{
        .id = "c-huge",
        .kind = .read,
        .args = .{
            .read = .{
                .path = path,
                .from_line = 9999,
                .to_line = 9999,
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    try oh.snap(@src(),
        \\core.tools.read.test.read handler can target a line in very large file without TooLarge.Snap
        \\  .out_len: usize = 1
        \\  .chunk: []const u8
        \\    "line-9999
        \\"
        \\  .trunc: bool = false
    ).expectEqual(Snap{
        .out_len = res.out.len,
        .chunk = res.out[0].chunk,
        .trunc = res.out[0].truncated,
    });
}

test "read handler denies hardlinked file" {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "base.txt", .data = "secret\n" });
    try std.posix.linkat(tmp.dir.fd, "base.txt", tmp.dir.fd, "alias.txt", 0);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 64,
    });
    try std.testing.expectError(error.Denied, handler.run(.{
        .id = "c-link",
        .kind = .read,
        .args = .{
            .read = .{ .path = "alias.txt" },
        },
        .src = .model,
        .at_ms = 0,
    }, sink));
}
