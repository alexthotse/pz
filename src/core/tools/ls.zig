//! Directory listing tool with path guarding.
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
        if (call.kind != .ls) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .ls) return error.KindMismatch;

        const args = call.args.ls;
        if (args.path.len == 0) return error.InvalidArgs;

        var dir = path_guard.openDir(args.path, .{ .iterate = true }) catch |open_err| {
            return shared.mapFsErr(open_err);
        };
        defer dir.close();

        var items = std.ArrayList(Item).empty;
        defer {
            for (items.items) |it| self.alloc.free(it.name);
            items.deinit(self.alloc);
        }

        var it = dir.iterate();
        while (it.next() catch |next_err| return shared.mapFsErr(next_err)) |ent| {
            if (!args.all and ent.name.len > 0 and ent.name[0] == '.') continue;

            const name = self.alloc.dupe(u8, ent.name) catch return error.OutOfMemory;
            errdefer self.alloc.free(name);
            items.append(self.alloc, .{
                .name = name,
                .kind = ent.kind,
            }) catch return error.OutOfMemory;
        }

        std.sort.pdq(Item, items.items, {}, lessItem);

        var acc = Acc.init(self.alloc, self.max_bytes);
        defer acc.deinit();

        for (items.items) |item| {
            try acc.append(item.name);
            if (item.kind == .directory) try acc.append("/");
            try acc.append("\n");
        }

        const data = acc.takeOwned() catch return error.OutOfMemory;
        errdefer self.alloc.free(data);

        return shared.buildResult(self.alloc, call.id, self.now_ms, data, self.max_bytes, acc.full_bytes) catch return error.OutOfMemory;
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        shared.deinitResult(self.alloc, res);
    }
};

const Item = struct {
    name: []u8,
    kind: std.fs.Dir.Entry.Kind,
};

fn lessItem(_: void, a: Item, b: Item) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}



test "ls handler lists entries in deterministic order and marks directories" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("d");
    try tmp.dir.writeFile(.{ .sub_path = "b.txt", .data = "b" });
    try tmp.dir.writeFile(.{ .sub_path = "a.txt", .data = "a" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 44,
    });
    const call: tools.Call = .{
        .id = "l1",
        .kind = .ls,
        .args = .{
            .ls = .{
                .path = root,
            },
        },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "out={d}\n0={s}|{s}|{}\n", .{
        res.out.len,
        @tagName(res.out[0].stream),
        res.out[0].chunk,
        res.out[0].truncated,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "out=1
        \\0=stdout|a.txt
        \\b.txt
        \\d/
        \\|false
        \\"
    ).expectEqual(snap);
}

test "ls handler rejects missing path and wrong kind" {
    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 64,
    });

    const bad_kind: tools.Call = .{
        .id = "l2",
        .kind = .read,
        .args = .{
            .read = .{ .path = "x" },
        },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.KindMismatch, handler.run(bad_kind, sink));

    const missing: tools.Call = .{
        .id = "l3",
        .kind = .ls,
        .args = .{
            .ls = .{ .path = "no-such-dir-29341" },
        },
        .src = .model,
        .at_ms = 0,
    };
    try std.testing.expectError(error.NotFound, handler.run(missing, sink));
}

test "ls handler emits truncation metadata when output exceeds limit" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "one", .data = "" });
    try tmp.dir.writeFile(.{ .sub_path = "two", .data = "" });
    try tmp.dir.writeFile(.{ .sub_path = "three", .data = "" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const sink = noop.sink();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 8,
    });
    const call: tools.Call = .{
        .id = "l4",
        .kind = .ls,
        .args = .{
            .ls = .{ .path = root },
        },
        .src = .model,
        .at_ms = 0,
    };
    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "out={d}\n0={s}|{}\n1={s}|len={d}\n", .{
        res.out.len,
        @tagName(res.out[0].stream),
        res.out[0].truncated,
        @tagName(res.out[1].stream),
        res.out[1].chunk.len,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "out=2
        \\0=stdout|true
        \\1=meta|len=99
        \\"
    ).expectEqual(snap);
}
