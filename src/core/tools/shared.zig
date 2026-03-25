//! Shared tool infrastructure: accumulator, error mapping, result builders.
const std = @import("std");
const tools = @import("../tools.zig");

// ── Saturating arithmetic ──────────────────────────────────────────

pub fn satAdd(comptime T: type, a: T, b: anytype) T {
    const wide: T = if (@TypeOf(b) == T)
        b
    else
        std.math.cast(T, b) orelse return std.math.maxInt(T);
    const sum, const ov = @addWithOverflow(a, wide);
    if (ov == 0) return sum;
    return std.math.maxInt(T);
}

pub fn satMul(comptime T: type, a: T, b: T) T {
    const out, const ov = @mulWithOverflow(a, b);
    if (ov == 0) return out;
    return std.math.maxInt(T);
}

// ── Accumulator ────────────────────────────────────────────────────

pub const Acc = struct {
    alloc: std.mem.Allocator,
    limit: usize,
    buf: std.ArrayList(u8) = .empty,
    full_bytes: usize = 0,

    pub fn init(alloc: std.mem.Allocator, limit: usize) Acc {
        return .{ .alloc = alloc, .limit = limit };
    }

    pub fn deinit(self: *Acc) void {
        self.buf.deinit(self.alloc);
        self.* = undefined;
    }

    pub fn append(self: *Acc, data: []const u8) !void {
        self.full_bytes = satAdd(usize, self.full_bytes, data.len);
        if (self.buf.items.len >= self.limit) return;
        const keep = @min(data.len, self.limit - self.buf.items.len);
        if (keep == 0) return;
        try self.buf.appendSlice(self.alloc, data[0..keep]);
    }

    pub fn appendByte(self: *Acc, b: u8) std.mem.Allocator.Error!void {
        self.full_bytes = satAdd(usize, self.full_bytes, @as(usize, 1));
        if (self.buf.items.len >= self.limit) return;
        try self.buf.append(self.alloc, b);
    }

    pub fn takeOwned(self: *Acc) ![]u8 {
        const out = try self.buf.toOwnedSlice(self.alloc);
        self.buf = .empty;
        return out;
    }
};

// ── Error mapping ──────────────────────────────────────────────────

pub const FsErr = error{
    NotFound,
    Denied,
    TooLarge,
    Io,
    OutOfMemory,
};

/// Superset FS error mapper: covers open/read/write/dir/seek.
pub fn mapFsErr(err: anyerror) FsErr {
    return switch (err) {
        error.FileNotFound, error.NotDir => error.NotFound,
        error.AccessDenied,
        error.PermissionDenied,
        error.ReadOnlyFileSystem,
        error.LockViolation,
        error.SymLinkLoop,
        => error.Denied,
        error.FileTooBig => error.TooLarge,
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

// ── Result helpers ─────────────────────────────────────────────────

/// Build a tools.Result with stdout data + optional truncation meta.
pub fn buildResult(
    alloc: std.mem.Allocator,
    call_id: []const u8,
    now_ms: i64,
    data: []u8,
    max_bytes: usize,
    full_bytes: usize,
) error{OutOfMemory}!tools.Result {
    const meta = tools.truncate.metaFor(max_bytes, full_bytes);
    var meta_chunk: ?[]u8 = null;
    if (meta) |m| {
        meta_chunk = try tools.truncate.metaJsonAlloc(alloc, .stdout, m);
    }
    errdefer if (meta_chunk) |chunk| alloc.free(chunk);

    const out_len: usize = 1 + @as(usize, @intFromBool(meta_chunk != null));
    const out = try alloc.alloc(tools.Output, out_len);
    errdefer alloc.free(out);

    out[0] = .{
        .call_id = call_id,
        .seq = 0,
        .at_ms = now_ms,
        .stream = .stdout,
        .chunk = data,
        .owned = true,
        .truncated = meta != null,
    };

    if (meta_chunk) |chunk| {
        out[1] = .{
            .call_id = call_id,
            .seq = 1,
            .at_ms = now_ms,
            .stream = .meta,
            .chunk = chunk,
            .owned = true,
            .truncated = false,
        };
        meta_chunk = null;
    }

    return .{
        .call_id = call_id,
        .started_at_ms = now_ms,
        .ended_at_ms = now_ms,
        .out = out,
        .out_owned = true,
        .final = .{
            .ok = .{ .code = 0 },
        },
    };
}

/// Build a tools.Result from an already-sliced Truncated (for agent/skill pattern).
pub fn buildSlicedResult(
    alloc: std.mem.Allocator,
    call_id: []const u8,
    now_ms: i64,
    slice: tools.truncate.Truncated,
) error{OutOfMemory}!tools.Result {
    const data = try alloc.dupe(u8, slice.chunk);
    errdefer alloc.free(data);

    var meta_chunk: ?[]u8 = null;
    if (slice.meta) |meta| {
        meta_chunk = try tools.truncate.metaJsonAlloc(alloc, .stdout, meta);
    }
    errdefer if (meta_chunk) |chunk| alloc.free(chunk);

    const out_len: usize = 1 + @as(usize, @intFromBool(meta_chunk != null));
    const out = try alloc.alloc(tools.Output, out_len);
    errdefer alloc.free(out);

    out[0] = .{
        .call_id = call_id,
        .seq = 0,
        .at_ms = now_ms,
        .stream = .stdout,
        .chunk = data,
        .owned = true,
        .truncated = slice.truncated,
    };

    if (meta_chunk) |chunk| {
        out[1] = .{
            .call_id = call_id,
            .seq = 1,
            .at_ms = now_ms,
            .stream = .meta,
            .chunk = chunk,
            .owned = true,
            .truncated = false,
        };
    }

    return .{
        .call_id = call_id,
        .started_at_ms = now_ms,
        .ended_at_ms = now_ms,
        .out = out,
        .out_owned = true,
        .final = .{
            .ok = .{ .code = 0 },
        },
    };
}

/// Free a tools.Result whose out slice is owned.
pub fn deinitResult(alloc: std.mem.Allocator, res: tools.Result) void {
    if (!res.out_owned) return;
    for (res.out) |out| {
        if (out.owned) alloc.free(out.chunk);
    }
    alloc.free(res.out);
}

/// Construct a failed result (no output chunks).
pub fn fail(call: tools.Call, kind: tools.Result.ErrKind, msg: []const u8) tools.Result {
    return .{
        .call_id = call.id,
        .started_at_ms = call.at_ms,
        .ended_at_ms = call.at_ms,
        .out = &.{},
        .final = .{
            .failed = .{
                .kind = kind,
                .msg = msg,
            },
        },
    };
}

/// No-op event sink for tests.
pub fn noopSink() *tools.Sink {
    const Impl = struct {
        sink: tools.Sink = .{ .vt = &Bind.vt },
        fn push(_: *@This(), _: tools.Event) !void {}
        const Bind = tools.Sink.Bind(@This(), push);
    };
    const S = struct {
        var impl: Impl = .{};
    };
    return &S.impl.sink;
}

// ── Tests ──────────────────────────────────────────────────────────

test "satAdd usize overflow saturates" {
    try std.testing.expectEqual(std.math.maxInt(usize), satAdd(usize, std.math.maxInt(usize), @as(usize, 1)));
    try std.testing.expectEqual(@as(usize, 5), satAdd(usize, @as(usize, 2), @as(usize, 3)));
}

test "satAdd u32 overflow saturates" {
    try std.testing.expectEqual(std.math.maxInt(u32), satAdd(u32, std.math.maxInt(u32), @as(u32, 1)));
    try std.testing.expectEqual(@as(u32, 10), satAdd(u32, @as(u32, 7), @as(u32, 3)));
}

test "satMul usize overflow saturates" {
    try std.testing.expectEqual(std.math.maxInt(usize), satMul(usize, std.math.maxInt(usize), 2));
    try std.testing.expectEqual(@as(usize, 6), satMul(usize, 2, 3));
}

test "Acc truncates at limit" {
    var acc = Acc.init(std.testing.allocator, 5);
    defer acc.deinit();
    try acc.append("abc");
    try acc.append("defgh");
    try std.testing.expectEqual(@as(usize, 8), acc.full_bytes);
    const out = try acc.takeOwned();
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("abcde", out);
}

test "Acc appendByte truncates at limit" {
    var acc = Acc.init(std.testing.allocator, 2);
    defer acc.deinit();
    try acc.appendByte('a');
    try acc.appendByte('b');
    try acc.appendByte('c');
    try std.testing.expectEqual(@as(usize, 3), acc.full_bytes);
    const out = try acc.takeOwned();
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("ab", out);
}

test "buildResult no truncation" {
    const data = try std.testing.allocator.dupe(u8, "hello");
    const res = try buildResult(std.testing.allocator, "t1", 10, data, 100, 5);
    defer deinitResult(std.testing.allocator, res);
    try std.testing.expectEqual(@as(usize, 1), res.out.len);
    try std.testing.expectEqualStrings("hello", res.out[0].chunk);
    try std.testing.expect(!res.out[0].truncated);
}

test "buildResult with truncation" {
    const data = try std.testing.allocator.dupe(u8, "he");
    const res = try buildResult(std.testing.allocator, "t2", 10, data, 2, 100);
    defer deinitResult(std.testing.allocator, res);
    try std.testing.expectEqual(@as(usize, 2), res.out.len);
    try std.testing.expect(res.out[0].truncated);
    try std.testing.expectEqual(tools.Output.Stream.meta, res.out[1].stream);
}

test "fail builds failed result" {
    const call: tools.Call = .{
        .id = "f1",
        .kind = .read,
        .args = .{ .read = .{ .path = "x" } },
        .src = .model,
        .at_ms = 5,
    };
    const res = fail(call, .not_found, "gone");
    try std.testing.expectEqualStrings("f1", res.call_id);
    try std.testing.expectEqualStrings("gone", res.final.failed.msg);
}

test "mapFsErr maps known errors" {
    try std.testing.expectEqual(FsErr.NotFound, mapFsErr(error.FileNotFound));
    try std.testing.expectEqual(FsErr.NotFound, mapFsErr(error.NotDir));
    try std.testing.expectEqual(FsErr.Denied, mapFsErr(error.AccessDenied));
    try std.testing.expectEqual(FsErr.Denied, mapFsErr(error.SymLinkLoop));
    try std.testing.expectEqual(FsErr.TooLarge, mapFsErr(error.FileTooBig));
    try std.testing.expectEqual(FsErr.OutOfMemory, mapFsErr(error.OutOfMemory));
    try std.testing.expectEqual(FsErr.Io, mapFsErr(error.Unexpected));
}
