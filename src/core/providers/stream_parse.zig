//! Line-oriented stream parser for provider SSE responses.
const std = @import("std");
const providers = @import("api.zig");
const types = @import("types.zig");

pub const Err = types.Err;

pub const Parser = struct {
    buf: std.ArrayListUnmanaged(u8) = .{},
    saw_stop: bool = false,

    pub fn deinit(self: *Parser, alloc: std.mem.Allocator) void {
        self.buf.deinit(alloc);
    }

    pub fn feed(
        self: *Parser,
        alloc: std.mem.Allocator,
        evs: *std.ArrayListUnmanaged(providers.Event),
        chunk: []const u8,
    ) Err!void {
        self.buf.appendSlice(alloc, chunk) catch return error.OutOfMemory;

        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, self.buf.items, start, '\n')) |nl| {
            const line = trimCr(self.buf.items[start..nl]);
            if (line.len > 0) {
                try parseLine(alloc, evs, line, &self.saw_stop);
            }
            start = nl + 1;
        }

        if (start == 0) return;
        const rem = self.buf.items[start..];
        std.mem.copyForwards(u8, self.buf.items[0..rem.len], rem);
        self.buf.items.len = rem.len;
    }

    pub fn finish(
        self: *Parser,
        alloc: std.mem.Allocator,
        evs: *std.ArrayListUnmanaged(providers.Event),
    ) Err!void {
        if (self.buf.items.len > 0) {
            const line = trimCr(self.buf.items);
            if (line.len > 0) {
                try parseLine(alloc, evs, line, &self.saw_stop);
            }
            self.buf.items.len = 0;
        }

        if (!self.saw_stop) return error.MissingStop;
    }
};

fn trimCr(raw: []const u8) []const u8 {
    if (raw.len > 0 and raw[raw.len - 1] == '\r') return raw[0 .. raw.len - 1];
    return raw;
}

fn parseLine(
    alloc: std.mem.Allocator,
    evs: *std.ArrayListUnmanaged(providers.Event),
    line: []const u8,
    saw_stop: *bool,
) Err!void {
    const sep = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadFrame;
    const tag = line[0..sep];
    const val = line[sep + 1 ..];

    const Tag = enum { text, thinking, tool_call, tool_result, usage, stop, err };
    const tag_map = std.StaticStringMap(Tag).initComptime(.{
        .{ "text", .text },
        .{ "thinking", .thinking },
        .{ "tool_call", .tool_call },
        .{ "tool_result", .tool_result },
        .{ "usage", .usage },
        .{ "stop", .stop },
        .{ "err", .err },
    });

    const resolved = tag_map.get(tag) orelse return error.UnknownTag;
    const ev: providers.Event = switch (resolved) {
        .text => .{ .text = try dup(alloc, val) },
        .thinking => .{ .thinking = try dup(alloc, val) },
        .tool_call => blk: {
            const parts = try split3(val, '|');
            break :blk .{ .tool_call = .{
                .id = try dup(alloc, parts[0]),
                .name = try dup(alloc, parts[1]),
                .args = try dup(alloc, parts[2]),
            } };
        },
        .tool_result => blk: {
            const parts = try split3(val, '|');
            break :blk .{ .tool_result = .{
                .id = try dup(alloc, parts[0]),
                .out = try dup(alloc, parts[2]),
                .is_err = try parseBool(parts[1]),
            } };
        },
        .usage => .{ .usage = try parseUsage(val) },
        .stop => blk: {
            saw_stop.* = true;
            break :blk .{ .stop = .{ .reason = try parseStop(val) } };
        },
        .err => .{ .err = try dup(alloc, val) },
    };
    try appendEv(alloc, evs, ev);
}

fn appendEv(
    alloc: std.mem.Allocator,
    evs: *std.ArrayListUnmanaged(providers.Event),
    ev: providers.Event,
) Err!void {
    evs.append(alloc, ev) catch return error.OutOfMemory;
}

fn split3(raw: []const u8, sep: u8) Err![3][]const u8 {
    var out: [3][]const u8 = undefined;
    var idx: usize = 0;
    var from: usize = 0;
    while (idx < 2) : (idx += 1) {
        const at = std.mem.indexOfScalarPos(u8, raw, from, sep) orelse return error.BadFrame;
        out[idx] = raw[from..at];
        from = at + 1;
    }
    if (from > raw.len) return error.BadFrame;
    out[2] = raw[from..];
    return out;
}

fn parseBool(raw: []const u8) Err!bool {
    const map = std.StaticStringMap(bool).initComptime(.{
        .{ "0", false },
        .{ "1", true },
    });
    return map.get(raw) orelse error.BadFrame;
}

fn parseUsage(raw: []const u8) Err!providers.Usage {
    const parts = try split3(raw, ',');
    return .{
        .in_tok = try parseU64(parts[0]),
        .out_tok = try parseU64(parts[1]),
        .tot_tok = try parseU64(parts[2]),
    };
}

fn parseU64(raw: []const u8) Err!u64 {
    return std.fmt.parseUnsigned(u64, raw, 10) catch return error.InvalidUsage;
}

fn parseStop(raw: []const u8) Err!providers.StopReason {
    const map = std.StaticStringMap(providers.StopReason).initComptime(.{
        .{ "done", .done },
        .{ "max_out", .max_out },
        .{ "tool", .tool },
        .{ "canceled", .canceled },
        .{ "err", .err },
    });
    return map.get(raw) orelse error.UnknownStop;
}

fn dup(alloc: std.mem.Allocator, raw: []const u8) Err![]const u8 {
    return alloc.dupe(u8, raw) catch return error.OutOfMemory;
}

const ParseRes = struct {
    arena: std.heap.ArenaAllocator,
    evs: []providers.Event,

    fn deinit(self: *ParseRes) void {
        self.arena.deinit();
    }
};

fn parseChunks(alloc: std.mem.Allocator, chunks: []const []const u8) Err!ParseRes {
    var arena = std.heap.ArenaAllocator.init(alloc);
    errdefer arena.deinit();

    const ar = arena.allocator();

    var p = Parser{};
    defer p.deinit(ar);

    var evs: std.ArrayListUnmanaged(providers.Event) = .{};
    errdefer evs.deinit(ar);

    for (chunks) |chunk| {
        try p.feed(ar, &evs, chunk);
    }
    try p.finish(ar, &evs);

    return .{
        .arena = arena,
        .evs = evs.toOwnedSlice(ar) catch return error.OutOfMemory,
    };
}

test "parser normalizes chunked frames and preserves order" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const chunks = [_][]const u8{
        "text:he",
        "llo\r\nthinking:plan\n",
        "tool_call:id-1|read|{\"path\":\"a\"}\n",
        "stop:done\n",
    };

    var out = try parseChunks(std.testing.allocator, chunks[0..]);
    defer out.deinit();

    try std.testing.expectEqual(@as(usize, 4), out.evs.len);
    const got = try snapEvs(std.testing.allocator, out.evs);
    defer std.testing.allocator.free(got);
    try oh.snap(@src(),
        \\[]core.providers.stream_parse.SnapEv
        \\  [0]: core.providers.stream_parse.SnapEv
        \\    .text: []const u8
        \\      "hello"
        \\  [1]: core.providers.stream_parse.SnapEv
        \\    .thinking: []const u8
        \\      "plan"
        \\  [2]: core.providers.stream_parse.SnapEv
        \\    .tool_call: core.providers.stream_parse.SnapEv.ToolCall
        \\      .id: []const u8
        \\        "id-1"
        \\      .name: []const u8
        \\        "read"
        \\      .args_path: ?[]const u8
        \\        "a"
        \\      .args_raw: ?[]const u8
        \\        null
        \\  [3]: core.providers.stream_parse.SnapEv
        \\    .stop: core.providers.api.StopReason
        \\      .done
    ).expectEqual(got);
}

test "parser handles tool_result usage and err frames" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const chunks = [_][]const u8{
        "tool_result:call-7|1|stderr\nusage:3,5,8\nerr:oops\nstop:err",
    };

    var out = try parseChunks(std.testing.allocator, chunks[0..]);
    defer out.deinit();

    try std.testing.expectEqual(@as(usize, 4), out.evs.len);
    const got = try snapEvs(std.testing.allocator, out.evs);
    defer std.testing.allocator.free(got);
    try oh.snap(@src(),
        \\[]core.providers.stream_parse.SnapEv
        \\  [0]: core.providers.stream_parse.SnapEv
        \\    .tool_result: core.providers.stream_parse.SnapEv.ToolResult
        \\      .id: []const u8
        \\        "call-7"
        \\      .out: []const u8
        \\        "stderr"
        \\      .is_err: bool = true
        \\  [1]: core.providers.stream_parse.SnapEv
        \\    .usage: core.providers.api.Usage
        \\      .in_tok: u64 = 3
        \\      .out_tok: u64 = 5
        \\      .tot_tok: u64 = 8
        \\      .cache_read: u64 = 0
        \\      .cache_write: u64 = 0
        \\  [2]: core.providers.stream_parse.SnapEv
        \\    .err: []const u8
        \\      "oops"
        \\  [3]: core.providers.stream_parse.SnapEv
        \\    .stop: core.providers.api.StopReason
        \\      .err
    ).expectEqual(got);
}

test "parser rejects malformed frames and missing stop" {
    const bad_chunks = [_][]const u8{"bad-frame\n"};
    try std.testing.expectError(error.BadFrame, parseChunks(std.testing.allocator, bad_chunks[0..]));

    const no_stop = [_][]const u8{"text:ok\n"};
    try std.testing.expectError(error.MissingStop, parseChunks(std.testing.allocator, no_stop[0..]));

    const bad_usage = [_][]const u8{"usage:1,2,nope\nstop:done\n"};
    try std.testing.expectError(error.InvalidUsage, parseChunks(std.testing.allocator, bad_usage[0..]));
}

fn splitWithSeed(alloc: std.mem.Allocator, raw: []const u8, seed: u64) ![][]const u8 {
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();

    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer out.deinit(alloc);

    var at: usize = 0;
    while (at < raw.len) {
        const rem = raw.len - at;
        const n = rnd.intRangeAtMost(usize, 1, @min(rem, 7));
        try out.append(alloc, raw[at .. at + n]);
        at += n;
    }
    return try out.toOwnedSlice(alloc);
}

fn eventJson(alloc: std.mem.Allocator, ev: providers.Event) ![]u8 {
    return std.json.Stringify.valueAlloc(alloc, ev, .{});
}

fn eventsJson(alloc: std.mem.Allocator, evs: []const providers.Event) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    for (evs, 0..) |ev, i| {
        if (i != 0) try out.append(alloc, '\n');
        const raw = try eventJson(alloc, ev);
        defer alloc.free(raw);
        try out.appendSlice(alloc, raw);
    }
    return out.toOwnedSlice(alloc);
}

const SnapEv = union(enum) {
    const ToolCall = struct {
        id: []const u8,
        name: []const u8,
        args_path: ?[]const u8 = null,
        args_raw: ?[]const u8 = null,
    };

    const ToolResult = struct {
        id: []const u8,
        out: []const u8,
        is_err: bool,
    };

    text: []const u8,
    thinking: []const u8,
    tool_call: ToolCall,
    tool_result: ToolResult,
    usage: providers.Usage,
    stop: providers.StopReason,
    err: []const u8,
};

fn snapEvs(alloc: std.mem.Allocator, evs: []const providers.Event) ![]SnapEv {
    var out = std.ArrayList(SnapEv).empty;
    defer out.deinit(alloc);
    for (evs) |ev| switch (ev) {
        .text => |text| try out.append(alloc, .{ .text = text }),
        .thinking => |text| try out.append(alloc, .{ .thinking = text }),
        .tool_call => |call| try out.append(alloc, .{ .tool_call = .{
            .id = call.id,
            .name = call.name,
            .args_path = toolCallPath(call.args),
            .args_raw = if (toolCallPath(call.args) == null) call.args else null,
        } }),
        .tool_result => |res| try out.append(alloc, .{ .tool_result = .{
            .id = res.id,
            .out = res.out,
            .is_err = res.is_err,
        } }),
        .usage => |usage| try out.append(alloc, .{ .usage = usage }),
        .stop => |stop| try out.append(alloc, .{ .stop = stop.reason }),
        .err => |text| try out.append(alloc, .{ .err = text }),
    };
    return out.toOwnedSlice(alloc);
}

fn toolCallPath(raw: []const u8) ?[]const u8 {
    const key = "\"path\":\"";
    const start = std.mem.indexOf(u8, raw, key) orelse return null;
    const val = raw[start + key.len ..];
    const end = std.mem.indexOfScalar(u8, val, '"') orelse return null;
    return val[0..end];
}

test "parser property random chunk boundaries preserve parsed stream" {
    const payload =
        \\text:alpha
        \\thinking:beta
        \\tool_call:id-1|read|{"path":"a.txt"}
        \\tool_result:id-1|0|ok
        \\usage:3,5,8
        \\err:oops
        \\stop:done
        \\
    ;

    const base_chunks = [_][]const u8{payload};
    var baseline = try parseChunks(std.testing.allocator, base_chunks[0..]);
    defer baseline.deinit();

    var seed: u64 = 1;
    while (seed <= 96) : (seed += 1) {
        const chunks = try splitWithSeed(std.testing.allocator, payload, seed);
        defer std.testing.allocator.free(chunks);

        var out = try parseChunks(std.testing.allocator, chunks);
        defer out.deinit();

        try std.testing.expectEqual(baseline.evs.len, out.evs.len);
        for (baseline.evs, out.evs) |lhs, rhs| {
            const lhs_json = try eventJson(std.testing.allocator, lhs);
            defer std.testing.allocator.free(lhs_json);
            const rhs_json = try eventJson(std.testing.allocator, rhs);
            defer std.testing.allocator.free(rhs_json);
            try std.testing.expectEqualStrings(lhs_json, rhs_json);
        }
    }
}

test "parser fuzz malformed frames return typed errors only" {
    var prng = std.Random.DefaultPrng.init(0xC0DE_5EED);
    const rnd = prng.random();

    var iter: usize = 0;
    while (iter < 4096) : (iter += 1) {
        const n = rnd.intRangeAtMost(usize, 1, 64);
        var raw: [64]u8 = undefined;
        rnd.bytes(raw[0..n]);

        var i: usize = 0;
        while (i < n) : (i += 1) {
            if (raw[i] == '\n' or raw[i] == '\r' or raw[i] == 0) raw[i] = 'x';
        }

        var payload = std.ArrayList(u8).empty;
        defer payload.deinit(std.testing.allocator);
        try payload.appendSlice(std.testing.allocator, raw[0..n]);
        try payload.appendSlice(std.testing.allocator, "\nstop:done\n");

        const chunks = [_][]const u8{payload.items};
        var out = parseChunks(std.testing.allocator, chunks[0..]) catch |err| switch (err) {
            error.BadFrame,
            error.UnknownTag,
            error.InvalidUsage,
            error.UnknownStop,
            error.OutOfMemory,
            => continue,
            else => return err,
        };
        out.deinit();
    }
}
