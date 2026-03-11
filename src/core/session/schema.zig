const std = @import("std");

pub const version_current: u16 = 1;

pub const Event = struct {
    version: u16 = version_current,
    at_ms: i64 = 0,
    data: Data = .{ .noop = {} },

    pub const Data = union(Tag) {
        noop: void,
        prompt: Text,
        text: Text,
        thinking: Text,
        tool_call: ToolCall,
        tool_result: ToolResult,
        usage: Usage,
        stop: Stop,
        err: Text,
    };

    pub const Tag = enum {
        noop,
        prompt,
        text,
        thinking,
        tool_call,
        tool_result,
        usage,
        stop,
        err,
    };

    pub const Text = struct {
        text: []const u8,
    };

    pub const ToolCall = struct {
        id: []const u8,
        name: []const u8,
        args: []const u8,
    };

    pub const ToolResult = struct {
        id: []const u8,
        out: []const u8,
        is_err: bool = false,
    };

    pub const Usage = struct {
        in_tok: u64 = 0,
        out_tok: u64 = 0,
        tot_tok: u64 = 0,
        cache_read: u64 = 0,
        cache_write: u64 = 0,
    };

    pub const Stop = struct {
        reason: StopReason,
    };

    pub const StopReason = enum {
        done,
        max_out,
        tool,
        canceled,
        err,
    };

    /// Deep-copy all string slices into `alloc`. The result is fully
    /// independent of the source (e.g. a ReplayReader's per-call arena).
    pub fn dupe(self: Event, alloc: std.mem.Allocator) error{OutOfMemory}!Event {
        return .{
            .version = self.version,
            .at_ms = self.at_ms,
            .data = try dupeData(alloc, self.data),
        };
    }

    /// Free strings previously allocated by `dupe`.
    pub fn free(self: Event, alloc: std.mem.Allocator) void {
        freeData(alloc, self.data);
    }

    fn dupeData(alloc: std.mem.Allocator, data: Data) error{OutOfMemory}!Data {
        return switch (data) {
            .noop => .{ .noop = {} },
            .prompt => |t| .{ .prompt = .{ .text = try alloc.dupe(u8, t.text) } },
            .text => |t| .{ .text = .{ .text = try alloc.dupe(u8, t.text) } },
            .thinking => |t| .{ .thinking = .{ .text = try alloc.dupe(u8, t.text) } },
            .tool_call => |tc| blk: {
                const id = try alloc.dupe(u8, tc.id);
                errdefer alloc.free(id);
                const name = try alloc.dupe(u8, tc.name);
                errdefer alloc.free(name);
                const args = try alloc.dupe(u8, tc.args);
                break :blk .{ .tool_call = .{ .id = id, .name = name, .args = args } };
            },
            .tool_result => |tr| blk: {
                const id = try alloc.dupe(u8, tr.id);
                errdefer alloc.free(id);
                const out = try alloc.dupe(u8, tr.out);
                break :blk .{ .tool_result = .{ .id = id, .out = out, .is_err = tr.is_err } };
            },
            .usage => |u| .{ .usage = u },
            .stop => |s| .{ .stop = s },
            .err => |t| .{ .err = .{ .text = try alloc.dupe(u8, t.text) } },
        };
    }

    fn freeData(alloc: std.mem.Allocator, data: Data) void {
        switch (data) {
            .noop, .usage, .stop => {},
            .prompt, .text, .thinking, .err => |t| alloc.free(t.text),
            .tool_call => |tc| {
                alloc.free(tc.id);
                alloc.free(tc.name);
                alloc.free(tc.args);
            },
            .tool_result => |tr| {
                alloc.free(tr.id);
                alloc.free(tr.out);
            },
        }
    }
};

pub const DecodeError = std.json.ParseError(std.json.Scanner) || error{
    UnsupportedVersion,
};

pub fn encodeAlloc(alloc: std.mem.Allocator, ev: Event) error{OutOfMemory}![]u8 {
    var out = ev;
    out.version = version_current;
    return std.json.Stringify.valueAlloc(alloc, out, .{});
}

pub fn decodeSlice(alloc: std.mem.Allocator, raw: []const u8) DecodeError!std.json.Parsed(Event) {
    var parsed = try std.json.parseFromSlice(Event, alloc, raw, .{
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();

    if (parsed.value.version != version_current) return error.UnsupportedVersion;

    return parsed;
}

test "session event json roundtrip" {
    const ev = Event{
        .version = 99,
        .at_ms = 42,
        .data = .{ .tool_result = .{
            .id = "call-1",
            .out = "{\"ok\":true}",
            .is_err = false,
        } },
    };

    const raw = try encodeAlloc(std.testing.allocator, ev);
    defer std.testing.allocator.free(raw);

    var parsed = try decodeSlice(std.testing.allocator, raw);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u16, version_current), parsed.value.version);
    try std.testing.expectEqual(@as(i64, 42), parsed.value.at_ms);

    switch (parsed.value.data) {
        .tool_result => |out| {
            try std.testing.expectEqualStrings("call-1", out.id);
            try std.testing.expectEqualStrings("{\"ok\":true}", out.out);
            try std.testing.expect(!out.is_err);
        },
        else => try std.testing.expect(false),
    }
}

test "session event json rejects wrong version" {
    const raw = "{\"version\":7,\"at_ms\":1,\"data\":{\"noop\":{}}}";
    try std.testing.expectError(error.UnsupportedVersion, decodeSlice(std.testing.allocator, raw));
}

test "Event.dupe deep-copies tool_call strings" {
    const alloc = std.testing.allocator;
    const orig = Event{
        .at_ms = 42,
        .data = .{ .tool_call = .{
            .id = "call-1",
            .name = "bash",
            .args = "{\"cmd\":\"ls\"}",
        } },
    };
    const d = try orig.dupe(alloc);
    defer d.free(alloc);

    try std.testing.expectEqual(@as(i64, 42), d.at_ms);
    const tc = d.data.tool_call;
    try std.testing.expectEqualStrings("call-1", tc.id);
    try std.testing.expectEqualStrings("bash", tc.name);
    try std.testing.expectEqualStrings("{\"cmd\":\"ls\"}", tc.args);

    // Verify independent allocation (pointers differ)
    try std.testing.expect(tc.id.ptr != orig.data.tool_call.id.ptr);
    try std.testing.expect(tc.name.ptr != orig.data.tool_call.name.ptr);
    try std.testing.expect(tc.args.ptr != orig.data.tool_call.args.ptr);
}

test "Event.dupe deep-copies tool_result strings" {
    const alloc = std.testing.allocator;
    const orig = Event{
        .at_ms = 10,
        .data = .{ .tool_result = .{
            .id = "c2",
            .out = "output-data",
            .is_err = true,
        } },
    };
    const d = try orig.dupe(alloc);
    defer d.free(alloc);

    const tr = d.data.tool_result;
    try std.testing.expectEqualStrings("c2", tr.id);
    try std.testing.expectEqualStrings("output-data", tr.out);
    try std.testing.expect(tr.is_err);
    try std.testing.expect(tr.id.ptr != orig.data.tool_result.id.ptr);
}

test "Event.dupe copies text variants" {
    const alloc = std.testing.allocator;
    const cases = [_]Event{
        .{ .data = .{ .text = .{ .text = "hello" } } },
        .{ .data = .{ .prompt = .{ .text = "prompt" } } },
        .{ .data = .{ .thinking = .{ .text = "think" } } },
        .{ .data = .{ .err = .{ .text = "oops" } } },
    };
    for (cases) |ev| {
        const d = try ev.dupe(alloc);
        defer d.free(alloc);
        // Encode both and compare — ensures full fidelity
        const a = try encodeAlloc(alloc, ev);
        defer alloc.free(a);
        const b = try encodeAlloc(alloc, d);
        defer alloc.free(b);
        try std.testing.expectEqualStrings(a, b);
    }
}

test "Event.dupe noop/usage/stop are trivial" {
    const alloc = std.testing.allocator;
    const noop = Event{ .data = .{ .noop = {} } };
    const d1 = try noop.dupe(alloc);
    d1.free(alloc); // no-op free

    const usage = Event{ .data = .{ .usage = .{ .in_tok = 5 } } };
    const d2 = try usage.dupe(alloc);
    try std.testing.expectEqual(@as(u64, 5), d2.data.usage.in_tok);
    d2.free(alloc);

    const stop = Event{ .data = .{ .stop = .{ .reason = .done } } };
    const d3 = try stop.dupe(alloc);
    try std.testing.expectEqual(Event.StopReason.done, d3.data.stop.reason);
    d3.free(alloc);
}

// Property: encode/decode roundtrip preserves text events
test "schema property: text event roundtrip" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { ts: i64, text: zc.String }) bool {
            const alloc = std.testing.allocator;
            const ev = Event{
                .at_ms = args.ts,
                .data = .{ .text = .{ .text = args.text.slice() } },
            };
            const raw = encodeAlloc(alloc, ev) catch return true;
            defer alloc.free(raw);
            var parsed = decodeSlice(alloc, raw) catch return false;
            defer parsed.deinit();
            if (parsed.value.at_ms != args.ts) return false;
            return switch (parsed.value.data) {
                .text => |t| std.mem.eql(u8, t.text, args.text.slice()),
                else => false,
            };
        }
    }.prop, .{ .iterations = 200 });
}

// Property: encode/decode roundtrip preserves tool_call events
test "schema property: tool_call event roundtrip" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { id: zc.Id, name: zc.Id, a: zc.String }) bool {
            const alloc = std.testing.allocator;
            const ev = Event{
                .at_ms = 100,
                .data = .{ .tool_call = .{
                    .id = args.id.slice(),
                    .name = args.name.slice(),
                    .args = args.a.slice(),
                } },
            };
            const raw = encodeAlloc(alloc, ev) catch return true;
            defer alloc.free(raw);
            var parsed = decodeSlice(alloc, raw) catch return false;
            defer parsed.deinit();
            return switch (parsed.value.data) {
                .tool_call => |tc| std.mem.eql(u8, tc.id, args.id.slice()) and
                    std.mem.eql(u8, tc.name, args.name.slice()) and
                    std.mem.eql(u8, tc.args, args.a.slice()),
                else => false,
            };
        }
    }.prop, .{ .iterations = 200 });
}

// Property: dupe+encode == encode (dupe preserves all data)
test "schema property: dupe preserves tool_call encode" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { id: zc.Id, name: zc.Id, a: zc.String }) bool {
            const alloc = std.testing.allocator;
            const ev = Event{
                .at_ms = 100,
                .data = .{ .tool_call = .{
                    .id = args.id.slice(),
                    .name = args.name.slice(),
                    .args = args.a.slice(),
                } },
            };
            const d = ev.dupe(alloc) catch return true;
            defer d.free(alloc);
            const a = encodeAlloc(alloc, ev) catch return true;
            defer alloc.free(a);
            const b = encodeAlloc(alloc, d) catch return true;
            defer alloc.free(b);
            return std.mem.eql(u8, a, b);
        }
    }.prop, .{ .iterations = 200 });
}

test "schema property: tool_result event roundtrip" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { id: zc.Id, out: zc.String, is_err: bool }) bool {
            const alloc = std.testing.allocator;
            const ev = Event{
                .at_ms = 100,
                .data = .{ .tool_result = .{
                    .id = args.id.slice(),
                    .out = args.out.slice(),
                    .is_err = args.is_err,
                } },
            };
            const raw = encodeAlloc(alloc, ev) catch return true;
            defer alloc.free(raw);
            var parsed = decodeSlice(alloc, raw) catch return false;
            defer parsed.deinit();
            return switch (parsed.value.data) {
                .tool_result => |tr| std.mem.eql(u8, tr.id, args.id.slice()) and
                    std.mem.eql(u8, tr.out, args.out.slice()) and
                    tr.is_err == args.is_err,
                else => false,
            };
        }
    }.prop, .{ .iterations = 200 });
}

test "schema property: dupe preserves tool_result encode" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { id: zc.Id, out: zc.String, is_err: bool }) bool {
            const alloc = std.testing.allocator;
            const ev = Event{
                .at_ms = 100,
                .data = .{ .tool_result = .{
                    .id = args.id.slice(),
                    .out = args.out.slice(),
                    .is_err = args.is_err,
                } },
            };
            const dup = ev.dupe(alloc) catch return true;
            defer dup.free(alloc);
            const a = encodeAlloc(alloc, ev) catch return true;
            defer alloc.free(a);
            const b = encodeAlloc(alloc, dup) catch return true;
            defer alloc.free(b);
            return std.mem.eql(u8, a, b);
        }
    }.prop, .{ .iterations = 200 });
}
