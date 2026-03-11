const std = @import("std");
const testing = std.testing;

pub const protocol_version: u16 = 1;
pub const hash_hex_len: usize = 64;

/// JSON-line wire frame for parent/child agent RPC.
pub const Frame = struct {
    protocol_version: u16,
    seq: u32,
    msg: Msg,

    pub fn init(seq: u32, msg: Msg) Frame {
        return .{
            .protocol_version = protocol_version,
            .seq = seq,
            .msg = msg,
        };
    }
};

pub const Msg = union(Tag) {
    hello: Hello,
    run: Run,
    cancel: Cancel,
    out: Out,
    done: Done,
    err: Err,

    pub const Tag = enum {
        hello,
        run,
        cancel,
        out,
        done,
        err,
    };
};

pub const Role = enum {
    parent,
    child,
};

pub const Hello = struct {
    role: Role,
    agent_id: []const u8,
    policy_hash: []const u8,
};

pub const Run = struct {
    id: []const u8,
    prompt: []const u8,
};

pub const Cancel = struct {
    id: []const u8,
};

pub const Out = struct {
    id: []const u8,
    kind: OutKind = .text,
    text: []const u8,
};

pub const OutKind = enum {
    text,
    info,
};

pub const Done = struct {
    id: []const u8,
    stop: Stop = .done,
    truncated: bool = false,
};

pub const Stop = enum {
    done,
    canceled,
    err,
};

pub const Err = struct {
    id: ?[]const u8 = null,
    code: []const u8,
    message: []const u8,
    fatal: bool = true,
};

pub const DecodeError = std.json.ParseError(std.json.Scanner) || error{
    UnsupportedVersion,
    InvalidId,
    InvalidPolicyHash,
    EmptyPrompt,
    EmptyText,
    EmptyCode,
    EmptyMessage,
};

pub fn encodeAlloc(alloc: std.mem.Allocator, frame: Frame) error{OutOfMemory}![]u8 {
    var out = frame;
    out.protocol_version = protocol_version;
    return std.json.Stringify.valueAlloc(alloc, out, .{});
}

pub fn encodeLineAlloc(alloc: std.mem.Allocator, frame: Frame) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);
    const raw = try encodeAlloc(alloc, frame);
    defer alloc.free(raw);
    try w.writeAll(raw);
    try w.writeByte('\n');
    return try buf.toOwnedSlice(alloc);
}

pub fn decodeSlice(alloc: std.mem.Allocator, raw: []const u8) DecodeError!std.json.Parsed(Frame) {
    var parsed = try std.json.parseFromSlice(Frame, alloc, raw, .{
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();

    if (parsed.value.protocol_version != protocol_version) return error.UnsupportedVersion;
    try validate(parsed.value);
    return parsed;
}

fn validate(frame: Frame) DecodeError!void {
    switch (frame.msg) {
        .hello => |hello| {
            try validateId(hello.agent_id);
            try validateHash(hello.policy_hash);
        },
        .run => |run| {
            try validateId(run.id);
            if (run.prompt.len == 0) return error.EmptyPrompt;
        },
        .cancel => |cancel| try validateId(cancel.id),
        .out => |out| {
            try validateId(out.id);
            if (out.text.len == 0) return error.EmptyText;
        },
        .done => |done| try validateId(done.id),
        .err => |rpc_err| {
            if (rpc_err.id) |id| try validateId(id);
            if (rpc_err.code.len == 0) return error.EmptyCode;
            if (rpc_err.message.len == 0) return error.EmptyMessage;
        },
    }
}

fn validateId(id: []const u8) DecodeError!void {
    if (id.len == 0) return error.InvalidId;
}

fn validateHash(hash: []const u8) DecodeError!void {
    if (hash.len != hash_hex_len) return error.InvalidPolicyHash;
    for (hash) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return error.InvalidPolicyHash,
        }
    }
}

test "frame hello roundtrip enforces protocol version" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const frame = Frame.init(7, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-core",
            .policy_hash = hash,
        },
    });

    const raw = try encodeAlloc(testing.allocator, frame);
    defer testing.allocator.free(raw);

    var parsed = try decodeSlice(testing.allocator, raw);
    defer parsed.deinit();

    try testing.expectEqual(@as(u16, protocol_version), parsed.value.protocol_version);
    try testing.expectEqual(@as(u32, 7), parsed.value.seq);

    switch (parsed.value.msg) {
        .hello => |hello| {
            try testing.expectEqual(Role.child, hello.role);
            try testing.expectEqualStrings("agent-core", hello.agent_id);
            try testing.expectEqualStrings(hash, hello.policy_hash);
        },
        else => try testing.expect(false),
    }
}

test "decode rejects missing protocol version" {
    const raw =
        "{\"seq\":1,\"msg\":{\"run\":{\"id\":\"job-1\",\"prompt\":\"hi\"}}}";
    try testing.expectError(error.MissingField, decodeSlice(testing.allocator, raw));
}

test "decode rejects future protocol version" {
    const raw =
        "{\"protocol_version\":9,\"seq\":1,\"msg\":{\"run\":{\"id\":\"job-1\",\"prompt\":\"hi\"}}}";
    try testing.expectError(error.UnsupportedVersion, decodeSlice(testing.allocator, raw));
}

test "decode rejects unknown fields" {
    const raw =
        "{\"protocol_version\":1,\"seq\":1,\"msg\":{\"done\":{\"id\":\"job-1\",\"truncated\":false}},\"extra\":true}";
    try testing.expectError(error.UnknownField, decodeSlice(testing.allocator, raw));
}

test "decode rejects invalid policy hash" {
    const raw =
        "{\"protocol_version\":1,\"seq\":1,\"msg\":{\"hello\":{\"role\":\"child\",\"agent_id\":\"agent-core\",\"policy_hash\":\"deadbeef\"}}}";
    try testing.expectError(error.InvalidPolicyHash, decodeSlice(testing.allocator, raw));
}

test "decode rejects empty run prompt" {
    const raw =
        "{\"protocol_version\":1,\"seq\":1,\"msg\":{\"run\":{\"id\":\"job-1\",\"prompt\":\"\"}}}";
    try testing.expectError(error.EmptyPrompt, decodeSlice(testing.allocator, raw));
}

test "info output and truncation survive roundtrip" {
    const frame = Frame.init(3, .{
        .out = .{
            .id = "job-7",
            .kind = .info,
            .text = "delegated to child agent",
        },
    });

    const out_raw = try encodeLineAlloc(testing.allocator, frame);
    defer testing.allocator.free(out_raw);
    try testing.expectEqual(@as(u8, '\n'), out_raw[out_raw.len - 1]);

    var out_parsed = try decodeSlice(testing.allocator, out_raw[0 .. out_raw.len - 1]);
    defer out_parsed.deinit();

    switch (out_parsed.value.msg) {
        .out => |out| {
            try testing.expectEqual(OutKind.info, out.kind);
            try testing.expectEqualStrings("job-7", out.id);
            try testing.expectEqualStrings("delegated to child agent", out.text);
        },
        else => try testing.expect(false),
    }

    const done = Frame.init(4, .{
        .done = .{
            .id = "job-7",
            .stop = .done,
            .truncated = true,
        },
    });
    const done_raw = try encodeAlloc(testing.allocator, done);
    defer testing.allocator.free(done_raw);

    var done_parsed = try decodeSlice(testing.allocator, done_raw);
    defer done_parsed.deinit();

    switch (done_parsed.value.msg) {
        .done => |msg| {
            try testing.expectEqual(Stop.done, msg.stop);
            try testing.expect(msg.truncated);
        },
        else => try testing.expect(false),
    }
}
