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

pub const Req = struct {
    id: []const u8,
    prompt: []const u8,
};

pub const Ev = union(Tag) {
    ready: Hello,
    out: Out,
    done: Done,
    err: Err,

    pub const Tag = enum {
        ready,
        out,
        done,
        err,
    };
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

pub const StubError = DecodeError || error{
    InvalidState,
    UnexpectedMsg,
    UnexpectedRole,
    UnexpectedId,
    SeqOrder,
    PolicyMismatch,
};

pub const Stub = struct {
    agent_id: []const u8,
    policy_hash: []const u8,
    send_seq: u32 = 1,
    recv_seq: u32 = 0,
    state: State = .init,
    run_id: ?[]const u8 = null,

    pub const State = enum {
        init,
        wait_hello,
        idle,
        running,
    };

    pub fn init(agent_id: []const u8, policy_hash: []const u8) DecodeError!Stub {
        try validateId(agent_id);
        try validateHash(policy_hash);
        return .{
            .agent_id = agent_id,
            .policy_hash = policy_hash,
        };
    }

    pub fn activeId(self: Stub) ?[]const u8 {
        return self.run_id;
    }

    pub fn hello(self: *Stub) StubError!Frame {
        if (self.state != .init) return error.InvalidState;
        self.state = .wait_hello;
        return self.next(.{
            .hello = .{
                .role = .parent,
                .agent_id = self.agent_id,
                .policy_hash = self.policy_hash,
            },
        });
    }

    pub fn run(self: *Stub, req: Req) StubError!Frame {
        if (self.state != .idle) return error.InvalidState;
        try validateId(req.id);
        if (req.prompt.len == 0) return error.EmptyPrompt;
        self.state = .running;
        self.run_id = req.id;
        return self.next(.{
            .run = .{
                .id = req.id,
                .prompt = req.prompt,
            },
        });
    }

    pub fn cancel(self: *Stub) StubError!Frame {
        if (self.state != .running) return error.InvalidState;
        const id = self.run_id orelse return error.InvalidState;
        return self.next(.{
            .cancel = .{
                .id = id,
            },
        });
    }

    pub fn recv(self: *Stub, frame: Frame) StubError!Ev {
        try validateFrame(frame);
        if (frame.seq <= self.recv_seq) return error.SeqOrder;
        self.recv_seq = frame.seq;

        return switch (frame.msg) {
            .hello => |msg| try self.recvHello(msg),
            .out => |out| try self.recvOut(out),
            .done => |done| try self.recvDone(done),
            .err => |rpc_err| try self.recvErr(rpc_err),
            .run, .cancel => error.UnexpectedMsg,
        };
    }

    fn next(self: *Stub, msg: Msg) Frame {
        const seq = self.send_seq;
        self.send_seq += 1;
        return Frame.init(seq, msg);
    }

    fn recvHello(self: *Stub, msg: Hello) StubError!Ev {
        if (self.state != .wait_hello) return error.UnexpectedMsg;
        if (msg.role != .child) return error.UnexpectedRole;
        if (!std.mem.eql(u8, msg.policy_hash, self.policy_hash)) return error.PolicyMismatch;
        self.state = .idle;
        return .{ .ready = msg };
    }

    fn recvOut(self: *Stub, out: Out) StubError!Ev {
        const id = self.run_id orelse return error.InvalidState;
        if (self.state != .running) return error.UnexpectedMsg;
        if (!std.mem.eql(u8, out.id, id)) return error.UnexpectedId;
        return .{ .out = out };
    }

    fn recvDone(self: *Stub, done: Done) StubError!Ev {
        const id = self.run_id orelse return error.InvalidState;
        if (self.state != .running) return error.UnexpectedMsg;
        if (!std.mem.eql(u8, done.id, id)) return error.UnexpectedId;
        self.state = .idle;
        self.run_id = null;
        return .{ .done = done };
    }

    fn recvErr(self: *Stub, rpc_err: Err) StubError!Ev {
        switch (self.state) {
            .wait_hello => {
                if (rpc_err.id != null) return error.UnexpectedId;
                self.state = .init;
                return .{ .err = rpc_err };
            },
            .running => {
                const id = self.run_id orelse return error.InvalidState;
                if (rpc_err.id) |got| {
                    if (!std.mem.eql(u8, got, id)) return error.UnexpectedId;
                } else if (!rpc_err.fatal) {
                    return error.UnexpectedMsg;
                }
                self.state = .idle;
                self.run_id = null;
                return .{ .err = rpc_err };
            },
            else => return error.UnexpectedMsg,
        }
    }
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

    try validateFrame(parsed.value);
    return parsed;
}

fn validateFrame(frame: Frame) DecodeError!void {
    if (frame.protocol_version != protocol_version) return error.UnsupportedVersion;
    try validate(frame);
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

test "stub handshake run output done flow" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);

    const hello = try stub.hello();
    try testing.expectEqual(@as(u32, 1), hello.seq);
    try testing.expectEqual(Stub.State.wait_hello, stub.state);
    try testing.expect(stub.activeId() == null);
    switch (hello.msg) {
        .hello => |msg| {
            try testing.expectEqual(Role.parent, msg.role);
            try testing.expectEqualStrings("tool-parent", msg.agent_id);
            try testing.expectEqualStrings(hash, msg.policy_hash);
        },
        else => try testing.expect(false),
    }

    const ready = try stub.recv(Frame.init(4, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-child",
            .policy_hash = hash,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    switch (ready) {
        .ready => |msg| {
            try testing.expectEqual(Role.child, msg.role);
            try testing.expectEqualStrings("agent-child", msg.agent_id);
            try testing.expectEqualStrings(hash, msg.policy_hash);
        },
        else => try testing.expect(false),
    }

    const run = try stub.run(.{
        .id = "job-1",
        .prompt = "delegate this",
    });
    try testing.expectEqual(@as(u32, 2), run.seq);
    try testing.expectEqual(Stub.State.running, stub.state);
    try testing.expectEqualStrings("job-1", stub.activeId().?);
    switch (run.msg) {
        .run => |msg| {
            try testing.expectEqualStrings("job-1", msg.id);
            try testing.expectEqualStrings("delegate this", msg.prompt);
        },
        else => try testing.expect(false),
    }

    const out_ev = try stub.recv(Frame.init(5, .{
        .out = .{
            .id = "job-1",
            .kind = .info,
            .text = "delegated to child agent",
        },
    }));
    switch (out_ev) {
        .out => |out| {
            try testing.expectEqual(OutKind.info, out.kind);
            try testing.expectEqualStrings("job-1", out.id);
            try testing.expectEqualStrings("delegated to child agent", out.text);
        },
        else => try testing.expect(false),
    }

    const done_ev = try stub.recv(Frame.init(6, .{
        .done = .{
            .id = "job-1",
            .stop = .done,
            .truncated = false,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    try testing.expect(stub.activeId() == null);
    switch (done_ev) {
        .done => |done| {
            try testing.expectEqual(Stop.done, done.stop);
            try testing.expect(!done.truncated);
        },
        else => try testing.expect(false),
    }
}

test "stub rejects run before child hello" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);

    try testing.expectError(error.InvalidState, stub.run(.{
        .id = "job-1",
        .prompt = "delegate this",
    }));
}

test "stub cancel keeps run live until terminal frame" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);
    _ = try stub.hello();
    _ = try stub.recv(Frame.init(1, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-child",
            .policy_hash = hash,
        },
    }));
    _ = try stub.run(.{
        .id = "job-2",
        .prompt = "delegate this too",
    });

    const cancel = try stub.cancel();
    try testing.expectEqual(@as(u32, 3), cancel.seq);
    try testing.expectEqual(Stub.State.running, stub.state);
    try testing.expectEqualStrings("job-2", stub.activeId().?);
    switch (cancel.msg) {
        .cancel => |msg| try testing.expectEqualStrings("job-2", msg.id),
        else => try testing.expect(false),
    }

    const done_ev = try stub.recv(Frame.init(2, .{
        .done = .{
            .id = "job-2",
            .stop = .canceled,
            .truncated = true,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    try testing.expect(stub.activeId() == null);
    switch (done_ev) {
        .done => |done| {
            try testing.expectEqual(Stop.canceled, done.stop);
            try testing.expect(done.truncated);
        },
        else => try testing.expect(false),
    }
}

test "stub rejects mismatched run id" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);
    _ = try stub.hello();
    _ = try stub.recv(Frame.init(1, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-child",
            .policy_hash = hash,
        },
    }));
    _ = try stub.run(.{
        .id = "job-3",
        .prompt = "delegate again",
    });

    try testing.expectError(error.UnexpectedId, stub.recv(Frame.init(2, .{
        .out = .{
            .id = "job-x",
            .kind = .text,
            .text = "wrong job",
        },
    })));
}

test "stub rejects out of order inbound seq" {
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);
    _ = try stub.hello();
    _ = try stub.recv(Frame.init(7, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-child",
            .policy_hash = hash,
        },
    }));
    _ = try stub.run(.{
        .id = "job-4",
        .prompt = "delegate seq",
    });

    try testing.expectError(error.SeqOrder, stub.recv(Frame.init(7, .{
        .out = .{
            .id = "job-4",
            .kind = .text,
            .text = "late frame",
        },
    })));
}
