const std = @import("std");
const testing = std.testing;

pub const protocol_version: u16 = 1;
pub const hash_hex_len: usize = 64;
pub const version_mismatch_exit_code: u8 = 78;

pub fn driverPathAlloc(alloc: std.mem.Allocator) ![]u8 {
    return std.fs.selfExePathAlloc(alloc);
}

pub fn exitOnVersionMismatch(err: DecodeError) void {
    if (err != error.UnsupportedVersion) return;
    std.process.exit(version_mismatch_exit_code);
}

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

pub const ChildMode = enum {
    echo,
    mismatch,
    empty_hash,
    invalid_hash,
    fd_report,
    pgid_report,
};

pub const ChildProc = struct {
    alloc: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    proc: std.process.Child,
    stdin_file: std.fs.File,
    stdout_file: std.fs.File,
    stdin_writer: std.fs.File.Writer,
    stdout_reader: std.fs.File.Reader,
    stub: Stub,
    in_buf: [4096]u8 = undefined,
    out_buf: [4096]u8 = undefined,

    pub const RunRes = struct {
        out: ?Out = null,
        done: ?Done = null,
        err: ?Err = null,
    };

    pub fn spawnHarness(
        alloc: std.mem.Allocator,
        harness_path: []const u8,
        mode: ChildMode,
        agent_id: []const u8,
        policy_hash: []const u8,
    ) !ChildProc {
        if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
            try markOpenFdsCloexec();
        }
        var arena = std.heap.ArenaAllocator.init(alloc);
        errdefer arena.deinit();
        const argv = [_][]const u8{
            harness_path,
            @tagName(mode),
            agent_id,
            policy_hash,
        };
        var proc = std.process.Child.init(argv[0..], alloc);
        proc.stdin_behavior = .Pipe;
        proc.stdout_behavior = .Pipe;
        proc.stderr_behavior = .Ignore;
        if (@import("builtin").os.tag != .windows and @import("builtin").os.tag != .wasi) {
            proc.pgid = 0;
        }
        try proc.spawn();
        const stdin_file = proc.stdin orelse return error.BrokenPipe;
        const stdout_file = proc.stdout orelse return error.BrokenPipe;
        proc.stdin = null;
        proc.stdout = null;
        var out: ChildProc = undefined;
        out.alloc = alloc;
        out.arena = arena;
        out.proc = proc;
        out.stdin_file = stdin_file;
        out.stdout_file = stdout_file;
        out.stdin_writer = stdin_file.writerStreaming(&out.in_buf);
        out.stdout_reader = stdout_file.readerStreaming(&out.out_buf);
        out.stub = try Stub.init(agent_id, policy_hash);
        return out;
    }

    pub fn deinit(self: *ChildProc) void {
        self.stdin_file.close();
        self.stdout_file.close();
        std.posix.kill(self.proc.id, std.posix.SIG.TERM) catch |err| switch (err) {
            error.ProcessNotFound => {},
            else => {},
        };
        _ = self.proc.wait() catch {};
        self.arena.deinit();
    }

    pub fn connect(self: *ChildProc) !Hello {
        try self.send(try self.stub.hello());
        const ev = try self.stub.recv(try self.recv());
        return switch (ev) {
            .ready => |ready| ready,
            else => error.UnexpectedMsg,
        };
    }

    pub fn runReq(self: *ChildProc, req: Req) !RunRes {
        try self.send(try self.stub.run(req));
        var res: RunRes = .{};
        while (true) {
            const ev = try self.stub.recv(try self.recv());
            switch (ev) {
                .out => |out| res.out = out,
                .done => |done| {
                    res.done = done;
                    return res;
                },
                .err => |rpc_err| {
                    res.err = rpc_err;
                    return res;
                },
                else => return error.UnexpectedMsg,
            }
        }
    }

    pub fn cancelReq(self: *ChildProc) !Done {
        try self.send(try self.stub.cancel());
        while (true) {
            const ev = try self.stub.recv(try self.recv());
            switch (ev) {
                .done => |done| return done,
                .err => |rpc_err| return if (rpc_err.fatal) error.UnexpectedMsg else error.UnexpectedMsg,
                else => {},
            }
        }
    }

    fn send(self: *ChildProc, frame: Frame) !void {
        const raw = try encodeLineAlloc(self.alloc, frame);
        defer self.alloc.free(raw);
        try self.stdin_writer.interface.writeAll(raw);
        try self.stdin_writer.interface.flush();
    }

    fn recv(self: *ChildProc) !Frame {
        const line = try self.stdout_reader.interface.takeDelimiter('\n');
        const raw = line orelse return error.EndOfStream;
        const parsed = try decodeSlice(self.arena.allocator(), raw);
        return parsed.value;
    }
};

fn markOpenFdsCloexec() !void {
    const lim = try std.posix.getrlimit(.NOFILE);
    const max_fd: usize = @intCast(@min(lim.cur, 1024));
    var fd: usize = 3;
    while (fd < max_fd) : (fd += 1) {
        const raw_fd: std.posix.fd_t = @intCast(fd);
        const flags_rc = std.posix.system.fcntl(raw_fd, std.posix.F.GETFD, @as(c_int, 0));
        switch (std.posix.errno(flags_rc)) {
            .SUCCESS => {
                const flags: c_int = @intCast(flags_rc);
                _ = std.posix.system.fcntl(raw_fd, std.posix.F.SETFD, flags | @as(c_int, std.posix.FD_CLOEXEC));
            },
            .BADF => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

pub fn closeInheritedFds() !void {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;
    const lim = try std.posix.getrlimit(.NOFILE);
    const max_fd: usize = @intCast(@min(lim.cur, 1024));
    var fd: usize = 3;
    while (fd < max_fd) : (fd += 1) {
        switch (std.posix.errno(std.posix.system.close(@intCast(fd)))) {
            .SUCCESS, .BADF => {},
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

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

fn propId(raw: []const u8) []const u8 {
    return if (raw.len == 0) "a" else raw;
}

fn propHash(buf: *[hash_hex_len]u8, a: u64, b: u64, c: u64, d: u64) void {
    var x = a ^ std.math.rotl(u64, b, 13) ^ std.math.rotl(u64, c, 29) ^ std.math.rotl(u64, d, 47);
    for (buf, 0..) |*dst, i| {
        x ^= 0x9e3779b97f4a7c15 +% @as(u64, @intCast(i));
        x = std.math.rotl(u64, x *% 0xbf58476d1ce4e5b9, 7);
        dst.* = "0123456789abcdef"[@intCast(x & 0x0f)];
    }
}

fn mutateValidHash(buf: *[hash_hex_len]u8, flip: u8) void {
    const idx: usize = @intCast(flip % hash_hex_len);
    buf[idx] = if (buf[idx] == 'f') '0' else 'f';
}

fn mutateInvalidHash(buf: *[hash_hex_len]u8, flip: u8) void {
    const idx: usize = @intCast(flip % hash_hex_len);
    buf[idx] = 'x';
}

test "frame hello roundtrip enforces protocol version" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

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
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .hello: core.agent.Hello
        \\    .role: core.agent.Role
        \\      .child
        \\    .agent_id: []const u8
        \\      "agent-core"
        \\    .policy_hash: []const u8
        \\      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expectEqual(parsed.value.msg);
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

test "driver path resolves current executable" {
    const path = try driverPathAlloc(testing.allocator);
    defer testing.allocator.free(path);

    try testing.expect(path.len > 0);
    try testing.expect(std.fs.path.isAbsolute(path));
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
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

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
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .out: core.agent.Out
        \\    .id: []const u8
        \\      "job-7"
        \\    .kind: core.agent.OutKind
        \\      .info
        \\    .text: []const u8
        \\      "delegated to child agent"
    ).expectEqual(out_parsed.value.msg);

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
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .done: core.agent.Done
        \\    .id: []const u8
        \\      "job-7"
        \\    .stop: core.agent.Stop
        \\      .done
        \\    .truncated: bool = true
    ).expectEqual(done_parsed.value.msg);
}

test "stub handshake run output done flow" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("tool-parent", hash);

    const hello = try stub.hello();
    try testing.expectEqual(@as(u32, 1), hello.seq);
    try testing.expectEqual(Stub.State.wait_hello, stub.state);
    try testing.expect(stub.activeId() == null);
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .hello: core.agent.Hello
        \\    .role: core.agent.Role
        \\      .parent
        \\    .agent_id: []const u8
        \\      "tool-parent"
        \\    .policy_hash: []const u8
        \\      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expectEqual(hello.msg);

    const ready = try stub.recv(Frame.init(4, .{
        .hello = .{
            .role = .child,
            .agent_id = "agent-child",
            .policy_hash = hash,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    try oh.snap(@src(),
        \\core.agent.Ev
        \\  .ready: core.agent.Hello
        \\    .role: core.agent.Role
        \\      .child
        \\    .agent_id: []const u8
        \\      "agent-child"
        \\    .policy_hash: []const u8
        \\      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expectEqual(ready);

    const run = try stub.run(.{
        .id = "job-1",
        .prompt = "delegate this",
    });
    try testing.expectEqual(@as(u32, 2), run.seq);
    try testing.expectEqual(Stub.State.running, stub.state);
    try testing.expectEqualStrings("job-1", stub.activeId().?);
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .run: core.agent.Run
        \\    .id: []const u8
        \\      "job-1"
        \\    .prompt: []const u8
        \\      "delegate this"
    ).expectEqual(run.msg);

    const out_ev = try stub.recv(Frame.init(5, .{
        .out = .{
            .id = "job-1",
            .kind = .info,
            .text = "delegated to child agent",
        },
    }));
    try oh.snap(@src(),
        \\core.agent.Ev
        \\  .out: core.agent.Out
        \\    .id: []const u8
        \\      "job-1"
        \\    .kind: core.agent.OutKind
        \\      .info
        \\    .text: []const u8
        \\      "delegated to child agent"
    ).expectEqual(out_ev);

    const done_ev = try stub.recv(Frame.init(6, .{
        .done = .{
            .id = "job-1",
            .stop = .done,
            .truncated = false,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    try testing.expect(stub.activeId() == null);
    try oh.snap(@src(),
        \\core.agent.Ev
        \\  .done: core.agent.Done
        \\    .id: []const u8
        \\      "job-1"
        \\    .stop: core.agent.Stop
        \\      .done
        \\    .truncated: bool = false
    ).expectEqual(done_ev);
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
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
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
    try oh.snap(@src(),
        \\core.agent.Msg
        \\  .cancel: core.agent.Cancel
        \\    .id: []const u8
        \\      "job-2"
    ).expectEqual(cancel.msg);

    const done_ev = try stub.recv(Frame.init(2, .{
        .done = .{
            .id = "job-2",
            .stop = .canceled,
            .truncated = true,
        },
    }));
    try testing.expectEqual(Stub.State.idle, stub.state);
    try testing.expect(stub.activeId() == null);
    try oh.snap(@src(),
        \\core.agent.Ev
        \\  .done: core.agent.Done
        \\    .id: []const u8
        \\      "job-2"
        \\    .stop: core.agent.Stop
        \\      .canceled
        \\    .truncated: bool = true
    ).expectEqual(done_ev);
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

test "spawned child handshake and run succeed" {
    const OhSnap = @import("ohsnap");
    const build_options = @import("build_options");
    const oh = OhSnap{};
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .echo, "agent-child", hash);
    defer child.deinit();

    const ready = try child.connect();
    const res = try child.runReq(.{
        .id = "job-1",
        .prompt = "delegate this",
    });
    const Snap = struct {
        ready: Hello,
        out: ?Out,
        done: ?Done,
    };
    try oh.snap(@src(),
        \\core.agent.test.spawned child handshake and run succeed.Snap
        \\  .ready: core.agent.Hello
        \\    .role: core.agent.Role
        \\      .child
        \\    .agent_id: []const u8
        \\      "agent-child"
        \\    .policy_hash: []const u8
        \\      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\  .out: ?core.agent.Out
        \\    .id: []const u8
        \\      "job-1"
        \\    .kind: core.agent.OutKind
        \\      .info
        \\    .text: []const u8
        \\      "echo:delegate this"
        \\  .done: ?core.agent.Done
        \\    .id: []const u8
        \\      "job-1"
        \\    .stop: core.agent.Stop
        \\      .done
        \\    .truncated: bool = false
    ).expectEqual(Snap{
        .ready = ready,
        .out = res.out,
        .done = res.done,
    });
}

test "spawned child rejects mismatched policy hash" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .mismatch, "agent-child", hash);
    defer child.deinit();

    try testing.expectError(error.PolicyMismatch, child.connect());
}

test "spawned child rejects empty policy hash" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .empty_hash, "agent-child", hash);
    defer child.deinit();

    try testing.expectError(error.InvalidPolicyHash, child.connect());
}

test "spawned child rejects invalid policy hash" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .invalid_hash, "agent-child", hash);
    defer child.deinit();

    try testing.expectError(error.InvalidPolicyHash, child.connect());
}

test "spawned child accepts inherited policy hash" {
    const OhSnap = @import("ohsnap");
    const build_options = @import("build_options");
    const oh = OhSnap{};
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .echo, "agent-child", hash);
    defer child.deinit();

    const hello = try child.connect();
    const res = try child.runReq(.{
        .id = "job-echo",
        .prompt = "inherit",
    });
    const Snap = struct {
        hello: Hello,
        out: ?Out,
        done: ?Done,
    };
    try oh.snap(@src(),
        \\core.agent.test.spawned child accepts inherited policy hash.Snap
        \\  .hello: core.agent.Hello
        \\    .role: core.agent.Role
        \\      .child
        \\    .agent_id: []const u8
        \\      "agent-child"
        \\    .policy_hash: []const u8
        \\      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        \\  .out: ?core.agent.Out
        \\    .id: []const u8
        \\      "job-echo"
        \\    .kind: core.agent.OutKind
        \\      .info
        \\    .text: []const u8
        \\      "echo:inherit"
        \\  .done: ?core.agent.Done
        \\    .id: []const u8
        \\      "job-echo"
        \\    .stop: core.agent.Stop
        \\      .done
        \\    .truncated: bool = false
    ).expectEqual(Snap{
        .hello = hello,
        .out = res.out,
        .done = res.done,
    });
}

test "spawned child inherits only stdio fds" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const leak_fd = try std.posix.openZ("/dev/null", .{ .ACCMODE = .RDONLY }, 0);
    defer std.posix.close(leak_fd);

    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .fd_report, "agent-child", hash);
    defer child.deinit();

    _ = try child.connect();
    const res = try child.runReq(.{
        .id = "job-fd",
        .prompt = "list fds",
    });
    const out = res.out orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("0,1,2", out.text);
    try testing.expect(std.mem.indexOfScalar(u8, out.text, @as(u8, '3')) == null);
}

test "spawned child runs in its own process group" {
    const build_options = @import("build_options");
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .pgid_report, "agent-child", hash);
    defer child.deinit();

    _ = try child.connect();
    const res = try child.runReq(.{
        .id = "job-pgid",
        .prompt = "report pgid",
    });
    const out = res.out orelse return error.TestUnexpectedResult;

    var it = std.mem.tokenizeScalar(u8, out.text, ' ');
    const pid_raw = it.next() orelse return error.TestUnexpectedResult;
    const pgid_raw = it.next() orelse return error.TestUnexpectedResult;
    const pid = try std.fmt.parseInt(i32, pid_raw["pid=".len..], 10);
    const pgid = try std.fmt.parseInt(i32, pgid_raw["pgid=".len..], 10);

    try testing.expectEqual(pid, pgid);
    try testing.expect(pgid != std.c.getpid());
}

test "property: valid ids and hashes validate" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            id: zc.String,
            a: u64,
            b: u64,
            c: u64,
            d: u64,
        }) bool {
            var hash: [hash_hex_len]u8 = undefined;
            propHash(&hash, args.a, args.b, args.c, args.d);
            validateId(propId(args.id.slice())) catch return false;
            validateHash(hash[0..]) catch return false;
            return true;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0xa93e_7101,
    });
}

test "property: mutated hello hash is rejected or mismatched" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            id: zc.String,
            a: u64,
            b: u64,
            c: u64,
            d: u64,
            flip: u8,
            invalid: bool,
        }) bool {
            const id = propId(args.id.slice());

            var want: [hash_hex_len]u8 = undefined;
            propHash(&want, args.a, args.b, args.c, args.d);
            var got = want;
            if (args.invalid) {
                mutateInvalidHash(&got, args.flip);
            } else {
                mutateValidHash(&got, args.flip);
            }

            var stub = Stub.init(id, want[0..]) catch return false;
            _ = stub.hello() catch return false;

            const frame = Frame.init(1, .{
                .hello = .{
                    .role = .child,
                    .agent_id = id,
                    .policy_hash = got[0..],
                },
            });

            if (args.invalid) {
                return validateFrame(frame) catch |err| err == error.InvalidPolicyHash;
            }

            validateFrame(frame) catch return false;
            return stub.recv(frame) catch |err| err == error.PolicyMismatch;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0xa93e_7102,
    });
}

test "property: mutated run frames reject empty id or prompt" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            id: zc.String,
            prompt: zc.String,
            clear_id: bool,
        }) bool {
            const good_id = propId(args.id.slice());
            const good_prompt = propId(args.prompt.slice());

            validateFrame(Frame.init(1, .{
                .run = .{
                    .id = good_id,
                    .prompt = good_prompt,
                },
            })) catch return false;

            const bad = if (args.clear_id)
                Frame.init(1, .{
                    .run = .{
                        .id = "",
                        .prompt = good_prompt,
                    },
                })
            else
                Frame.init(1, .{
                    .run = .{
                        .id = good_id,
                        .prompt = "",
                    },
                });

            return validateFrame(bad) catch |err|
                err == if (args.clear_id) error.InvalidId else error.EmptyPrompt;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0xa93e_7103,
    });
}

test "property: decodeSlice survives crap-and-mutate hello frames" {
    const zc = @import("zcheck");
    const pbt = @import("pbt.zig");

    try zc.check(struct {
        fn prop(args: struct {
            id: zc.String,
            a: u64,
            b: u64,
            c: u64,
            d: u64,
            seed: u64,
            slack: u8,
        }) bool {
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            var hash: [hash_hex_len]u8 = undefined;
            propHash(&hash, args.a, args.b, args.c, args.d);
            const raw = encodeLineAlloc(alloc, Frame.init(1, .{
                .hello = .{
                    .role = .child,
                    .agent_id = propId(args.id.slice()),
                    .policy_hash = hash[0..],
                },
            })) catch return false;
            const lim = raw.len + @as(usize, args.slack % 8);
            const bad = pbt.Mut.crapOrMutateAlloc(alloc, raw, args.seed, lim) catch return false;

            _ = decodeSlice(alloc, bad) catch |err| return err != error.OutOfMemory;
            return true;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0xa93e_7104,
    });
}
