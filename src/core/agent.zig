//! Child agent RPC protocol: spawn, message framing, version negotiation.
const std = @import("std");
const signing = @import("signing.zig");
const event_loop = @import("event_loop.zig");
const EventLoop = event_loop.EventLoop;
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
    kind: OutputKind = .text,
    text: []const u8,
};

pub const OutputKind = enum {
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

pub const Request = struct {
    id: []const u8,
    prompt: []const u8,
};

pub const Event = union(Tag) {
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

    pub fn run(self: *Stub, req: Request) StubError!Frame {
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

    pub fn recv(self: *Stub, frame: Frame) StubError!Event {
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

    fn recvHello(self: *Stub, msg: Hello) StubError!Event {
        if (self.state != .wait_hello) return error.UnexpectedMsg;
        if (msg.role != .child) return error.UnexpectedRole;
        if (!signing.ctEql(msg.policy_hash, self.policy_hash)) return error.PolicyMismatch;
        self.state = .idle;
        return .{ .ready = msg };
    }

    fn recvOut(self: *Stub, out: Out) StubError!Event {
        const id = self.run_id orelse return error.InvalidState;
        if (self.state != .running) return error.UnexpectedMsg;
        if (!std.mem.eql(u8, out.id, id)) return error.UnexpectedId;
        return .{ .out = out };
    }

    fn recvDone(self: *Stub, done: Done) StubError!Event {
        const id = self.run_id orelse return error.InvalidState;
        if (self.state != .running) return error.UnexpectedMsg;
        if (!std.mem.eql(u8, done.id, id)) return error.UnexpectedId;
        self.state = .idle;
        self.run_id = null;
        return .{ .done = done };
    }

    fn recvErr(self: *Stub, rpc_err: Err) StubError!Event {
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

/// Maximum RPC frame size (1 MiB). Frames exceeding this are rejected.
pub const max_frame_len: usize = 1 << 20;

pub const ChildMode = enum {
    echo,
    mismatch,
    empty_hash,
    invalid_hash,
    fd_report,
    pgid_report,
    stdout_noise,
    oversize,
};

pub const ChildProc = struct {
    alloc: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    proc: std.process.Child,
    stdin_file: std.fs.File,
    stdout_file: std.fs.File,
    rpc_file: std.fs.File,
    stdin_writer: std.fs.File.Writer,
    rpc_reader: std.fs.File.Reader,
    el: EventLoop,
    stub: Stub,
    in_buf: [4096]u8 = undefined,
    rpc_buf: [4096]u8 = undefined,

    /// Grace period before SIGTERM→SIGKILL escalation (ms).
    pub const kill_grace_ms: u32 = 150;
    /// Number of WNOHANG polls during grace period.
    const kill_polls: u32 = 15;
    /// Sleep between polls (ms).
    const poll_sleep_ms: u64 = 10;

    pub const RunResult = struct {
        out: ?Out = null,
        done: ?Done = null,
        err: ?Err = null,
        stdout: ?[]const u8 = null,
    };

    pub fn spawnHarness(
        alloc: std.mem.Allocator,
        harness_path: []const u8,
        mode: ChildMode,
        agent_id: []const u8,
        policy_hash: []const u8,
    ) !ChildProc {
        const builtin = @import("builtin");
        const is_posix = builtin.os.tag != .windows and builtin.os.tag != .wasi;
        if (is_posix) {
            try markOpenFdsCloexec();
        }

        // Create dedicated RPC pipe: child writes to rpc_w, parent reads from rpc_r.
        // rpc_r: CLOEXEC (parent-only), rpc_w: no CLOEXEC (inherited by child).
        const rpc_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
        const rpc_r: std.posix.fd_t = rpc_pipe[0];
        const rpc_w: std.posix.fd_t = rpc_pipe[1];
        errdefer std.posix.close(rpc_r);
        errdefer std.posix.close(rpc_w);

        // Clear CLOEXEC on write end so child inherits it.
        if (is_posix) {
            try clearCloexec(rpc_w);
        }

        var arena = std.heap.ArenaAllocator.init(alloc);
        errdefer arena.deinit();
        const rpc_fd_str = try std.fmt.allocPrint(arena.allocator(), "{d}", .{rpc_w});
        const argv = [_][]const u8{
            harness_path,
            @tagName(mode),
            agent_id,
            policy_hash,
            rpc_fd_str,
        };
        var proc = std.process.Child.init(argv[0..], alloc);
        proc.stdin_behavior = .Pipe;
        proc.stdout_behavior = .Pipe;
        proc.stderr_behavior = .Ignore;
        if (is_posix) {
            proc.pgid = 0;
        }
        try proc.spawn();

        // Parent closes write end; only child uses it.
        std.posix.close(rpc_w);

        const stdin_file = proc.stdin orelse return error.BrokenPipe;
        const stdout_file = proc.stdout orelse return error.BrokenPipe;
        proc.stdin = null;
        proc.stdout = null;
        const rpc_file: std.fs.File = .{ .handle = rpc_r };

        var el = try EventLoop.init();
        errdefer el.deinit();
        try el.register(rpc_r, .read);

        var out: ChildProc = undefined;
        out.alloc = alloc;
        out.arena = arena;
        out.proc = proc;
        out.stdin_file = stdin_file;
        out.stdout_file = stdout_file;
        out.rpc_file = rpc_file;
        out.stdin_writer = stdin_file.writerStreaming(&out.in_buf);
        out.rpc_reader = rpc_file.readerStreaming(&out.rpc_buf);
        out.el = el;
        out.stub = try Stub.init(agent_id, policy_hash);
        return out;
    }

    pub fn deinit(self: *ChildProc) void {
        self.el.deinit();
        self.stdin_file.close();
        self.stdout_file.close();
        self.rpc_file.close();
        killAndWait(&self.proc);
        self.arena.deinit();
    }

    /// Drain child stdout into arena-owned slice (tool output spool).
    pub fn spoolStdout(self: *ChildProc) ![]const u8 {
        const a = self.arena.allocator();
        var list: std.ArrayListUnmanaged(u8) = .empty;
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = self.stdout_file.read(&buf) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (n == 0) break;
            try list.appendSlice(a, buf[0..n]);
        }
        return try list.toOwnedSlice(a);
    }

    /// Hello handshake deadline (ms).
    pub const hello_deadline_ms: i64 = 5_000;
    /// Default run completion deadline (ms). Caller may override via runReqTimeout.
    pub const default_run_deadline_ms: i64 = 5 * 60 * 1_000;
    /// Cancel acknowledgment deadline (ms). After expiry, escalate to SIGKILL.
    pub const cancel_deadline_ms: i64 = 2_000;

    pub fn connect(self: *ChildProc) !Hello {
        try self.send(try self.stub.hello());
        const deadline = std.time.milliTimestamp() + hello_deadline_ms;
        const ev = try self.stub.recv(try self.recvDeadline(deadline));
        return switch (ev) {
            .ready => |ready| ready,
            else => error.UnexpectedMsg,
        };
    }

    pub fn runReq(self: *ChildProc, req: Request) !RunResult {
        return self.runReqTimeout(req, default_run_deadline_ms);
    }

    pub fn runReqTimeout(self: *ChildProc, req: Request, timeout_ms: i64) !RunResult {
        try self.send(try self.stub.run(req));
        const deadline = std.time.milliTimestamp() + timeout_ms;
        var res: RunResult = .{};
        while (true) {
            const ev = try self.stub.recv(try self.recvDeadline(deadline));
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
        const deadline = std.time.milliTimestamp() + cancel_deadline_ms;
        while (true) {
            const frame = self.recvDeadline(deadline) catch |err| {
                if (err == error.Timeout) {
                    // Deadline expired — escalate to SIGKILL.
                    self.killEscalate();
                    return error.Timeout;
                }
                return err;
            };
            const ev = try self.stub.recv(frame);
            switch (ev) {
                .done => |done| return done,
                .err => |rpc_err| return if (rpc_err.fatal) error.UnexpectedMsg else error.UnexpectedMsg,
                else => {},
            }
        }
    }

    /// SIGKILL the child process group immediately.
    fn killEscalate(self: *ChildProc) void {
        const b = @import("builtin");
        if (b.os.tag == .windows or b.os.tag == .wasi) return;
        std.posix.kill(-self.proc.id, std.posix.SIG.KILL) catch {};
    }

    fn send(self: *ChildProc, frame: Frame) !void {
        const raw = try encodeLineAlloc(self.alloc, frame);
        defer self.alloc.free(raw);
        try self.stdin_writer.interface.writeAll(raw);
        try self.stdin_writer.interface.flush();
    }

    fn recv(self: *ChildProc) !Frame {
        return self.recvDeadline(std.math.maxInt(i64));
    }

    /// Receive a frame with an absolute deadline (ms since epoch).
    /// Returns error.Timeout if deadline passes before a full line arrives.
    fn recvDeadline(self: *ChildProc, deadline: i64) !Frame {
        if (self.rpc_reader.interface.bufferedLen() == 0) {
            const remain = deadline - std.time.milliTimestamp();
            if (remain <= 0) return error.Timeout;
            self.waitRpcMs(@intCast(@min(remain, std.math.maxInt(i32)))) catch {}; // cleanup: propagation impossible
        }
        const line = self.rpc_reader.interface.takeDelimiter('\n') catch |err| {
            // If no data available and we're past deadline, surface timeout.
            if (std.time.milliTimestamp() >= deadline) return error.Timeout;
            return err;
        };
        const raw = line orelse {
            if (std.time.milliTimestamp() >= deadline) return error.Timeout;
            return error.EndOfStream;
        };
        if (raw.len > max_frame_len) return error.FrameTooLarge;
        const parsed = try decodeSlice(self.arena.allocator(), raw);
        return parsed.value;
    }

    fn waitRpcMs(self: *ChildProc, timeout_ms: i32) !void {
        var ev_buf: [event_loop.max_events]event_loop.Event = undefined;
        const events = try self.el.wait(timeout_ms, &ev_buf);
        for (events) |ev| {
            if (ev.fd == self.rpc_file.handle and ev.readable) return;
        }
    }
};

/// SIGTERM the process group, poll for exit, escalate to SIGKILL.
fn killAndWait(child: *std.process.Child) void {
    const builtin = @import("builtin");
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        _ = child.wait() catch {}; // cleanup: propagation impossible
        return;
    }
    const pid = child.id;
    // TERM the process group.
    std.posix.kill(-pid, std.posix.SIG.TERM) catch |err| switch (err) {
        error.ProcessNotFound => {
            _ = child.wait() catch {}; // cleanup: propagation impossible
            return;
        },
        else => {
            _ = child.wait() catch {}; // cleanup: propagation impossible
            return;
        },
    };

    // Poll with WNOHANG during grace period.
    var polls: u32 = 0;
    while (polls < ChildProc.kill_polls) : (polls += 1) {
        const res = std.posix.waitpid(pid, std.c.W.NOHANG);
        if (res.pid != 0) {
            child.id = undefined;
            return;
        }
        std.Thread.sleep(ChildProc.poll_sleep_ms * std.time.ns_per_ms);
    }

    // Escalate to SIGKILL on the process group.
    std.posix.kill(-pid, std.posix.SIG.KILL) catch |err| switch (err) {
        error.ProcessNotFound => {},
        else => {},
    };
    _ = child.wait() catch {}; // cleanup: propagation impossible
}

fn clearCloexec(fd: std.posix.fd_t) !void {
    const flags_rc = std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(c_int, 0));
    switch (std.posix.errno(flags_rc)) {
        .SUCCESS => {
            const flags: c_int = @intCast(flags_rc);
            _ = std.posix.system.fcntl(fd, std.posix.F.SETFD, flags & ~@as(c_int, std.posix.FD_CLOEXEC));
        },
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

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

/// Close inherited fds >= 3, optionally keeping one fd open.
pub fn closeInheritedFds(keep_fd: ?std.posix.fd_t) !void {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;
    const lim = try std.posix.getrlimit(.NOFILE);
    const max_fd: usize = @intCast(@min(lim.cur, 1024));
    var fd: usize = 3;
    while (fd < max_fd) : (fd += 1) {
        if (keep_fd) |k| {
            if (@as(usize, @intCast(k)) == fd) continue;
        }
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

/// Status of an individual agent execution.
pub const AgentStatus = enum {
    running,
    done,
    err,
    canceled,

    pub fn fromEvent(ev: Event) AgentStatus {
        return switch (ev) {
            .out => .running,
            .done => |d| switch (d.stop) {
                .done => .done,
                .canceled => .canceled,
                .err => .err,
            },
            .err => .err,
            .ready => .running,
        };
    }

    pub fn terminal(self: AgentStatus) bool {
        return self != .running;
    }
};

/// Per-agent tracking entry for parallel execution.
pub const AgentEntry = struct {
    id: []const u8,
    status: AgentStatus = .running,
    out_bytes: usize = 0,
    last_line: ?[]const u8 = null,
    started_ms: i64 = 0,
    ended_ms: i64 = 0,
};

/// Progress event emitted by `ProgressStream`.
pub const ProgressEvent = union(ProgressTag) {
    out: ProgressOut,
    done: ProgressDone,
    err: ProgressErr,

    pub const ProgressOut = struct {
        agent_id: []const u8,
        text: []const u8,
    };

    pub const ProgressDone = struct {
        agent_id: []const u8,
        status: AgentStatus,
    };

    pub const ProgressErr = struct {
        agent_id: []const u8,
        code: []const u8,
        message: []const u8,
    };
};

pub const ProgressTag = enum {
    out,
    done,
    err,
};

/// Callback type for progress events.
pub const ProgressCb = struct {
    ctx: *anyopaque,
    push_fn: *const fn (ctx: *anyopaque, ev: ProgressEvent) void,

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime push_fn: fn (ctx: *T, ev: ProgressEvent) void,
    ) ProgressCb {
        const Wrap = struct {
            fn call(raw: *anyopaque, ev: ProgressEvent) void {
                const typed: *T = @ptrCast(@alignCast(raw));
                push_fn(typed, ev);
            }
        };
        return .{ .ctx = ctx, .push_fn = Wrap.call };
    }

    pub fn push(self: ProgressCb, ev: ProgressEvent) void {
        self.push_fn(self.ctx, ev);
    }
};

/// Non-blocking progress stream that wraps a `Stub` and forwards
/// decoded RPC events to a `ProgressCb`. Designed for use by the
/// agent tool handler to emit incremental status while the child runs.
pub const ProgressStream = struct {
    stub: *Stub,
    agent_id: []const u8,
    cb: ProgressCb,
    status: AgentStatus = .running,

    pub fn init(stub: *Stub, agent_id: []const u8, cb: ProgressCb) ProgressStream {
        return .{
            .stub = stub,
            .agent_id = agent_id,
            .cb = cb,
        };
    }

    /// Feed a decoded RPC event into the stream. Updates status and
    /// emits to the callback. Returns the new status.
    pub fn feed(self: *ProgressStream, ev: Event) AgentStatus {
        self.status = AgentStatus.fromEvent(ev);
        switch (ev) {
            .out => |o| self.cb.push(.{ .out = .{
                .agent_id = self.agent_id,
                .text = o.text,
            } }),
            .done => |d| self.cb.push(.{ .done = .{
                .agent_id = self.agent_id,
                .status = AgentStatus.fromEvent(.{ .done = d }),
            } }),
            .err => |e| self.cb.push(.{ .err = .{
                .agent_id = self.agent_id,
                .code = e.code,
                .message = e.message,
            } }),
            .ready => {},
        }
        return self.status;
    }

    pub fn isDone(self: *const ProgressStream) bool {
        return self.status.terminal();
    }
};

/// Tracks multiple concurrent agents and aggregates their status.
pub const MultiTracker = struct {
    entries: [max_agents]AgentEntry = undefined,
    len: u8 = 0,

    pub const max_agents: u8 = 8;

    pub fn add(self: *MultiTracker, id: []const u8, now_ms: i64) error{Overflow}!u8 {
        if (self.len >= max_agents) return error.Overflow;
        const idx = self.len;
        self.entries[idx] = .{
            .id = id,
            .started_ms = now_ms,
        };
        self.len += 1;
        return idx;
    }

    pub fn update(self: *MultiTracker, idx: u8, ev: ProgressEvent, now_ms: i64) void {
        if (idx >= self.len) return;
        var e = &self.entries[idx];
        switch (ev) {
            .out => |o| {
                e.out_bytes += o.text.len;
                e.last_line = lastLine(o.text);
            },
            .done => |d| {
                e.status = d.status;
                e.ended_ms = now_ms;
            },
            .err => {
                e.status = .err;
                e.ended_ms = now_ms;
            },
        }
    }

    pub fn allDone(self: *const MultiTracker) bool {
        for (self.entries[0..self.len]) |e| {
            if (!e.status.terminal()) return false;
        }
        return self.len > 0;
    }

    pub fn countByStatus(self: *const MultiTracker, s: AgentStatus) u8 {
        var n: u8 = 0;
        for (self.entries[0..self.len]) |e| {
            if (e.status == s) n += 1;
        }
        return n;
    }

    pub fn get(self: *const MultiTracker, idx: u8) ?AgentEntry {
        if (idx >= self.len) return null;
        return self.entries[idx];
    }
};

fn lastLine(text: []const u8) ?[]const u8 {
    if (text.len == 0) return null;
    const trimmed = std.mem.trimRight(u8, text, "\n");
    if (trimmed.len == 0) return null;
    if (std.mem.lastIndexOfScalar(u8, trimmed, '\n')) |pos| {
        return trimmed[pos + 1 ..];
    }
    return trimmed;
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
        \\    .kind: core.agent.OutputKind
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
        \\core.agent.Event
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
        \\core.agent.Event
        \\  .out: core.agent.Out
        \\    .id: []const u8
        \\      "job-1"
        \\    .kind: core.agent.OutputKind
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
        \\core.agent.Event
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
        \\core.agent.Event
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
        \\    .kind: core.agent.OutputKind
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
        \\    .kind: core.agent.OutputKind
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

test "spawned child inherits only stdio and rpc fds" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // Open a leaked fd that should NOT survive into the child.
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
    // Child should have: 0 (stdin), 1 (stdout), 2 (stderr/null), and the RPC write fd.
    // The leaked fd must not appear.
    var has_rpc = false;
    var it = std.mem.tokenizeScalar(u8, out.text, ',');
    while (it.next()) |tok| {
        const fd_val = std.fmt.parseInt(i32, tok, 10) catch return error.TestUnexpectedResult;
        if (fd_val != 0 and fd_val != 1 and fd_val != 2) {
            // Must be the RPC fd, and only one extra.
            if (has_rpc) return error.TestUnexpectedResult;
            has_rpc = true;
        }
        if (fd_val == leak_fd) return error.TestUnexpectedResult;
    }
    try testing.expect(has_rpc);
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
    const pbt = @import("prop_test.zig");

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

test "tool stdout does not corrupt RPC channel" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .stdout_noise, "agent-child", hash);
    defer child.deinit();

    _ = try child.connect();
    const res = try child.runReq(.{
        .id = "job-noise",
        .prompt = "make noise",
    });
    // RPC frames arrive intact despite stdout noise.
    const out = res.out orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("rpc:make noise", out.text);
    try testing.expect(res.done != null);

    // Stdout contains the tool output noise, not RPC data.
    const spool = try child.spoolStdout();
    try testing.expect(spool.len > 0);
    try testing.expect(std.mem.indexOf(u8, spool, "TOOL_OUTPUT_NOISE") != null);
}

test "oversized RPC frame is rejected" {
    const build_options = @import("build_options");
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var child = try ChildProc.spawnHarness(testing.allocator, build_options.agent_child_harness_path, .oversize, "agent-child", hash);
    defer child.deinit();

    _ = try child.connect();
    // The child sends a frame larger than max_frame_len. Parent must reject.
    const err = child.runReq(.{
        .id = "job-big",
        .prompt = "overflow",
    });
    try testing.expectError(error.FrameTooLarge, err);
}

test "progress stream fires callback on child output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const hash =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var stub = try Stub.init("parent", hash);
    _ = try stub.hello();
    _ = try stub.recv(Frame.init(1, .{
        .hello = .{ .role = .child, .agent_id = "child", .policy_hash = hash },
    }));
    _ = try stub.run(.{ .id = "j1", .prompt = "go" });

    const Collector = struct {
        events: [8]ProgressTag = undefined,
        n: u8 = 0,

        fn push(self: *@This(), ev: ProgressEvent) void {
            if (self.n < 8) {
                self.events[self.n] = std.meta.activeTag(ev);
                self.n += 1;
            }
        }
    };

    var col = Collector{};
    var ps = ProgressStream.init(&stub, "child", ProgressCb.from(Collector, &col, Collector.push));

    const ev_out = try stub.recv(Frame.init(2, .{
        .out = .{ .id = "j1", .kind = .text, .text = "hello" },
    }));
    _ = ps.feed(ev_out);
    try testing.expect(!ps.isDone());

    const ev_done = try stub.recv(Frame.init(3, .{
        .done = .{ .id = "j1", .stop = .done },
    }));
    _ = ps.feed(ev_done);
    try testing.expect(ps.isDone());
    try testing.expectEqual(@as(u8, 2), col.n);

    const Snap = struct { e0: ProgressTag, e1: ProgressTag };
    try oh.snap(@src(),
        \\core.agent.test.progress stream fires callback on child output.Snap
        \\  .e0: core.agent.ProgressTag
        \\    .out
        \\  .e1: core.agent.ProgressTag
        \\    .done
    ).expectEqual(Snap{ .e0 = col.events[0], .e1 = col.events[1] });
}

test "multi tracker aggregates parallel agent status" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mt = MultiTracker{};
    const idx0 = try mt.add("scout", 100);
    const idx1 = try mt.add("critic", 100);

    try testing.expect(!mt.allDone());
    try testing.expectEqual(@as(u8, 2), mt.countByStatus(.running));

    mt.update(idx0, .{ .out = .{ .agent_id = "scout", .text = "line1\nline2\n" } }, 110);
    mt.update(idx0, .{ .done = .{ .agent_id = "scout", .status = .done } }, 120);

    try testing.expect(!mt.allDone());
    try testing.expectEqual(@as(u8, 1), mt.countByStatus(.done));

    mt.update(idx1, .{ .err = .{ .agent_id = "critic", .code = "fail", .message = "boom" } }, 130);
    try testing.expect(mt.allDone());

    const e0 = mt.get(idx0).?;
    const e1 = mt.get(idx1).?;

    const Snap = struct {
        s0: AgentStatus,
        bytes0: usize,
        last0: ?[]const u8,
        s1: AgentStatus,
    };
    try oh.snap(@src(),
        \\core.agent.test.multi tracker aggregates parallel agent status.Snap
        \\  .s0: core.agent.AgentStatus
        \\    .done
        \\  .bytes0: usize = 12
        \\  .last0: ?[]const u8
        \\    "line2"
        \\  .s1: core.agent.AgentStatus
        \\    .err
    ).expectEqual(Snap{
        .s0 = e0.status,
        .bytes0 = e0.out_bytes,
        .last0 = e0.last_line,
        .s1 = e1.status,
    });
}

test "agent status fromEvent maps correctly" {
    try testing.expectEqual(AgentStatus.running, AgentStatus.fromEvent(.{
        .out = .{ .id = "x", .text = "hi" },
    }));
    try testing.expectEqual(AgentStatus.done, AgentStatus.fromEvent(.{
        .done = .{ .id = "x", .stop = .done },
    }));
    try testing.expectEqual(AgentStatus.canceled, AgentStatus.fromEvent(.{
        .done = .{ .id = "x", .stop = .canceled },
    }));
    try testing.expectEqual(AgentStatus.err, AgentStatus.fromEvent(.{
        .err = .{ .code = "e", .message = "m" },
    }));
}

test "multi tracker overflow at max agents" {
    var mt = MultiTracker{};
    var i: u8 = 0;
    while (i < MultiTracker.max_agents) : (i += 1) {
        _ = try mt.add("a", 0);
    }
    try testing.expectError(error.Overflow, mt.add("overflow", 0));
}

test "lastLine extracts final line" {
    try testing.expectEqualStrings("c", lastLine("a\nb\nc\n").?);
    try testing.expectEqualStrings("only", lastLine("only").?);
    try testing.expect(lastLine("") == null);
    try testing.expect(lastLine("\n") == null);
    try testing.expectEqualStrings("b", lastLine("a\nb").?);
}
