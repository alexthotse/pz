const builtin = @import("builtin");
const std = @import("std");
const policy = @import("../policy.zig");
const sandbox = @import("../sandbox.zig");
const shell = @import("../shell.zig");
const tools = @import("mod.zig");
const tool_snap = @import("../../test/tool_snap.zig");

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
    runner: ?Runner = null,
};

const Launch = struct {
    argv: []const []const u8,
    cwd: ?[]const u8,
    env: *const std.process.EnvMap,
    cancel: ?tools.CancelSrc,
};

pub const Runner = struct {
    ctx: *anyopaque,
    run_fn: *const fn (*anyopaque, Handler, Launch) Err!RunOut,

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime run_fn: *const fn (*T, Handler, Launch) Err!RunOut,
    ) Runner {
        const Wrap = struct {
            fn call(ptr: *anyopaque, handler: Handler, launch: Launch) Err!RunOut {
                const self: *T = @ptrCast(@alignCast(ptr));
                return run_fn(self, handler, launch);
            }
        };
        return .{
            .ctx = ctx,
            .run_fn = Wrap.call,
        };
    }

    fn exec(self: Runner, handler: Handler, launch: Launch) Err!RunOut {
        return self.run_fn(self.ctx, handler, launch);
    }
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,
    runner: ?Runner,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
            .runner = opts.runner,
        };
    }

    pub fn run(self: Handler, call: tools.Call, sink: tools.Sink) Err!tools.Result {
        if (call.kind != .bash) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .bash) return error.KindMismatch;

        const args = call.args.bash;
        if (args.cmd.len == 0) return error.InvalidArgs;

        if (args.cwd) |cwd| {
            if (cwd.len == 0) return error.InvalidArgs;
        }

        for (args.env) |kv| {
            if (!isValidEnv(kv.key, kv.val)) return error.InvalidArgs;
        }
        if (try deniesProtectedCmd(self.alloc, args.cmd)) return error.Denied;

        var env = std.process.getEnvMap(self.alloc) catch |env_err| {
            return mapEnvErr(env_err);
        };
        defer env.deinit();

        for (args.env) |kv| {
            env.put(kv.key, kv.val) catch |put_err| {
                return mapEnvErr(put_err);
            };
        }
        if (args.cwd) |cwd| {
            if (policy.isProtectedPath(cwd)) return error.Denied;
        }

        var launch_plan = try sandbox.prepareBash(self.alloc, &env, args.cwd, args.cmd);
        defer launch_plan.deinit(self.alloc);

        const launch: Launch = .{
            .argv = launch_plan.argv,
            .cwd = launch_plan.cwd,
            .env = &env,
            .cancel = call.cancel,
        };
        const run_res = if (self.runner) |runner|
            try runner.exec(self, launch)
        else
            try runChild(self, launch.argv, launch.cwd, launch.env, launch.cancel, call.id, self.now_ms, sink);

        var stdout_chunk = run_res.stdout.chunk;
        errdefer self.alloc.free(stdout_chunk);

        var stderr_chunk = run_res.stderr.chunk;
        errdefer self.alloc.free(stderr_chunk);

        const stdout_meta = tools.output.metaFor(self.max_bytes, run_res.stdout.full_bytes);
        const stderr_meta = tools.output.metaFor(self.max_bytes, run_res.stderr.full_bytes);

        var stdout_meta_chunk: ?[]u8 = null;
        if (stdout_meta) |meta| {
            stdout_meta_chunk = tools.output.metaJsonAlloc(self.alloc, .stdout, meta) catch {
                return error.OutOfMemory;
            };
        }
        errdefer if (stdout_meta_chunk) |chunk| self.alloc.free(chunk);

        var stderr_meta_chunk: ?[]u8 = null;
        if (stderr_meta) |meta| {
            stderr_meta_chunk = tools.output.metaJsonAlloc(self.alloc, .stderr, meta) catch {
                return error.OutOfMemory;
            };
        }
        errdefer if (stderr_meta_chunk) |chunk| self.alloc.free(chunk);

        const out_len =
            @as(usize, @intFromBool(run_res.stdout.full_bytes != 0)) +
            @as(usize, @intFromBool(run_res.stderr.full_bytes != 0)) +
            @as(usize, @intFromBool(stdout_meta_chunk != null)) +
            @as(usize, @intFromBool(stderr_meta_chunk != null));

        const out = self.alloc.alloc(tools.Output, out_len) catch {
            return error.OutOfMemory;
        };
        errdefer self.alloc.free(out);

        var idx: usize = 0;
        if (run_res.stdout.full_bytes != 0) {
            out[idx] = .{
                .call_id = call.id,
                .seq = @intCast(idx),
                .at_ms = self.now_ms,
                .stream = .stdout,
                .chunk = stdout_chunk,
                .owned = true,
                .truncated = stdout_meta != null,
            };
            idx += 1;
            stdout_chunk = &.{};

            if (stdout_meta_chunk) |chunk| {
                out[idx] = .{
                    .call_id = call.id,
                    .seq = @intCast(idx),
                    .at_ms = self.now_ms,
                    .stream = .meta,
                    .chunk = chunk,
                    .owned = true,
                    .truncated = false,
                };
                idx += 1;
                stdout_meta_chunk = null;
            }
        } else {
            self.alloc.free(stdout_chunk);
            stdout_chunk = &.{};
        }

        if (run_res.stderr.full_bytes != 0) {
            out[idx] = .{
                .call_id = call.id,
                .seq = @intCast(idx),
                .at_ms = self.now_ms,
                .stream = .stderr,
                .chunk = stderr_chunk,
                .owned = true,
                .truncated = stderr_meta != null,
            };
            idx += 1;
            stderr_chunk = &.{};

            if (stderr_meta_chunk) |chunk| {
                out[idx] = .{
                    .call_id = call.id,
                    .seq = @intCast(idx),
                    .at_ms = self.now_ms,
                    .stream = .meta,
                    .chunk = chunk,
                    .owned = true,
                    .truncated = false,
                };
                idx += 1;
                stderr_meta_chunk = null;
            }
        } else {
            self.alloc.free(stderr_chunk);
            stderr_chunk = &.{};
        }

        return .{
            .call_id = call.id,
            .started_at_ms = self.now_ms,
            .ended_at_ms = self.now_ms,
            .out = out,
            .out_owned = true,
            .out_streamed = self.runner == null,
            .final = run_res.final,
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

pub fn deniesProtectedCmd(alloc: std.mem.Allocator, cmd: []const u8) Err!bool {
    const toks = shell.tokenize(alloc, cmd) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return false,
    };
    defer shell.free(alloc, toks);

    for (toks) |tok| {
        if (cmdTouchesProtected(tok.cmd)) return true;
    }
    return false;
}

const Capture = struct {
    chunk: []u8,
    full_bytes: usize,
};

const RunOut = struct {
    stdout: Capture,
    stderr: Capture,
    final: tools.Result.Final,
};

const WaitPoll = union(enum) {
    pending,
    status: u32,
};

const wait_poll_ms: u64 = 10;
const term_grace_ms: u64 = 150;

fn runChild(
    self: Handler,
    argv: []const []const u8,
    cwd: ?[]const u8,
    env: *const std.process.EnvMap,
    cancel: ?tools.CancelSrc,
    call_id: []const u8,
    at_ms: i64,
    sink: tools.Sink,
) Err!RunOut {
    var child = std.process.Child.init(argv, self.alloc);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.cwd = cwd;
    child.env_map = env;
    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) child.pgid = 0;

    child.spawn() catch |spawn_err| return mapProcErr(spawn_err);

    const stdout_file = child.stdout orelse return error.Io;
    const stderr_file = child.stderr orelse return error.Io;
    child.stdout = null;
    child.stderr = null;

    setNonblock(stdout_file.handle) catch |set_err| return mapProcErr(set_err);
    setNonblock(stderr_file.handle) catch |set_err| return mapProcErr(set_err);

    var stdout_buf = std.ArrayList(u8).empty;
    errdefer stdout_buf.deinit(self.alloc);
    var stderr_buf = std.ArrayList(u8).empty;
    errdefer stderr_buf.deinit(self.alloc);

    var stdout_full: usize = 0;
    var stderr_full: usize = 0;
    var stdout_open = true;
    var stderr_open = true;
    var seq: u32 = 0;
    var final: ?tools.Result.Final = null;

    while (stdout_open or stderr_open or final == null) {
        if (cancel) |src| {
            if (final == null and src.isCanceled()) {
                _ = terminateAndReap(&child) catch |kill_err| return mapProcErr(kill_err);
                final = .{ .cancelled = .{ .reason = .user } };
            }
        }

        if (final == null) {
            switch (pollChild(&child)) {
                .status => |status| final = statusToFinal(status),
                .pending => {},
            }
        }

        var fds: [2]std.posix.pollfd = undefined;
        var n_fds: usize = 0;
        if (stdout_open) {
            fds[n_fds] = .{
                .fd = stdout_file.handle,
                .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
                .revents = 0,
            };
            n_fds += 1;
        }
        if (stderr_open) {
            fds[n_fds] = .{
                .fd = stderr_file.handle,
                .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
                .revents = 0,
            };
            n_fds += 1;
        }
        if (n_fds != 0) {
            _ = std.posix.poll(fds[0..n_fds], @intCast(wait_poll_ms)) catch |poll_err| {
                return mapCollectErr(poll_err);
            };
            var idx: usize = 0;
            if (stdout_open) {
                stdout_open = readReady(
                    self.alloc,
                    stdout_file.handle,
                    call_id,
                    at_ms,
                    .stdout,
                    self.max_bytes,
                    &stdout_buf,
                    &stdout_full,
                    sink,
                    &seq,
                    fds[idx].revents,
                ) catch |read_err| return mapCollectErr(read_err);
                idx += 1;
            }
            if (stderr_open) {
                stderr_open = readReady(
                    self.alloc,
                    stderr_file.handle,
                    call_id,
                    at_ms,
                    .stderr,
                    self.max_bytes,
                    &stderr_buf,
                    &stderr_full,
                    sink,
                    &seq,
                    fds[idx].revents,
                ) catch |read_err| return mapCollectErr(read_err);
            }
        }
    }

    stdout_file.close();
    stderr_file.close();

    const stdout_chunk = stdout_buf.toOwnedSlice(self.alloc) catch return error.OutOfMemory;
    errdefer self.alloc.free(stdout_chunk);

    const stderr_chunk = stderr_buf.toOwnedSlice(self.alloc) catch return error.OutOfMemory;

    return .{
        .stdout = .{
            .chunk = stdout_chunk,
            .full_bytes = stdout_full,
        },
        .stderr = .{
            .chunk = stderr_chunk,
            .full_bytes = stderr_full,
        },
        .final = final orelse .{ .failed = .{
            .kind = .internal,
            .msg = "bash terminated without status",
        } },
    };
}

fn killAndWait(child: *std.process.Child) Err!void {
    _ = terminateAndReap(child) catch |kill_err| return mapProcErr(kill_err);
}

fn setNonblock(fd: std.posix.fd_t) !void {
    const cur = try std.posix.fcntl(fd, std.posix.F.GETFL, 0);
    const want = cur | @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }));
    _ = try std.posix.fcntl(fd, std.posix.F.SETFL, want);
}

fn readReady(
    alloc: std.mem.Allocator,
    fd: std.posix.fd_t,
    call_id: []const u8,
    at_ms: i64,
    stream: tools.Output.Stream,
    max_bytes: usize,
    buf: *std.ArrayList(u8),
    full_bytes: *usize,
    sink: tools.Sink,
    seq: *u32,
    revents: i16,
) !bool {
    if ((revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR)) == 0) return true;

    var scratch: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &scratch) catch |read_err| switch (read_err) {
            error.WouldBlock => return true,
            else => return read_err,
        };
        if (n == 0) return false;

        full_bytes.* = satAdd(full_bytes.*, n);
        if (buf.items.len < max_bytes) {
            const keep_len = @min(n, max_bytes - buf.items.len);
            if (keep_len != 0) try buf.appendSlice(alloc, scratch[0..keep_len]);
        }

        try sink.push(.{
            .output = .{
                .call_id = call_id,
                .seq = seq.*,
                .at_ms = at_ms,
                .stream = stream,
                .chunk = scratch[0..n],
            },
        });
        seq.* += 1;
    }
}

fn terminateAndReap(child: *std.process.Child) anyerror!u32 {
    switch (pollChild(child)) {
        .status => |status| return status,
        .pending => {},
    }

    signalChild(child.id, std.posix.SIG.TERM) catch |kill_err| switch (kill_err) {
        error.ProcessNotFound => return reapChild(child),
        else => return kill_err,
    };

    var polls: u64 = 0;
    while (polls < (term_grace_ms / wait_poll_ms)) : (polls += 1) {
        std.Thread.sleep(wait_poll_ms * std.time.ns_per_ms);
        switch (pollChild(child)) {
            .status => |status| return status,
            .pending => {},
        }
    }

    signalChild(child.id, std.posix.SIG.KILL) catch |kill_err| switch (kill_err) {
        error.ProcessNotFound => {},
        else => return kill_err,
    };

    return reapChild(child);
}

fn signalChild(pid: std.posix.pid_t, sig: @TypeOf(std.posix.SIG.TERM)) !void {
    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        try std.posix.kill(-pid, sig);
        return;
    }
    try std.posix.kill(pid, sig);
}

fn pollChild(child: *std.process.Child) WaitPoll {
    const res = std.posix.waitpid(child.id, std.c.W.NOHANG);
    if (res.pid == 0) return .pending;
    child.id = undefined;
    return .{ .status = res.status };
}

fn reapChild(child: *std.process.Child) u32 {
    const res = std.posix.waitpid(child.id, 0);
    child.id = undefined;
    return res.status;
}

fn satAdd(a: usize, b: usize) usize {
    const sum = @addWithOverflow(a, b);
    if (sum[1] == 0) return sum[0];
    return std.math.maxInt(usize);
}

fn cmdTouchesProtected(cmd: []const u8) bool {
    var i: usize = 0;
    while (i < cmd.len) {
        while (i < cmd.len and isCmdDelim(cmd[i])) i += 1;
        const start = i;
        while (i < cmd.len and !isCmdDelim(cmd[i])) i += 1;
        if (start == i) continue;
        if (policy.isProtectedPath(cmd[start..i])) return true;
    }
    return false;
}

fn isCmdDelim(c: u8) bool {
    return std.ascii.isWhitespace(c) or switch (c) {
        '<', '>', '(', ')', '=', ',' => true,
        else => false,
    };
}

fn isValidEnv(key: []const u8, val: []const u8) bool {
    if (key.len == 0) return false;
    if (std.mem.indexOfScalar(u8, key, '=')) |_| return false;
    if (std.mem.indexOfScalar(u8, key, 0)) |_| return false;
    if (std.mem.indexOfScalar(u8, val, 0)) |_| return false;
    return true;
}

fn mapEnvErr(err: anyerror) Err {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

fn mapProcErr(err: anyerror) Err {
    return switch (err) {
        error.FileNotFound,
        error.NotDir,
        => error.NotFound,
        error.AccessDenied, error.PermissionDenied, error.ReadOnlyFileSystem => error.Denied,
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

fn mapCollectErr(err: anyerror) Err {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

fn statusToFinal(status: u32) tools.Result.Final {
    if (statusToError(status)) |failed| {
        return .{ .failed = failed };
    }
    return .{ .ok = .{ .code = 0 } };
}

fn statusToError(status: u32) ?tools.Result.Failed {
    if (std.posix.W.IFEXITED(status)) {
        const code = std.posix.W.EXITSTATUS(status);
        if (code == 0) return null;
        return .{
            .code = @as(i32, code),
            .kind = .exec,
            .msg = "bash exited non-zero",
        };
    }

    if (std.posix.W.IFSIGNALED(status)) {
        return .{
            .code = null,
            .kind = .exec,
            .msg = "bash terminated by signal",
        };
    }

    if (std.posix.W.IFSTOPPED(status)) {
        return .{
            .code = null,
            .kind = .exec,
            .msg = "bash stopped",
        };
    }

    return .{
        .code = null,
        .kind = .exec,
        .msg = "bash terminated",
    };
}

test "bash handler captures stdout and stderr with deterministic timestamps" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 99,
    });
    const call: tools.Call = .{
        .id = "b1",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf 'out'; printf 'err' 1>&2",
        } },
        .src = .system,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const code = switch (res.final) {
        .ok => |ok| ok.code,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "start={d}\nend={d}\nout={d}\n0={d}|{d}|{s}|{s}|{}\n1={d}|{d}|{s}|{s}|{}\ncode={d}\n", .{
        res.started_at_ms,
        res.ended_at_ms,
        res.out.len,
        res.out[0].seq,
        res.out[0].at_ms,
        @tagName(res.out[0].stream),
        res.out[0].chunk,
        res.out[0].truncated,
        res.out[1].seq,
        res.out[1].at_ms,
        @tagName(res.out[1].stream),
        res.out[1].chunk,
        res.out[1].truncated,
        code,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "start=99
        \\end=99
        \\out=2
        \\0=0|99|stdout|out|false
        \\1=1|99|stderr|err|false
        \\code=0
        \\"
    ).expectEqual(snap);
}

test "bash handler applies explicit env variables" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        stream: tools.Output.Stream,
        chunk: []const u8,
        final: tools.Result.Final,
    };
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const env = [_]tools.Call.Env{
        .{
            .key = "PZ_BASH_ENV",
            .val = "ok",
        },
    };
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b2",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf '%s' \"$PZ_BASH_ENV\"",
            .env = env[0..],
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    try std.testing.expectEqual(@as(usize, 1), res.out.len);
    try oh.snap(@src(),
        \\core.tools.bash.test.bash handler applies explicit env variables.Snap
        \\  .stream: core.tools.mod.Output.Stream
        \\    .stdout
        \\  .chunk: []const u8
        \\    "ok"
        \\  .final: core.tools.mod.Result.Final
        \\    .ok: core.tools.mod.Result.Ok
        \\      .code: i32 = 0
    ).expectEqual(Snap{
        .stream = res.out[0].stream,
        .chunk = res.out[0].chunk,
        .final = res.final,
    });
}

test "bash handler installs sandbox before bash exec" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        arg0: []const u8,
        arg1: []const u8,
        profile_has_root: bool,
        arg3: []const u8,
        arg4: []const u8,
        arg5: []const u8,
        arg6: []const u8,
        arg7: []const u8,
        cwd_matches_sub: bool,
    };
    const RunnerCtx = struct {
        alloc: std.mem.Allocator,
        argv: ?[][]const u8 = null,
        cwd: ?[]const u8 = null,

        fn run(self: *@This(), handler: Handler, launch: Launch) Err!RunOut {
            self.argv = try self.alloc.alloc([]const u8, launch.argv.len);
            errdefer {
                if (self.argv) |argv| self.alloc.free(argv);
                self.argv = null;
            }
            var n: usize = 0;
            errdefer if (self.argv) |argv| {
                for (argv[0..n]) |arg| self.alloc.free(arg);
            };
            for (launch.argv, 0..) |arg, i| {
                self.argv.?[i] = try self.alloc.dupe(u8, arg);
                n += 1;
            }
            if (launch.cwd) |cwd| self.cwd = try self.alloc.dupe(u8, cwd);
            return .{
                .stdout = .{ .chunk = try handler.alloc.dupe(u8, "ok"), .full_bytes = 2 },
                .stderr = .{ .chunk = try handler.alloc.dupe(u8, ""), .full_bytes = 0 },
                .final = .{ .ok = .{ .code = 0 } },
            };
        }

        fn deinit(self: *@This()) void {
            if (self.argv) |argv| {
                for (argv) |arg| self.alloc.free(arg);
                self.alloc.free(argv);
            }
            if (self.cwd) |cwd| self.alloc.free(cwd);
            self.* = undefined;
        }
    };
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sub");
    const path_guard = @import("path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    var runner_ctx = RunnerCtx{ .alloc = std.testing.allocator };
    defer runner_ctx.deinit();

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
        .runner = Runner.from(RunnerCtx, &runner_ctx, RunnerCtx.run),
    });
    const call: tools.Call = .{
        .id = "b2-sandbox",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf ok",
            .cwd = "sub",
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const sub = try tmp.dir.realpathAlloc(std.testing.allocator, "sub");
    defer std.testing.allocator.free(sub);

    const argv = runner_ctx.argv orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 8), argv.len);
    try oh.snap(@src(),
        \\core.tools.bash.test.bash handler installs sandbox before bash exec.Snap
        \\  .arg0: []const u8
        \\    "/usr/bin/sandbox-exec"
        \\  .arg1: []const u8
        \\    "-p"
        \\  .profile_has_root: bool = true
        \\  .arg3: []const u8
        \\    "/bin/bash"
        \\  .arg4: []const u8
        \\    "--noprofile"
        \\  .arg5: []const u8
        \\    "--norc"
        \\  .arg6: []const u8
        \\    "-lc"
        \\  .arg7: []const u8
        \\    "printf ok"
        \\  .cwd_matches_sub: bool = true
    ).expectEqual(Snap{
        .arg0 = argv[0],
        .arg1 = argv[1],
        .profile_has_root = std.mem.indexOf(u8, argv[2], root) != null,
        .arg3 = argv[3],
        .arg4 = argv[4],
        .arg5 = argv[5],
        .arg6 = argv[6],
        .arg7 = argv[7],
        .cwd_matches_sub = std.mem.eql(u8, sub, runner_ctx.cwd.?),
    });
}

test "bash handler returns failed final on non-zero exit" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const call: tools.Call = .{
        .id = "b3",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf 'fail' 1>&2; exit 7",
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const failed = switch (res.final) {
        .failed => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "out={d}\n0={s}|{s}\nfailed={any}|{s}|{s}\n", .{
        res.out.len,
        @tagName(res.out[0].stream),
        res.out[0].chunk,
        failed.code,
        @tagName(failed.kind),
        failed.msg,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "out=1
        \\0=stderr|fail
        \\failed=7|exec|bash exited non-zero
        \\"
    ).expectEqual(snap);
}

test "bash handler returns failed final on signal exit" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const call: tools.Call = .{
        .id = "b3-signal",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "kill -TERM $$",
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const failed = switch (res.final) {
        .failed => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "out={d}\nfailed={any}|{s}|{s}\n", .{
        res.out.len,
        failed.code,
        @tagName(failed.kind),
        failed.msg,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "out=0
        \\failed=null|exec|bash terminated by signal
        \\"
    ).expectEqual(snap);
}

test "bash handler returns invalid args on empty command" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b4",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "",
        } },
        .src = .system,
        .at_ms = 0,
    };

    try std.testing.expectError(error.InvalidArgs, handler.run(call, sink));
}

test "bash handler returns invalid args on bad env key" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const env = [_]tools.Call.Env{
        .{
            .key = "BAD=KEY",
            .val = "x",
        },
    };
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b5",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "true",
            .env = env[0..],
        } },
        .src = .system,
        .at_ms = 0,
    };

    try std.testing.expectError(error.InvalidArgs, handler.run(call, sink));
}

test "bash handler returns not found for missing cwd" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b6",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf x",
            .cwd = "/tmp/this-dir-should-not-exist-79a1f55a",
        } },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.NotFound, handler.run(call, sink));
}

test "bash handler denies direct protected state access" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b6-deny-direct",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "cat ./.pz/settings.json AGENTS.md",
        } },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.Denied, handler.run(call, sink));
}

test "bash handler denies wrapped protected state access" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b6-deny-wrap",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "bash -c 'cat ~/.pz/settings.json'",
        } },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.Denied, handler.run(call, sink));
}

test "bash handler denies file reads outside workspace inside sandbox" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const secret = try std.fs.cwd().realpathAlloc(std.testing.allocator, "README.md");
    defer std.testing.allocator.free(secret);

    const path_guard = @import("path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const cmd = try std.fmt.allocPrint(std.testing.allocator, "cat '{s}'", .{secret});
    defer std.testing.allocator.free(cmd);
    const call: tools.Call = .{
        .id = "b-file-deny",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = cmd,
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const raw_snap = try tool_snap.resultAlloc(std.testing.allocator, res);
    defer std.testing.allocator.free(raw_snap);
    const snap = try std.mem.replaceOwned(u8, std.testing.allocator, raw_snap, secret, "<repo>/README.md");
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "call=b-file-deny
        \\start=0
        \\end=0
        \\out=1
        \\0=b-file-deny|0|stderr|false|cat: <repo>/README.md: Operation not permitted
        \\
        \\final=failed|exec|bash exited non-zero|.{ 1 }
        \\"
    ).expectEqual(snap);
}

test "bash handler denies process exec outside workspace inside sandbox" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const script_rel = ".zig-cache/p30a-run.sh";
    defer std.fs.cwd().deleteFile(script_rel) catch {};
    try std.fs.cwd().writeFile(.{ .sub_path = script_rel, .data = "#!/bin/sh\nprintf nope\n" });
    var script_file = try std.fs.cwd().openFile(script_rel, .{ .mode = .read_only });
    defer script_file.close();
    try script_file.chmod(0o755);
    const script = try std.fs.cwd().realpathAlloc(std.testing.allocator, script_rel);
    defer std.testing.allocator.free(script);

    const path_guard = @import("path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const cmd = try std.fmt.allocPrint(std.testing.allocator, "'{s}'", .{script});
    defer std.testing.allocator.free(cmd);
    const call: tools.Call = .{
        .id = "b-proc-deny",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = cmd,
        } },
        .src = .model,
        .at_ms = 0,
    };

    const res = try handler.run(call, sink);
    defer handler.deinitResult(res);
    const raw_snap = try tool_snap.resultAlloc(std.testing.allocator, res);
    defer std.testing.allocator.free(raw_snap);
    const snap = try std.mem.replaceOwned(u8, std.testing.allocator, raw_snap, script, "<repo>/.zig-cache/p30a-run.sh");
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "call=b-proc-deny
        \\start=0
        \\end=0
        \\out=1
        \\0=b-proc-deny|0|stderr|false|/bin/bash: <repo>/.zig-cache/p30a-run.sh: Operation not permitted
        \\
        \\final=failed|exec|bash exited non-zero|.{ 126 }
        \\"
    ).expectEqual(snap);
}

test "bash handler denies network connects inside sandbox" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    const Server = struct {
        listener: std.net.Server,
        stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn run(self: *@This()) void {
            var conn = self.acceptReady() catch return orelse return;
            conn.stream.close();
        }

        fn join(self: *@This(), thr: std.Thread) void {
            self.stop.store(true, .release);
            thr.join();
            self.listener.deinit();
        }

        fn acceptReady(self: *@This()) !?std.net.Server.Connection {
            var fds = [_]std.posix.pollfd{.{
                .fd = self.listener.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            while (true) {
                if (self.stop.load(.acquire)) return null;
                const ready = try std.posix.poll(fds[0..], 20);
                if (ready == 0) continue;
                return try self.listener.accept();
            }
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path_guard = @import("path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    var server = Server{
        .listener = try addr.listen(.{
            .reuse_address = true,
        }),
    };
    const port = server.listener.listen_address.in.getPort();
    const thr = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer server.join(thr);

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const cmd = try std.fmt.allocPrint(std.testing.allocator, "nc -z 127.0.0.1 {d}", .{port});
    defer std.testing.allocator.free(cmd);
    const call: tools.Call = .{
        .id = "b-net-deny",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = cmd,
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
        \\  "call=b-net-deny
        \\start=0
        \\end=0
        \\out=0
        \\final=failed|exec|bash exited non-zero|.{ 1 }
        \\"
    ).expectEqual(snap);
}

test "bash handler allows workspace file actions inside sandbox" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path_guard = @import("path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const call: tools.Call = .{
        .id = "b-allow-workspace",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "mkdir -p sub; printf ok > sub/out.txt; cat sub/out.txt",
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
        \\  "call=b-allow-workspace
        \\start=0
        \\end=0
        \\out=1
        \\0=b-allow-workspace|0|stdout|false|ok
        \\final=ok|0
        \\"
    ).expectEqual(snap);
}

test "bash handler truncates oversized output and emits metadata" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 3,
    });
    const call: tools.Call = .{
        .id = "b7",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "printf 'abcd'",
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
        \\  "call=b7
        \\start=0
        \\end=0
        \\out=2
        \\0=b7|0|stdout|true|abc
        \\1=b7|0|meta|false|{"type":"trunc","stream":"stdout","limit_bytes":3,"full_bytes":4,"kept_bytes":3,"dropped_bytes":1}
        \\final=ok|0
        \\"
    ).expectEqual(snap);
}

test "bash handler returns kind mismatch for wrong call kind" {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 128,
    });
    const call: tools.Call = .{
        .id = "b8",
        .kind = .read,
        .args = .{ .read = .{
            .path = "x",
        } },
        .src = .model,
        .at_ms = 0,
    };

    try std.testing.expectError(error.KindMismatch, handler.run(call, sink));
}

test "bash handler cancels running child and reaps TERM-resistant process" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        stream: tools.Output.Stream,
        pid_valid: bool,
        saw_out: bool,
        out_before_done: bool,
        final: tools.Result.Final,
    };
    const WaitGone = struct {
        fn run(pid: std.posix.pid_t) !void {
            var polls: usize = 0;
            while (polls < 50) : (polls += 1) {
                std.posix.kill(pid, 0) catch |kill_err| switch (kill_err) {
                    error.ProcessNotFound => return,
                    else => return kill_err,
                };
                std.Thread.sleep(10 * std.time.ns_per_ms);
            }
            return error.TestUnexpectedResult;
        }
    };
    const SinkImpl = struct {
        mu: std.Thread.Mutex = .{},
        saw_out: bool = false,
        out_before_done: bool = false,
        done: bool = false,

        fn push(self: *@This(), ev: tools.Event) !void {
            self.mu.lock();
            defer self.mu.unlock();
            switch (ev) {
                .output => {
                    self.saw_out = true;
                    if (!self.done) self.out_before_done = true;
                },
                .finish => self.done = true,
                else => {},
            }
        }
    };
    const CancelImpl = struct {
        canceled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn isCanceled(self: *@This()) bool {
            return self.canceled.load(.acquire);
        }
    };
    const RunCtx = struct {
        handler: Handler,
        call: tools.Call,
        sink: tools.Sink,
        res: ?tools.Result = null,
        err: ?Err = null,

        fn run(self: *@This()) void {
            self.res = self.handler.run(self.call, self.sink) catch |run_err| {
                self.err = run_err;
                return;
            };
        }
    };

    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
    var cancel_impl = CancelImpl{};
    const cancel = tools.CancelSrc.from(CancelImpl, &cancel_impl, CancelImpl.isCanceled);

    const handler = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const call: tools.Call = .{
        .id = "b9",
        .kind = .bash,
        .args = .{ .bash = .{
            .cmd = "trap '' TERM; sh -c 'trap \"\" TERM; while :; do sleep 1; done' & bg=$!; printf '%s' \"$bg\"; while :; do sleep 1; done",
        } },
        .src = .model,
        .at_ms = 0,
        .cancel = cancel,
    };

    var ctx = RunCtx{
        .handler = handler,
        .call = call,
        .sink = sink,
    };

    const thr = try std.Thread.spawn(.{}, RunCtx.run, .{&ctx});
    std.Thread.sleep(20 * std.time.ns_per_ms);
    cancel_impl.canceled.store(true, .release);
    thr.join();

    if (ctx.err) |run_err| return run_err;
    const res = ctx.res orelse return error.TestUnexpectedResult;
    defer handler.deinitResult(res);

    sink_impl.mu.lock();
    const saw_out = sink_impl.saw_out;
    const out_before_done = sink_impl.out_before_done;
    sink_impl.mu.unlock();

    try std.testing.expectEqual(@as(usize, 1), res.out.len);
    const bg_pid = try std.fmt.parseInt(std.posix.pid_t, res.out[0].chunk, 10);
    defer std.posix.kill(bg_pid, std.posix.SIG.KILL) catch {};
    try WaitGone.run(bg_pid);
    try oh.snap(@src(),
        \\core.tools.bash.test.bash handler cancels running child and reaps TERM-resistant process.Snap
        \\  .stream: core.tools.mod.Output.Stream
        \\    .stdout
        \\  .pid_valid: bool = true
        \\  .saw_out: bool = true
        \\  .out_before_done: bool = true
        \\  .final: core.tools.mod.Result.Final
        \\    .cancelled: core.tools.mod.Result.Cancelled
        \\      .reason: core.tools.mod.Result.CancelReason
        \\        .user
    ).expectEqual(Snap{
        .stream = res.out[0].stream,
        .pid_valid = bg_pid > 0,
        .saw_out = saw_out,
        .out_before_done = out_before_done,
        .final = res.final,
    });
}
