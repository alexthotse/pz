//! Background job management: spawn, track, and reap child processes.
const std = @import("std");
const core = @import("../core.zig");
const journal_mod = @import("job_journal.zig");
const shell = @import("../core/shell.zig");
const syslog_mock = @import("../test/syslog_mock.zig");

pub const State = enum {
    running,
    exited,
    signaled,
    stopped,
    unknown,
    wait_err,
};

pub fn stateName(st: State) []const u8 {
    return switch (st) {
        .running => "running",
        .exited => "exited",
        .signaled => "signaled",
        .stopped => "stopped",
        .unknown => "unknown",
        .wait_err => "wait_err",
    };
}

pub const StopResult = enum {
    sent,
    already_done,
    not_found,
};

pub const View = struct {
    id: u64,
    pid: i32,
    cmd: []u8,
    log_path: []u8,
    state: State,
    code: ?i32,
    started_at_ms: i64,
    ended_at_ms: ?i64,
    err_name: ?[]const u8,
};

pub fn deinitViews(alloc: std.mem.Allocator, views: []View) void {
    for (views) |v| {
        alloc.free(v.cmd);
        alloc.free(v.log_path);
    }
    alloc.free(views);
}

pub fn deinitView(alloc: std.mem.Allocator, v: View) void {
    alloc.free(v.cmd);
    alloc.free(v.log_path);
}

const WaitCtx = struct {
    mgr: *Manager,
    job_id: u64,
    child: std.process.Child,
};

const Job = struct {
    id: u64,
    pid: i32,
    cmd: []u8,
    log_path: []u8,
    state: State = .running,
    code: ?i32 = null,
    started_at_ms: i64,
    ended_at_ms: ?i64 = null,
    err_name: ?[]const u8 = null,
    thr: ?std.Thread = null,
    ctx: *WaitCtx,
};

pub const Manager = struct {
    pub const Opts = struct {
        state_dir: ?[]const u8 = null,
        recover: bool = true,
        emit_audit_ctx: ?*anyopaque = null,
        emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, core.audit.Entry) anyerror!void = null,
        now_ms: *const fn () i64 = nowMs,
    };

    alloc: std.mem.Allocator,
    mu: std.Thread.Mutex = .{},
    audit_mu: std.Thread.Mutex = .{},
    jobs: std.ArrayListUnmanaged(Job) = .empty,
    done: std.ArrayListUnmanaged(u64) = .empty,
    next_id: u64 = 1,
    wake_r: std.posix.fd_t,
    wake_w: std.posix.fd_t,
    journal: journal_mod.Journal,
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, core.audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = nowMs,
    audit_seq: u64 = 1,

    pub fn init(alloc: std.mem.Allocator) !Manager {
        return initWithOpts(alloc, .{});
    }

    pub fn initWithOpts(alloc: std.mem.Allocator, opts: Opts) !Manager {
        if (opts.emit_audit != null and opts.emit_audit_ctx == null) return error.InvalidArgs;
        const pipe = try std.posix.pipe2(.{
            .NONBLOCK = true,
            .CLOEXEC = true,
        });
        errdefer {
            std.posix.close(pipe[0]);
            std.posix.close(pipe[1]);
        }

        var out: Manager = .{
            .alloc = alloc,
            .wake_r = pipe[0],
            .wake_w = pipe[1],
            .journal = try journal_mod.Journal.init(alloc, .{
                .state_dir = opts.state_dir,
            }),
            .emit_audit_ctx = opts.emit_audit_ctx,
            .emit_audit = opts.emit_audit,
            .now_ms = opts.now_ms,
        };
        errdefer out.journal.deinit();

        if (opts.recover) {
            try out.recoverStale();
        }
        return out;
    }

    pub fn deinit(self: *Manager) void {
        self.mu.lock();
        for (self.jobs.items) |job| {
            if (job.state == .running) {
                _ = std.posix.kill(@as(std.posix.pid_t, @intCast(job.pid)), std.posix.SIG.KILL) catch {};
                self.journal.appendCleanup(job.id, "shutdown_kill") catch {};
            }
        }
        self.mu.unlock();

        var i: usize = 0;
        while (true) : (i += 1) {
            var thr: ?std.Thread = null;

            self.mu.lock();
            if (i >= self.jobs.items.len) {
                self.mu.unlock();
                break;
            }
            thr = self.jobs.items[i].thr;
            self.jobs.items[i].thr = null;
            self.mu.unlock();

            if (thr) |t| t.join();
        }

        self.mu.lock();
        for (self.jobs.items) |job| {
            self.alloc.destroy(job.ctx);
            self.alloc.free(job.cmd);
            self.alloc.free(job.log_path);
        }
        self.jobs.deinit(self.alloc);
        self.done.deinit(self.alloc);
        self.mu.unlock();

        std.posix.close(self.wake_r);
        std.posix.close(self.wake_w);
        self.journal.deinit();
        self.* = undefined;
    }

    pub fn wakeFd(self: *const Manager) std.posix.fd_t {
        return self.wake_r;
    }

    pub fn start(self: *Manager, cmd_raw: []const u8, cwd: ?[]const u8) !u64 {
        const cmd = std.mem.trim(u8, cmd_raw, " \t");
        const cwd_txt = cwd orelse "";
        const start_attrs = [_]core.audit.Attribute{
            .{ .key = "cwd", .vis = .mask, .val = .{ .str = cwd_txt } },
        };
        try self.emitControlAudit(.{
            .op = "start",
            .msg = .{ .text = "bg control start", .vis = .@"pub" },
            .argv = .{ .text = cmd, .vis = .mask },
            .attrs = &start_attrs,
        });
        if (cmd.len == 0) {
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = "InvalidArgs", .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return error.InvalidArgs;
        }
        if (try shell.touchesProtectedPath(self.alloc, cmd)) {
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = "Denied", .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return error.AccessDenied;
        }

        const id = blk: {
            self.mu.lock();
            defer self.mu.unlock();
            const out = self.next_id;
            self.next_id +%= 1;
            break :blk out;
        };

        const log_path = try self.mkLogPath(id);
        errdefer self.alloc.free(log_path);

        const cmd_dup = try self.alloc.dupe(u8, cmd);
        errdefer self.alloc.free(cmd_dup);

        var env = try std.process.getEnvMap(self.alloc);
        defer env.deinit();
        try env.put("PZ_BG_LOG", log_path);

        const wrapped = try std.fmt.allocPrint(self.alloc, "({s}) >\"${{PZ_BG_LOG}}\" 2>&1", .{cmd});
        defer self.alloc.free(wrapped);

        const argv = [_][]const u8{
            "/bin/bash",
            "-lc",
            wrapped,
        };

        var child = std.process.Child.init(argv[0..], self.alloc);
        child.stdin_behavior = .Ignore;
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;
        child.cwd = cwd;
        child.env_map = &env;
        child.spawn() catch |err| {
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(err), .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return err;
        };

        const ctx = try self.alloc.create(WaitCtx);
        errdefer self.alloc.destroy(ctx);
        ctx.* = .{
            .mgr = self,
            .job_id = id,
            .child = child,
        };

        const pid: i32 = @intCast(child.id);
        const started_at_ms = std.time.milliTimestamp();

        self.journal.appendLaunch(id, pid, cmd_dup, log_path, started_at_ms) catch |err| {
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(err), .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return err;
        };

        self.mu.lock();
        const idx = self.jobs.items.len;
        self.jobs.append(self.alloc, .{
            .id = id,
            .pid = pid,
            .cmd = cmd_dup,
            .log_path = log_path,
            .state = .running,
            .code = null,
            .started_at_ms = started_at_ms,
            .ended_at_ms = null,
            .err_name = null,
            .thr = null,
            .ctx = ctx,
        }) catch |append_err| {
            self.mu.unlock();
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            self.journal.appendCleanup(id, "start_append_fail") catch {};
            self.alloc.destroy(ctx);
            self.alloc.free(cmd_dup);
            self.alloc.free(log_path);
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(append_err), .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return append_err;
        };
        self.mu.unlock();

        const thr = std.Thread.spawn(.{}, waitThread, .{ctx}) catch |spawn_err| {
            _ = child.kill() catch {};
            _ = child.wait() catch {};
            self.journal.appendCleanup(id, "start_spawn_fail") catch {};

            self.mu.lock();
            if (idx < self.jobs.items.len and self.jobs.items[idx].id == id) {
                const removed = self.jobs.orderedRemove(idx);
                self.mu.unlock();
                self.alloc.destroy(removed.ctx);
                self.alloc.free(removed.cmd);
                self.alloc.free(removed.log_path);
            } else {
                self.mu.unlock();
            }
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(spawn_err), .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return spawn_err;
        };

        self.mu.lock();
        if (idx < self.jobs.items.len and self.jobs.items[idx].id == id) {
            self.jobs.items[idx].thr = thr;
        } else {
            self.mu.unlock();
            thr.join();
            self.journal.appendCleanup(id, "start_internal_error") catch {};
            try self.emitControlAudit(.{
                .op = "start",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = "InternalError", .vis = .mask },
                .argv = .{ .text = cmd, .vis = .mask },
                .attrs = &start_attrs,
            });
            return error.InternalError;
        }
        self.mu.unlock();

        const ok_attrs = [_]core.audit.Attribute{
            .{ .key = "job_id", .val = .{ .uint = id } },
            .{ .key = "pid", .val = .{ .uint = @intCast(pid) } },
            .{ .key = "cwd", .vis = .mask, .val = .{ .str = cwd_txt } },
            .{ .key = "log_path", .vis = .mask, .val = .{ .str = log_path } },
        };
        try self.emitControlAudit(.{
            .op = "start",
            .msg = .{ .text = "bg control success", .vis = .@"pub" },
            .argv = .{ .text = cmd, .vis = .mask },
            .attrs = &ok_attrs,
        });
        return id;
    }

    pub fn stop(self: *Manager, id: u64) !StopResult {
        const start_attrs = [_]core.audit.Attribute{
            .{ .key = "job_id", .val = .{ .uint = id } },
        };
        try self.emitControlAudit(.{
            .op = "stop",
            .msg = .{ .text = "bg control start", .vis = .@"pub" },
            .attrs = &start_attrs,
        });
        self.mu.lock();
        const idx = self.findIdxLocked(id) orelse {
            self.mu.unlock();
            const fail_attrs = [_]core.audit.Attribute{
                .{ .key = "job_id", .val = .{ .uint = id } },
                .{ .key = "status", .val = .{ .str = "not_found" } },
            };
            try self.emitControlAudit(.{
                .op = "stop",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = "bg not found", .vis = .@"pub" },
                .attrs = &fail_attrs,
            });
            return .not_found;
        };
        const job = self.jobs.items[idx];
        if (job.state != .running) {
            self.mu.unlock();
            const done_attrs = [_]core.audit.Attribute{
                .{ .key = "job_id", .val = .{ .uint = id } },
                .{ .key = "status", .val = .{ .str = "already_done" } },
            };
            try self.emitControlAudit(.{
                .op = "stop",
                .msg = .{ .text = "bg control success", .vis = .@"pub" },
                .attrs = &done_attrs,
            });
            return .already_done;
        }
        const pid: std.posix.pid_t = @intCast(job.pid);
        self.mu.unlock();

        std.posix.kill(pid, std.posix.SIG.TERM) catch |err| switch (err) {
            error.ProcessNotFound => {
                const done_attrs = [_]core.audit.Attribute{
                    .{ .key = "job_id", .val = .{ .uint = id } },
                    .{ .key = "status", .val = .{ .str = "already_done" } },
                };
                try self.emitControlAudit(.{
                    .op = "stop",
                    .msg = .{ .text = "bg control success", .vis = .@"pub" },
                    .attrs = &done_attrs,
                });
                return .already_done;
            },
            else => {
                try self.emitControlAudit(.{
                    .op = "stop",
                    .outcome = .fail,
                    .severity = .err,
                    .msg = .{ .text = @errorName(err), .vis = .mask },
                    .attrs = &start_attrs,
                });
                return err;
            },
        };
        const ok_attrs = [_]core.audit.Attribute{
            .{ .key = "job_id", .val = .{ .uint = id } },
            .{ .key = "status", .val = .{ .str = "sent" } },
        };
        try self.emitControlAudit(.{
            .op = "stop",
            .msg = .{ .text = "bg control success", .vis = .@"pub" },
            .attrs = &ok_attrs,
        });
        return .sent;
    }

    pub fn list(self: *Manager, alloc: std.mem.Allocator) ![]View {
        try self.emitControlAudit(.{
            .op = "list",
            .msg = .{ .text = "bg control start", .vis = .@"pub" },
        });
        self.mu.lock();
        defer self.mu.unlock();

        const out = alloc.alloc(View, self.jobs.items.len) catch |err| {
            try self.emitControlAudit(.{
                .op = "list",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(err), .vis = .mask },
            });
            return err;
        };
        errdefer alloc.free(out);

        var i: usize = 0;
        errdefer {
            var j: usize = 0;
            while (j < i) : (j += 1) {
                alloc.free(out[j].cmd);
                alloc.free(out[j].log_path);
            }
            alloc.free(out);
        }

        for (self.jobs.items) |job| {
            out[i] = copyJob(alloc, job) catch |err| {
                try self.emitControlAudit(.{
                    .op = "list",
                    .outcome = .fail,
                    .severity = .err,
                    .msg = .{ .text = @errorName(err), .vis = .mask },
                });
                return err;
            };
            i += 1;
        }
        const ok_attrs = [_]core.audit.Attribute{
            .{ .key = "count", .val = .{ .uint = @intCast(out.len) } },
        };
        try self.emitControlAudit(.{
            .op = "list",
            .msg = .{ .text = "bg control success", .vis = .@"pub" },
            .attrs = &ok_attrs,
        });
        return out;
    }

    pub fn view(self: *Manager, alloc: std.mem.Allocator, id: u64) !?View {
        self.mu.lock();
        defer self.mu.unlock();

        const idx = self.findIdxLocked(id) orelse return null;
        return try copyJob(alloc, self.jobs.items[idx]);
    }

    pub fn drainDone(self: *Manager, alloc: std.mem.Allocator) ![]View {
        try self.emitControlAudit(.{
            .op = "drain",
            .msg = .{ .text = "bg control start", .vis = .@"pub" },
        });
        self.mu.lock();
        const ids = alloc.alloc(u64, self.done.items.len) catch |err| {
            self.mu.unlock();
            try self.emitControlAudit(.{
                .op = "drain",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(err), .vis = .mask },
            });
            return err;
        };
        for (self.done.items, 0..) |id, i| ids[i] = id;
        self.done.clearRetainingCapacity();
        self.mu.unlock();
        defer alloc.free(ids);

        const out = alloc.alloc(View, ids.len) catch |err| {
            try self.emitControlAudit(.{
                .op = "drain",
                .outcome = .fail,
                .severity = .err,
                .msg = .{ .text = @errorName(err), .vis = .mask },
            });
            return err;
        };
        errdefer alloc.free(out);

        var i: usize = 0;
        errdefer {
            var j: usize = 0;
            while (j < i) : (j += 1) {
                alloc.free(out[j].cmd);
                alloc.free(out[j].log_path);
            }
            alloc.free(out);
        }

        for (ids) |id| {
            const v = (self.view(alloc, id) catch |err| {
                try self.emitControlAudit(.{
                    .op = "drain",
                    .outcome = .fail,
                    .severity = .err,
                    .msg = .{ .text = @errorName(err), .vis = .mask },
                });
                return err;
            }) orelse {
                try self.emitControlAudit(.{
                    .op = "drain",
                    .outcome = .fail,
                    .severity = .err,
                    .msg = .{ .text = "InternalError", .vis = .mask },
                });
                return error.InternalError;
            };
            out[i] = v;
            i += 1;
        }
        const ok_attrs = [_]core.audit.Attribute{
            .{ .key = "count", .val = .{ .uint = @intCast(out.len) } },
        };
        try self.emitControlAudit(.{
            .op = "drain",
            .msg = .{ .text = "bg control success", .vis = .@"pub" },
            .attrs = &ok_attrs,
        });
        return out;
    }

    fn waitThread(ctx: *WaitCtx) void {
        const wait_term = ctx.child.wait();
        const ended_at_ms = std.time.milliTimestamp();
        ctx.mgr.onExit(ctx.job_id, ended_at_ms, wait_term);
    }

    fn onExit(self: *Manager, id: u64, ended_at_ms: i64, wait_term: anyerror!std.process.Child.Term) void {
        self.mu.lock();
        defer self.mu.unlock();

        const idx = self.findIdxLocked(id) orelse return;
        var job = &self.jobs.items[idx];
        job.ended_at_ms = ended_at_ms;

        if (wait_term) |term| {
            switch (term) {
                .Exited => |code| {
                    job.state = .exited;
                    job.code = @as(i32, code);
                    job.err_name = null;
                },
                .Signal => |sig| {
                    job.state = .signaled;
                    job.code = @intCast(sig);
                    job.err_name = null;
                },
                .Stopped => |sig| {
                    job.state = .stopped;
                    job.code = @intCast(sig);
                    job.err_name = null;
                },
                .Unknown => |sig| {
                    job.state = .unknown;
                    job.code = @intCast(sig);
                    job.err_name = null;
                },
            }
        } else |wait_err| {
            job.state = .wait_err;
            job.code = null;
            job.err_name = @errorName(wait_err);
        }

        self.journal.appendExit(
            id,
            stateName(job.state),
            job.code,
            ended_at_ms,
            job.err_name,
        ) catch {};

        self.done.append(self.alloc, job.id) catch {};
        const b = [_]u8{1};
        _ = std.posix.write(self.wake_w, &b) catch {};
    }

    fn recoverStale(self: *Manager) !void {
        const active = try self.journal.replayActive(self.alloc);
        defer journal_mod.deinitActives(self.alloc, active);

        for (active) |job| {
            const pid: std.posix.pid_t = @intCast(job.pid);
            std.posix.kill(pid, std.posix.SIG.TERM) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => {},
            };
            // Give TERM a chance, then force kill to avoid lingering jobs.
            std.Thread.sleep(150 * std.time.ns_per_ms);
            std.posix.kill(pid, std.posix.SIG.KILL) catch |err| switch (err) {
                error.ProcessNotFound => {},
                else => {},
            };
            self.journal.appendCleanup(job.id, "startup_reap") catch {};
        }
    }

    fn findIdxLocked(self: *Manager, id: u64) ?usize {
        for (self.jobs.items, 0..) |job, i| {
            if (job.id == id) return i;
        }
        return null;
    }

    fn mkLogPath(self: *Manager, id: u64) ![]u8 {
        var n: u32 = 0;
        while (n < 64) : (n += 1) {
            const ts = std.time.milliTimestamp();
            const path = try std.fmt.allocPrint(self.alloc, "/tmp/pz-bg-{d}-{d}.log", .{
                id,
                ts + @as(i64, n),
            });

            const f = std.fs.createFileAbsolute(path, .{
                .read = true,
                .exclusive = true,
            }) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    self.alloc.free(path);
                    continue;
                },
                else => {
                    self.alloc.free(path);
                    return err;
                },
            };
            f.close();
            return path;
        }
        return error.PathAlreadyExists;
    }

    fn emitControlAudit(self: *Manager, req: ControlAudit) !void {
        const emit = self.emit_audit orelse return;
        self.audit_mu.lock();
        const seq = self.audit_seq;
        self.audit_seq +%= 1;
        self.audit_mu.unlock();

        try emit(self.emit_audit_ctx.?, self.alloc, .{
            .ts_ms = self.now_ms(),
            .sid = "bg",
            .seq = seq,
            .severity = req.severity,
            .outcome = req.outcome,
            .actor = .{ .kind = .sys },
            .res = .{
                .kind = .cmd,
                .name = .{ .text = "bg", .vis = .@"pub" },
                .op = req.op,
            },
            .msg = req.msg,
            .data = .{
                .tool = .{
                    .name = .{ .text = "bg", .vis = .@"pub" },
                    .call_id = req.op,
                    .argv = req.argv,
                },
            },
            .attrs = req.attrs,
        });
    }
};

const ControlAudit = struct {
    op: []const u8,
    outcome: core.audit.Outcome = .ok,
    severity: core.audit.Severity = .info,
    msg: ?core.audit.Str,
    argv: ?core.audit.Str = null,
    attrs: []const core.audit.Attribute = &.{},
};

fn nowMs() i64 {
    return std.time.milliTimestamp();
}

fn copyJob(alloc: std.mem.Allocator, job: Job) !View {
    return .{
        .id = job.id,
        .pid = job.pid,
        .cmd = try alloc.dupe(u8, job.cmd),
        .log_path = try alloc.dupe(u8, job.log_path),
        .state = job.state,
        .code = job.code,
        .started_at_ms = job.started_at_ms,
        .ended_at_ms = job.ended_at_ms,
        .err_name = job.err_name,
    };
}

fn waitWake(fd: std.posix.fd_t, timeout_ms: i32) !bool {
    var fds = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = try std.posix.poll(&fds, timeout_ms);
    if (n <= 0) return false;
    return (fds[0].revents & std.posix.POLL.IN) != 0;
}

const DoneSnap = struct {
    id: u64,
    state: []const u8,
    code: ?i32,
    cmd: []const u8,
    has_log: bool,
    has_out: bool,
    has_err: bool,
};

const JobSnap = struct {
    id: u64,
    state: []const u8,
    code: ?i32,
    cmd: []const u8,
    has_log: bool,
};

fn toJobSnap(v: View) JobSnap {
    return .{
        .id = v.id,
        .state = stateName(v.state),
        .code = v.code,
        .cmd = v.cmd,
        .has_log = v.log_path.len > 0,
    };
}

const ChainSnap = struct {
    lines: u64,
    last_key_id: ?u32,
    has_last_mac: bool,
};

fn toChainSnap(ok: anytype) ChainSnap {
    return .{
        .lines = ok.lines,
        .last_key_id = ok.last_key_id,
        .has_last_mac = ok.last_mac != null,
    };
}

const AuditCap = struct {
    rows: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        for (self.rows.items) |row| alloc.free(row);
        self.rows.deinit(alloc);
    }
};

fn captureAudit(ctx: *anyopaque, alloc: std.mem.Allocator, ent: core.audit.Entry) !void {
    const cap: *AuditCap = @ptrCast(@alignCast(ctx));
    const raw = try core.audit.encodeAlloc(alloc, ent);
    try cap.rows.append(alloc, raw);
}

fn scrubBgAudit(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = try alloc.dupe(u8, raw);

    const log_pat = "\"key\":\"log_path\",\"vis\":\"mask\",\"ty\":\"str\",\"val\":\"/tmp/pz-bg-";
    if (std.mem.indexOf(u8, out, log_pat)) |log_idx| {
        const start = log_idx + log_pat.len;
        const end_rel = std.mem.indexOfScalar(u8, out[start..], '"') orelse return out;
        const end = start + end_rel;
        const repl = try std.mem.concat(alloc, u8, &.{ out[0..start], "LOG", out[end..] });
        alloc.free(out);
        out = repl;
    }

    const redacted_log_pat = "\"key\":\"log_path\",\"vis\":\"mask\",\"ty\":\"str\",\"val\":\"";
    if (std.mem.indexOf(u8, out, redacted_log_pat)) |log_idx| {
        const start = log_idx + redacted_log_pat.len;
        const end_rel = std.mem.indexOfScalar(u8, out[start..], '"') orelse return out;
        const end = start + end_rel;
        const repl = try std.mem.concat(alloc, u8, &.{ out[0..start], "[mask:LOG]", out[end..] });
        alloc.free(out);
        out = repl;
    }

    const pid_pat = "\"key\":\"pid\",\"vis\":\"pub\",\"ty\":\"uint\",\"val\":";
    if (std.mem.indexOf(u8, out, pid_pat)) |pid_idx| {
        const start = pid_idx + pid_pat.len;
        const end_rel = std.mem.indexOfAny(u8, out[start..], "},") orelse return out;
        const end = start + end_rel;
        const repl = try std.mem.concat(alloc, u8, &.{ out[0..start], "0", out[end..] });
        alloc.free(out);
        out = repl;
    }

    const sent = "\"key\":\"status\",\"vis\":\"pub\",\"ty\":\"str\",\"val\":\"sent\"";
    const done = "\"key\":\"status\",\"vis\":\"pub\",\"ty\":\"str\",\"val\":\"already_done\"";
    if (std.mem.indexOf(u8, out, sent) != null) {
        const repl = try std.mem.replaceOwned(
            u8,
            alloc,
            out,
            sent,
            "\"key\":\"status\",\"vis\":\"pub\",\"ty\":\"str\",\"val\":\"OUTCOME\"",
        );
        alloc.free(out);
        out = repl;
    } else if (std.mem.indexOf(u8, out, done) != null) {
        const repl = try std.mem.replaceOwned(
            u8,
            alloc,
            out,
            done,
            "\"key\":\"status\",\"vis\":\"pub\",\"ty\":\"str\",\"val\":\"OUTCOME\"",
        );
        alloc.free(out);
        out = repl;
    }

    return out;
}

const AuditHdrDoc = struct {
    ts_ms: i64,
    sid: []const u8,
    seq: u64,
    sev: core.audit.Severity,
};

const AuditSealDoc = struct {
    mac: []const u8,
    body: []const u8,
};

fn e2eAuditKey() core.audit_integrity.Key {
    return .{
        .id = 7,
        .bytes = [_]u8{0x37} ** core.audit_integrity.mac_len,
    };
}

fn e2eFrameOpts() core.audit.FrameOpts {
    return .{
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
        .msgid = "audit",
    };
}

fn shipAuditRows(alloc: std.mem.Allocator, sender: *core.syslog.Sender, rows: []const []const u8) !void {
    const key = e2eAuditKey();
    var prev: ?core.audit_integrity.Mac = null;

    for (rows) |row| {
        const hdr = try std.json.parseFromSlice(AuditHdrDoc, alloc, row, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer hdr.deinit();

        const sealed = try core.audit_integrity.sealAlloc(alloc, key, prev, row);
        defer alloc.free(sealed);

        const doc = try std.json.parseFromSlice(AuditSealDoc, alloc, sealed, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer doc.deinit();

        var next: core.audit_integrity.Mac = undefined;
        _ = try std.fmt.hexToBytes(next[0..], doc.value.mac);

        const frame = try core.audit.encodeFrameBodyAlloc(alloc, e2eFrameOpts(), .{
            .ts_ms = hdr.value.ts_ms,
            .sid = hdr.value.sid,
            .seq = hdr.value.seq,
            .severity = hdr.value.sev,
        }, sealed);
        defer alloc.free(frame);

        try sender.sendRaw(frame);
        prev = next;
    }
}

fn extractSyslogMsg(raw: []const u8) ![]const u8 {
    const idx = std.mem.indexOf(u8, raw, "] {") orelse return error.InvalidFrame;
    return raw[idx + 2 ..];
}

fn joinShippedLinesAlloc(alloc: std.mem.Allocator, collector: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (0..collector.msgCount()) |i| {
        try out.appendSlice(alloc, try extractSyslogMsg(collector.messageAt(i)));
        try out.append(alloc, '\n');
    }
    return try out.toOwnedSlice(alloc);
}

fn joinShippedBodiesAlloc(alloc: std.mem.Allocator, collector: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (0..collector.msgCount()) |i| {
        const raw = try extractSyslogMsg(collector.messageAt(i));
        const doc = try std.json.parseFromSlice(AuditSealDoc, alloc, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer doc.deinit();

        if (i > 0) try out.append(alloc, '\n');
        try out.appendSlice(alloc, doc.value.body);
    }
    return try out.toOwnedSlice(alloc);
}

test "bg manager rejects empty command" {
    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();
    try std.testing.expectError(error.InvalidArgs, mgr.start("", null));
    try std.testing.expectError(error.InvalidArgs, mgr.start("   ", null));
}

test "bg manager rejects protected commands" {
    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();
    try std.testing.expectError(error.AccessDenied, mgr.start("env FOO=1 bash -c 'cat ~/.pz/settings.json'", null));
}

test "bg manager captures stdout+stderr and reports completion" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    _ = try mgr.start("printf 'out'; printf 'err' 1>&2", null);
    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const done = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, done);

    try std.testing.expectEqual(@as(usize, 1), done.len);

    const f = try std.fs.openFileAbsolute(done[0].log_path, .{ .mode = .read_only });
    defer f.close();
    const out = try f.readToEndAlloc(std.testing.allocator, 1024);
    defer std.testing.allocator.free(out);

    const snap = DoneSnap{
        .id = done[0].id,
        .state = stateName(done[0].state),
        .code = done[0].code,
        .cmd = done[0].cmd,
        .has_log = done[0].log_path.len > 0,
        .has_out = std.mem.indexOf(u8, out, "out") != null,
        .has_err = std.mem.indexOf(u8, out, "err") != null,
    };
    try oh.snap(@src(),
        \\app.bg.DoneSnap
        \\  .id: u64 = 1
        \\  .state: []const u8
        \\    "exited"
        \\  .code: ?i32
        \\    0
        \\  .cmd: []const u8
        \\    "printf 'out'; printf 'err' 1>&2"
        \\  .has_log: bool = true
        \\  .has_out: bool = true
        \\  .has_err: bool = true
    ).expectEqual(snap);
}

test "bg manager supports multiple concurrent jobs" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    _ = try mgr.start("sleep 1", null);
    _ = try mgr.start("sleep 1", null);

    const jobs = try mgr.list(std.testing.allocator);
    defer deinitViews(std.testing.allocator, jobs);

    try std.testing.expectEqual(@as(usize, 2), jobs.len);
    const snaps = [_]JobSnap{
        toJobSnap(jobs[0]),
        toJobSnap(jobs[1]),
    };
    try oh.snap(@src(),
        \\[2]app.bg.JobSnap
        \\  [0]: app.bg.JobSnap
        \\    .id: u64 = 1
        \\    .state: []const u8
        \\      "running"
        \\    .code: ?i32
        \\      null
        \\    .cmd: []const u8
        \\      "sleep 1"
        \\    .has_log: bool = true
        \\  [1]: app.bg.JobSnap
        \\    .id: u64 = 2
        \\    .state: []const u8
        \\      "running"
        \\    .code: ?i32
        \\      null
        \\    .cmd: []const u8
        \\      "sleep 1"
        \\    .has_log: bool = true
    ).expectEqual(snaps);
}

test "bg manager records non-zero exit code" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    _ = try mgr.start("printf 'bad'; exit 7", null);
    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const done = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, done);
    try std.testing.expectEqual(@as(usize, 1), done.len);

    const snap = toJobSnap(done[0]);
    try oh.snap(@src(),
        \\app.bg.JobSnap
        \\  .id: u64 = 1
        \\  .state: []const u8
        \\    "exited"
        \\  .code: ?i32
        \\    7
        \\  .cmd: []const u8
        \\    "printf 'bad'; exit 7"
        \\  .has_log: bool = true
    ).expectEqual(snap);
}

test "bg manager view handles missing ids" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect((try mgr.view(std.testing.allocator, 1)) == null);

    const id = try mgr.start("sleep 1", null);
    const view = (try mgr.view(std.testing.allocator, id)) orelse return error.TestUnexpectedResult;
    defer deinitView(std.testing.allocator, view);
    try oh.snap(@src(),
        \\app.bg.JobSnap
        \\  .id: u64 = 1
        \\  .state: []const u8
        \\    "running"
        \\  .code: ?i32
        \\    null
        \\  .cmd: []const u8
        \\    "sleep 1"
        \\  .has_log: bool = true
    ).expectEqual(toJobSnap(view));

    try std.testing.expect((try mgr.view(std.testing.allocator, id + 9999)) == null);
}

test "bg manager drainDone is empty after first drain" {
    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    _ = try mgr.start("printf x", null);
    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const first = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, first);
    try std.testing.expectEqual(@as(usize, 1), first.len);

    const second = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, second);
    try std.testing.expectEqual(@as(usize, 0), second.len);
}

test "bg manager stop reports already_done after completion" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    const id = try mgr.start("printf done", null);
    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const done = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, done);
    try std.testing.expectEqual(@as(usize, 1), done.len);
    try oh.snap(@src(),
        \\app.bg.JobSnap
        \\  .id: u64 = 1
        \\  .state: []const u8
        \\    "exited"
        \\  .code: ?i32
        \\    0
        \\  .cmd: []const u8
        \\    "printf done"
        \\  .has_log: bool = true
    ).expectEqual(toJobSnap(done[0]));

    const stop = try mgr.stop(id);
    try std.testing.expect(stop == .already_done);
}

test "bg manager stop sends termination signal" {
    var mgr = try Manager.init(std.testing.allocator);
    defer mgr.deinit();

    const id = try mgr.start("sleep 5", null);
    const stop = try mgr.stop(id);
    try std.testing.expect(stop == .sent or stop == .already_done);

    try std.testing.expect((try mgr.stop(999999)) == .not_found);
}

test "bg manager recovers and clears stale journal launch entries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(state_dir);

    var j = try journal_mod.Journal.init(std.testing.allocator, .{
        .state_dir = state_dir,
        .enabled = true,
    });
    try j.appendLaunch(99, 999_999, "sleep 30", "/tmp/none.log", 1);
    j.deinit();

    var mgr = try Manager.initWithOpts(std.testing.allocator, .{
        .state_dir = state_dir,
        .recover = true,
    });
    defer mgr.deinit();

    const active = try mgr.journal.replayActive(std.testing.allocator);
    defer journal_mod.deinitActives(std.testing.allocator, active);
    try std.testing.expectEqual(@as(usize, 0), active.len);
}

test "bg manager audit emits start and success entries for control ops" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    var mgr = try Manager.initWithOpts(std.testing.allocator, .{
        .emit_audit_ctx = &cap,
        .emit_audit = captureAudit,
        .now_ms = struct {
            fn f() i64 {
                return 123;
            }
        }.f,
    });
    defer mgr.deinit();

    const id = try mgr.start("printf done", "/tmp/secret");
    const listed = try mgr.list(std.testing.allocator);
    defer deinitViews(std.testing.allocator, listed);
    try std.testing.expectEqual(@as(usize, 1), listed.len);

    const stop = try mgr.stop(id);
    try std.testing.expect(stop == .sent or stop == .already_done);

    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const done = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, done);
    try std.testing.expectEqual(@as(usize, 1), done.len);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    const scrubbed = try scrubBgAudit(std.testing.allocator, joined);
    defer std.testing.allocator.free(scrubbed);

    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":123,"sid":"bg","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"start"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"start","argv":{"text":"[mask:dc2b0ed26cdc3e2e]","vis":"mask"}},"attrs":[{"key":"cwd","vis":"mask","ty":"str","val":"[mask:93f882d68ce39638]"}]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"start"},"msg":{"text":"bg control success","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"start","argv":{"text":"[mask:dc2b0ed26cdc3e2e]","vis":"mask"}},"attrs":[{"key":"job_id","vis":"pub","ty":"uint","val":1},{"key":"pid","vis":"pub","ty":"uint","val":0},{"key":"cwd","vis":"mask","ty":"str","val":"[mask:93f882d68ce39638]"},{"key":"log_path","vis":"mask","ty":"str","val":"[mask:LOG]"}]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":3,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"list"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"list"},"attrs":[]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":4,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"list"},"msg":{"text":"bg control success","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"list"},"attrs":[{"key":"count","vis":"pub","ty":"uint","val":1}]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":5,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"stop"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"stop"},"attrs":[{"key":"job_id","vis":"pub","ty":"uint","val":1}]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":6,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"stop"},"msg":{"text":"bg control success","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"stop"},"attrs":[{"key":"job_id","vis":"pub","ty":"uint","val":1},{"key":"status","vis":"pub","ty":"str","val":"OUTCOME"}]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":7,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"drain"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"drain"},"attrs":[]}
        \\{"v":1,"ts_ms":123,"sid":"bg","seq":8,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"drain"},"msg":{"text":"bg control success","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"drain"},"attrs":[{"key":"count","vis":"pub","ty":"uint","val":1}]}"
    ).expectEqual(scrubbed);
}

test "bg manager audit emits failure entries for invalid start and missing stop" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    var mgr = try Manager.initWithOpts(std.testing.allocator, .{
        .emit_audit_ctx = &cap,
        .emit_audit = captureAudit,
        .now_ms = struct {
            fn f() i64 {
                return 456;
            }
        }.f,
    });
    defer mgr.deinit();

    try std.testing.expectError(error.InvalidArgs, mgr.start("   ", null));
    try std.testing.expectEqual(StopResult.not_found, try mgr.stop(42));

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);

    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":456,"sid":"bg","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"start"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"start","argv":{"text":"[mask:0409638ee2bde459]","vis":"mask"}},"attrs":[{"key":"cwd","vis":"mask","ty":"str","val":"[mask:0409638ee2bde459]"}]}
        \\{"v":1,"ts_ms":456,"sid":"bg","seq":2,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"start"},"msg":{"text":"[mask:f2c3def0536a2885]","vis":"mask"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"start","argv":{"text":"[mask:0409638ee2bde459]","vis":"mask"}},"attrs":[{"key":"cwd","vis":"mask","ty":"str","val":"[mask:0409638ee2bde459]"}]}
        \\{"v":1,"ts_ms":456,"sid":"bg","seq":3,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"stop"},"msg":{"text":"bg control start","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"stop"},"attrs":[{"key":"job_id","vis":"pub","ty":"uint","val":42}]}
        \\{"v":1,"ts_ms":456,"sid":"bg","seq":4,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"bg","vis":"pub"},"op":"stop"},"msg":{"text":"bg not found","vis":"pub"},"data":{"name":{"text":"bg","vis":"pub"},"call_id":"stop"},"attrs":[{"key":"job_id","vis":"pub","ty":"uint","val":42},{"key":"status","vis":"pub","ty":"str","val":"not_found"}]}"
    ).expectEqual(joined);
}

test "bg manager syslog e2e ships redacted chained success audit over udp" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    var mgr = try Manager.initWithOpts(std.testing.allocator, .{
        .emit_audit_ctx = &cap,
        .emit_audit = captureAudit,
        .now_ms = struct {
            fn f() i64 {
                return 123;
            }
        }.f,
    });
    defer mgr.deinit();

    const id = try mgr.start("printf done", "/tmp/secret");
    const listed = try mgr.list(std.testing.allocator);
    defer deinitViews(std.testing.allocator, listed);
    try std.testing.expectEqual(@as(usize, 1), listed.len);

    const stop = try mgr.stop(id);
    try std.testing.expect(stop == .sent or stop == .already_done);

    const woke = try waitWake(mgr.wakeFd(), 5000);
    try std.testing.expect(woke);

    const done = try mgr.drainDone(std.testing.allocator);
    defer deinitViews(std.testing.allocator, done);
    try std.testing.expectEqual(@as(usize, 1), done.len);

    var collector = try syslog_mock.UdpCollector.init();
    defer collector.deinit();
    const t = try collector.spawnCount(cap.rows.items.len);

    var sender = try core.syslog.Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try shipAuditRows(std.testing.allocator, &sender, cap.rows.items);
    t.join();

    try std.testing.expectEqual(cap.rows.items.len, collector.msgCount());

    const shipped_lines = try joinShippedLinesAlloc(std.testing.allocator, &collector);
    defer std.testing.allocator.free(shipped_lines);
    const got_chain = try core.audit_integrity.verifyLogAlloc(std.testing.allocator, shipped_lines, &.{e2eAuditKey()});
    switch (got_chain) {
        .ok => |ok| try oh.snap(@src(),
            \\app.bg.ChainSnap
            \\  .lines: u64 = 8
            \\  .last_key_id: ?u32
            \\    7
            \\  .has_last_mac: bool = true
        ).expectEqual(toChainSnap(ok)),
        .fail => return error.InvalidAuditChain,
    }

    for (0..collector.msgCount()) |i| {
        const raw = collector.messageAt(i);
        try std.testing.expect(std.mem.indexOf(u8, raw, "printf done") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "/tmp/secret") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "[pz@32473 sid=\"bg\" seq=\"") != null);
    }

    const shipped_bodies = try joinShippedBodiesAlloc(std.testing.allocator, &collector);
    defer std.testing.allocator.free(shipped_bodies);
    const scrubbed = try scrubBgAudit(std.testing.allocator, shipped_bodies);
    defer std.testing.allocator.free(scrubbed);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    const expected = try scrubBgAudit(std.testing.allocator, joined);
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, scrubbed);
}

test "bg manager syslog e2e ships redacted chained failure audit over tcp" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    var mgr = try Manager.initWithOpts(std.testing.allocator, .{
        .emit_audit_ctx = &cap,
        .emit_audit = captureAudit,
        .now_ms = struct {
            fn f() i64 {
                return 456;
            }
        }.f,
    });
    defer mgr.deinit();

    try std.testing.expectError(error.InvalidArgs, mgr.start("   ", null));
    try std.testing.expectEqual(StopResult.not_found, try mgr.stop(42));

    var collector = try syslog_mock.TcpCollector.init();
    defer collector.deinit();
    const t = try collector.spawnCount(cap.rows.items.len);

    var sender = try core.syslog.Sender.init(std.testing.allocator, .{
        .transport = .tcp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try shipAuditRows(std.testing.allocator, &sender, cap.rows.items);
    t.join();

    try std.testing.expectEqual(cap.rows.items.len, collector.msgCount());

    const shipped_lines = try joinShippedLinesAlloc(std.testing.allocator, &collector);
    defer std.testing.allocator.free(shipped_lines);
    const got_chain = try core.audit_integrity.verifyLogAlloc(std.testing.allocator, shipped_lines, &.{e2eAuditKey()});
    switch (got_chain) {
        .ok => |ok| try oh.snap(@src(),
            \\app.bg.ChainSnap
            \\  .lines: u64 = 4
            \\  .last_key_id: ?u32
            \\    7
            \\  .has_last_mac: bool = true
        ).expectEqual(toChainSnap(ok)),
        .fail => return error.InvalidAuditChain,
    }

    for (0..collector.msgCount()) |i| {
        const raw = collector.messageAt(i);
        try std.testing.expect(std.mem.indexOf(u8, raw, "InvalidArgs") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "[pz@32473 sid=\"bg\" seq=\"") != null);
    }

    const shipped_bodies = try joinShippedBodiesAlloc(std.testing.allocator, &collector);
    defer std.testing.allocator.free(shipped_bodies);
    const scrubbed = try scrubBgAudit(std.testing.allocator, shipped_bodies);
    defer std.testing.allocator.free(scrubbed);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    const expected = try scrubBgAudit(std.testing.allocator, joined);
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, scrubbed);
}
