//! Agent tool: spawn child agent via RPC.
const std = @import("std");
const audit = @import("../audit.zig");
const rpc = @import("../agent.zig");
const tools = @import("../tools.zig");

const shared = @import("shared.zig");
const noop = @import("../../test/noop_sink.zig");

pub const Err = error{
    KindMismatch,
    InvalidArgs,
    OutOfMemory,
    PolicyMismatch,
};

pub const Hook = struct {
    vt: *const Vt,

    pub const Vt = struct {
        run: *const fn (self: *Hook, args: tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunResult,
    };

    pub fn run(self: *Hook, args: tools.Call.AgentArgs) !rpc.ChildProc.RunResult {
        return self.vt.run(self, args);
    }

    pub fn Bind(comptime T: type, comptime run_fn: fn (*T, tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunResult) type {
        return struct {
            pub const vt = Vt{
                .run = runFn,
            };
            fn runFn(h: *Hook, args: tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunResult {
                const self: *T = @fieldParentPtr("hook", h);
                return run_fn(self, args);
            }
        };
    }
};

/// Hook that yields incremental progress events while running.
pub const StreamHook = struct {
    vt: *const Vt,

    pub const Vt = struct {
        run: *const fn (self: *StreamHook, args: tools.Call.AgentArgs, cb: *rpc.ProgressCb) anyerror!rpc.ChildProc.RunResult,
    };

    pub fn run(self: *StreamHook, args: tools.Call.AgentArgs, cb: *rpc.ProgressCb) !rpc.ChildProc.RunResult {
        return self.vt.run(self, args, cb);
    }

    pub fn Bind(comptime T: type, comptime run_fn: fn (*T, tools.Call.AgentArgs, *rpc.ProgressCb) anyerror!rpc.ChildProc.RunResult) type {
        return struct {
            pub const vt = Vt{
                .run = runFn,
            };
            fn runFn(sh: *StreamHook, args: tools.Call.AgentArgs, cb: *rpc.ProgressCb) anyerror!rpc.ChildProc.RunResult {
                const self: *T = @fieldParentPtr("stream_hook", sh);
                return run_fn(self, args, cb);
            }
        };
    }
};

/// Production agent spawner with policy hash for child validation.
/// Owns the spawned child process; caller must call `cleanup()` after
/// the `RunResult` slices are no longer needed.
pub const PolicySpawnCtx = struct {
    stream_hook: StreamHook = .{ .vt = &StreamHookBind.vt },
    alloc: std.mem.Allocator,
    policy_hash: []const u8,
    child: ?*rpc.ChildProc = null,

    const StreamHookBind = StreamHook.Bind(PolicySpawnCtx, run);

    pub fn run(self: *PolicySpawnCtx, args: tools.Call.AgentArgs, cb: *rpc.ProgressCb) anyerror!rpc.ChildProc.RunResult {
        const child = try self.alloc.create(rpc.ChildProc);
        errdefer self.alloc.destroy(child);
        child.* = try rpc.ChildProc.spawnAgent(self.alloc, args.agent_id, self.policy_hash);
        errdefer child.deinit();

        _ = try child.connect();

        var ps = rpc.ProgressStream.init(&child.stub, args.agent_id, cb);
        const res = try child.runReqStreaming(
            .{ .id = "agent-0", .prompt = args.prompt },
            rpc.ChildProc.default_run_deadline_ms,
            &ps,
        );

        // Keep child alive — result slices point into child.arena.
        self.child = child;
        return res;
    }

    /// Free the child process and arena. Call after RunResult is consumed.
    pub fn cleanup(self: *PolicySpawnCtx) void {
        if (self.child) |child| {
            child.deinit();
            self.alloc.destroy(child);
            self.child = null;
        }
    }
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64 = 0,
    hook: ?*Hook = null,
    stream_hook: ?*StreamHook = null,
    /// Parent's verified policy hash. Child must match or spawn fails.
    policy_hash: ?[]const u8 = null,
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,
    hook: ?*Hook,
    stream_hook: ?*StreamHook,
    policy_hash: ?[]const u8,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
            .hook = opts.hook,
            .stream_hook = opts.stream_hook,
            .policy_hash = opts.policy_hash,
        };
    }

    pub fn run(self: Handler, call: tools.Call, sink: *tools.Sink) Err!tools.Result {
        if (call.kind != .agent) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .agent) return error.KindMismatch;

        const args = call.args.agent;
        if (args.agent_id.len == 0) return error.InvalidArgs;
        if (args.prompt.len == 0) return error.InvalidArgs;

        // Enforce authoritative policy inheritance: parent must have a
        // verified policy hash, and the hook receives it for the child
        // to validate during the hello handshake.
        if (self.policy_hash == null) return error.PolicyMismatch;

        // Prefer streaming hook for incremental progress.
        if (self.stream_hook) |sh| {
            var bridge = SinkBridge{ .sink = sink, .call_id = call.id, .at_ms = self.now_ms };
            const run_res = sh.run(args, &bridge.cb) catch |run_err| switch (run_err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(call, .io, @errorName(run_err)),
            };
            return finish(self, call, args.agent_id, run_res, bridge.dropped);
        }

        var hook = self.hook orelse return fail(call, .internal, "agent tool unavailable");
        const run_res = hook.run(args) catch |run_err| switch (run_err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(call, .io, @errorName(run_err)),
        };
        return finish(self, call, args.agent_id, run_res, 0);
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        shared.deinitResult(self.alloc, res);
    }
};

/// Bridges `ProgressEvent`s from a streaming hook into the tool `Sink`,
/// emitting incremental `output` events so the TUI can render progress.
const SinkBridge = struct {
    cb: rpc.ProgressCb = .{ .vt = &CbBind.vt },
    sink: *tools.Sink,
    call_id: []const u8,
    at_ms: i64,
    seq: u32 = 0,
    dropped: u32 = 0,

    const CbBind = rpc.ProgressCb.Bind(SinkBridge, push);

    fn push(self: *SinkBridge, ev: rpc.ProgressEvent) void {
        const chunk: []const u8 = switch (ev) {
            .out => |o| o.text,
            .done => |d| @tagName(d.status),
            .err => |e| e.message,
        };
        const stream: tools.Output.Stream = switch (ev) {
            .out => .stdout,
            .done => .meta,
            .err => .stderr,
        };
        const out: tools.Output = .{
            .call_id = self.call_id,
            .seq = self.seq,
            .at_ms = self.at_ms,
            .stream = stream,
            .chunk = chunk,
        };
        self.seq += 1;
        self.sink.push(.{ .output = out }) catch {
            self.dropped += 1;
        };
    }
};

fn finish(self: Handler, call: tools.Call, agent_id: []const u8, run_res: rpc.ChildProc.RunResult, dropped: u32) Err!tools.Result {
    const raw = try renderAlloc(self.alloc, agent_id, run_res, dropped);
    defer self.alloc.free(raw);
    // Redact secrets from child agent output before returning to model.
    const full = audit.redactTextAlloc(self.alloc, raw, .@"pub") catch return error.OutOfMemory;
    defer self.alloc.free(full);

    const slice = tools.truncate.apply(full, self.max_bytes);
    const body = self.alloc.dupe(u8, slice.chunk) catch return error.OutOfMemory;
    errdefer self.alloc.free(body);

    var meta_chunk: ?[]u8 = null;
    if (slice.meta) |meta| {
        meta_chunk = tools.truncate.metaJsonAlloc(self.alloc, .stdout, meta) catch return error.OutOfMemory;
    }
    errdefer if (meta_chunk) |chunk| self.alloc.free(chunk);

    const out_len: usize = 1 + @as(usize, @intFromBool(meta_chunk != null));
    const out = self.alloc.alloc(tools.Output, out_len) catch return error.OutOfMemory;
    errdefer self.alloc.free(out);

    out[0] = .{
        .call_id = call.id,
        .seq = 0,
        .at_ms = self.now_ms,
        .stream = .stdout,
        .chunk = body,
        .owned = true,
        .truncated = slice.truncated,
    };
    if (meta_chunk) |chunk| {
        out[1] = .{
            .call_id = call.id,
            .seq = 1,
            .at_ms = self.now_ms,
            .stream = .meta,
            .chunk = chunk,
            .owned = true,
            .truncated = false,
        };
    }

    return .{
        .call_id = call.id,
        .started_at_ms = self.now_ms,
        .ended_at_ms = self.now_ms,
        .out = out,
        .out_owned = true,
        .final = finalFor(run_res),
    };
}

fn finalFor(run_res: rpc.ChildProc.RunResult) tools.Result.Final {
    if (run_res.err != null) {
        return .{ .failed = .{
            .kind = .exec,
            .msg = "agent failed",
        } };
    }
    const done = run_res.done orelse return .{ .failed = .{
        .kind = .internal,
        .msg = "agent missing terminal frame",
    } };
    return switch (done.stop) {
        .done => .{
            .ok = .{ .code = 0 },
        },
        .canceled => .{
            .cancelled = .{ .reason = .user },
        },
        .err => .{
            .failed = .{
                .kind = .exec,
                .msg = "agent stopped with err",
            },
        },
    };
}

fn renderAlloc(alloc: std.mem.Allocator, agent_id: []const u8, run_res: rpc.ChildProc.RunResult, dropped: u32) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    const wr = out.writer(alloc);

    const kind = if (run_res.out) |msg| @tagName(msg.kind) else "none";
    const stop = if (run_res.done) |done| @tagName(done.stop) else if (run_res.err != null) "err" else "missing";
    const child_trunc = if (run_res.done) |done| done.truncated else false;

    try wr.print("agent: {s}\n", .{agent_id});
    try wr.print("kind: {s}\n", .{kind});
    try wr.print("stop: {s}\n", .{stop});
    try wr.print("truncated: {}\n", .{child_trunc});
    if (dropped > 0) try wr.print("dropped_output: {d}\n", .{dropped});
    if (run_res.artifact_path) |ap| try wr.print("artifact: {s}\n", .{ap});
    if (run_res.err) |rpc_err| {
        try wr.print("error: {s}\n", .{rpc_err.code});
        try wr.print("fatal: {}\n\n", .{rpc_err.fatal});
    } else {
        try wr.writeAll("\n");
    }

    if (run_res.out) |msg| try wr.writeAll(msg.text);
    if (run_res.err) |rpc_err| {
        if (run_res.out != null) try wr.writeAll("\n\n");
        try wr.writeAll(rpc_err.message);
    }

    return out.toOwnedSlice(alloc);
}

const fail = shared.fail;

test "agent handler renders info block and output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const HookImpl = struct {
        hook: Hook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), args: tools.Call.AgentArgs) !rpc.ChildProc.RunResult {
            return .{
                .out = .{
                    .id = "req-1",
                    .kind = .text,
                    .text = args.prompt,
                },
                .done = .{
                    .id = "req-1",
                    .stop = .done,
                    .truncated = false,
                },
            };
        }
        const Bind = Hook.Bind(@This(), run);
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 44,
        .hook = &hook_impl.hook,
        .policy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
    const call: tools.Call = .{
        .id = "agent-1",
        .kind = .agent,
        .args = .{
            .agent = .{
                .agent_id = "critic",
                .prompt = "delegated to child agent",
            },
        },
        .src = .model,
        .at_ms = 44,
    };

    const res = try h.run(call, noop.sink());
    defer h.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "final={s}\nout={s}\n", .{
        @tagName(res.final),
        res.out[0].chunk,
    });
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "final=ok
        \\out=agent: critic
        \\kind: text
        \\stop: done
        \\truncated: false
        \\
        \\delegated to child agent
        \\"
    ).expectEqual(snap);
}

test "agent handler truncates deterministically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const HookImpl = struct {
        hook: Hook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), _: tools.Call.AgentArgs) !rpc.ChildProc.RunResult {
            return .{
                .out = .{
                    .id = "req-2",
                    .kind = .info,
                    .text = "abcdefghijklmnopqrstuvwxyz",
                },
                .done = .{
                    .id = "req-2",
                    .stop = .done,
                    .truncated = true,
                },
            };
        }
        const Bind = Hook.Bind(@This(), run);
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 32,
        .now_ms = 45,
        .hook = &hook_impl.hook,
        .policy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
    const call: tools.Call = .{
        .id = "agent-2",
        .kind = .agent,
        .args = .{
            .agent = .{
                .agent_id = "scout",
                .prompt = "ignored",
            },
        },
        .src = .model,
        .at_ms = 45,
    };

    const res = try h.run(call, noop.sink());
    defer h.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "rows={d}\ntrunc={}\nbody={s}\nmeta={s}\n", .{
        res.out.len,
        res.out[0].truncated,
        res.out[0].chunk,
        res.out[1].chunk,
    });
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "rows=2
        \\trunc=true
        \\body=agent: scout
        \\kind: info
        \\stop: do
        \\meta={"type":"trunc","stream":"stdout","limit_bytes":32,"full_bytes":78,"kept_bytes":32,"dropped_bytes":46}
        \\"
    ).expectEqual(snap);
}

test "agent handler maps rpc error to failed final" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const HookImpl = struct {
        hook: Hook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), _: tools.Call.AgentArgs) !rpc.ChildProc.RunResult {
            return .{
                .err = .{
                    .id = "req-3",
                    .code = "bad_input",
                    .message = "child rejected prompt",
                    .fatal = false,
                },
            };
        }
        const Bind = Hook.Bind(@This(), run);
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 46,
        .hook = &hook_impl.hook,
        .policy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
    const call: tools.Call = .{
        .id = "agent-3",
        .kind = .agent,
        .args = .{
            .agent = .{
                .agent_id = "reviewer",
                .prompt = "bad",
            },
        },
        .src = .model,
        .at_ms = 46,
    };

    const res = try h.run(call, noop.sink());
    defer h.deinitResult(res);

    const snap = try std.fmt.allocPrint(std.testing.allocator, "final={s}\nmsg={s}\nout={s}\n", .{
        @tagName(res.final),
        res.final.failed.msg,
        res.out[0].chunk,
    });
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "final=failed
        \\msg=agent failed
        \\out=agent: reviewer
        \\kind: none
        \\stop: err
        \\truncated: false
        \\error: bad_input
        \\fatal: false
        \\
        \\child rejected prompt
        \\"
    ).expectEqual(snap);
}

test "agent handler rejects missing policy hash" {
    const HookImpl = struct {
        hook: Hook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), _: tools.Call.AgentArgs) !rpc.ChildProc.RunResult {
            return .{
                .done = .{ .id = "req-4", .stop = .done },
            };
        }
        const Bind = Hook.Bind(@This(), run);
    };
    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 47,
        .hook = &hook_impl.hook,
        .policy_hash = null,
    });
    const call: tools.Call = .{
        .id = "agent-4",
        .kind = .agent,
        .args = .{ .agent = .{ .agent_id = "child", .prompt = "test" } },
        .src = .model,
        .at_ms = 47,
    };
    try std.testing.expectError(error.PolicyMismatch, h.run(call, noop.sink()));
}

test "stream hook emits progress via sink bridge" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const StreamImpl = struct {
        stream_hook: StreamHook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), args: tools.Call.AgentArgs, cb: *rpc.ProgressCb) !rpc.ChildProc.RunResult {
            // Simulate incremental progress events.
            cb.push(.{ .out = .{ .agent_id = "s1", .text = args.prompt } });
            cb.push(.{ .done = .{ .agent_id = "s1", .status = .done } });
            return .{
                .out = .{ .id = "req-s", .kind = .text, .text = args.prompt },
                .done = .{ .id = "req-s", .stop = .done },
            };
        }
        const Bind = StreamHook.Bind(@This(), run);
    };

    const SinkCollector = struct {
        sink: tools.Sink = .{ .vt = &SinkBind.vt },
        n: u8 = 0,
        streams: [4]tools.Output.Stream = undefined,

        fn push(self: *@This(), ev: tools.Event) !void {
            switch (ev) {
                .output => |o| {
                    if (self.n < 4) {
                        self.streams[self.n] = o.stream;
                        self.n += 1;
                    }
                },
                else => {}, // .start, .finish not tracked in this test sink
            }
        }
        const SinkBind = tools.Sink.Bind(@This(), push);
    };

    var stream_impl = StreamImpl{};
    var col = SinkCollector{};

    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 50,
        .stream_hook = &stream_impl.stream_hook,
        .policy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    });
    const call: tools.Call = .{
        .id = "agent-s",
        .kind = .agent,
        .args = .{ .agent = .{ .agent_id = "s1", .prompt = "streaming" } },
        .src = .model,
        .at_ms = 50,
    };

    const res = try h.run(call, &col.sink);
    defer h.deinitResult(res);

    // Verify 2 progress events were pushed through the sink bridge.
    try std.testing.expectEqual(@as(u8, 2), col.n);

    const Snap = struct {
        s0: tools.Output.Stream,
        s1: tools.Output.Stream,
        final: tools.Result.Tag,
    };
    try oh.snap(@src(),
        \\core.tools.agent.test.stream hook emits progress via sink bridge.Snap
        \\  .s0: core.tools.Output.Stream
        \\    .stdout
        \\  .s1: core.tools.Output.Stream
        \\    .meta
        \\  .final: core.tools.Result.Tag
        \\    .ok
    ).expectEqual(Snap{
        .s0 = col.streams[0],
        .s1 = col.streams[1],
        .final = std.meta.activeTag(res.final),
    });
}
