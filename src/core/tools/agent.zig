const std = @import("std");
const rpc = @import("../agent.zig");
const tools = @import("../tools.zig");

pub const Err = error{
    KindMismatch,
    InvalidArgs,
    OutOfMemory,
};

pub const Hook = struct {
    ctx: *anyopaque,
    run_fn: *const fn (ctx: *anyopaque, args: tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunRes,

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime run_fn: fn (ctx: *T, args: tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunRes,
    ) Hook {
        const Wrap = struct {
            fn call(raw: *anyopaque, args: tools.Call.AgentArgs) anyerror!rpc.ChildProc.RunRes {
                const typed: *T = @ptrCast(@alignCast(raw));
                return run_fn(typed, args);
            }
        };

        return .{
            .ctx = ctx,
            .run_fn = Wrap.call,
        };
    }

    pub fn run(self: Hook, args: tools.Call.AgentArgs) !rpc.ChildProc.RunRes {
        return self.run_fn(self.ctx, args);
    }
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64 = 0,
    hook: ?Hook = null,
};

pub const Handler = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    now_ms: i64,
    hook: ?Hook,

    pub fn init(opts: Opts) Handler {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .now_ms = opts.now_ms,
            .hook = opts.hook,
        };
    }

    pub fn run(self: Handler, call: tools.Call, _: tools.Sink) Err!tools.Result {
        if (call.kind != .agent) return error.KindMismatch;
        if (std.meta.activeTag(call.args) != .agent) return error.KindMismatch;

        const args = call.args.agent;
        if (args.agent_id.len == 0) return error.InvalidArgs;
        if (args.prompt.len == 0) return error.InvalidArgs;

        const hook = self.hook orelse return fail(call, .internal, "agent tool unavailable");
        const run_res = hook.run(args) catch |run_err| switch (run_err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return fail(call, .io, @errorName(run_err)),
        };
        return finish(self, call, args.agent_id, run_res);
    }

    pub fn deinitResult(self: Handler, res: tools.Result) void {
        if (!res.out_owned) return;
        for (res.out) |out| {
            if (out.owned) self.alloc.free(out.chunk);
        }
        self.alloc.free(res.out);
    }
};

fn finish(self: Handler, call: tools.Call, agent_id: []const u8, run_res: rpc.ChildProc.RunRes) Err!tools.Result {
    const full = try renderAlloc(self.alloc, agent_id, run_res);
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

fn finalFor(run_res: rpc.ChildProc.RunRes) tools.Result.Final {
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

fn renderAlloc(alloc: std.mem.Allocator, agent_id: []const u8, run_res: rpc.ChildProc.RunRes) ![]u8 {
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

fn fail(call: tools.Call, kind: tools.Result.ErrKind, msg: []const u8) tools.Result {
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

fn noopSink() tools.Sink {
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    return tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);
}

test "agent handler renders info block and output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const HookImpl = struct {
        fn run(_: *@This(), args: tools.Call.AgentArgs) !rpc.ChildProc.RunRes {
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
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 44,
        .hook = Hook.from(HookImpl, &hook_impl, HookImpl.run),
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

    const res = try h.run(call, noopSink());
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
        fn run(_: *@This(), _: tools.Call.AgentArgs) !rpc.ChildProc.RunRes {
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
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 32,
        .now_ms = 45,
        .hook = Hook.from(HookImpl, &hook_impl, HookImpl.run),
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

    const res = try h.run(call, noopSink());
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
        fn run(_: *@This(), _: tools.Call.AgentArgs) !rpc.ChildProc.RunRes {
            return .{
                .err = .{
                    .id = "req-3",
                    .code = "bad_input",
                    .message = "child rejected prompt",
                    .fatal = false,
                },
            };
        }
    };

    var hook_impl = HookImpl{};
    const h = Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
        .now_ms = 46,
        .hook = Hook.from(HookImpl, &hook_impl, HookImpl.run),
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

    const res = try h.run(call, noopSink());
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
