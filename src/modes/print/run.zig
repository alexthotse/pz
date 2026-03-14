const std = @import("std");
const core = @import("../../core.zig");
const mode = @import("../mode.zig");
const format = @import("format.zig");
const run_err = @import("errors.zig");

pub const model_default = "default";

pub fn exec(run_ctx: mode.Ctx) run_err.Err!run_err.Result {
    var out = std.fs.File.stdout().deprecatedWriter();
    return execWithWriter(run_ctx, out.any());
}

pub fn execWithWriter(run_ctx: mode.Ctx, out: std.Io.AnyWriter) run_err.Err!run_err.Result {
    return execVerbose(run_ctx, out, false);
}

fn execVerbose(run_ctx: mode.Ctx, out: std.Io.AnyWriter, verbose: bool) run_err.Err!run_err.Result {
    var formatter = format.Formatter.init(run_ctx.alloc, out);
    formatter.verbose = verbose;
    defer formatter.deinit();

    run_ctx.store.append(run_ctx.sid, .{
        .at_ms = std.time.milliTimestamp(),
        .data = .{ .prompt = .{ .text = run_ctx.prompt } },
    }) catch return error.PromptWrite;

    const parts = [_]core.providers.Part{
        .{ .text = run_ctx.prompt },
    };
    const msgs = [_]core.providers.Msg{
        .{
            .role = .user,
            .parts = parts[0..],
        },
    };

    var stream = run_ctx.provider.start(.{
        .model = model_default,
        .msgs = msgs[0..],
    }) catch return error.ProviderStart;
    defer stream.deinit();

    var stop_reason: ?core.providers.StopReason = null;
    while (true) {
        const ev = (stream.next() catch return error.StreamRead) orelse break;

        switch (ev) {
            .stop => |stop| {
                stop_reason = core.providers.StopReason.merge(stop_reason, stop.reason);
            },
            else => {},
        }

        formatter.push(ev) catch return error.OutputFormat;
        run_ctx.store.append(run_ctx.sid, mapEvent(ev)) catch return error.EventWrite;
    }

    formatter.finish() catch return error.OutputFlush;

    if (stop_reason) |reason| {
        if (reason != .done) return .{ .stop = reason };
    }
    return .ok;
}

fn mapEvent(ev: core.providers.Ev) core.session.Event {
    return .{
        .at_ms = std.time.milliTimestamp(),
        .data = switch (ev) {
            .text => |text| .{ .text = .{ .text = text } },
            .thinking => |text| .{ .thinking = .{ .text = text } },
            .tool_call => |tc| .{ .tool_call = .{
                .id = tc.id,
                .name = tc.name,
                .args = tc.args,
            } },
            .tool_result => |tr| .{ .tool_result = .{
                .id = tr.id,
                .out = tr.out,
                .is_err = tr.is_err,
            } },
            .usage => |usage| .{ .usage = .{
                .in_tok = usage.in_tok,
                .out_tok = usage.out_tok,
                .tot_tok = usage.tot_tok,
            } },
            .stop => |stop| .{ .stop = .{
                .reason = switch (stop.reason) {
                    .done => .done,
                    .max_out => .max_out,
                    .tool => .tool,
                    .canceled => .canceled,
                    .err => .err,
                },
            } },
            .err => |text| .{ .err = .{ .text = text } },
        },
    };
}

const RunProviderSnap = struct {
    start_ct: usize,
    model: []const u8,
    msg_ct: usize,
    part_ct: usize,
    role: core.providers.Role,
    prompt: []const u8,
    deinit_ct: usize,
};

const RunStoreSnap = struct {
    replay_ct: usize,
    append_ct: usize,
    len: usize,
    sid: []const u8,
};

const RunToolCallSnap = struct {
    id: []const u8,
    name: []const u8,
    args: []const u8,
};

const RunToolResultSnap = struct {
    id: []const u8,
    out: []const u8,
    is_err: bool,
};

const RunUsageSnap = struct {
    in_tok: u64,
    out_tok: u64,
    tot_tok: u64,
};

const RunEventsSnap = struct {
    prompt: []const u8,
    text: []const u8,
    thinking: []const u8,
    tool_call: RunToolCallSnap,
    tool_result: RunToolResultSnap,
    usage: RunUsageSnap,
    stop: core.session.Event.StopReason,
    err: []const u8,
};

const RunVerboseSnap = struct {
    provider: RunProviderSnap,
    store: RunStoreSnap,
    events: RunEventsSnap,
    out: []const u8,
};

const RunErrSnap = struct {
    deinit_ct: usize,
    append_ct: usize,
    prompt: []const u8,
    out: []const u8,
};

const RunStopSnap = struct {
    deinit_ct: usize,
    append_ct: usize,
    out: []const u8,
};

test "exec runs prompt path and persists mapped provider events" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const StreamImpl = struct {
        idx: usize = 0,
        deinit_ct: usize = 0,
        evs: []const core.providers.Ev,

        fn next(self: *@This()) !?core.providers.Ev {
            if (self.idx >= self.evs.len) return null;
            const ev = self.evs[self.idx];
            self.idx += 1;
            return ev;
        }

        fn deinit(self: *@This()) void {
            self.deinit_ct += 1;
        }
    };

    const ProviderImpl = struct {
        start_ct: usize = 0,
        model: []const u8 = "",
        msg_ct: usize = 0,
        part_ct: usize = 0,
        role: core.providers.Role = .assistant,
        prompt: []const u8 = "",
        stream: StreamImpl,

        fn start(self: *@This(), req: core.providers.Req) !core.providers.Stream {
            self.start_ct += 1;
            self.model = req.model;
            self.msg_ct = req.msgs.len;

            if (req.msgs.len > 0) {
                const msg = req.msgs[0];
                self.role = msg.role;
                self.part_ct = msg.parts.len;
                if (msg.parts.len > 0) {
                    switch (msg.parts[0]) {
                        .text => |text| self.prompt = text,
                        else => return error.BadPromptPart,
                    }
                }
            }

            return core.providers.Stream.from(
                StreamImpl,
                &self.stream,
                StreamImpl.next,
                StreamImpl.deinit,
            );
        }
    };

    const ReaderImpl = struct {
        fn next(_: *@This()) !?core.session.Event {
            return null;
        }

        fn deinit(_: *@This()) void {}
    };

    const StoreImpl = struct {
        append_ct: usize = 0,
        replay_ct: usize = 0,
        deinit_ct: usize = 0,
        sid: []const u8 = "",
        evs: [16]core.session.Event = undefined,
        len: usize = 0,
        rdr: ReaderImpl = .{},

        fn append(self: *@This(), sid: []const u8, ev: core.session.Event) !void {
            if (self.len >= self.evs.len) return error.StoreFull;
            self.append_ct += 1;
            self.sid = sid;
            self.evs[self.len] = ev;
            self.len += 1;
        }

        fn replay(self: *@This(), _: []const u8) !core.session.Reader {
            self.replay_ct += 1;
            return core.session.Reader.from(
                ReaderImpl,
                &self.rdr,
                ReaderImpl.next,
                ReaderImpl.deinit,
            );
        }

        fn deinit(self: *@This()) void {
            self.deinit_ct += 1;
        }
    };

    const in_evs = [_]core.providers.Ev{
        .{ .text = "out-a" },
        .{ .thinking = "think-a" },
        .{ .tool_call = .{
            .id = "call-1",
            .name = "read",
            .args = "{\"path\":\"x\"}",
        } },
        .{ .tool_result = .{
            .id = "call-1",
            .out = "ok",
            .is_err = false,
        } },
        .{ .usage = .{
            .in_tok = 5,
            .out_tok = 7,
            .tot_tok = 12,
        } },
        .{ .stop = .{
            .reason = .done,
        } },
        .{ .err = "warn-a" },
    };

    var provider_impl = ProviderImpl{
        .stream = .{
            .evs = in_evs[0..],
        },
    };
    const provider = core.providers.Provider.from(
        ProviderImpl,
        &provider_impl,
        ProviderImpl.start,
    );

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(
        StoreImpl,
        &store_impl,
        StoreImpl.append,
        StoreImpl.replay,
        StoreImpl.deinit,
    );

    var out_buf: [512]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const result = try execVerbose(.{
        .alloc = std.testing.allocator,
        .provider = provider,
        .store = store,
        .sid = "sid-1",
        .prompt = "ship-it",
    }, out_fbs.writer().any(), true);

    try std.testing.expectEqual(run_err.Result.ok, result);

    const snap = RunVerboseSnap{
        .provider = .{
            .start_ct = provider_impl.start_ct,
            .model = provider_impl.model,
            .msg_ct = provider_impl.msg_ct,
            .part_ct = provider_impl.part_ct,
            .role = provider_impl.role,
            .prompt = provider_impl.prompt,
            .deinit_ct = provider_impl.stream.deinit_ct,
        },
        .store = .{
            .replay_ct = store_impl.replay_ct,
            .append_ct = store_impl.append_ct,
            .len = store_impl.len,
            .sid = store_impl.sid,
        },
        .events = .{
            .prompt = switch (store_impl.evs[0].data) {
                .prompt => |out| out.text,
                else => return error.TestUnexpectedResult,
            },
            .text = switch (store_impl.evs[1].data) {
                .text => |out| out.text,
                else => return error.TestUnexpectedResult,
            },
            .thinking = switch (store_impl.evs[2].data) {
                .thinking => |out| out.text,
                else => return error.TestUnexpectedResult,
            },
            .tool_call = switch (store_impl.evs[3].data) {
                .tool_call => |out| .{ .id = out.id, .name = out.name, .args = out.args },
                else => return error.TestUnexpectedResult,
            },
            .tool_result = switch (store_impl.evs[4].data) {
                .tool_result => |out| .{ .id = out.id, .out = out.out, .is_err = out.is_err },
                else => return error.TestUnexpectedResult,
            },
            .usage = switch (store_impl.evs[5].data) {
                .usage => |out| .{ .in_tok = out.in_tok, .out_tok = out.out_tok, .tot_tok = out.tot_tok },
                else => return error.TestUnexpectedResult,
            },
            .stop = switch (store_impl.evs[6].data) {
                .stop => |out| out.reason,
                else => return error.TestUnexpectedResult,
            },
            .err = switch (store_impl.evs[7].data) {
                .err => |out| out.text,
                else => return error.TestUnexpectedResult,
            },
        },
        .out = out_fbs.getWritten(),
    };
    try oh.snap(@src(),
        \\modes.print.run.RunVerboseSnap
        \\  .provider: modes.print.run.RunProviderSnap
        \\    .start_ct: usize = 1
        \\    .model: []const u8
        \\      "default"
        \\    .msg_ct: usize = 1
        \\    .part_ct: usize = 1
        \\    .role: core.providers.contract.Role
        \\      .user
        \\    .prompt: []const u8
        \\      "ship-it"
        \\    .deinit_ct: usize = 1
        \\  .store: modes.print.run.RunStoreSnap
        \\    .replay_ct: usize = 0
        \\    .append_ct: usize = 8
        \\    .len: usize = 8
        \\    .sid: []const u8
        \\      "sid-1"
        \\  .events: modes.print.run.RunEventsSnap
        \\    .prompt: []const u8
        \\      "ship-it"
        \\    .text: []const u8
        \\      "out-a"
        \\    .thinking: []const u8
        \\      "think-a"
        \\    .tool_call: modes.print.run.RunToolCallSnap
        \\      .id: []const u8
        \\        "call-1"
        \\      .name: []const u8
        \\        "read"
        \\      .args: []const u8
        \\        "{"path":"x"}"
        \\    .tool_result: modes.print.run.RunToolResultSnap
        \\      .id: []const u8
        \\        "call-1"
        \\      .out: []const u8
        \\        "ok"
        \\      .is_err: bool = false
        \\    .usage: modes.print.run.RunUsageSnap
        \\      .in_tok: u64 = 5
        \\      .out_tok: u64 = 7
        \\      .tot_tok: u64 = 12
        \\    .stop: core.session.schema.Event.StopReason
        \\      .done
        \\    .err: []const u8
        \\      "warn-a"
        \\  .out: []const u8
        \\    "out-a
        \\thinking "think-a"
        \\tool_call id="call-1" name="read" args="{\"path\":\"x\"}"
        \\tool_result id="call-1" is_err=false out="ok"
        \\usage in=5 out=7 total=12
        \\stop reason=done
        \\err "warn-a"
        \\"
    ).expectEqual(snap);
}

test "exec deinit stream and maps stream next error to typed print error" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const StreamImpl = struct {
        idx: usize = 0,
        fail_at: usize = 0,
        deinit_ct: usize = 0,

        fn next(self: *@This()) !?core.providers.Ev {
            if (self.idx == self.fail_at) return error.StreamFail;
            self.idx += 1;
            return .{ .text = "nope" };
        }

        fn deinit(self: *@This()) void {
            self.deinit_ct += 1;
        }
    };

    const ProviderImpl = struct {
        stream: StreamImpl = .{},

        fn start(self: *@This(), _: core.providers.Req) !core.providers.Stream {
            return core.providers.Stream.from(
                StreamImpl,
                &self.stream,
                StreamImpl.next,
                StreamImpl.deinit,
            );
        }
    };

    const ReaderImpl = struct {
        fn next(_: *@This()) !?core.session.Event {
            return null;
        }

        fn deinit(_: *@This()) void {}
    };

    const StoreImpl = struct {
        append_ct: usize = 0,
        evs: [2]core.session.Event = undefined,
        rdr: ReaderImpl = .{},

        fn append(self: *@This(), _: []const u8, ev: core.session.Event) !void {
            if (self.append_ct >= self.evs.len) return error.StoreFull;
            self.evs[self.append_ct] = ev;
            self.append_ct += 1;
        }

        fn replay(self: *@This(), _: []const u8) !core.session.Reader {
            return core.session.Reader.from(
                ReaderImpl,
                &self.rdr,
                ReaderImpl.next,
                ReaderImpl.deinit,
            );
        }

        fn deinit(_: *@This()) void {}
    };

    var provider_impl = ProviderImpl{};
    const provider = core.providers.Provider.from(
        ProviderImpl,
        &provider_impl,
        ProviderImpl.start,
    );

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(
        StoreImpl,
        &store_impl,
        StoreImpl.append,
        StoreImpl.replay,
        StoreImpl.deinit,
    );

    var out_buf: [32]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    try std.testing.expectError(error.StreamRead, execVerbose(.{
        .alloc = std.testing.allocator,
        .provider = provider,
        .store = store,
        .sid = "sid-2",
        .prompt = "prompt-2",
    }, out_fbs.writer().any(), true));

    const snap = RunErrSnap{
        .deinit_ct = provider_impl.stream.deinit_ct,
        .append_ct = store_impl.append_ct,
        .prompt = switch (store_impl.evs[0].data) {
            .prompt => |out| out.text,
            else => return error.TestUnexpectedResult,
        },
        .out = out_fbs.getWritten(),
    };
    try oh.snap(@src(),
        \\modes.print.run.RunErrSnap
        \\  .deinit_ct: usize = 1
        \\  .append_ct: usize = 1
        \\  .prompt: []const u8
        \\    "prompt-2"
        \\  .out: []const u8
        \\    ""
    ).expectEqual(snap);
}

test "exec maps max_out stop reason to deterministic typed error" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const StreamImpl = struct {
        idx: usize = 0,
        deinit_ct: usize = 0,
        evs: []const core.providers.Ev,

        fn next(self: *@This()) !?core.providers.Ev {
            if (self.idx >= self.evs.len) return null;
            const ev = self.evs[self.idx];
            self.idx += 1;
            return ev;
        }

        fn deinit(self: *@This()) void {
            self.deinit_ct += 1;
        }
    };

    const ProviderImpl = struct {
        stream: StreamImpl,

        fn start(self: *@This(), _: core.providers.Req) !core.providers.Stream {
            return core.providers.Stream.from(
                StreamImpl,
                &self.stream,
                StreamImpl.next,
                StreamImpl.deinit,
            );
        }
    };

    const ReaderImpl = struct {
        fn next(_: *@This()) !?core.session.Event {
            return null;
        }

        fn deinit(_: *@This()) void {}
    };

    const StoreImpl = struct {
        append_ct: usize = 0,
        evs: [4]core.session.Event = undefined,
        rdr: ReaderImpl = .{},

        fn append(self: *@This(), _: []const u8, ev: core.session.Event) !void {
            if (self.append_ct >= self.evs.len) return error.StoreFull;
            self.evs[self.append_ct] = ev;
            self.append_ct += 1;
        }

        fn replay(self: *@This(), _: []const u8) !core.session.Reader {
            return core.session.Reader.from(
                ReaderImpl,
                &self.rdr,
                ReaderImpl.next,
                ReaderImpl.deinit,
            );
        }

        fn deinit(_: *@This()) void {}
    };

    const in_evs = [_]core.providers.Ev{
        .{ .text = "out-z" },
        .{ .stop = .{ .reason = .max_out } },
    };

    var provider_impl = ProviderImpl{
        .stream = .{
            .evs = in_evs[0..],
        },
    };
    const provider = core.providers.Provider.from(
        ProviderImpl,
        &provider_impl,
        ProviderImpl.start,
    );

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(
        StoreImpl,
        &store_impl,
        StoreImpl.append,
        StoreImpl.replay,
        StoreImpl.deinit,
    );

    var out_buf: [128]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const result = try execVerbose(.{
        .alloc = std.testing.allocator,
        .provider = provider,
        .store = store,
        .sid = "sid-3",
        .prompt = "prompt-3",
    }, out_fbs.writer().any(), true);

    try std.testing.expectEqual(run_err.Result{ .stop = .max_out }, result);

    const snap = RunStopSnap{
        .deinit_ct = provider_impl.stream.deinit_ct,
        .append_ct = store_impl.append_ct,
        .out = out_fbs.getWritten(),
    };
    try oh.snap(@src(),
        \\modes.print.run.RunStopSnap
        \\  .deinit_ct: usize = 1
        \\  .append_ct: usize = 3
        \\  .out: []const u8
        \\    "out-z
        \\stop reason=max_out
        \\"
    ).expectEqual(snap);
}

