//! Runtime orchestration: wire providers, tools, and modes together.
const builtin = @import("builtin");
const std = @import("std");
const cli = @import("cli.zig");
const bg = @import("bg.zig");
const changelog = @import("changelog.zig");
const report = @import("report.zig");
const update_mod = @import("update.zig");
const version_check = @import("version.zig");
const config = @import("config.zig");
const core = @import("../core.zig");
const core_skill = @import("../core/skill.zig");
const prov_contract = @import("../core/providers/contract.zig");
const print_fmt = @import("../modes/print/format.zig");
const print_err = @import("../modes/print/errors.zig");
const tui_harness = @import("../modes/tui/harness.zig");
const tui_render = @import("../modes/tui/render.zig");
const tui_term = @import("../modes/tui/term.zig");
const tui_transcript = @import("../modes/tui/transcript.zig");
const tui_input = @import("../modes/tui/input.zig");
const tui_editor = @import("../modes/tui/editor.zig");
const tui_frame = @import("../modes/tui/frame.zig");
const tui_theme = @import("../modes/tui/theme.zig");
const tui_overlay = @import("../modes/tui/overlay.zig");
const tui_panels = @import("../modes/tui/panels.zig");
const tui_path_complete = @import("../modes/tui/path_complete.zig");
const args_mod = @import("args.zig");
const path_guard = @import("../core/tools/path_guard.zig");
const audit_e2e = @import("../test/audit_e2e.zig");
const provider_mock = @import("../test/provider_mock.zig");
const syslog_mock = @import("../test/syslog_mock.zig");

pub const Err = error{
    SessionNotFound,
    AmbiguousSession,
    InvalidSessionPath,
    TerminalSetupFailed,
};

const map_ctx_t = struct {
    fn map(_: *@This(), err: anyerror) core.providers.types.Err {
        if (err == error.Timeout or err == error.WireBreak) return error.TransportTransient;
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.TransportFatal;
    }
};

const ProviderRuntime = struct {
    tr: core.providers.proc_transport.Transport,
    map_ctx: map_ctx_t = .{},
    map: core.providers.types.Adapter = undefined,
    pol: core.providers.client.Policy = undefined,
    client: core.providers.client.Client = undefined,

    fn init(self: *ProviderRuntime, alloc: std.mem.Allocator, provider_cmd: []const u8) !void {
        self.tr = try core.providers.proc_transport.Transport.init(.{
            .alloc = alloc,
            .cmd = provider_cmd,
        });
        self.map_ctx = .{};
        self.map = core.providers.types.Adapter.from(map_ctx_t, &self.map_ctx, map_ctx_t.map);
        self.pol = try core.providers.client.Policy.init(.{
            .max_tries = 4,
            .backoff = .{
                .base_ms = 2000,
                .max_ms = 60000,
                .mul = 2,
            },
            .retryable = core.providers.types.retryable,
        });
        self.client = core.providers.client.Client.init(
            alloc,
            self.tr.asRawTransport(),
            self.map,
            self.pol,
            null,
        );
    }

    fn deinit(self: *ProviderRuntime) void {
        self.tr.deinit();
        self.* = undefined;
    }
};

const NativeProviderKind = enum { anthropic, openai };
const native_provider_kind_map = std.StaticStringMap(NativeProviderKind).initComptime(.{
    .{ "anthropic", .anthropic },
    .{ "openai", .openai },
});

fn parseNativeProviderKind(provider: []const u8) ?NativeProviderKind {
    return native_provider_kind_map.get(provider);
}

const NativeProviderRuntime = union(enum) {
    anthropic: core.providers.anthropic.Client,
    openai: core.providers.openai.Client,

    fn init(alloc: std.mem.Allocator, kind: NativeProviderKind, hooks: core.providers.auth.Hooks) !NativeProviderRuntime {
        return switch (kind) {
            .anthropic => .{ .anthropic = try core.providers.anthropic.Client.init(alloc, hooks) },
            .openai => .{ .openai = try core.providers.openai.Client.init(alloc, hooks) },
        };
    }

    fn asProvider(self: *NativeProviderRuntime) core.providers.Provider {
        return switch (self.*) {
            .anthropic => |*client| client.asProvider(),
            .openai => |*client| client.asProvider(),
        };
    }

    fn isSub(self: *const NativeProviderRuntime) bool {
        return switch (self.*) {
            .anthropic => |client| client.isSub(),
            .openai => |client| client.isSub(),
        };
    }

    fn deinit(self: *NativeProviderRuntime) void {
        switch (self.*) {
            .anthropic => |*client| client.deinit(),
            .openai => |*client| client.deinit(),
        }
        self.* = undefined;
    }
};

const missing_provider_msg = "provider unavailable; choose anthropic/openai with credentials or set --provider-cmd/PZ_PROVIDER_CMD";
const missing_anthropic_provider_msg = "anthropic credentials missing; set ANTHROPIC_API_KEY or ANTHROPIC_OAUTH_TOKEN, run /login anthropic, or set --provider-cmd/PZ_PROVIDER_CMD";
const missing_openai_provider_msg = "openai credentials missing; set OPENAI_API_KEY, run /login openai, or set --provider-cmd/PZ_PROVIDER_CMD";
const unsupported_native_provider_msg = "native provider unavailable for this provider label; use anthropic/openai or set --provider-cmd/PZ_PROVIDER_CMD";
const policy_denied_msg = "blocked by policy";

fn missingProviderMsgForInitErr(kind: NativeProviderKind, err: anyerror) []const u8 {
    return switch (kind) {
        .anthropic => switch (err) {
            error.AuthNotFound => missing_anthropic_provider_msg,
            else => missing_provider_msg,
        },
        .openai => switch (err) {
            error.AuthNotFound => missing_openai_provider_msg,
            else => missing_provider_msg,
        },
    };
}

const RuntimePolicy = struct {
    alloc: std.mem.Allocator,
    resolved: core.policy.Resolved,

    fn load(alloc: std.mem.Allocator) !RuntimePolicy {
        const cwd = try std.process.getCwdAlloc(alloc);
        defer alloc.free(cwd);
        const home = if (builtin.is_test) null else std.posix.getenv("HOME");
        return .{
            .alloc = alloc,
            .resolved = try core.policy.loadResolved(alloc, cwd, home),
        };
    }

    fn deinit(self: *RuntimePolicy) void {
        core.policy.deinitResolved(self.alloc, self.resolved);
        self.* = undefined;
    }

    fn hash(self: *const RuntimePolicy) []const u8 {
        return self.resolved.hash_hex[0..];
    }

    fn bind(self: *const RuntimePolicy) core.policy.ApprovalBind {
        return self.resolved.bind();
    }

    fn enforced(self: *const RuntimePolicy) bool {
        return self.resolved.has_files;
    }

    fn allows(self: *const RuntimePolicy, path: []const u8, tool: ?[]const u8) bool {
        if (!self.enforced()) return true;
        return core.policy.evaluate(self.resolved.doc.rules, path, tool) == .allow;
    }

    fn allowsCmd(self: *const RuntimePolicy, name: []const u8) bool {
        var buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "runtime/cmd/{s}", .{name}) catch return false;
        return self.allows(path, null);
    }

    fn allowsSubagent(self: *const RuntimePolicy, agent_id: []const u8) bool {
        var buf: [128]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "runtime/subagent/{s}", .{agent_id}) catch return false;
        return self.allows(path, null);
    }

    fn allowsTool(self: *const RuntimePolicy, name: []const u8, call: core.tools.Call) bool {
        var buf: [256]u8 = undefined;
        const path = toolPolicyPath(&buf, name, call) catch return false;
        return self.allows(path, name);
    }
};

fn toolPolicyPath(buf: *[256]u8, name: []const u8, call: core.tools.Call) ![]const u8 {
    return switch (call.args) {
        .read => |args| args.path,
        .write => |args| args.path,
        .bash => |args| args.cwd orelse try std.fmt.bufPrint(buf, "runtime/tool/{s}", .{name}),
        .edit => |args| args.path,
        .grep => |args| args.path,
        .find => |args| args.path,
        .ls => |args| args.path,
        .agent => |args| try std.fmt.bufPrint(buf, "runtime/subagent/{s}", .{args.agent_id}),
        .web => try std.fmt.bufPrint(buf, "runtime/tool/{s}", .{name}),
        .ask => try std.fmt.bufPrint(buf, "runtime/tool/{s}", .{name}),
        .skill => |args| try std.fmt.bufPrint(buf, "runtime/skill/{s}", .{args.name}),
    };
}

const PolicyToolDispatch = struct {
    pol: *const RuntimePolicy,
    name: []const u8,
    audit: ?PolicyToolAudit = null,
    inner: core.tools.Dispatch,

    fn run(self: *@This(), call: core.tools.Call, sink: core.tools.Sink) !core.tools.Result {
        if (!self.pol.allowsTool(self.name, call)) {
            if (self.audit) |audit| try audit.emit(call, self.name);
            return .{
                .call_id = call.id,
                .started_at_ms = call.at_ms,
                .ended_at_ms = call.at_ms,
                .out = &.{},
                .final = .{
                    .failed = .{
                        .kind = .denied,
                        .msg = policy_denied_msg,
                    },
                },
            };
        }
        return self.inner.run(call, sink);
    }
};

const PolicyToolRegistry = struct {
    ctxs: [10]PolicyToolDispatch = undefined,
    entries: [10]core.tools.Entry = undefined,
    reg: core.tools.Registry = undefined,

    fn init(self: *PolicyToolRegistry, pol: *const RuntimePolicy, base: core.tools.Registry, audit: ?PolicyToolAudit) void {
        for (base.entries, 0..) |entry, i| {
            self.ctxs[i] = .{
                .pol = pol,
                .name = entry.name,
                .audit = audit,
                .inner = entry.dispatch,
            };
            self.entries[i] = entry;
            self.entries[i].dispatch = core.tools.Dispatch.from(
                PolicyToolDispatch,
                &self.ctxs[i],
                PolicyToolDispatch.run,
            );
        }
        self.reg = core.tools.Registry.init(self.entries[0..base.entries.len]);
    }

    fn registry(self: *const PolicyToolRegistry) core.tools.Registry {
        return self.reg;
    }
};

const PolicyToolAuth = struct {
    alloc: std.mem.Allocator,
    pol: *const RuntimePolicy,
    sid: []const u8,
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, core.audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = std.time.milliTimestamp,
    seq: *u64,

    fn check(self: *@This(), call_id: []const u8, name: []const u8, kind: core.tools.Kind, parsed_args: core.tools.Call.Args) !void {
        const call: core.tools.Call = .{
            .id = "",
            .kind = kind,
            .args = parsed_args,
            .src = .model,
            .at_ms = 0,
            .cancel = null,
        };
        if (!self.pol.allowsTool(name, call)) {
            try self.emitDeny(call_id, name, kind, parsed_args);
            return error.PolicyDenied;
        }
    }

    fn emitDeny(self: *@This(), call_id: []const u8, name: []const u8, kind: core.tools.Kind, parsed_args: core.tools.Call.Args) !void {
        const emit = self.emit_audit orelse return;
        const seq = self.seq.*;
        self.seq.* +%= 1;
        const info = toolAuditInfo(kind, parsed_args);
        try emit(self.emit_audit_ctx.?, self.alloc, .{
            .ts_ms = self.now_ms(),
            .sid = self.sid,
            .seq = seq,
            .sev = .warn,
            .out = .deny,
            .actor = .{
                .kind = .tool,
                .id = .{ .text = name, .vis = .@"pub" },
            },
            .res = .{
                .kind = info.res_kind,
                .name = .{ .text = info.target, .vis = .mask },
                .op = info.op,
            },
            .msg = .{ .text = "policy denied", .vis = .@"pub" },
            .data = .{
                .tool = .{
                    .name = .{ .text = name, .vis = .@"pub" },
                    .call_id = call_id,
                    .argv = .{ .text = info.argv, .vis = .mask },
                },
            },
        });
    }
};

const ToolAuditInfo = struct {
    res_kind: core.audit.ResKind,
    op: []const u8,
    target: []const u8,
    argv: []const u8,
};

fn toolAuditInfo(kind: core.tools.Kind, parsed_args: core.tools.Call.Args) ToolAuditInfo {
    return switch (kind) {
        .read => .{ .res_kind = .file, .op = "read", .target = parsed_args.read.path, .argv = parsed_args.read.path },
        .write => .{ .res_kind = .file, .op = "write", .target = parsed_args.write.path, .argv = parsed_args.write.path },
        .bash => .{ .res_kind = .cmd, .op = "exec", .target = parsed_args.bash.cmd, .argv = parsed_args.bash.cmd },
        .edit => .{ .res_kind = .file, .op = "edit", .target = parsed_args.edit.path, .argv = parsed_args.edit.path },
        .grep => .{ .res_kind = .file, .op = "grep", .target = parsed_args.grep.path, .argv = parsed_args.grep.pattern },
        .find => .{ .res_kind = .file, .op = "find", .target = parsed_args.find.path, .argv = parsed_args.find.name },
        .ls => .{ .res_kind = .file, .op = "list", .target = parsed_args.ls.path, .argv = parsed_args.ls.path },
        .agent => .{ .res_kind = .cmd, .op = "run", .target = parsed_args.agent.agent_id, .argv = parsed_args.agent.agent_id },
        .web => .{ .res_kind = .net, .op = "request", .target = parsed_args.web.url, .argv = parsed_args.web.url },
        .ask => .{ .res_kind = .cfg, .op = "ask", .target = "ask", .argv = "ask" },
        .skill => .{ .res_kind = .cmd, .op = "run", .target = parsed_args.skill.name, .argv = parsed_args.skill.name },
    };
}

fn initSubagentStub(pol: *const RuntimePolicy, agent_id: []const u8) !core.agent.Stub {
    if (!pol.allowsSubagent(agent_id)) return error.PolicyDenied;
    return try core.agent.Stub.init(agent_id, pol.hash());
}

const MissingProvider = struct {
    alloc: std.mem.Allocator,
    msg: []const u8 = missing_provider_msg,

    fn asProvider(self: *MissingProvider) core.providers.Provider {
        return core.providers.Provider.from(MissingProvider, self, MissingProvider.start);
    }

    fn start(self: *MissingProvider, _: core.providers.Req) !core.providers.Stream {
        const stream = try self.alloc.create(MissingProviderStream);
        stream.* = .{
            .alloc = self.alloc,
            .msg = self.msg,
        };
        return core.providers.Stream.from(
            MissingProviderStream,
            stream,
            MissingProviderStream.next,
            MissingProviderStream.deinit,
        );
    }
};

const MissingProviderStream = struct {
    alloc: std.mem.Allocator,
    msg: []const u8,
    idx: u8 = 0,

    fn next(self: *MissingProviderStream) !?core.providers.Ev {
        defer self.idx +|= 1;

        return switch (self.idx) {
            0 => .{ .err = self.msg },
            1 => .{
                .stop = .{ .reason = .err },
            },
            else => null,
        };
    }

    fn deinit(self: *MissingProviderStream) void {
        self.alloc.destroy(self);
    }
};

const PrintSink = struct {
    fmt: print_fmt.Formatter,
    stop_reason: ?core.providers.StopReason = null,

    fn init(alloc: std.mem.Allocator, out: std.Io.AnyWriter) PrintSink {
        return .{
            .fmt = print_fmt.Formatter.init(alloc, out),
        };
    }

    fn deinit(self: *PrintSink) void {
        self.fmt.deinit();
    }

    fn push(self: *PrintSink, ev: core.loop.ModeEv) !void {
        switch (ev) {
            .provider => |pev| {
                switch (pev) {
                    .stop => |stop| {
                        // stop:tool is an internal handoff marker when loop continues.
                        if (stop.reason == .tool) return;
                        self.stop_reason = core.providers.StopReason.merge(self.stop_reason, stop.reason);
                    },
                    else => {},
                }
                try self.fmt.push(pev);
            },
            .session_write_err => |msg| {
                if (self.fmt.text_seen and !self.fmt.text_ended_nl) {
                    try self.fmt.out.writeByte('\n');
                    self.fmt.text_ended_nl = true;
                }
                try self.fmt.out.writeAll("[session write failed: ");
                try self.fmt.out.writeAll(msg);
                try self.fmt.out.writeAll("]\n");
            },
            else => {},
        }
    }
};

const TuiSink = struct {
    ui: *tui_harness.Ui,
    out: std.Io.AnyWriter,

    fn push(self: *TuiSink, ev: core.loop.ModeEv) !void {
        switch (ev) {
            .provider => |pev| try self.ui.onProvider(pev),
            .session_write_err => |msg| {
                const note = try std.fmt.allocPrint(self.ui.alloc, "[session write failed: {s}]", .{msg});
                defer self.ui.alloc.free(note);
                try self.ui.tr.infoText(note);
            },
            else => {},
        }
        try self.ui.draw(self.out);
    }
};

const AskUiCtx = struct {
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    out: std.Io.AnyWriter,
    watcher: *InputWatcher,

    const Answer = struct {
        id: []const u8,
        answer: []const u8,
        index: usize,
    };

    const StoredAnswer = struct {
        answer: ?[]u8 = null,
        index: ?usize = null,
    };

    const RowKind = union(enum) {
        option: usize,
        other: void,
        prev: void,
        next: void,
        submit: void,
    };

    const RowSet = struct {
        items: [][]u8,
        kinds: []RowKind,

        fn deinit(self: *RowSet, alloc: std.mem.Allocator) void {
            if (self.items.len > 0) {
                for (self.items) |item| alloc.free(item);
                alloc.free(self.items);
            }
            if (self.kinds.len > 0) alloc.free(self.kinds);
            self.items = &.{};
            self.kinds = &.{};
        }

        fn releaseItems(self: *RowSet) [][]u8 {
            const out = self.items;
            self.items = &.{};
            return out;
        }
    };

    fn runOnMain(self: *AskUiCtx, reader: *tui_input.Reader, args: core.tools.Call.AskArgs) anyerror![]u8 {
        if (args.questions.len == 0) return error.InvalidArgs;

        self.watcher.setPaused(true);
        defer self.watcher.setPaused(false);
        return self.runWithReader(reader, args);
    }

    fn runWithReader(self: *AskUiCtx, reader: *tui_input.Reader, args: core.tools.Call.AskArgs) anyerror![]u8 {
        if (args.questions.len == 0) return error.InvalidArgs;

        var stored = try self.alloc.alloc(StoredAnswer, args.questions.len);
        defer {
            for (stored) |a| {
                if (a.answer) |txt| self.alloc.free(txt);
            }
            self.alloc.free(stored);
        }
        for (stored) |*a| a.* = .{};

        var sel_by_q = try self.alloc.alloc(usize, args.questions.len);
        defer self.alloc.free(sel_by_q);
        @memset(sel_by_q, 0);

        defer {
            if (self.ui.ov) |*ov| {
                ov.deinit(self.alloc);
                self.ui.ov = null;
                self.ui.draw(self.out) catch {};
            }
        }

        var q_idx: usize = 0;
        var typing_other = false;
        var other_ed = tui_editor.Editor.init(self.alloc);
        defer other_ed.deinit();
        var status_buf: [240]u8 = undefined;
        var status_len: usize = 0;

        while (true) {
            const q = args.questions[q_idx];
            if (q.id.len == 0 or q.question.len == 0) return error.InvalidArgs;

            if (self.ui.ov) |*cur| {
                cur.deinit(self.alloc);
                self.ui.ov = null;
            }

            var rows = try buildAskRows(self.alloc, q, stored[q_idx], q_idx == 0, q_idx + 1 == args.questions.len);
            defer rows.deinit(self.alloc);
            if (rows.items.len == 0) return error.InvalidArgs;
            if (sel_by_q[q_idx] >= rows.items.len) sel_by_q[q_idx] = 0;

            var title_buf: [256]u8 = undefined;
            const raw_title = if (q.header.len > 0) q.header else q.question;
            const title = std.fmt.bufPrint(
                &title_buf,
                "[{d}/{d}] {s}",
                .{ q_idx + 1, args.questions.len, raw_title },
            ) catch raw_title;

            const hint = if (status_len > 0)
                status_buf[0..status_len]
            else if (typing_other)
                "Type a custom answer. Enter saves it."
            else
                q.question;

            var ov = tui_overlay.Overlay.initDyn(
                self.alloc,
                rows.releaseItems(),
                title,
                .session,
            );
            ov.sel = sel_by_q[q_idx];
            ov.fixScroll();
            ov.hint = hint;
            if (typing_other) {
                ov.input_label = "Type something else";
                ov.input_text = other_ed.text();
                ov.input_cursor = true;
            }
            self.ui.ov = ov;
            try self.ui.draw(self.out);

            switch (reader.next()) {
                .key => |key| {
                    switch (key) {
                        .esc, .ctrl_c => {
                            if (self.ui.ov) |*cur| {
                                cur.deinit(self.alloc);
                                self.ui.ov = null;
                                try self.ui.draw(self.out);
                            }
                            const partial = try collectAskAnswers(self.alloc, args.questions, stored);
                            defer self.alloc.free(partial);
                            return buildAskResult(self.alloc, true, partial);
                        },
                        else => {},
                    }

                    if (typing_other) {
                        const act = try other_ed.apply(key);
                        switch (act) {
                            .submit => {
                                const trimmed = std.mem.trim(u8, other_ed.text(), " \t\r\n");
                                if (trimmed.len == 0) {
                                    setStatus(&status_buf, &status_len, "Type a non-empty custom answer.");
                                } else {
                                    try self.setStoredAnswer(&stored[q_idx], trimmed, q.options.len);
                                    typing_other = false;
                                    status_len = 0;
                                }
                            },
                            else => {},
                        }
                        continue;
                    }

                    switch (key) {
                        .up => {
                            sel_by_q[q_idx] = if (sel_by_q[q_idx] > 0) sel_by_q[q_idx] - 1 else rows.kinds.len - 1;
                            status_len = 0;
                        },
                        .down => {
                            sel_by_q[q_idx] = if (sel_by_q[q_idx] + 1 < rows.kinds.len) sel_by_q[q_idx] + 1 else 0;
                            status_len = 0;
                        },
                        .left, .page_up => {
                            if (q_idx > 0) q_idx -= 1;
                            status_len = 0;
                        },
                        .right, .page_down => {
                            if (q_idx + 1 < args.questions.len) q_idx += 1;
                            status_len = 0;
                        },
                        .char => |cp| {
                            if (cp >= '1' and cp <= '9') {
                                const n: usize = @intCast(cp - '1');
                                if (n < q.options.len) {
                                    try self.setStoredAnswer(&stored[q_idx], q.options[n].label, n);
                                    status_len = 0;
                                }
                            }
                        },
                        .enter => switch (rows.kinds[sel_by_q[q_idx]]) {
                            .option => |opt_idx| {
                                try self.setStoredAnswer(&stored[q_idx], q.options[opt_idx].label, opt_idx);
                                status_len = 0;
                            },
                            .other => {
                                typing_other = true;
                                const existing = if (stored[q_idx].index != null and stored[q_idx].index.? == q.options.len and stored[q_idx].answer != null)
                                    stored[q_idx].answer.?
                                else
                                    "";
                                try other_ed.setText(existing);
                                status_len = 0;
                            },
                            .prev => {
                                if (q_idx > 0) q_idx -= 1;
                                status_len = 0;
                            },
                            .next => {
                                if (stored[q_idx].answer == null) {
                                    setStatus(&status_buf, &status_len, "Pick an answer before moving to the next question.");
                                } else if (q_idx + 1 < args.questions.len) {
                                    q_idx += 1;
                                    status_len = 0;
                                }
                            },
                            .submit => {
                                if (firstUnanswered(stored)) |miss| {
                                    q_idx = miss;
                                    setStatus(&status_buf, &status_len, "Please answer all questions before submitting.");
                                } else {
                                    if (self.ui.ov) |*cur| {
                                        cur.deinit(self.alloc);
                                        self.ui.ov = null;
                                        try self.ui.draw(self.out);
                                    }
                                    const out_answers = try collectAskAnswers(self.alloc, args.questions, stored);
                                    defer self.alloc.free(out_answers);
                                    return buildAskResult(self.alloc, false, out_answers);
                                }
                            },
                        },
                        else => {},
                    }
                },
                .resize => {
                    if (tui_term.size(std.posix.STDOUT_FILENO)) |sz| {
                        try self.ui.resize(sz.w, sz.h);
                    }
                },
                .none => continue,
                .err => return error.TerminalSetupFailed,
                else => {},
            }
        }
    }

    fn setStoredAnswer(self: *AskUiCtx, dst: *StoredAnswer, text: []const u8, index: usize) !void {
        if (dst.answer) |old| self.alloc.free(old);
        dst.answer = try self.alloc.dupe(u8, text);
        dst.index = index;
    }
};

fn collectAskAnswers(
    alloc: std.mem.Allocator,
    questions: []const core.tools.Call.AskArgs.Question,
    stored: []const AskUiCtx.StoredAnswer,
) ![]AskUiCtx.Answer {
    var ct: usize = 0;
    for (stored) |a| {
        if (a.answer != null) ct += 1;
    }
    const out = try alloc.alloc(AskUiCtx.Answer, ct);
    var i: usize = 0;
    for (questions, stored) |q, a| {
        const txt = a.answer orelse continue;
        out[i] = .{
            .id = q.id,
            .answer = txt,
            .index = a.index orelse 0,
        };
        i += 1;
    }
    return out;
}

fn firstUnanswered(stored: []const AskUiCtx.StoredAnswer) ?usize {
    for (stored, 0..) |a, i| {
        if (a.answer == null) return i;
    }
    return null;
}

fn setStatus(buf: *[240]u8, len: *usize, text: []const u8) void {
    const n = @min(buf.len, text.len);
    @memcpy(buf[0..n], text[0..n]);
    len.* = n;
}

fn buildAskRows(
    alloc: std.mem.Allocator,
    q: core.tools.Call.AskArgs.Question,
    selected: AskUiCtx.StoredAnswer,
    is_first: bool,
    is_last: bool,
) !AskUiCtx.RowSet {
    const TmpRow = struct {
        label: []u8,
        kind: AskUiCtx.RowKind,
    };

    var rows: std.ArrayListUnmanaged(TmpRow) = .empty;
    errdefer {
        for (rows.items) |r| alloc.free(r.label);
        rows.deinit(alloc);
    }

    for (q.options, 0..) |opt, idx| {
        const is_sel = selected.index != null and selected.index.? == idx;
        const prefix = if (is_sel) "[x]" else "[ ]";
        const label = if (opt.description.len == 0)
            try std.fmt.allocPrint(alloc, "{s} {s}", .{ prefix, opt.label })
        else
            try std.fmt.allocPrint(alloc, "{s} {s} - {s}", .{ prefix, opt.label, opt.description });
        try rows.append(alloc, .{
            .label = label,
            .kind = .{ .option = idx },
        });
    }

    const has_other = q.allow_other or q.options.len == 0;
    if (has_other) {
        const other_idx = q.options.len;
        const is_sel = selected.index != null and selected.index.? == other_idx;
        const prefix = if (is_sel) "[x]" else "[ ]";
        const label = if (is_sel and selected.answer != null)
            try std.fmt.allocPrint(alloc, "{s} Type something else: {s}", .{ prefix, selected.answer.? })
        else
            try std.fmt.allocPrint(alloc, "{s} Type something else", .{prefix});
        try rows.append(alloc, .{
            .label = label,
            .kind = .other,
        });
    }

    if (!is_first) {
        try rows.append(alloc, .{
            .label = try alloc.dupe(u8, "Previous question"),
            .kind = .prev,
        });
    }
    try rows.append(alloc, .{
        .label = try alloc.dupe(u8, if (is_last) "Submit answers" else "Next question"),
        .kind = if (is_last) .submit else .next,
    });

    const out_items = try alloc.alloc([]u8, rows.items.len);
    errdefer alloc.free(out_items);
    const out_kinds = try alloc.alloc(AskUiCtx.RowKind, rows.items.len);
    errdefer alloc.free(out_kinds);
    for (rows.items, 0..) |r, i| {
        out_items[i] = r.label;
        out_kinds[i] = r.kind;
    }
    rows.deinit(alloc);
    return .{
        .items = out_items,
        .kinds = out_kinds,
    };
}

fn buildAskResult(alloc: std.mem.Allocator, cancelled: bool, answers: []const AskUiCtx.Answer) ![]u8 {
    const OutAnswer = struct {
        id: []const u8,
        answer: []const u8,
        index: usize,
    };
    const Out = struct {
        cancelled: bool,
        answers: []const OutAnswer,
    };

    const out_answers = try alloc.alloc(OutAnswer, answers.len);
    defer alloc.free(out_answers);
    for (answers, 0..) |ans, i| {
        out_answers[i] = .{
            .id = ans.id,
            .answer = ans.answer,
            .index = ans.index,
        };
    }
    return std.json.Stringify.valueAlloc(alloc, Out{
        .cancelled = cancelled,
        .answers = out_answers,
    }, .{});
}

/// Reads stdin on a dedicated thread during streaming. Sets an atomic
/// flag when ESC is pressed, allowing the core loop's CancelSrc to
/// detect cancellation without platform-specific non-blocking hacks.
/// Mirrors pi's CancellableLoader + AbortController pattern.
const InputWatcher = struct {
    canceled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    paused: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    fd: std.posix.fd_t,
    wake_r: std.posix.fd_t,
    wake_w: std.posix.fd_t,
    /// Buffer for non-ESC bytes consumed during streaming, replayed after join().
    stash: [64]u8 = undefined,
    stash_len: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn init(fd: std.posix.fd_t) !InputWatcher {
        const pipe = try std.posix.pipe2(.{
            .NONBLOCK = true,
            .CLOEXEC = true,
        });
        errdefer {
            std.posix.close(pipe[0]);
            std.posix.close(pipe[1]);
        }
        return .{
            .fd = fd,
            .wake_r = pipe[0],
            .wake_w = pipe[1],
        };
    }

    fn deinit(self: *InputWatcher) void {
        self.join(null);
        std.posix.close(self.wake_r);
        std.posix.close(self.wake_w);
        self.* = undefined;
    }

    /// Start watching stdin for ESC on a background thread.
    /// Returns false if thread spawn failed (cancel unavailable).
    fn start(self: *InputWatcher) bool {
        self.canceled.store(false, .release);
        self.stop.store(false, .release);
        self.paused.store(false, .release);
        self.stash_len.store(0, .release);
        drainWake(self.wake_r);
        self.thread = std.Thread.spawn(.{}, watchFn, .{self}) catch return false;
        return true;
    }

    /// Stop the watcher, join the thread, replay stashed bytes into reader.
    fn join(self: *InputWatcher, reader: ?*tui_input.Reader) void {
        self.stop.store(true, .release);
        signalWake(self.wake_w);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        const n = self.stash_len.load(.acquire);
        if (n > 0) {
            if (reader) |r| r.inject(self.stash[0..n]);
        }
    }

    fn isCanceled(self: *InputWatcher) bool {
        return self.canceled.load(.acquire);
    }

    fn setPaused(self: *InputWatcher, paused: bool) void {
        self.paused.store(paused, .release);
        signalWake(self.wake_w);
    }

    fn isPaused(self: *InputWatcher) bool {
        return self.paused.load(.acquire);
    }

    fn watchFn(self: *InputWatcher) void {
        while (!self.stop.load(.acquire)) {
            const paused = self.paused.load(.acquire);
            var fds = [2]std.posix.pollfd{
                .{
                    .fd = self.wake_r,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                },
                .{
                    .fd = self.fd,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                },
            };
            const nfd: usize = if (paused) 1 else 2;
            const n = std.posix.poll(fds[0..nfd], -1) catch break;
            if (n == 0) continue;
            if ((fds[0].revents & std.posix.POLL.IN) != 0) {
                drainWake(self.wake_r);
                continue;
            }
            if (paused or (fds[1].revents & std.posix.POLL.IN) == 0) continue;
            var buf: [1]u8 = undefined;
            const r = std.posix.read(self.fd, &buf) catch break;
            if (r == 1 and buf[0] == 0x1b) {
                self.canceled.store(true, .release);
                return;
            }
            if (r == 1) {
                const cur = self.stash_len.load(.acquire);
                if (cur < self.stash.len) {
                    self.stash[cur] = buf[0];
                    self.stash_len.store(cur + 1, .release);
                }
            }
        }
    }
};

fn signalWake(fd: std.posix.fd_t) void {
    _ = std.posix.write(fd, "\x01") catch {};
}

fn drainWake(fd: std.posix.fd_t) void {
    var buf: [32]u8 = undefined;
    while (true) {
        _ = std.posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => return,
            else => return,
        };
    }
}

const TurnCancelFlag = struct {
    canceled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn clear(self: *TurnCancelFlag) void {
        self.canceled.store(false, .release);
    }

    fn request(self: *TurnCancelFlag) void {
        self.canceled.store(true, .release);
    }

    fn isCanceled(self: *TurnCancelFlag) bool {
        return self.canceled.load(.acquire);
    }
};

const LiveTurn = struct {
    const Req = struct {
        sid: []u8,
        prompt: []u8,
        model: []u8,
        provider_label: []u8,
        provider_opts: core.providers.Opts,
        system_prompt: ?[]u8 = null,

        fn deinit(self: *Req, alloc: std.mem.Allocator) void {
            alloc.free(self.sid);
            alloc.free(self.prompt);
            alloc.free(self.model);
            alloc.free(self.provider_label);
            if (self.system_prompt) |sp| alloc.free(sp);
            self.* = undefined;
        }
    };

    const ThreadCtx = struct {
        live: *LiveTurn,
        tctx: *const TurnCtx,
        req: Req,
    };

    alloc: std.mem.Allocator,
    mu: std.Thread.Mutex = .{},
    evs: std.ArrayListUnmanaged(SeqProviderEv) = .empty,
    ev_head: usize = 0,
    next_seq: u64 = 1,
    done: bool = false,
    running: bool = false,
    err_name: ?[]u8 = null,
    thr: ?std.Thread = null,
    wake_r: std.posix.fd_t,
    wake_w: std.posix.fd_t,
    cancel_flag: TurnCancelFlag = .{},
    abort_slot: core.providers.AbortSlot = .{},
    last_req: ?Req = null,
    last_stop: ?core.providers.StopReason = null,
    last_err: ?[]u8 = null,
    last_model: ?[]u8 = null,
    ask_txn: ?*AskTxn = null,

    const AskTxn = struct {
        mu: std.Thread.Mutex = .{},
        cv: std.Thread.Condition = .{},
        claimed: bool = false,
        done: bool = false,
        args: OwnedAskArgs,
        out: ?[]u8 = null,
        err: ?anyerror = null,

        fn wait(self: *AskTxn) ![]u8 {
            self.mu.lock();
            defer self.mu.unlock();
            while (!self.done) self.cv.wait(&self.mu);
            if (self.err) |err| return err;
            return self.out orelse error.TerminalSetupFailed;
        }
    };

    const SeqProviderEv = struct {
        seq: u64,
        ev: core.providers.Ev,
    };

    fn init(alloc: std.mem.Allocator) !LiveTurn {
        const pipe = try std.posix.pipe2(.{
            .NONBLOCK = true,
            .CLOEXEC = true,
        });
        errdefer {
            std.posix.close(pipe[0]);
            std.posix.close(pipe[1]);
        }
        return .{
            .alloc = alloc,
            .wake_r = pipe[0],
            .wake_w = pipe[1],
        };
    }

    fn deinit(self: *LiveTurn) void {
        self.requestCancel();
        self.failAsk(error.Canceled);
        if (self.thr) |thr| {
            thr.join();
            self.thr = null;
        }
        self.mu.lock();
        for (self.evs.items[self.ev_head..]) |sev| freeProviderEv(self.alloc, sev.ev);
        self.evs.deinit(self.alloc);
        if (self.err_name) |name| self.alloc.free(name);
        if (self.last_err) |e| self.alloc.free(e);
        if (self.last_model) |m| self.alloc.free(m);
        if (self.last_req) |*req| req.deinit(self.alloc);
        self.mu.unlock();
        std.posix.close(self.wake_r);
        std.posix.close(self.wake_w);
        self.* = undefined;
    }

    fn wakeFd(self: *const LiveTurn) std.posix.fd_t {
        return self.wake_r;
    }

    fn isRunning(self: *LiveTurn) bool {
        self.mu.lock();
        defer self.mu.unlock();
        return self.running;
    }

    fn requestCancel(self: *LiveTurn) void {
        self.cancel_flag.request();
        self.abort_slot.abort();
    }

    fn ask(self: *LiveTurn, args: core.tools.Call.AskArgs) ![]u8 {
        var tx = AskTxn{
            .args = try dupAskArgs(self.alloc, args),
        };
        defer tx.args.deinit(self.alloc);

        self.mu.lock();
        if (self.ask_txn != null) {
            self.mu.unlock();
            return error.AlreadyRunning;
        }
        self.ask_txn = &tx;
        self.mu.unlock();
        self.nudge();
        return tx.wait();
    }

    fn takeAsk(self: *LiveTurn) ?*AskTxn {
        self.mu.lock();
        defer self.mu.unlock();

        const tx = self.ask_txn orelse return null;
        if (tx.claimed) return null;
        tx.claimed = true;
        return tx;
    }

    fn finishAsk(self: *LiveTurn, tx: *AskTxn, out: anyerror![]u8) void {
        tx.mu.lock();
        if (out) |text| {
            tx.out = text;
        } else |err| {
            tx.err = err;
        }
        tx.done = true;
        tx.cv.signal();
        tx.mu.unlock();

        self.mu.lock();
        if (self.ask_txn == tx) self.ask_txn = null;
        self.mu.unlock();
        self.nudge();
    }

    fn failAsk(self: *LiveTurn, err: anyerror) void {
        self.mu.lock();
        const tx = self.ask_txn;
        self.ask_txn = null;
        self.mu.unlock();
        if (tx) |pending| {
            pending.mu.lock();
            if (!pending.done) {
                pending.err = err;
                pending.done = true;
                pending.cv.signal();
            }
            pending.mu.unlock();
        }
    }

    fn enqueueProvider(self: *LiveTurn, ev: core.providers.Ev) !void {
        const dup = try dupProviderEv(self.alloc, ev);
        errdefer freeProviderEv(self.alloc, dup);

        self.mu.lock();
        const seq = self.next_seq;
        self.next_seq += 1;
        self.evs.append(self.alloc, .{
            .seq = seq,
            .ev = dup,
        }) catch |append_err| {
            self.mu.unlock();
            return append_err;
        };
        switch (ev) {
            .stop => |s| self.last_stop = s.reason,
            .err => |txt| {
                if (self.last_err) |old| self.alloc.free(old);
                self.last_err = self.alloc.dupe(u8, txt) catch null;
            },
            else => {},
        }
        self.mu.unlock();
        self.nudge();
    }

    fn popProvider(self: *LiveTurn) ?SeqProviderEv {
        self.mu.lock();
        defer self.mu.unlock();

        if (self.ev_head >= self.evs.items.len) return null;
        const ev = self.evs.items[self.ev_head];
        self.ev_head += 1;
        if (self.ev_head == self.evs.items.len) {
            self.evs.items.len = 0;
            self.ev_head = 0;
        }
        return ev;
    }

    const Completion = struct {
        err_name: ?[]u8 = null,
    };

    fn takeCompletion(self: *LiveTurn) ?Completion {
        var thr: ?std.Thread = null;
        var out: Completion = .{};

        self.mu.lock();
        if (!self.done) {
            self.mu.unlock();
            return null;
        }
        self.done = false;
        thr = self.thr;
        self.thr = null;
        out.err_name = self.err_name;
        self.err_name = null;
        self.mu.unlock();

        if (thr) |t| t.join();
        return out;
    }

    fn cloneReq(self: *LiveTurn, alloc: std.mem.Allocator) !?Req {
        self.mu.lock();
        defer self.mu.unlock();
        const req = self.last_req orelse return null;
        return try dupStoredReq(alloc, req);
    }

    fn start(self: *LiveTurn, tctx: *const TurnCtx, opts: TurnCtx.TurnOpts) !void {
        var saved_req = try dupReq(self.alloc, opts);
        errdefer saved_req.deinit(self.alloc);

        self.mu.lock();
        if (self.running) {
            self.mu.unlock();
            return error.AlreadyRunning;
        }
        self.running = true;
        self.done = false;
        if (self.err_name) |name| {
            self.alloc.free(name);
            self.err_name = null;
        }
        self.last_stop = null;
        if (self.last_err) |e| {
            self.alloc.free(e);
            self.last_err = null;
        }
        if (self.last_model) |m| {
            self.alloc.free(m);
            self.last_model = null;
        }
        for (self.evs.items[self.ev_head..]) |sev| freeProviderEv(self.alloc, sev.ev);
        self.evs.items.len = 0;
        self.ev_head = 0;
        self.next_seq = 1;
        self.last_model = self.alloc.dupe(u8, opts.model) catch null;
        self.mu.unlock();

        self.cancel_flag.clear();

        const ctx = try self.alloc.create(ThreadCtx);
        errdefer self.alloc.destroy(ctx);
        ctx.* = .{
            .live = self,
            .tctx = tctx,
            .req = try dupReq(self.alloc, opts),
        };

        const thr = std.Thread.spawn(.{}, runThread, .{ctx}) catch |spawn_err| {
            ctx.req.deinit(self.alloc);
            self.alloc.destroy(ctx);
            self.mu.lock();
            self.running = false;
            self.done = false;
            self.mu.unlock();
            return spawn_err;
        };

        self.mu.lock();
        if (self.last_req) |*req| req.deinit(self.alloc);
        self.last_req = saved_req;
        self.thr = thr;
        self.mu.unlock();
    }

    fn runThread(ctx: *ThreadCtx) void {
        defer {
            ctx.req.deinit(ctx.live.alloc);
            ctx.live.alloc.destroy(ctx);
        }

        const run_res = ctx.tctx.run(.{
            .sid = ctx.req.sid,
            .prompt = ctx.req.prompt,
            .model = ctx.req.model,
            .provider_label = ctx.req.provider_label,
            .provider_opts = ctx.req.provider_opts,
            .system_prompt = ctx.req.system_prompt,
        });

        var err_name: ?[]u8 = null;
        if (run_res) |_| {} else |err| {
            err_name = ctx.live.alloc.dupe(u8, @errorName(err)) catch null;
        }

        ctx.live.mu.lock();
        ctx.live.running = false;
        ctx.live.done = true;
        if (ctx.live.err_name) |name| ctx.live.alloc.free(name);
        ctx.live.err_name = err_name;
        ctx.live.mu.unlock();
        ctx.live.nudge();
    }

    fn nudge(self: *LiveTurn) void {
        const b = [_]u8{1};
        _ = std.posix.write(self.wake_w, &b) catch {};
    }
};

const LiveTurnSink = struct {
    live: *LiveTurn,

    fn push(self: *LiveTurnSink, ev: core.loop.ModeEv) !void {
        switch (ev) {
            .provider => |pev| try self.live.enqueueProvider(pev),
            else => {},
        }
    }
};

const LiveAskCtx = struct {
    live: *LiveTurn,

    fn run(self: *LiveAskCtx, args: core.tools.Call.AskArgs) ![]u8 {
        return self.live.ask(args);
    }
};

fn dupReq(alloc: std.mem.Allocator, opts: TurnCtx.TurnOpts) !LiveTurn.Req {
    const sid = try alloc.dupe(u8, opts.sid);
    errdefer alloc.free(sid);
    const prompt = try alloc.dupe(u8, opts.prompt);
    errdefer alloc.free(prompt);
    const model = try alloc.dupe(u8, opts.model);
    errdefer alloc.free(model);
    const provider_label = try alloc.dupe(u8, opts.provider_label);
    errdefer alloc.free(provider_label);
    const system_prompt = if (opts.system_prompt) |sp| try alloc.dupe(u8, sp) else null;
    errdefer if (system_prompt) |sp| alloc.free(sp);

    return .{
        .sid = sid,
        .prompt = prompt,
        .model = model,
        .provider_label = provider_label,
        .provider_opts = opts.provider_opts,
        .system_prompt = system_prompt,
    };
}

fn dupStoredReq(alloc: std.mem.Allocator, req: LiveTurn.Req) !LiveTurn.Req {
    const sid = try alloc.dupe(u8, req.sid);
    errdefer alloc.free(sid);
    const prompt = try alloc.dupe(u8, req.prompt);
    errdefer alloc.free(prompt);
    const model = try alloc.dupe(u8, req.model);
    errdefer alloc.free(model);
    const provider_label = try alloc.dupe(u8, req.provider_label);
    errdefer alloc.free(provider_label);
    const system_prompt = if (req.system_prompt) |sp| try alloc.dupe(u8, sp) else null;
    errdefer if (system_prompt) |sp| alloc.free(sp);

    return .{
        .sid = sid,
        .prompt = prompt,
        .model = model,
        .provider_label = provider_label,
        .provider_opts = req.provider_opts,
        .system_prompt = system_prompt,
    };
}

const OwnedAskArgs = struct {
    questions: []core.tools.Call.AskArgs.Question,

    fn view(self: *const OwnedAskArgs) core.tools.Call.AskArgs {
        return .{ .questions = self.questions };
    }

    fn deinit(self: *OwnedAskArgs, alloc: std.mem.Allocator) void {
        for (self.questions) |q| {
            alloc.free(q.id);
            alloc.free(q.header);
            alloc.free(q.question);
            for (q.options) |opt| {
                alloc.free(opt.label);
                alloc.free(opt.description);
            }
            alloc.free(q.options);
        }
        alloc.free(self.questions);
        self.questions = &.{};
    }
};

fn dupAskArgs(alloc: std.mem.Allocator, args: core.tools.Call.AskArgs) !OwnedAskArgs {
    const qs = try alloc.alloc(core.tools.Call.AskArgs.Question, args.questions.len);
    var q_n: usize = 0;
    errdefer {
        for (qs[0..q_n]) |q| {
            alloc.free(q.id);
            alloc.free(q.header);
            alloc.free(q.question);
            for (q.options) |opt| {
                alloc.free(opt.label);
                alloc.free(opt.description);
            }
            alloc.free(q.options);
        }
        alloc.free(qs);
    }

    for (args.questions, 0..) |q, i| {
        const opts = try alloc.alloc(core.tools.Call.AskArgs.Option, q.options.len);
        var opt_n: usize = 0;
        errdefer {
            for (opts[0..opt_n]) |opt| {
                alloc.free(opt.label);
                alloc.free(opt.description);
            }
            alloc.free(opts);
        }
        for (q.options, 0..) |opt, j| {
            opts[j] = .{
                .label = try alloc.dupe(u8, opt.label),
                .description = try alloc.dupe(u8, opt.description),
            };
            opt_n = j + 1;
        }
        qs[i] = .{
            .id = try alloc.dupe(u8, q.id),
            .header = try alloc.dupe(u8, q.header),
            .question = try alloc.dupe(u8, q.question),
            .options = opts,
            .allow_other = q.allow_other,
        };
        q_n = i + 1;
    }

    return .{ .questions = qs };
}

fn dupProviderEv(alloc: std.mem.Allocator, ev: core.providers.Ev) !core.providers.Ev {
    return switch (ev) {
        .text => |txt| .{ .text = try alloc.dupe(u8, txt) },
        .thinking => |txt| .{ .thinking = try alloc.dupe(u8, txt) },
        .tool_call => |tc| blk: {
            const id = try alloc.dupe(u8, tc.id);
            errdefer alloc.free(id);
            const name = try alloc.dupe(u8, tc.name);
            errdefer alloc.free(name);
            const args = try alloc.dupe(u8, tc.args);
            break :blk .{
                .tool_call = .{
                    .id = id,
                    .name = name,
                    .args = args,
                },
            };
        },
        .tool_result => |tr| blk: {
            const id = try alloc.dupe(u8, tr.id);
            errdefer alloc.free(id);
            const out = try alloc.dupe(u8, tr.out);
            break :blk .{
                .tool_result = .{
                    .id = id,
                    .out = out,
                    .is_err = tr.is_err,
                },
            };
        },
        .usage => |usage| .{ .usage = usage },
        .stop => |stop| .{ .stop = stop },
        .err => |txt| .{ .err = try alloc.dupe(u8, txt) },
    };
}

fn freeProviderEv(alloc: std.mem.Allocator, ev: core.providers.Ev) void {
    switch (ev) {
        .text => |txt| alloc.free(txt),
        .thinking => |txt| alloc.free(txt),
        .tool_call => |tc| {
            alloc.free(tc.id);
            alloc.free(tc.name);
            alloc.free(tc.args);
        },
        .tool_result => |tr| {
            alloc.free(tr.id);
            alloc.free(tr.out);
        },
        .usage, .stop => {},
        .err => |txt| alloc.free(txt),
    }
}

const JsonSink = struct {
    alloc: std.mem.Allocator,
    out: std.Io.AnyWriter,

    fn push(self: *JsonSink, ev: core.loop.ModeEv) !void {
        switch (ev) {
            .replay => |payload| try self.emit("replay", payload),
            .session => |payload| try self.emit("session", payload),
            .provider => |payload| try self.emit("provider", payload),
            .tool => |payload| try self.emit("tool", payload),
            .session_write_err => |msg| try self.emit("session_write_err", msg),
        }
    }

    fn emit(self: *JsonSink, typ: []const u8, payload: anytype) !void {
        const raw = try std.json.Stringify.valueAlloc(self.alloc, .{
            .type = typ,
            .event = payload,
        }, .{});
        defer self.alloc.free(raw);
        try self.out.writeAll(raw);
        try self.out.writeAll("\n");
    }
};

const RpcReq = struct {
    id: ?[]const u8 = null,
    cmd: ?[]const u8 = null,
    type: ?[]const u8 = null,
    text: ?[]const u8 = null,
    arg: ?[]const u8 = null,
    tools: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    session: ?[]const u8 = null,
    model: ?[]const u8 = null,
    model_id: ?[]const u8 = null,
    session_path: ?[]const u8 = null,
    sid: ?[]const u8 = null,
};

const AuditHooks = struct {
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, core.audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = std.time.milliTimestamp,
    auth_home: ?[]const u8 = null,
    auth_lock: core.policy.Lock = .{},
    ca_file: ?[]const u8 = null,
    share_gist: *const fn (std.mem.Allocator, []const u8) anyerror![]u8 = shareGist,
    run_upgrade: *const fn (std.mem.Allocator, update_mod.AuditHooks) anyerror!update_mod.Outcome = update_mod.runOutcomeAudited,

    fn auth(self: AuditHooks) core.providers.auth.Hooks {
        return .{
            .home_override = self.auth_home,
            .ca_file = self.ca_file,
            .lock = self.auth_lock,
            .emit_audit_ctx = self.emit_audit_ctx,
            .emit_audit = self.emit_audit,
            .now_ms = self.now_ms,
        };
    }
};

const RuntimeCtlAudit = struct {
    hooks: AuditHooks,
    seq: u64 = 1,

    const Req = struct {
        op: []const u8,
        res_kind: core.audit.ResKind,
        res_name: core.audit.Str,
        out: core.audit.Outcome = .ok,
        sev: core.audit.Severity = .info,
        msg: core.audit.Str,
        argv: ?core.audit.Str = null,
        attrs: []const core.audit.Attr = &.{},
    };

    fn emit(self: *RuntimeCtlAudit, alloc: std.mem.Allocator, req: Req) !void {
        const emit_fn = self.hooks.emit_audit orelse return;
        const seq = self.seq;
        self.seq +%= 1;
        try emit_fn(self.hooks.emit_audit_ctx.?, alloc, .{
            .ts_ms = self.hooks.now_ms(),
            .sid = "runtime",
            .seq = seq,
            .sev = req.sev,
            .out = req.out,
            .actor = .{ .kind = .sys },
            .res = .{
                .kind = req.res_kind,
                .name = req.res_name,
                .op = req.op,
            },
            .msg = req.msg,
            .data = .{
                .tool = .{
                    .name = .{ .text = "runtime", .vis = .@"pub" },
                    .call_id = req.op,
                    .argv = req.argv,
                },
            },
            .attrs = req.attrs,
        });
    }
};

const PolicyToolAudit = struct {
    alloc: std.mem.Allocator,
    hooks: AuditHooks,
    sid: []const u8,
    seq: *u64,

    fn emit(self: PolicyToolAudit, call: core.tools.Call, name: []const u8) !void {
        const emit_fn = self.hooks.emit_audit orelse return;
        const seq = self.seq.*;
        self.seq.* +%= 1;
        try emit_fn(self.hooks.emit_audit_ctx.?, self.alloc, .{
            .ts_ms = self.hooks.now_ms(),
            .sid = self.sid,
            .seq = seq,
            .out = .deny,
            .actor = .{ .kind = .sys },
            .res = .{
                .kind = auditResKind(call.kind),
                .name = .{ .text = name, .vis = .@"pub" },
                .op = auditResOp(call.kind),
            },
            .msg = .{ .text = policy_denied_msg, .vis = .@"pub" },
            .data = .{
                .policy = .{
                    .eff = .deny,
                    .scope = "tool",
                },
            },
        });
    }
};

fn auditResKind(kind: core.tools.Kind) core.audit.ResKind {
    return switch (kind) {
        .read, .write, .edit, .grep, .find, .ls => .file,
        .web => .net,
        .agent, .bash, .skill => .cmd,
        .ask => .cfg,
    };
}

fn auditResOp(kind: core.tools.Kind) []const u8 {
    return switch (kind) {
        .read => "read",
        .write => "write",
        .edit => "edit",
        .grep => "grep",
        .find => "find",
        .ls => "list",
        .web => "request",
        .agent => "spawn",
        .bash => "run",
        .skill => "run",
        .ask => "prompt",
    };
}

fn runtimeCfgResName() core.audit.Str {
    return .{ .text = "runtime", .vis = .@"pub" };
}

fn runtimeSessResName() core.audit.Str {
    return .{ .text = "session", .vis = .@"pub" };
}

fn runtimeExportResName() core.audit.Str {
    return .{ .text = "session-export", .vis = .@"pub" };
}

fn runtimeShareResName() core.audit.Str {
    return .{ .text = "gist", .vis = .@"pub" };
}

fn runtimeUpgradeResName() core.audit.Str {
    return .{ .text = "upgrade", .vis = .@"pub" };
}

fn exportAuditHooks(hooks: AuditHooks) core.session.@"export".AuditHooks {
    return .{
        .emit_audit_ctx = hooks.emit_audit_ctx,
        .emit_audit = hooks.emit_audit,
        .now_ms = hooks.now_ms,
    };
}

fn updateAuditHooks(hooks: AuditHooks) update_mod.AuditHooks {
    return .{
        .emit_audit_ctx = hooks.emit_audit_ctx,
        .emit_audit = hooks.emit_audit,
        .now_ms = hooks.now_ms,
    };
}

fn runtimeCtlStart(
    audit: *RuntimeCtlAudit,
    alloc: std.mem.Allocator,
    op: []const u8,
    res_kind: core.audit.ResKind,
    res_name: core.audit.Str,
    argv: ?core.audit.Str,
    attrs: []const core.audit.Attr,
) !void {
    try audit.emit(alloc, .{
        .op = op,
        .res_kind = res_kind,
        .res_name = res_name,
        .msg = .{ .text = "runtime control start", .vis = .@"pub" },
        .argv = argv,
        .attrs = attrs,
    });
}

fn runtimeCtlSuccess(
    audit: *RuntimeCtlAudit,
    alloc: std.mem.Allocator,
    op: []const u8,
    res_kind: core.audit.ResKind,
    res_name: core.audit.Str,
    argv: ?core.audit.Str,
    attrs: []const core.audit.Attr,
) !void {
    try audit.emit(alloc, .{
        .op = op,
        .res_kind = res_kind,
        .res_name = res_name,
        .sev = .notice,
        .msg = .{ .text = "runtime control success", .vis = .@"pub" },
        .argv = argv,
        .attrs = attrs,
    });
}

fn runtimeCtlFail(
    audit: *RuntimeCtlAudit,
    alloc: std.mem.Allocator,
    op: []const u8,
    res_kind: core.audit.ResKind,
    res_name: core.audit.Str,
    argv: ?core.audit.Str,
    msg: core.audit.Str,
    attrs: []const core.audit.Attr,
) !void {
    try audit.emit(alloc, .{
        .op = op,
        .res_kind = res_kind,
        .res_name = res_name,
        .out = .fail,
        .sev = .err,
        .msg = msg,
        .argv = argv,
        .attrs = attrs,
    });
}

fn replaceOwnedText(
    alloc: std.mem.Allocator,
    current: *([]const u8),
    owned: *?[]u8,
    next: []const u8,
) !void {
    const dup = try alloc.dupe(u8, next);
    if (owned.*) |old| alloc.free(old);
    owned.* = dup;
    current.* = dup;
}

const ReloadRes = enum {
    loaded,
    empty,
};

fn reloadContextWithAudit(
    alloc: std.mem.Allocator,
    sys_prompt: *?[]const u8,
    sys_prompt_owned: *?[]u8,
    audit: *RuntimeCtlAudit,
    load_fn: *const fn (std.mem.Allocator) anyerror!?[]u8,
) !ReloadRes {
    try runtimeCtlStart(audit, alloc, "reload", .cfg, runtimeCfgResName(), null, &.{});
    const next_ctx = load_fn(alloc) catch |err| {
        try runtimeCtlFail(
            audit,
            alloc,
            "reload",
            .cfg,
            runtimeCfgResName(),
            null,
            .{ .text = @errorName(err), .vis = .mask },
            &.{},
        );
        return err;
    };
    if (next_ctx) |new_ctx| {
        if (sys_prompt_owned.*) |old| alloc.free(old);
        sys_prompt_owned.* = new_ctx;
        sys_prompt.* = new_ctx;
        const attrs = [_]core.audit.Attr{
            .{
                .key = "loaded",
                .vis = .@"pub",
                .val = .{ .bool = true },
            },
        };
        try runtimeCtlSuccess(audit, alloc, "reload", .cfg, runtimeCfgResName(), null, &attrs);
        return .loaded;
    }
    if (sys_prompt_owned.*) |old| alloc.free(old);
    sys_prompt_owned.* = null;
    sys_prompt.* = null;
    const attrs = [_]core.audit.Attr{
        .{
            .key = "loaded",
            .vis = .@"pub",
            .val = .{ .bool = false },
        },
    };
    try runtimeCtlSuccess(audit, alloc, "reload", .cfg, runtimeCfgResName(), null, &attrs);
    return .empty;
}

pub fn exec(alloc: std.mem.Allocator, run_cmd: cli.Run) (Err || anyerror)![]u8 {
    return execWithIo(alloc, run_cmd, null, null);
}

pub fn execWithWriter(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    out: ?std.Io.AnyWriter,
) (Err || anyerror)![]u8 {
    return execWithIo(alloc, run_cmd, null, out);
}

pub fn execWithIo(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    in: ?std.Io.AnyReader,
    out: ?std.Io.AnyWriter,
) (Err || anyerror)![]u8 {
    return execWithIoHooks(alloc, run_cmd, in, out, .{});
}

const TuiHooks = struct {
    stdin_fd: std.posix.fd_t = std.posix.STDIN_FILENO,
    live: ?bool = null,
    raw_mode: bool = true,
    exit_on_idle: bool = false,
    stop_after_completions: ?u8 = null,
    submit_text: ?[]const u8 = null,
};

fn execWithIoHooks(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    in: ?std.Io.AnyReader,
    out: ?std.Io.AnyWriter,
    audit_hooks: AuditHooks,
) (Err || anyerror)![]u8 {
    return execWithIoTuiHooks(alloc, run_cmd, in, out, audit_hooks, .{});
}

fn execWithIoTuiHooks(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    in: ?std.Io.AnyReader,
    out: ?std.Io.AnyWriter,
    audit_hooks: AuditHooks,
    tui_hooks: TuiHooks,
) (Err || anyerror)![]u8 {
    var provider_rt: ProviderRuntime = undefined;
    var native_rt: NativeProviderRuntime = undefined;
    var hooks = audit_hooks;
    if (hooks.ca_file == null) hooks.ca_file = run_cmd.cfg.ca_file;
    hooks.auth_lock = run_cmd.cfg.policy_lock;
    var missing_provider = MissingProvider{
        .alloc = alloc,
        .msg = missing_provider_msg,
    };
    var provider: core.providers.Provider = undefined;
    var has_provider_rt = false;
    var has_native_rt = false;
    defer if (has_provider_rt) provider_rt.deinit();
    defer if (has_native_rt) native_rt.deinit();

    var pol = try RuntimePolicy.load(alloc);
    defer pol.deinit();

    var tools_rt = core.tools.builtin.Runtime.init(.{
        .alloc = alloc,
        .tool_mask = run_cmd.tool_mask,
    });

    var sid: []u8 = &.{};
    var session_dir_path: ?[]u8 = null;
    defer if (session_dir_path) |path| alloc.free(path);
    errdefer if (sid.len > 0) alloc.free(sid);

    var store: ?core.session.SessionStore = null;
    var fs_store_impl: core.session.fs_store.Store = undefined;
    var null_store_impl = core.session.NullStore.init();

    defer if (store) |*s| s.deinit();

    const writer = if (out) |w| w else std.fs.File.stdout().deprecatedWriter().any();
    const reader = if (in) |r| r else std.fs.File.stdin().deprecatedReader().any();
    const ExecState = enum {
        init_provider,
        init_store,
        dispatch,
        done,
    };
    var st: ExecState = .init_provider;

    fsm: while (true) switch (st) {
        .init_provider => {
            if (run_cmd.cfg.provider_cmd) |provider_cmd| {
                try provider_rt.init(alloc, provider_cmd);
                has_provider_rt = true;
                provider = provider_rt.client.asProvider();
            } else {
                const provider_name = resolveDefaultProvider(run_cmd.cfg.provider);
                if (parseNativeProviderKind(provider_name)) |native_kind| {
                    if (NativeProviderRuntime.init(alloc, native_kind, hooks.auth())) |nr| {
                        native_rt = nr;
                        has_native_rt = true;
                        provider = native_rt.asProvider();
                    } else |err| {
                        missing_provider.msg = missingProviderMsgForInitErr(native_kind, err);
                        provider = missing_provider.asProvider();
                    }
                } else {
                    missing_provider.msg = unsupported_native_provider_msg;
                    provider = missing_provider.asProvider();
                }
            }
            st = .init_store;
            continue :fsm;
        },
        .init_store => {
            if (run_cmd.no_session) {
                sid = try newSid(alloc);
                store = null_store_impl.asSessionStore();
            } else {
                const plan = try resolveSessionPlan(alloc, run_cmd);
                sid = plan.sid;
                session_dir_path = plan.dir_path;

                try core.fs_secure.ensureDirPath(plan.dir_path);
                var session_dir = try std.fs.cwd().openDir(plan.dir_path, .{ .iterate = true });
                errdefer session_dir.close();
                core.session.cleanOrphanTmpFiles(session_dir);
                fs_store_impl = try core.session.fs_store.Store.init(.{
                    .alloc = alloc,
                    .dir = session_dir,
                    .flush = .{
                        .always = {},
                    },
                    .replay = .{},
                });
                store = fs_store_impl.asSessionStore();
            }
            st = .dispatch;
            continue :fsm;
        },
        .dispatch => {
            const sess_store = store.?;
            const sys_prompt = try buildSystemPrompt(alloc, run_cmd);
            defer if (sys_prompt) |sp| alloc.free(sp);

            switch (run_cmd.mode) {
                .print => try runPrint(
                    alloc,
                    run_cmd,
                    sid,
                    provider,
                    sess_store,
                    &pol,
                    &tools_rt,
                    writer,
                    sys_prompt,
                    audit_hooks,
                ),
                .json => try runJson(
                    alloc,
                    run_cmd,
                    sid,
                    provider,
                    sess_store,
                    &pol,
                    &tools_rt,
                    reader,
                    writer,
                    sys_prompt,
                    hooks,
                ),
                .tui => try runTui(
                    alloc,
                    run_cmd,
                    &sid,
                    provider,
                    sess_store,
                    &pol,
                    &tools_rt,
                    reader,
                    writer,
                    session_dir_path,
                    run_cmd.no_session,
                    sys_prompt,
                    has_native_rt and native_rt.isSub(),
                    hooks,
                    tui_hooks,
                ),
                .rpc => try runRpc(
                    alloc,
                    run_cmd,
                    &sid,
                    provider,
                    sess_store,
                    &pol,
                    &tools_rt,
                    reader,
                    writer,
                    session_dir_path,
                    run_cmd.no_session,
                    sys_prompt,
                    hooks,
                ),
            }
            st = .done;
            continue :fsm;
        },
        .done => break :fsm,
    };

    return sid;
}

fn runPrint(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    sid: []const u8,
    provider: core.providers.Provider,
    store: core.session.SessionStore,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    out: std.Io.AnyWriter,
    sys_prompt: ?[]const u8,
    audit_hooks: AuditHooks,
) !void {
    const prompt = run_cmd.prompt orelse return error.EmptyPrompt;

    var sink_impl = PrintSink.init(alloc, out);
    defer sink_impl.deinit();
    sink_impl.fmt.verbose = run_cmd.verbose;

    const mode = core.loop.ModeSink.from(PrintSink, &sink_impl, PrintSink.push);
    var reg: PolicyToolRegistry = undefined;
    var tool_audit_seq: u64 = 1;
    const tool_audit = PolicyToolAudit{
        .alloc = alloc,
        .hooks = audit_hooks,
        .sid = sid,
        .seq = &tool_audit_seq,
    };
    reg.init(pol, tools_rt.registry(), tool_audit);
    var tool_auth_impl = PolicyToolAuth{
        .alloc = alloc,
        .pol = pol,
        .sid = sid,
        .emit_audit_ctx = audit_hooks.emit_audit_ctx,
        .emit_audit = audit_hooks.emit_audit,
        .now_ms = audit_hooks.now_ms,
        .seq = &tool_audit_seq,
    };
    var cmd_cache = core.loop.CmdCache.init(alloc);
    defer cmd_cache.deinit();
    const approval_bind = try loadApprovalBindAlloc(alloc);
    defer approval_bind.deinit(alloc);
    const approval_loc = try getApprovalLocAlloc(alloc);
    defer freeApprovalLoc(alloc, approval_loc);

    _ = try core.loop.run(.{
        .alloc = alloc,
        .sid = sid,
        .prompt = prompt,
        .model = run_cmd.cfg.model,
        .provider_label = run_cmd.cfg.provider,
        .provider = provider,
        .store = store,
        .reg = reg.registry(),
        .tool_auth = core.loop.ToolAuth.from(PolicyToolAuth, &tool_auth_impl, PolicyToolAuth.check),
        .mode = mode,
        .system_prompt = sys_prompt,
        .provider_opts = run_cmd.thinking.toProviderOpts(),
        .max_turns = run_cmd.max_turns,
        .cmd_cache = &cmd_cache,
        .approval = .{
            .loc = approval_loc,
            .policy = approval_bind,
        },
    });

    try sink_impl.fmt.finish();
    if (sink_impl.stop_reason) |reason| {
        if (print_err.mapResult(.{ .stop = reason })) |_| return error.ProviderStopped;
    }
}

const PromptAskCtx = struct {
    ask_ui: *AskUiCtx,
    reader: *tui_input.Reader,

    fn run(self: *PromptAskCtx, args: core.tools.Call.AskArgs) ![]u8 {
        return self.ask_ui.runOnMain(self.reader, args);
    }
};

const ApprovalAnswer = struct {
    cancelled: bool = false,
    answers: []const struct {
        index: usize = 0,
    } = &.{},
};

const HookApprover = struct {
    alloc: std.mem.Allocator,
    hook: core.tools.builtin.AskHook,
    cache: *core.loop.CmdCache,

    fn check(self: *@This(), key: core.loop.CmdCache.Key, cached: bool) !void {
        if (cached) return;

        const summary = try approvalSummaryFromKeyAlloc(self.alloc, key);
        defer self.alloc.free(summary);
        const question = try std.fmt.allocPrint(
            self.alloc,
            "Run {s}? This action was derived from untrusted input.",
            .{summary},
        );
        defer self.alloc.free(question);

        const options = [_]core.tools.Call.AskArgs.Option{
            .{ .label = "Approve" },
            .{ .label = "Deny" },
        };
        const questions = [_]core.tools.Call.AskArgs.Question{
            .{
                .id = "approve",
                .header = "Approval required",
                .question = question,
                .options = options[0..],
                .allow_other = false,
            },
        };

        const raw = try self.hook.run(.{ .questions = questions[0..] });
        defer self.alloc.free(raw);

        var parsed = try std.json.parseFromSlice(ApprovalAnswer, self.alloc, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        if (parsed.value.cancelled) return error.ApprovalDenied;
        if (parsed.value.answers.len == 0) return error.ApprovalDenied;
        if (parsed.value.answers[0].index != 0) return error.ApprovalDenied;
        try self.cache.add(key);
    }
};

fn approvalSummaryFromKeyAlloc(alloc: std.mem.Allocator, key: core.loop.CmdCache.Key) ![]u8 {
    return switch (key.tool) {
        .write => blk: {
            var parsed = try std.json.parseFromSlice(core.tools.Call.WriteArgs, alloc, key.cmd, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            });
            defer parsed.deinit();
            break :blk std.fmt.allocPrint(alloc, "write {s}", .{parsed.value.path});
        },
        .bash => blk: {
            var parsed = try std.json.parseFromSlice(core.tools.Call.BashArgs, alloc, key.cmd, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            });
            defer parsed.deinit();
            break :blk std.fmt.allocPrint(alloc, "bash `{s}`", .{parsed.value.cmd});
        },
        .edit => blk: {
            var parsed = try std.json.parseFromSlice(core.tools.Call.EditArgs, alloc, key.cmd, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            });
            defer parsed.deinit();
            break :blk std.fmt.allocPrint(alloc, "edit {s}", .{parsed.value.path});
        },
        .web => blk: {
            var parsed = try std.json.parseFromSlice(core.tools.Call.WebArgs, alloc, key.cmd, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            });
            defer parsed.deinit();
            break :blk core.tools.web.approvalSummaryAlloc(alloc, parsed.value);
        },
        else => alloc.dupe(u8, key.cmd),
    };
}

fn runJson(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    sid: []const u8,
    provider: core.providers.Provider,
    store: core.session.SessionStore,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    in: std.Io.AnyReader,
    out: std.Io.AnyWriter,
    sys_prompt: ?[]const u8,
    audit_hooks: AuditHooks,
) !void {
    var sink_impl = JsonSink{
        .alloc = alloc,
        .out = out,
    };
    const mode = core.loop.ModeSink.from(JsonSink, &sink_impl, JsonSink.push);
    const popts = run_cmd.thinking.toProviderOpts();
    var cmd_cache = core.loop.CmdCache.init(alloc);
    defer cmd_cache.deinit();
    const approval_bind = try loadApprovalBindAlloc(alloc);
    defer approval_bind.deinit(alloc);
    const approval_loc = try getApprovalLocAlloc(alloc);
    defer freeApprovalLoc(alloc, approval_loc);
    const tctx = TurnCtx{
        .alloc = alloc,
        .provider = provider,
        .store = store,
        .pol = pol,
        .tools_rt = tools_rt,
        .mode = mode,
        .max_turns = run_cmd.max_turns,
        .cmd_cache = &cmd_cache,
        .approval_bind = approval_bind,
        .approval_loc = approval_loc,
        .audit_hooks = audit_hooks,
    };

    if (run_cmd.prompt) |prompt| {
        try tctx.run(.{
            .sid = sid,
            .prompt = prompt,
            .model = resolveDefault(run_cmd.cfg.model),
            .provider_label = resolveDefaultProvider(run_cmd.cfg.provider),
            .provider_opts = popts,
            .system_prompt = sys_prompt,
        });
        return;
    }

    var turn_ct: usize = 0;
    while (try in.readUntilDelimiterOrEofAlloc(alloc, '\n', 64 * 1024)) |raw_line| {
        defer alloc.free(raw_line);

        var line = raw_line;
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0) continue;

        try tctx.run(.{
            .sid = sid,
            .prompt = trimmed,
            .model = resolveDefault(run_cmd.cfg.model),
            .provider_label = resolveDefaultProvider(run_cmd.cfg.provider),
            .provider_opts = popts,
            .system_prompt = sys_prompt,
        });
        turn_ct += 1;
    }
    if (turn_ct == 0) return error.EmptyPrompt;
}

fn runTui(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    sid: *([]u8),
    provider: core.providers.Provider,
    store: core.session.SessionStore,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    in: std.Io.AnyReader,
    out: std.Io.AnyWriter,
    session_dir_path: ?[]const u8,
    no_session: bool,
    sys_prompt_arg: ?[]const u8,
    is_sub: bool,
    audit_hooks: AuditHooks,
    tui_hooks: TuiHooks,
) !void {
    var ctl_audit = RuntimeCtlAudit{ .hooks = audit_hooks };
    var model: []const u8 = resolveDefault(run_cmd.cfg.model);
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |m| alloc.free(m);
    var provider_label: []const u8 = resolveDefaultProvider(run_cmd.cfg.provider);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |p| alloc.free(p);
    var sys_prompt: ?[]const u8 = sys_prompt_arg;
    var sys_prompt_owned: ?[]u8 = null;
    defer if (sys_prompt_owned) |s| alloc.free(s);

    // Model cycle list: from config or default
    const cfg_models = run_cmd.cfg.enabled_models;
    const models_list: []const []const u8 = if (cfg_models) |m| blk: {
        const ptr: [*]const []const u8 = @ptrCast(m.ptr);
        break :blk ptr[0..m.len];
    } else &model_cycle;

    const cwd_path = getProjectPath(alloc) catch "";
    defer if (cwd_path.len > 0) alloc.free(cwd_path);
    const branch = getGitBranch(alloc) catch "";
    defer if (branch.len > 0) alloc.free(branch);

    const tsz = tui_term.size(std.posix.STDOUT_FILENO) orelse tui_term.Size{ .w = 80, .h = 24 };
    var ui = try tui_harness.Ui.initFull(alloc, tsz.w, tsz.h, model, provider_label, cwd_path, branch, run_cmd.cfg.theme);
    defer ui.deinit();
    ui.img_cap = @import("../modes/tui/image.zig").detect();
    ui.panels.ctx_limit = modelCtxWindow(model);
    ui.panels.is_sub = is_sub;

    _ = tui_term.installSigwinch();
    try tui_render.Renderer.setup(out);
    try tui_render.Renderer.setTitle(out, cwd_path);

    defer {
        tui_render.Renderer.setTitle(out, "") catch |err| {
            std.debug.print("warning: title reset failed: {s}\n", .{@errorName(err)});
        };
        tui_render.Renderer.cleanup(out) catch |err| {
            std.debug.print("warning: terminal cleanup failed: {s}\n", .{@errorName(err)});
        };
    }

    var sink_impl = TuiSink{
        .ui = &ui,
        .out = out,
    };
    const mode = core.loop.ModeSink.from(TuiSink, &sink_impl, TuiSink.push);

    const stdin_fd = tui_hooks.stdin_fd;
    const is_tty = tui_hooks.live orelse std.posix.isatty(stdin_fd);

    // Enable raw mode early so the InputWatcher's poll() works for -p prompts
    if (is_tty and tui_hooks.raw_mode) {
        if (!tui_term.enableRaw(stdin_fd)) return error.TerminalSetupFailed;
    }
    defer if (is_tty and tui_hooks.raw_mode) tui_term.restore(stdin_fd);

    var watcher = try InputWatcher.init(stdin_fd);
    defer watcher.deinit();
    const cancel = core.loop.CancelSrc.from(InputWatcher, &watcher, InputWatcher.isCanceled);
    var cmd_cache = core.loop.CmdCache.init(alloc);
    defer cmd_cache.deinit();
    const approval_bind = try loadApprovalBindAlloc(alloc);
    defer approval_bind.deinit(alloc);
    const approval_loc = try getApprovalLocAlloc(alloc);
    defer freeApprovalLoc(alloc, approval_loc);
    var bg_mgr = try bg.Mgr.initWithOpts(alloc, .{
        .emit_audit_ctx = audit_hooks.emit_audit_ctx,
        .emit_audit = audit_hooks.emit_audit,
        .now_ms = audit_hooks.now_ms,
    });
    defer bg_mgr.deinit();
    try syncBgFooter(alloc, &ui, &bg_mgr);

    var ask_ui_ctx = AskUiCtx{
        .alloc = alloc,
        .ui = &ui,
        .out = out,
        .watcher = &watcher,
    };
    var prompt_reader = tui_input.Reader.init(stdin_fd);
    var prompt_ask_ctx = PromptAskCtx{
        .ask_ui = &ask_ui_ctx,
        .reader = &prompt_reader,
    };
    const prompt_ask_hook = core.tools.builtin.AskHook.from(PromptAskCtx, &prompt_ask_ctx, PromptAskCtx.run);
    var prompt_approver_impl = HookApprover{
        .alloc = alloc,
        .hook = prompt_ask_hook,
        .cache = &cmd_cache,
    };
    const prompt_approver = core.loop.Approver.from(HookApprover, &prompt_approver_impl, HookApprover.check);
    const tctx = TurnCtx{
        .alloc = alloc,
        .provider = provider,
        .store = store,
        .pol = pol,
        .tools_rt = tools_rt,
        .mode = mode,
        .max_turns = run_cmd.max_turns,
        .cancel = cancel,
        .cmd_cache = &cmd_cache,
        .approval_bind = approval_bind,
        .approval_loc = approval_loc,
        .approver = prompt_approver,
    };
    defer tools_rt.ask_hook = null;
    var thinking = run_cmd.thinking;
    var popts = thinking.toProviderOpts();
    var auto_compact_on: bool = true;
    ui.panels.thinking_label = thinkingLabel(thinking);
    ui.border_fg = thinkingBorderFg(thinking);

    // Background version check (TUI only, skip for dev builds)
    const force_ver = std.posix.getenv("PZ_FORCE_VERSION_CHECK") != null;
    const skip_ver = (!force_ver and builtin.is_test) or
        std.posix.getenv("PZ_SKIP_VERSION_CHECK") != null or
        (!force_ver and std.mem.indexOf(u8, cli.version, "-dev") != null);
    var ver_check = version_check.Checker.init(alloc);
    var ver_notice_done = skip_ver;
    if (!skip_ver) ver_check.spawn();
    defer ver_check.deinit();

    // Startup info matching pi's display
    const is_resumed = switch (run_cmd.session) {
        .cont, .resm, .explicit => true,
        .auto => false,
    };
    if (is_resumed) {
        const restored = try tryRestoreSessionIntoUi(alloc, &ui, session_dir_path, no_session, sid.*);
        if (!restored) try showStartup(alloc, &ui, true);
    } else {
        try showStartup(alloc, &ui, false);
    }

    // Set terminal title (OSC 0)
    try out.writeAll("\x1b]0;pz\x07");
    defer out.writeAll("\x1b]0;\x07") catch |err| {
        std.debug.print("warning: title clear failed: {s}\n", .{@errorName(err)});
    };

    try ui.draw(out);
    try maybeShowVersionUpdate(alloc, &ui, &ver_check, &ver_notice_done, out);
    if (run_cmd.prompt) |prompt| {
        var init_cmd_buf: [4096]u8 = undefined;
        var init_cmd_fbs = std.io.fixedBufferStream(&init_cmd_buf);
        const cmd = try handleSlashCommand(
            alloc,
            prompt,
            sid,
            &model,
            &model_owned,
            &provider_label,
            &provider_owned,
            pol,
            tools_rt,
            &bg_mgr,
            session_dir_path,
            no_session,
            sys_prompt,
            init_cmd_fbs.writer().any(),
            audit_hooks,
            &ctl_audit,
        );
        if (cmd == .quit) return;
        if (cmd == .clear) {
            ui.clearTranscript();
        }
        if (cmd == .copy) {
            try copyLastResponse(alloc, &ui);
        }
        if (cmd == .cost) {
            try showCost(alloc, &ui);
        }
        if (cmd == .reload) {
            const reloaded = try reloadContextWithAudit(alloc, &sys_prompt, &sys_prompt_owned, &ctl_audit, core.context.load);
            switch (reloaded) {
                .loaded => try ui.tr.infoText("[context reloaded]"),
                .empty => try ui.tr.infoText("[context reloaded (no files)]"),
            }
        }
        if (cmd == .resumed) {
            _ = try tryRestoreSessionIntoUi(alloc, &ui, session_dir_path, no_session, sid.*);
        }
        if (cmd == .select_model) {
            var cur_idx: usize = 0;
            for (models_list, 0..) |m, i| {
                if (std.mem.eql(u8, model, m)) {
                    cur_idx = i;
                    break;
                }
            }
            ui.ov = tui_overlay.Overlay.init(models_list, cur_idx);
        }
        if (cmd == .select_session) {
            _ = try showResumeOverlay(alloc, &ui, session_dir_path);
        }
        if (cmd == .select_settings) {
            ui.ov = try buildSettingsOverlay(alloc, &ui, auto_compact_on);
        }
        if (cmd == .select_fork) {
            if (session_dir_path) |sdp| {
                if (listUserMessages(alloc, sdp, sid.*)) |msgs| {
                    if (msgs.len > 0) {
                        var ov = tui_overlay.Overlay.initDyn(alloc, msgs, "Fork from message", .session);
                        ov.sel = msgs.len - 1;
                        ov.fixScroll();
                        ov.kind = .fork;
                        ui.ov = ov;
                    }
                } else |_| {}
            }
        }
        if (cmd == .compacted) {
            ui.panels.noteCompaction();
        }
        if (cmd == .handled or cmd == .compacted or cmd == .resumed or cmd == .clear or cmd == .copy or cmd == .cost or cmd == .reload or cmd == .select_model or cmd == .select_session or cmd == .select_settings or cmd == .select_fork) {
            const cmd_text = init_cmd_fbs.getWritten();
            if (cmd_text.len > 0) {
                try infoTextSafe(alloc, &ui, cmd_text);
                ui.tr.scrollToBottom();
            }
            try syncBgFooter(alloc, &ui, &bg_mgr);
            try ui.setModel(model);
            try ui.setProvider(provider_label);
        }
        if (cmd == .unhandled) {
            try ui.tr.userText(prompt);
            ui.tr.scrollToBottom();
            try ui.draw(out);
            if (is_tty and !watcher.start()) try ui.tr.infoText("[ESC cancel unavailable]");
            defer if (is_tty) watcher.join(null);
            try tctx.run(.{
                .sid = sid.*,
                .prompt = prompt,
                .model = model,
                .provider_label = provider_label,
                .provider_opts = popts,
                .system_prompt = sys_prompt,
            });
            if (is_tty and watcher.isCanceled()) try ui.tr.infoText("[canceled]");
            ui.panels.run_state = .idle;
        } else {
            try ui.setModel(model);
            try ui.setProvider(provider_label);
            try ui.draw(out);
        }
        // Fall through to input loop (stay in TUI like pi does)
    }

    if (is_tty) {
        // Raw mode already enabled above (before -p prompt path)
        var live_turn = try LiveTurn.init(alloc);
        defer live_turn.deinit();
        var live_sink_impl = LiveTurnSink{
            .live = &live_turn,
        };
        const live_mode = core.loop.ModeSink.from(LiveTurnSink, &live_sink_impl, LiveTurnSink.push);
        const live_cancel = core.loop.CancelSrc.from(TurnCancelFlag, &live_turn.cancel_flag, TurnCancelFlag.isCanceled);
        var live_cmd_cache = core.loop.CmdCache.init(alloc);
        defer live_cmd_cache.deinit();
        const live_approval_bind = try loadApprovalBindAlloc(alloc);
        defer live_approval_bind.deinit(alloc);
        const live_approval_loc = try getApprovalLocAlloc(alloc);
        defer freeApprovalLoc(alloc, live_approval_loc);
        var live_tctx = TurnCtx{
            .alloc = alloc,
            .provider = provider,
            .store = store,
            .pol = pol,
            .tools_rt = tools_rt,
            .mode = live_mode,
            .max_turns = run_cmd.max_turns,
            .cancel = live_cancel,
            .abort_slot = &live_turn.abort_slot,
            .cmd_cache = &live_cmd_cache,
            .approval_bind = live_approval_bind,
            .approval_loc = live_approval_loc,
        };
        var reader = tui_input.Reader.initWithNotify2(stdin_fd, bg_mgr.wakeFd(), live_turn.wakeFd());
        var live_ask_ctx = LiveAskCtx{
            .live = &live_turn,
        };
        tools_rt.ask_hook = core.tools.builtin.AskHook.from(LiveAskCtx, &live_ask_ctx, LiveAskCtx.run);
        var live_approver_impl = HookApprover{
            .alloc = alloc,
            .hook = tools_rt.ask_hook.?,
            .cache = &live_cmd_cache,
        };
        const live_approver = core.loop.Approver.from(HookApprover, &live_approver_impl, HookApprover.check);
        live_tctx.approver = live_approver;
        var pending = PendingQueue{};
        defer pending.deinit(alloc);
        const input_mode: tui_panels.InputMode = .steering;
        var retried_overflow = false;
        var stop_after_completions = tui_hooks.stop_after_completions;
        syncInputFooter(&ui, input_mode, pending.total());
        if (tui_hooks.submit_text) |prompt| {
            try startLiveTurnWithPrompt(&live_turn, &live_tctx, &ui, sid.*, prompt, model, provider_label, popts, sys_prompt, &retried_overflow);
            try ui.draw(out);
        }

        while (true) {
            try maybeShowVersionUpdate(alloc, &ui, &ver_check, &ver_notice_done, out);
            if (tui_term.pollResize()) {
                if (tui_term.size(std.posix.STDOUT_FILENO)) |sz| {
                    try ui.resize(sz.w, sz.h);
                    try ui.draw(out);
                }
            }

            const ev = reader.next();
            switch (ev) {
                .key => |key| {
                    // Overlay intercepts keys when open
                    if (ui.ov != null) {
                        switch (key) {
                            .up => ui.ov.?.up(),
                            .down => ui.ov.?.down(),
                            .enter => {
                                const sel = ui.ov.?.selected() orelse {
                                    ui.ov.?.deinit(alloc);
                                    ui.ov = null;
                                    continue;
                                };
                                switch (ui.ov.?.kind) {
                                    .model => {
                                        const argv: core.audit.Str = .{ .text = sel, .vis = .@"pub" };
                                        try runtimeCtlStart(&ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &.{});
                                        try replaceOwnedText(alloc, &model, &model_owned, sel);
                                        const attrs = [_]core.audit.Attr{
                                            .{
                                                .key = "provider",
                                                .vis = .@"pub",
                                                .val = .{ .str = provider_label },
                                            },
                                        };
                                        try runtimeCtlSuccess(&ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &attrs);
                                        ui.panels.ctx_limit = modelCtxWindow(model);
                                        try ui.setModel(model);
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                    .session => {
                                        const argv: core.audit.Str = .{ .text = sel, .vis = .mask };
                                        try runtimeCtlStart(&ctl_audit, alloc, "resume", .sess, runtimeSessResName(), argv, &.{});
                                        const next_sid = try alloc.dupe(u8, sel);
                                        alloc.free(sid.*);
                                        sid.* = next_sid;
                                        _ = try tryRestoreSessionIntoUi(alloc, &ui, session_dir_path, no_session, sid.*);
                                        try runtimeCtlSuccess(&ctl_audit, alloc, "resume", .sess, runtimeSessResName(), argv, &.{});
                                        const msg = try std.fmt.allocPrint(alloc, "resumed session {s}", .{sid.*});
                                        defer alloc.free(msg);
                                        try ui.tr.infoText(msg);
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                    .settings => {
                                        // Toggle the selected setting
                                        ui.ov.?.toggle();
                                        applySettingsToggle(&ui, ui.ov.?.sel, ui.ov.?.getToggle(ui.ov.?.sel) orelse false, &auto_compact_on);
                                    },
                                    .fork => {
                                        try runtimeCtlStart(&ctl_audit, alloc, "fork", .sess, runtimeSessResName(), null, &.{});
                                        const next_sid = try newSid(alloc);
                                        errdefer alloc.free(next_sid);
                                        if (session_dir_path) |sdp| {
                                            try forkSessionFile(sdp, sid.*, next_sid);
                                        }
                                        alloc.free(sid.*);
                                        sid.* = next_sid;
                                        try ui.ed.setText(sel);
                                        try ui.tr.infoText("[forked session]");
                                        try runtimeCtlSuccess(&ctl_audit, alloc, "fork", .sess, runtimeSessResName(), null, &.{});
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                    .login => {
                                        // Set env var hint in editor for API key entry
                                        const env_var = provider_env_map.get(sel) orelse "GOOGLE_API_KEY";
                                        const msg = try std.fmt.allocPrint(alloc, "Paste {s} API key (or set {s} env var):", .{ sel, env_var });
                                        defer alloc.free(msg);
                                        try ui.tr.infoText(msg);
                                        // Set editor to /login <provider>; API key or OAuth can follow.
                                        const prompt_text = try std.fmt.allocPrint(alloc, "/login {s} ", .{sel});
                                        defer alloc.free(prompt_text);
                                        try ui.ed.setText(prompt_text);
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                    .logout => {
                                        // Remove credentials for selected provider
                                        if (parseAuthProvider(sel)) |prov| {
                                            try core.providers.auth.logoutWithHooks(alloc, prov, audit_hooks.auth());
                                            const msg2 = try std.fmt.allocPrint(alloc, "logged out of {s}", .{core.providers.auth.providerName(prov)});
                                            defer alloc.free(msg2);
                                            try ui.tr.infoText(msg2);
                                        }
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                    .queue => {
                                        ui.ov.?.deinit(alloc);
                                        ui.ov = null;
                                    },
                                }
                            },
                            .esc, .ctrl_c, .ctrl_l => {
                                ui.ov.?.deinit(alloc);
                                ui.ov = null;
                            },
                            else => {},
                        }
                        try ui.draw(out);
                        continue;
                    }

                    // Command preview intercept
                    if (ui.picker) |*cp| {
                        switch (key) {
                            .up => {
                                cp.up();
                                try ui.draw(out);
                                continue;
                            },
                            .down => {
                                cp.down();
                                try ui.draw(out);
                                continue;
                            },
                            .tab, .enter => {
                                if (ui.path_items != null) {
                                    // File mode: replace last word
                                    if (cp.selectedArg()) |path| {
                                        const text = ui.ed.text();
                                        const cur = ui.ed.cursor();
                                        const ws = ui.ed.wordStart(cur);
                                        const has_at = ws < cur and text[ws] == '@';
                                        const at_s: []const u8 = if (has_at) "@" else "";
                                        const new_text = std.fmt.allocPrint(alloc, "{s}{s}{s}{s}", .{
                                            text[0..ws], at_s, path, text[cur..],
                                        }) catch continue;
                                        defer alloc.free(new_text);
                                        const new_cur = ws + at_s.len + path.len;
                                        ui.ed.buf.items.len = 0;
                                        try ui.ed.buf.appendSlice(ui.ed.alloc, new_text);
                                        ui.ed.cur = new_cur;
                                    }
                                } else if (cp.arg_src != null) {
                                    // Arg mode: replace arg in editor
                                    if (cp.selectedArg()) |arg| {
                                        const text = ui.ed.text();
                                        const sp = std.mem.indexOfScalar(u8, text, ' ') orelse text.len;
                                        ui.ed.buf.items.len = sp;
                                        try ui.ed.buf.appendSlice(ui.ed.alloc, " ");
                                        try ui.ed.buf.appendSlice(ui.ed.alloc, arg);
                                        ui.ed.cur = ui.ed.buf.items.len;
                                    }
                                } else {
                                    // Cmd mode: fill command name
                                    const cmd = cp.selected();
                                    ui.ed.buf.items.len = 0;
                                    try ui.ed.buf.appendSlice(ui.ed.alloc, "/");
                                    try ui.ed.buf.appendSlice(ui.ed.alloc, cmd.name);
                                    try ui.ed.buf.appendSlice(ui.ed.alloc, " ");
                                    ui.ed.cur = ui.ed.buf.items.len;
                                }
                                ui.picker = null;
                                ui.arg_src = resolveArgSrc(ui.ed.text(), models_list);
                                ui.updatePreview();
                                try ui.draw(out);
                                continue;
                            },
                            .esc => {
                                ui.picker = null;
                                ui.clearPathItems();
                                try ui.draw(out);
                                continue;
                            },
                            else => {},
                        }
                    }

                    // Capture editor text before onKey clears it on submit
                    const snap = ui.editorText();
                    var pre: ?[]u8 = if (snap.len > 0) try alloc.dupe(u8, snap) else null;

                    const act = try ui.onKey(key);
                    switch (act) {
                        .submit => {
                            const prompt = pre orelse {
                                try ui.draw(out);
                                continue;
                            };
                            pre = null; // ownership transferred
                            defer alloc.free(prompt);

                            var cmd_buf: [4096]u8 = undefined;
                            var cmd_fbs = std.io.fixedBufferStream(&cmd_buf);
                            const cmd = try handleSlashCommand(
                                alloc,
                                prompt,
                                sid,
                                &model,
                                &model_owned,
                                &provider_label,
                                &provider_owned,
                                pol,
                                tools_rt,
                                &bg_mgr,
                                session_dir_path,
                                no_session,
                                sys_prompt,
                                cmd_fbs.writer().any(),
                                audit_hooks,
                                &ctl_audit,
                            );
                            if (cmd == .quit) return;
                            if (cmd == .clear) {
                                ui.clearTranscript();
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .copy) {
                                try copyLastResponse(alloc, &ui);
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .cost) {
                                try showCost(alloc, &ui);
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .reload) {
                                const reloaded = try reloadContextWithAudit(alloc, &sys_prompt, &sys_prompt_owned, &ctl_audit, core.context.load);
                                switch (reloaded) {
                                    .loaded => try ui.tr.infoText("[context reloaded]"),
                                    .empty => try ui.tr.infoText("[context reloaded (no files)]"),
                                }
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .resumed) {
                                _ = try tryRestoreSessionIntoUi(alloc, &ui, session_dir_path, no_session, sid.*);
                            }
                            if (cmd == .select_model) {
                                var cur_idx: usize = 0;
                                for (models_list, 0..) |m, i| {
                                    if (std.mem.eql(u8, model, m)) {
                                        cur_idx = i;
                                        break;
                                    }
                                }
                                ui.ov = tui_overlay.Overlay.init(models_list, cur_idx);
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .select_session) {
                                _ = try showResumeOverlay(alloc, &ui, session_dir_path);
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .select_settings) {
                                ui.ov = try buildSettingsOverlay(alloc, &ui, auto_compact_on);
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .select_fork) {
                                if (session_dir_path) |sdp| {
                                    if (listUserMessages(alloc, sdp, sid.*)) |msgs| {
                                        if (msgs.len > 0) {
                                            var ov = tui_overlay.Overlay.initDyn(alloc, msgs, "Fork from message", .session);
                                            ov.sel = msgs.len - 1; // select last message
                                            ov.fixScroll();
                                            ov.kind = .fork;
                                            ui.ov = ov;
                                        }
                                    } else |_| {}
                                }
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .select_login) {
                                const login_items = [_][]const u8{ "anthropic", "openai", "google" };
                                var ov = tui_overlay.Overlay.init(&login_items, 0);
                                ov.title = "Login (set API key)";
                                ov.kind = .login;
                                ui.ov = ov;
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .select_logout) {
                                const providers = core.providers.auth.listLoggedIn(alloc) catch try alloc.alloc(core.providers.auth.Provider, 0);
                                defer alloc.free(providers);
                                if (!try showLogoutOverlay(alloc, &ui, providers)) {
                                    try ui.tr.infoText("no providers logged in");
                                }
                                try ui.draw(out);
                                continue;
                            }
                            if (cmd == .handled or cmd == .compacted or cmd == .resumed) {
                                if (cmd == .compacted) ui.panels.noteCompaction();
                                const cmd_text = cmd_fbs.getWritten();
                                if (cmd_text.len > 0) {
                                    try infoTextSafe(alloc, &ui, cmd_text);
                                    ui.tr.scrollToBottom();
                                }
                                try syncBgFooter(alloc, &ui, &bg_mgr);
                                try ui.setModel(model);
                                try ui.setProvider(provider_label);
                                try ui.draw(out);
                                continue;
                            }

                            // Bash mode: !cmd or !!cmd
                            if (parseBashCmd(prompt)) |bcmd| {
                                try runBashMode(alloc, &ui, bcmd, sid.*, store);
                                try ui.draw(out);
                                continue;
                            }

                            if (live_turn.isRunning()) {
                                try pending.pushSteering(alloc, prompt);
                                syncInputFooter(&ui, input_mode, pending.total());
                                live_turn.requestCancel();
                                try ui.tr.infoText("(queued steering message)");
                                try ui.draw(out);
                                continue;
                            }

                            try startLiveTurnWithPrompt(&live_turn, &live_tctx, &ui, sid.*, prompt, model, provider_label, popts, sys_prompt, &retried_overflow);
                            try ui.draw(out);
                        },
                        .cancel => {
                            if (pre) |p| alloc.free(p);
                            return;
                        },
                        .interrupt => {
                            if (pre) |p| alloc.free(p);
                            if (live_turn.isRunning()) {
                                const restored = try pending.restoreToEditor(alloc, &ui);
                                syncInputFooter(&ui, input_mode, pending.total());
                                live_turn.requestCancel();
                                if (restored > 0) {
                                    const msg = try std.fmt.allocPrint(alloc, "(restored {d} queued message{s})", .{
                                        restored,
                                        if (restored == 1) "" else "s",
                                    });
                                    defer alloc.free(msg);
                                    try ui.tr.infoText(msg);
                                }
                            }
                            try ui.draw(out);
                        },
                        .cycle_thinking => {
                            if (pre) |p| alloc.free(p);
                            thinking = cycleThinking(thinking);
                            popts = thinking.toProviderOpts();
                            ui.panels.thinking_label = thinkingLabel(thinking);
                            ui.border_fg = thinkingBorderFg(thinking);
                            try ui.draw(out);
                        },
                        .cycle_model => {
                            if (pre) |p| alloc.free(p);
                            model = try cycleModel(alloc, model, &model_owned, models_list);
                            ui.panels.ctx_limit = modelCtxWindow(model);
                            try ui.setModel(model);
                            try ui.draw(out);
                        },
                        .toggle_tools => {
                            if (pre) |p| alloc.free(p);
                            ui.tr.show_tools = !ui.tr.show_tools;
                            try ui.draw(out);
                        },
                        .toggle_thinking => {
                            if (pre) |p| alloc.free(p);
                            ui.tr.show_thinking = !ui.tr.show_thinking;
                            try ui.draw(out);
                        },
                        .kill_to_eol => {
                            if (pre) |p| alloc.free(p);
                            try ui.draw(out);
                        },
                        .@"suspend" => {
                            if (pre) |p| alloc.free(p);
                            // No-op: Ctrl+Z is now undo (handled by editor)
                            try ui.draw(out);
                        },
                        .select_model => {
                            if (pre) |p| alloc.free(p);
                            // Find current model index
                            var cur_idx: usize = 0;
                            for (models_list, 0..) |m, i| {
                                if (std.mem.eql(u8, model, m)) {
                                    cur_idx = i;
                                    break;
                                }
                            }
                            ui.ov = tui_overlay.Overlay.init(models_list, cur_idx);
                            try ui.draw(out);
                        },
                        .ext_editor => {
                            if (pre) |p| alloc.free(p);
                            tui_term.restore(stdin_fd);
                            const ed_result = openExtEditor(alloc, ui.editorText());
                            _ = tui_term.enableRaw(stdin_fd);
                            if (ed_result) |maybe_txt| {
                                if (maybe_txt) |txt| {
                                    defer alloc.free(txt);
                                    try ui.ed.setText(txt);
                                }
                            } else |err| {
                                const detail = try report.inlineMsg(alloc, err);
                                defer alloc.free(detail);
                                const msg = try std.fmt.allocPrint(alloc, "[editor failed: {s}]", .{detail});
                                defer alloc.free(msg);
                                try ui.tr.infoText(msg);
                            }
                            try ui.draw(out);
                        },
                        .queue_followup => {
                            if (pre) |p| alloc.free(p);
                            const snap2 = ui.editorText();
                            if (snap2.len > 0) {
                                try pending.pushFollowUp(alloc, snap2);
                                ui.ed.clear();
                                ui.updatePreview();
                                syncInputFooter(&ui, input_mode, pending.total());
                                try ui.tr.infoText(if (live_turn.isRunning()) "(queued follow-up message)" else "(queued message)");
                            }
                            try ui.draw(out);
                        },
                        .edit_queued => {
                            if (pre) |p| alloc.free(p);
                            const restored = try pending.restoreToEditor(alloc, &ui);
                            syncInputFooter(&ui, input_mode, pending.total());
                            if (restored == 0) {
                                try ui.tr.infoText("(queue is empty)");
                            } else {
                                const msg = try std.fmt.allocPrint(alloc, "(restored {d} queued message{s})", .{
                                    restored,
                                    if (restored == 1) "" else "s",
                                });
                                defer alloc.free(msg);
                                try ui.tr.infoText(msg);
                            }
                            try ui.draw(out);
                        },
                        .toggle_queue_mode => {
                            if (pre) |p| alloc.free(p);
                            try ui.tr.infoText("(use Enter for steering, Alt+Enter for follow-up)");
                            try ui.draw(out);
                        },
                        .paste_image => {
                            if (pre) |p| alloc.free(p);
                            try pasteImage(alloc, &ui);
                            try ui.draw(out);
                        },
                        .reverse_cycle_model => {
                            if (pre) |p| alloc.free(p);
                            model = try reverseCycleModel(alloc, model, &model_owned, models_list);
                            ui.panels.ctx_limit = modelCtxWindow(model);
                            try ui.setModel(model);
                            try ui.draw(out);
                        },
                        .tab_complete => {
                            if (pre) |p| alloc.free(p);
                            const tab_text = ui.ed.text();
                            if (tab_text.len > 0 and tab_text[0] == '/') {
                                completeSlashCmd(&ui.ed);
                            } else if (tab_text.len > 0) {
                                try completeFilePath(alloc, &ui);
                            }
                            ui.arg_src = resolveArgSrc(ui.ed.text(), models_list);
                            ui.updatePreview();
                            try ui.draw(out);
                        },
                        .scroll_up => {
                            if (pre) |p| alloc.free(p);
                            ui.tr.scrollUp(ui.frm.h / 2);
                            try ui.draw(out);
                        },
                        .scroll_down => {
                            if (pre) |p| alloc.free(p);
                            ui.tr.scrollDown(ui.frm.h / 2);
                            try ui.draw(out);
                        },
                        .none => {
                            if (pre) |p| alloc.free(p);
                            ui.arg_src = resolveArgSrc(ui.ed.text(), models_list);
                            ui.updatePreview();
                            try ui.draw(out);
                        },
                    }
                },
                .mouse => |mev| {
                    ui.onMouse(mev);
                    try ui.draw(out);
                },
                .notify => {
                    while (live_turn.takeAsk()) |ask_txn| {
                        live_turn.finishAsk(ask_txn, ask_ui_ctx.runOnMain(&reader, ask_txn.args.view()));
                    }

                    while (live_turn.popProvider()) |sev| {
                        defer freeProviderEv(alloc, sev.ev);
                        try ui.onProviderSeq(sev.seq, sev.ev);
                    }

                    if (live_turn.takeCompletion()) |done| {
                        defer if (done.err_name) |name| alloc.free(name);
                        var compact_out: AutoCompactOutcome = .skipped;

                        if (shouldRetryOverflow(alloc, &live_turn, model, retried_overflow)) {
                            compact_out = try autoCompact(alloc, &ui, out, sid.*, session_dir_path, no_session, true);
                            if (compact_out == .compacted) {
                                const retry_req = (try live_turn.cloneReq(alloc)) orelse return error.TestUnexpectedResult;
                                defer {
                                    var req = retry_req;
                                    req.deinit(alloc);
                                }
                                try ui.tr.infoText("[overflow detected: compacting and retrying]");
                                live_turn.start(&live_tctx, .{
                                    .sid = retry_req.sid,
                                    .prompt = retry_req.prompt,
                                    .model = retry_req.model,
                                    .provider_label = retry_req.provider_label,
                                    .provider_opts = retry_req.provider_opts,
                                    .system_prompt = retry_req.system_prompt,
                                }) catch |start_err| {
                                    const detail = try report.inlineMsg(alloc, start_err);
                                    defer alloc.free(detail);
                                    const msg = try std.fmt.allocPrint(alloc, "[retry start failed: {s}]", .{detail});
                                    defer alloc.free(msg);
                                    try ui.tr.infoText(msg);
                                    ui.panels.run_state = .idle;
                                    retried_overflow = false;
                                    try flushBgDone(alloc, &ui, &bg_mgr);
                                    try syncBgFooter(alloc, &ui, &bg_mgr);
                                    try ui.draw(out);
                                    continue;
                                };
                                retried_overflow = true;
                                ui.panels.run_state = .streaming;
                                try flushBgDone(alloc, &ui, &bg_mgr);
                                try syncBgFooter(alloc, &ui, &bg_mgr);
                                try ui.draw(out);
                                continue;
                            }
                        }

                        retried_overflow = false;
                        if (done.err_name) |name| {
                            if (compact_out != .stopped) {
                                const msg = try std.fmt.allocPrint(alloc, "[turn failed: {s}]", .{name});
                                defer alloc.free(msg);
                                try ui.tr.infoText(msg);
                            }
                        } else if (auto_compact_on) {
                            _ = try autoCompact(alloc, &ui, out, sid.*, session_dir_path, no_session, false);
                        }

                        if (pending.popNext()) |next_turn| {
                            defer alloc.free(next_turn.text);
                            syncInputFooter(&ui, input_mode, pending.total());
                            live_turn.start(&live_tctx, .{
                                .sid = sid.*,
                                .prompt = next_turn.text,
                                .model = model,
                                .provider_label = provider_label,
                                .provider_opts = popts,
                                .system_prompt = sys_prompt,
                            }) catch |start_err| {
                                const detail = try report.inlineMsg(alloc, start_err);
                                defer alloc.free(detail);
                                const msg = try std.fmt.allocPrint(alloc, "[queue start failed: {s}]", .{detail});
                                defer alloc.free(msg);
                                try ui.tr.infoText(msg);
                                ui.panels.run_state = .idle;
                                try flushBgDone(alloc, &ui, &bg_mgr);
                                try syncBgFooter(alloc, &ui, &bg_mgr);
                                try ui.draw(out);
                                continue;
                            };
                            retried_overflow = false;
                            ui.panels.run_state = .streaming;
                            try ui.tr.infoText(if (next_turn.kind == .steering) "(sending queued steering message)" else "(sending queued follow-up message)");
                        } else {
                            ui.panels.run_state = .idle;
                        }
                        if (stop_after_completions) |n| {
                            const next_n = n - 1;
                            stop_after_completions = next_n;
                            if (next_n == 0 and pending.total() == 0 and !live_turn.isRunning()) {
                                try flushBgDone(alloc, &ui, &bg_mgr);
                                try syncBgFooter(alloc, &ui, &bg_mgr);
                                try ui.draw(out);
                                return;
                            }
                        }
                    }

                    try flushBgDone(alloc, &ui, &bg_mgr);
                    try syncBgFooter(alloc, &ui, &bg_mgr);
                    try ui.draw(out);
                    if (tui_hooks.exit_on_idle and !live_turn.isRunning() and pending.total() == 0) return;
                },
                .paste => |text| {
                    if (text.len > 0) {
                        ui.ed.insertSlice(text) catch {
                            try ui.tr.infoText("[paste: invalid UTF-8]");
                        };
                        ui.arg_src = resolveArgSrc(ui.ed.text(), models_list);
                        ui.updatePreview();
                        try ui.draw(out);
                    }
                },
                .resize => {
                    if (tui_term.size(std.posix.STDOUT_FILENO)) |sz| {
                        try ui.resize(sz.w, sz.h);
                        try ui.draw(out);
                    }
                },
                .none => {
                    if (ui.panels.bg_running > 0) {
                        ui.panels.tickBgSpinner();
                        try ui.draw(out);
                    }
                },
                .err => {
                    try ui.tr.infoText("[stdin read error — exiting]");
                    try ui.draw(out);
                    return;
                },
            }
        }
    } else {
        // Non-TTY (piped input): line-buffered mode for tests/scripts
        var turn_ct: usize = 0;
        var cmd_ct: usize = 0;
        while (try in.readUntilDelimiterOrEofAlloc(alloc, '\n', 64 * 1024)) |raw_line| {
            defer alloc.free(raw_line);
            try maybeShowVersionUpdate(alloc, &ui, &ver_check, &ver_notice_done, out);

            if (tui_term.pollResize()) {
                if (tui_term.size(std.posix.STDOUT_FILENO)) |sz| {
                    try ui.resize(sz.w, sz.h);
                    try ui.draw(out);
                }
            }

            var line = raw_line;
            if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len == 0) continue;

            const cmd = try handleSlashCommand(
                alloc,
                trimmed,
                sid,
                &model,
                &model_owned,
                &provider_label,
                &provider_owned,
                pol,
                tools_rt,
                &bg_mgr,
                session_dir_path,
                no_session,
                sys_prompt,
                out,
                audit_hooks,
                &ctl_audit,
            );
            if (cmd == .quit) return;
            if (cmd == .clear) {
                ui.clearTranscript();
                try ui.draw(out);
                cmd_ct += 1;
                continue;
            }
            if (cmd == .copy) {
                try copyLastResponse(alloc, &ui);
                try ui.draw(out);
                cmd_ct += 1;
                continue;
            }
            if (cmd == .cost) {
                try showCost(alloc, &ui);
                try ui.draw(out);
                cmd_ct += 1;
                continue;
            }
            if (cmd == .reload) {
                _ = try reloadContextWithAudit(alloc, &sys_prompt, &sys_prompt_owned, &ctl_audit, core.context.load);
                try ui.draw(out);
                cmd_ct += 1;
                continue;
            }
            if (cmd == .resumed) {
                _ = try tryRestoreSessionIntoUi(alloc, &ui, session_dir_path, no_session, sid.*);
            }
            if (cmd == .handled or cmd == .compacted or cmd == .resumed) {
                if (cmd == .compacted) ui.panels.noteCompaction();
                try syncBgFooter(alloc, &ui, &bg_mgr);
                try ui.setModel(model);
                try ui.setProvider(provider_label);
                try ui.draw(out);
                cmd_ct += 1;
                continue;
            }

            // Bash mode: !cmd or !!cmd
            if (parseBashCmd(trimmed)) |bcmd| {
                try runBashMode(alloc, &ui, bcmd, sid.*, store);
                try ui.draw(out);
                turn_ct += 1;
                continue;
            }

            try tctx.run(.{
                .sid = sid.*,
                .prompt = trimmed,
                .model = model,
                .provider_label = provider_label,
                .provider_opts = popts,
                .system_prompt = sys_prompt,
            });
            if (auto_compact_on) _ = try autoCompact(alloc, &ui, out, sid.*, session_dir_path, no_session, false);
            turn_ct += 1;
        }
        if (turn_ct == 0 and cmd_ct == 0 and run_cmd.prompt == null) return error.EmptyPrompt;
    }
}

fn runRpc(
    alloc: std.mem.Allocator,
    run_cmd: cli.Run,
    sid: *([]u8),
    provider: core.providers.Provider,
    store: core.session.SessionStore,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    in: std.Io.AnyReader,
    out: std.Io.AnyWriter,
    session_dir_path: ?[]const u8,
    no_session: bool,
    sys_prompt: ?[]const u8,
    audit_hooks: AuditHooks,
) !void {
    var ctl_audit = RuntimeCtlAudit{ .hooks = audit_hooks };
    var model: []const u8 = resolveDefault(run_cmd.cfg.model);
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |m| alloc.free(m);
    var provider_label: []const u8 = resolveDefaultProvider(run_cmd.cfg.provider);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |p| alloc.free(p);

    var sink_impl = JsonSink{
        .alloc = alloc,
        .out = out,
    };
    const mode = core.loop.ModeSink.from(JsonSink, &sink_impl, JsonSink.push);
    const popts = run_cmd.thinking.toProviderOpts();
    var cmd_cache = core.loop.CmdCache.init(alloc);
    defer cmd_cache.deinit();
    const approval_bind = try loadApprovalBindAlloc(alloc);
    defer approval_bind.deinit(alloc);
    const approval_loc = try getApprovalLocAlloc(alloc);
    defer freeApprovalLoc(alloc, approval_loc);
    const tctx = TurnCtx{
        .alloc = alloc,
        .provider = provider,
        .store = store,
        .pol = pol,
        .tools_rt = tools_rt,
        .mode = mode,
        .max_turns = run_cmd.max_turns,
        .cmd_cache = &cmd_cache,
        .approval_bind = approval_bind,
        .approval_loc = approval_loc,
    };
    var bg_mgr = try bg.Mgr.initWithOpts(alloc, .{
        .emit_audit_ctx = audit_hooks.emit_audit_ctx,
        .emit_audit = audit_hooks.emit_audit,
        .now_ms = audit_hooks.now_ms,
    });
    defer bg_mgr.deinit();

    while (try in.readUntilDelimiterOrEofAlloc(alloc, '\n', 128 * 1024)) |raw_line| {
        defer alloc.free(raw_line);

        const bg_done = try bg_mgr.drainDone(alloc);
        defer bg.deinitViews(alloc, bg_done);
        for (bg_done) |job| {
            try writeJsonLine(alloc, out, .{
                .type = "rpc_bg_done",
                .bg_id = job.id,
                .state = bg.stateName(job.state),
                .code = job.code,
                .log = job.log_path,
                .cmdline = job.cmd,
            });
        }

        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        const parsed = std.json.parseFromSlice(RpcReq, alloc, line, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        }) catch {
            try writeJsonLine(alloc, out, .{
                .type = "rpc_error",
                .msg = "invalid JSON request payload",
            });
            continue;
        };
        defer parsed.deinit();
        const req = parsed.value;
        const raw_cmd = req.cmd orelse req.type orelse "";
        if (raw_cmd.len == 0) {
            try writeJsonLine(alloc, out, .{
                .type = "rpc_error",
                .id = req.id,
                .msg = "missing command field (cmd or type)",
            });
            continue;
        }
        const cmd = normalizeRpcCmd(raw_cmd);

        const RpcCmd = enum { prompt, model, provider, tools, bg, login, logout, upgrade, new, @"resume", session, tree, fork, compact, help, commands, quit, exit };
        const rpc_map = std.StaticStringMap(RpcCmd).initComptime(.{
            .{ "prompt", .prompt },
            .{ "model", .model },
            .{ "provider", .provider },
            .{ "tools", .tools },
            .{ "bg", .bg },
            .{ "login", .login },
            .{ "logout", .logout },
            .{ "upgrade", .upgrade },
            .{ "new", .new },
            .{ "resume", .@"resume" },
            .{ "session", .session },
            .{ "tree", .tree },
            .{ "fork", .fork },
            .{ "compact", .compact },
            .{ "help", .help },
            .{ "commands", .commands },
            .{ "quit", .quit },
            .{ "exit", .exit },
        });

        const resolved = rpc_map.get(cmd) orelse {
            try writeJsonLine(alloc, out, .{
                .type = "rpc_error",
                .id = req.id,
                .cmd = raw_cmd,
                .msg = "unknown command; run rpc help or rpc commands",
            });
            continue;
        };

        if (!pol.allowsCmd(cmd)) {
            try writeJsonLine(alloc, out, .{
                .type = "rpc_error",
                .id = req.id,
                .cmd = raw_cmd,
                .msg = policy_denied_msg,
            });
            continue;
        }

        switch (resolved) {
            .prompt => {
                const prompt = req.text orelse req.arg orelse "";
                if (prompt.len == 0) {
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = "missing prompt text",
                    });
                    continue;
                }
                try tctx.run(.{
                    .sid = sid.*,
                    .prompt = prompt,
                    .model = model,
                    .provider_label = provider_label,
                    .provider_opts = popts,
                    .system_prompt = sys_prompt,
                });
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                });
            },
            .model => {
                const next = req.model_id orelse req.model orelse req.arg orelse "";
                const argv = if (next.len > 0) core.audit.Str{ .text = next, .vis = .@"pub" } else null;
                const has_alias_provider = isSetModelAlias(raw_cmd) and req.provider != null and req.provider.?.len > 0;
                if (has_alias_provider) {
                    const start_attrs = [_]core.audit.Attr{
                        .{
                            .key = "provider",
                            .vis = .@"pub",
                            .val = .{ .str = req.provider.? },
                        },
                    };
                    try runtimeCtlStart(&ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &start_attrs);
                } else {
                    try runtimeCtlStart(&ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &.{});
                }
                if (next.len == 0) {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "model",
                        .cfg,
                        runtimeCfgResName(),
                        null,
                        .{ .text = "missing model value", .vis = .mask },
                        &.{},
                    );
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = "missing model value",
                    });
                    continue;
                }
                if (has_alias_provider) {
                    try replaceOwnedText(alloc, &provider_label, &provider_owned, req.provider.?);
                }
                try replaceOwnedText(alloc, &model, &model_owned, next);
                const done_attrs = [_]core.audit.Attr{
                    .{
                        .key = "provider",
                        .vis = .@"pub",
                        .val = .{ .str = provider_label },
                    },
                };
                try runtimeCtlSuccess(&ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &done_attrs);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .model = model,
                    .provider = provider_label,
                });
            },
            .provider => {
                const next = req.provider orelse req.arg orelse "";
                const argv = if (next.len > 0) core.audit.Str{ .text = next, .vis = .@"pub" } else null;
                try runtimeCtlStart(&ctl_audit, alloc, "provider", .cfg, runtimeCfgResName(), argv, &.{});
                if (next.len == 0) {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "provider",
                        .cfg,
                        runtimeCfgResName(),
                        null,
                        .{ .text = "missing provider value", .vis = .mask },
                        &.{},
                    );
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = "missing provider value",
                    });
                    continue;
                }
                try replaceOwnedText(alloc, &provider_label, &provider_owned, next);
                try runtimeCtlSuccess(&ctl_audit, alloc, "provider", .cfg, runtimeCfgResName(), argv, &.{});
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .provider = provider_label,
                });
            },
            .tools => {
                const raw = req.tools orelse req.arg orelse "";
                if (raw.len != 0) {
                    const argv: core.audit.Str = .{ .text = raw, .vis = .@"pub" };
                    try runtimeCtlStart(&ctl_audit, alloc, "tools", .cfg, runtimeCfgResName(), argv, &.{});
                    const mask = parseCmdToolMask(raw) catch {
                        try runtimeCtlFail(
                            &ctl_audit,
                            alloc,
                            "tools",
                            .cfg,
                            runtimeCfgResName(),
                            argv,
                            .{ .text = "invalid tools value", .vis = .mask },
                            &.{},
                        );
                        try writeJsonLine(alloc, out, .{
                            .type = "rpc_error",
                            .id = req.id,
                            .cmd = raw_cmd,
                            .msg = "invalid tools value",
                        });
                        continue;
                    };
                    tools_rt.tool_mask = mask;
                }
                const tool_csv = try toolMaskCsvAlloc(alloc, tools_rt.tool_mask);
                defer alloc.free(tool_csv);
                if (raw.len != 0) {
                    const argv: core.audit.Str = .{ .text = raw, .vis = .@"pub" };
                    const attrs = [_]core.audit.Attr{
                        .{
                            .key = "tools",
                            .vis = .@"pub",
                            .val = .{ .str = tool_csv },
                        },
                    };
                    try runtimeCtlSuccess(&ctl_audit, alloc, "tools", .cfg, runtimeCfgResName(), argv, &attrs);
                }
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .tools = tool_csv,
                });
            },
            .bg => {
                const bg_arg = req.arg orelse req.text orelse "list";
                const msg = try runBgCommand(alloc, &bg_mgr, bg_arg);
                defer alloc.free(msg);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_bg",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .msg = msg,
                });
            },
            .login => {
                const msg = runRpcLogin(alloc, req, audit_hooks.auth()) catch |err| {
                    const err_msg = try report.rpc(alloc, "login", err);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                defer alloc.free(msg);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_auth",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .msg = msg,
                });
            },
            .logout => {
                const msg = runRpcLogout(alloc, req, provider_label, audit_hooks.auth()) catch |err| {
                    const err_msg = try report.rpc(alloc, "logout", err);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                defer alloc.free(msg);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_auth",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .msg = msg,
                });
            },
            .upgrade => {
                try runtimeCtlStart(&ctl_audit, alloc, "upgrade", .cmd, runtimeUpgradeResName(), null, &.{});
                const outcome = audit_hooks.run_upgrade(alloc, updateAuditHooks(audit_hooks)) catch |err| {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "upgrade",
                        .cmd,
                        runtimeUpgradeResName(),
                        null,
                        .{ .text = @errorName(err), .vis = .mask },
                        &.{},
                    );
                    const err_msg = try report.rpc(alloc, "upgrade", err);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                defer outcome.deinit(alloc);
                if (outcome.ok) {
                    try runtimeCtlSuccess(&ctl_audit, alloc, "upgrade", .cmd, runtimeUpgradeResName(), null, &.{});
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_upgrade",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = outcome.msg,
                    });
                } else {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "upgrade",
                        .cmd,
                        runtimeUpgradeResName(),
                        null,
                        .{ .text = outcome.msg, .vis = .mask },
                        &.{},
                    );
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = outcome.msg,
                    });
                }
            },
            .new => {
                try runtimeCtlStart(&ctl_audit, alloc, "new", .sess, runtimeSessResName(), null, &.{});
                const next_sid = try newSid(alloc);
                alloc.free(sid.*);
                sid.* = next_sid;
                try runtimeCtlSuccess(&ctl_audit, alloc, "new", .sess, runtimeSessResName(), null, &.{});
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .sid = sid.*,
                });
            },
            .@"resume" => {
                const token = req.session_path orelse req.session orelse req.sid orelse req.arg;
                if (token) |raw| {
                    const argv: core.audit.Str = .{ .text = raw, .vis = .mask };
                    try runtimeCtlStart(&ctl_audit, alloc, "resume", .sess, runtimeSessResName(), argv, &.{});
                }
                applyResumeSid(alloc, sid, session_dir_path, no_session, token) catch |err| {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "resume",
                        .sess,
                        runtimeSessResName(),
                        if (token) |raw| .{ .text = raw, .vis = .mask } else null,
                        .{ .text = @errorName(err), .vis = .mask },
                        &.{},
                    );
                    const err_msg = try report.rpc(alloc, "resume session", err);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                try runtimeCtlSuccess(
                    &ctl_audit,
                    alloc,
                    "resume",
                    .sess,
                    runtimeSessResName(),
                    if (token) |raw| .{ .text = raw, .vis = .mask } else null,
                    &.{},
                );
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .sid = sid.*,
                });
            },
            .session => {
                const tool_csv = try toolMaskCsvAlloc(alloc, tools_rt.tool_mask);
                defer alloc.free(tool_csv);
                const stats = try sessionStats(alloc, session_dir_path, sid.*, no_session);
                defer if (stats.path_owned) |path| alloc.free(path);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_session",
                    .id = req.id,
                    .sid = sid.*,
                    .model = model,
                    .provider = provider_label,
                    .tools = tool_csv,
                    .session_dir = session_dir_path orelse "",
                    .session_file = stats.path,
                    .session_bytes = stats.bytes,
                    .session_lines = stats.lines,
                    .no_session = no_session,
                });
            },
            .tree => {
                const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                    const err_msg = try report.rpc(alloc, "list sessions", error.SessionDisabled);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                const tree = try listSessionsAlloc(alloc, session_dir);
                defer alloc.free(tree);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_tree",
                    .id = req.id,
                    .sessions = tree,
                });
            },
            .fork => {
                const fork_arg = req.sid orelse req.arg;
                if (fork_arg) |raw| {
                    const argv: core.audit.Str = .{ .text = raw, .vis = .mask };
                    try runtimeCtlStart(&ctl_audit, alloc, "fork", .sess, runtimeSessResName(), argv, &.{});
                }
                applyForkSid(alloc, sid, session_dir_path, no_session, req.sid orelse req.arg) catch |err| {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "fork",
                        .sess,
                        runtimeSessResName(),
                        if (fork_arg) |raw| .{ .text = raw, .vis = .mask } else null,
                        .{ .text = @errorName(err), .vis = .mask },
                        &.{},
                    );
                    const err_msg = try report.rpc(alloc, "fork session", err);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                try runtimeCtlSuccess(
                    &ctl_audit,
                    alloc,
                    "fork",
                    .sess,
                    runtimeSessResName(),
                    if (fork_arg) |raw| .{ .text = raw, .vis = .mask } else null,
                    &.{},
                );
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                    .sid = sid.*,
                });
            },
            .compact => {
                try runtimeCtlStart(&ctl_audit, alloc, "compact", .sess, runtimeSessResName(), null, &.{});
                const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "compact",
                        .sess,
                        runtimeSessResName(),
                        null,
                        .{ .text = @errorName(error.SessionDisabled), .vis = .mask },
                        &.{},
                    );
                    const err_msg = try report.rpc(alloc, "compact session", error.SessionDisabled);
                    defer alloc.free(err_msg);
                    try writeJsonLine(alloc, out, .{
                        .type = "rpc_error",
                        .id = req.id,
                        .cmd = raw_cmd,
                        .msg = err_msg,
                    });
                    continue;
                };
                var dir = try std.fs.cwd().openDir(session_dir, .{});
                defer dir.close();
                const ck = core.session.compactSession(alloc, dir, sid.*, audit_hooks.now_ms()) catch |err| {
                    try runtimeCtlFail(
                        &ctl_audit,
                        alloc,
                        "compact",
                        .sess,
                        runtimeSessResName(),
                        null,
                        .{ .text = @errorName(err), .vis = .mask },
                        &.{},
                    );
                    return err;
                };
                const attrs = [_]core.audit.Attr{
                    .{
                        .key = "in_lines",
                        .vis = .@"pub",
                        .val = .{ .uint = @intCast(ck.in_lines) },
                    },
                    .{
                        .key = "out_lines",
                        .vis = .@"pub",
                        .val = .{ .uint = @intCast(ck.out_lines) },
                    },
                };
                try runtimeCtlSuccess(&ctl_audit, alloc, "compact", .sess, runtimeSessResName(), null, &attrs);
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_compact",
                    .id = req.id,
                    .sid = sid.*,
                    .in_lines = ck.in_lines,
                    .out_lines = ck.out_lines,
                    .in_bytes = ck.in_bytes,
                    .out_bytes = ck.out_bytes,
                });
            },
            .help => {
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_help",
                    .id = req.id,
                    .commands = "prompt,model,provider,tools,bg,login,logout,upgrade,new,resume,session,tree,fork,compact,quit",
                });
            },
            .commands => {
                const commands = [_][]const u8{
                    "prompt", "model", "provider", "tools", "bg", "login", "logout", "upgrade", "new", "resume", "session", "tree", "fork", "compact", "help", "quit",
                };
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_commands",
                    .id = req.id,
                    .commands = commands[0..],
                });
            },
            .quit, .exit => {
                try writeJsonLine(alloc, out, .{
                    .type = "rpc_ack",
                    .id = req.id,
                    .cmd = raw_cmd,
                });
                return;
            },
        }
    }
}

const AuthReq = struct {
    prov: core.providers.auth.Provider,
    prov_name: []const u8,
    key: []const u8,
};

fn parseAuthReq(arg: []const u8, provider_hint: ?[]const u8) !AuthReq {
    const trimmed = std.mem.trim(u8, arg, " \t");
    if (provider_hint) |name| {
        const prov_name = std.mem.trim(u8, name, " \t");
        if (prov_name.len == 0) return error.InvalidArgs;
        return .{
            .prov = parseAuthProvider(prov_name) orelse return error.UnknownProvider,
            .prov_name = prov_name,
            .key = trimmed,
        };
    }

    if (trimmed.len == 0) return error.InvalidArgs;
    const sp = std.mem.indexOfAny(u8, trimmed, " \t");
    const prov_name = if (sp) |i| trimmed[0..i] else trimmed;
    return .{
        .prov = parseAuthProvider(prov_name) orelse return error.UnknownProvider,
        .prov_name = prov_name,
        .key = if (sp) |i| std.mem.trim(u8, trimmed[i + 1 ..], " \t") else "",
    };
}

fn runLoginFlow(
    alloc: std.mem.Allocator,
    out: std.Io.AnyWriter,
    req: AuthReq,
    hooks: core.providers.auth.Hooks,
) !void {
    const kind = classifyLoginInput(req.prov, req.key);
    const oauth_info = core.providers.auth.oauthLoginInfo(req.prov);
    if (kind == .oauth_start) {
        const info = oauth_info orelse unreachable;
        var listener = core.providers.oauth_callback.Listener.init(alloc, .{
            .path = info.callback_path,
        }) catch |err| {
            const em = try report.cli(alloc, "start local oauth callback server", err);
            defer alloc.free(em);
            try out.writeAll(em);
            return;
        };
        defer listener.deinit();

        const oauth_name = core.providers.auth.providerName(req.prov);
        var flow = core.providers.auth.beginOAuthWithRedirect(alloc, req.prov, listener.redirect_uri) catch |err| {
            const em = try report.cli(alloc, info.start_action, err);
            defer alloc.free(em);
            try out.writeAll(em);
            return;
        };
        defer flow.deinit(alloc);

        if (core.providers.auth.openBrowser(alloc, flow.url)) {
            try writeTextLine(alloc, out, "opened browser for {s} oauth\n", .{oauth_name});
        } else |_| {
            try out.writeAll("could not open browser automatically\n");
            try writeTextLine(alloc, out, "auth url: {s}\n", .{flow.url});
        }
        try out.writeAll("waiting for oauth callback...\n");

        var callback = listener.waitForCodeState(alloc, 5 * 60 * 1000) catch |err| {
            const em = try report.cli(alloc, "wait for oauth callback", err);
            defer alloc.free(em);
            try out.writeAll(em);
            try writeTextLine(alloc, out, "auth url: {s}\n", .{flow.url});
            try out.writeAll("if your browser showed localhost callback URL, run:\n");
            try writeTextLine(alloc, out, "  /login {s} <callback-url>\n", .{oauth_name});
            return;
        };
        defer callback.deinit(alloc);

        core.providers.auth.completeOAuthFromLocalCallbackWithHooks(
            alloc,
            req.prov,
            callback,
            listener.redirect_uri,
            flow.verifier,
            hooks,
        ) catch |err| {
            const em = try report.cli(alloc, info.complete_action, err);
            defer alloc.free(em);
            try out.writeAll(em);
            return;
        };
        try writeTextLine(alloc, out, "{s} oauth login complete\n", .{oauth_name});
        return;
    }
    if (kind == .oauth_complete) {
        const info = oauth_info orelse unreachable;
        const oauth_name = core.providers.auth.providerName(req.prov);
        core.providers.auth.completeOAuthWithHooks(alloc, req.prov, req.key, hooks) catch |err| {
            const em = try report.cli(alloc, info.complete_action, err);
            defer alloc.free(em);
            try out.writeAll(em);
            return;
        };
        try writeTextLine(alloc, out, "{s} oauth login complete\n", .{oauth_name});
        return;
    }
    if (req.key.len == 0) {
        const env_var = provider_env_map.get(req.prov_name) orelse "API_KEY";
        try writeTextLine(alloc, out, "Paste API key: /login {s} <key> (or set {s})\n", .{ req.prov_name, env_var });
        return;
    }
    try core.providers.auth.saveApiKeyWithHooks(alloc, req.prov, req.key, hooks);
    try writeTextLine(alloc, out, "API key saved for {s}\n", .{req.prov_name});
}

fn runRpcLogin(alloc: std.mem.Allocator, req: RpcReq, hooks: core.providers.auth.Hooks) ![]u8 {
    const auth_req = try parseAuthReq(req.arg orelse req.text orelse "", req.provider);
    const kind = classifyLoginInput(auth_req.prov, auth_req.key);
    const oauth_info = core.providers.auth.oauthLoginInfo(auth_req.prov);
    if (kind == .oauth_start) {
        const info = oauth_info orelse unreachable;
        var listener = try core.providers.oauth_callback.Listener.init(alloc, .{
            .path = info.callback_path,
        });
        defer listener.deinit();

        const oauth_name = core.providers.auth.providerName(auth_req.prov);
        var flow = try core.providers.auth.beginOAuthWithRedirect(alloc, auth_req.prov, listener.redirect_uri);
        defer flow.deinit(alloc);

        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(alloc);
        if (core.providers.auth.openBrowser(alloc, flow.url)) {
            try writeTextLine(alloc, out.writer(alloc).any(), "opened browser for {s} oauth\n", .{oauth_name});
        } else |_| {
            try out.appendSlice(alloc, "could not open browser automatically\n");
            try writeTextLine(alloc, out.writer(alloc).any(), "auth url: {s}\n", .{flow.url});
        }
        try out.appendSlice(alloc, "waiting for oauth callback...\n");

        var callback = try listener.waitForCodeState(alloc, 5 * 60 * 1000);
        defer callback.deinit(alloc);
        try core.providers.auth.completeOAuthFromLocalCallbackWithHooks(
            alloc,
            auth_req.prov,
            callback,
            listener.redirect_uri,
            flow.verifier,
            hooks,
        );
        try writeTextLine(alloc, out.writer(alloc).any(), "{s} oauth login complete\n", .{oauth_name});
        return out.toOwnedSlice(alloc);
    }
    if (kind == .oauth_complete) {
        try core.providers.auth.completeOAuthWithHooks(alloc, auth_req.prov, auth_req.key, hooks);
        return std.fmt.allocPrint(alloc, "{s} oauth login complete\n", .{core.providers.auth.providerName(auth_req.prov)});
    }
    if (auth_req.key.len == 0) {
        const env_var = provider_env_map.get(auth_req.prov_name) orelse "API_KEY";
        return std.fmt.allocPrint(alloc, "Paste API key: /login {s} <key> (or set {s})\n", .{ auth_req.prov_name, env_var });
    }
    try core.providers.auth.saveApiKeyWithHooks(alloc, auth_req.prov, auth_req.key, hooks);
    return std.fmt.allocPrint(alloc, "API key saved for {s}\n", .{auth_req.prov_name});
}

fn runRpcLogout(
    alloc: std.mem.Allocator,
    req: RpcReq,
    active_name: []const u8,
    hooks: core.providers.auth.Hooks,
) ![]u8 {
    const provider_name = if (req.provider) |name|
        std.mem.trim(u8, name, " \t")
    else
        std.mem.trim(u8, req.arg orelse req.text orelse "", " \t");

    if (provider_name.len != 0) {
        const prov = parseAuthProvider(provider_name) orelse return error.UnknownProvider;
        try core.providers.auth.logoutWithHooks(alloc, prov, hooks);
        return std.fmt.allocPrint(alloc, "logged out of {s}\n", .{core.providers.auth.providerName(prov)});
    }

    const logged_in = core.providers.auth.listLoggedIn(alloc) catch try alloc.alloc(core.providers.auth.Provider, 0);
    defer alloc.free(logged_in);
    if (logged_in.len == 0) return alloc.dupe(u8, "no providers logged in\n");
    const prov = chooseLogoutProvider(active_name, logged_in) orelse return error.InvalidArgs;
    try core.providers.auth.logoutWithHooks(alloc, prov, hooks);
    return std.fmt.allocPrint(alloc, "logged out of {s}\n", .{core.providers.auth.providerName(prov)});
}

const CmdRes = enum {
    unhandled,
    handled,
    compacted,
    resumed,
    quit,
    clear,
    copy,
    cost,
    reload,
    select_model,
    select_session,
    select_settings,
    select_fork,
    select_login,
    select_logout,
};

const SlashSkill = enum {
    missing,
    blocked,
    allowed,
};

fn classifySlashSkill(skills: []const core_skill.SkillInfo, name: []const u8) SlashSkill {
    const info = core_skill.findByDirName(skills, name) orelse return .missing;
    if (!info.meta.user_invocable) return .blocked;
    if (info.meta.disable_model_invocation) return .blocked;
    return .allowed;
}

fn loadSlashSkill(alloc: std.mem.Allocator, name: []const u8) !SlashSkill {
    const skills = try core_skill.discoverAndRead(alloc);
    defer core_skill.freeSkills(alloc, skills);
    return classifySlashSkill(skills, name);
}

fn handleSlashCommand(
    alloc: std.mem.Allocator,
    line: []const u8,
    sid: *([]u8),
    model: *([]const u8),
    model_owned: *?[]u8,
    provider: *([]const u8),
    provider_owned: *?[]u8,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    bg_mgr: *bg.Mgr,
    session_dir_path: ?[]const u8,
    no_session: bool,
    _: ?[]const u8, // sys_prompt (unused after settings became interactive)
    out: std.Io.AnyWriter,
    audit_hooks: AuditHooks,
    ctl_audit: *RuntimeCtlAudit,
) !CmdRes {
    if (line.len == 0 or line[0] != '/') return .unhandled;

    const body = std.mem.trim(u8, line[1..], " \t");
    if (body.len == 0) return .handled;

    const sp = std.mem.indexOfAny(u8, body, " \t");
    const cmd = if (sp) |i| body[0..i] else body;
    const arg = if (sp) |i| std.mem.trim(u8, body[i + 1 ..], " \t") else "";

    const Cmd = enum { help, quit, exit, session, model, provider, tools, bg, upgrade, new, @"resume", tree, fork, compact, @"export", settings, hotkeys, login, logout, clear, cost, copy, name, reload, share, changelog };
    const cmd_map = std.StaticStringMap(Cmd).initComptime(.{
        .{ "help", .help },
        .{ "quit", .quit },
        .{ "exit", .exit },
        .{ "session", .session },
        .{ "model", .model },
        .{ "provider", .provider },
        .{ "tools", .tools },
        .{ "bg", .bg },
        .{ "upgrade", .upgrade },
        .{ "new", .new },
        .{ "resume", .@"resume" },
        .{ "tree", .tree },
        .{ "fork", .fork },
        .{ "compact", .compact },
        .{ "export", .@"export" },
        .{ "settings", .settings },
        .{ "hotkeys", .hotkeys },
        .{ "login", .login },
        .{ "logout", .logout },
        .{ "clear", .clear },
        .{ "cost", .cost },
        .{ "copy", .copy },
        .{ "name", .name },
        .{ "reload", .reload },
        .{ "share", .share },
        .{ "changelog", .changelog },
    });

    const resolved = cmd_map.get(cmd) orelse {
        switch (try loadSlashSkill(alloc, cmd)) {
            .allowed => {
                if (pol.allowsCmd(cmd)) return .unhandled;
                try writeTextLine(alloc, out, "blocked by policy: /{s}\n", .{cmd});
            },
            .blocked => try writeTextLine(alloc, out, "skill blocked: /{s}\n", .{cmd}),
            .missing => try writeTextLine(alloc, out, "unknown command: /{s}\n", .{cmd}),
        }
        return .handled;
    };

    if (!pol.allowsCmd(cmd)) {
        try writeTextLine(alloc, out, "blocked by policy: /{s}\n", .{cmd});
        return .handled;
    }

    switch (resolved) {
        .help => {
            try out.writeAll(
                \\Commands:
                \\  /help              Show this help
                \\  /session           Session info
                \\  /settings          Current settings
                \\  /model [id]        Set/select model
                \\  /provider <id>     Set/show provider
                \\  /tools [list|all]  Set/show tools
                \\  /bg <subcommand>   Background jobs
                \\  /upgrade           Self-update to latest release
                \\  /clear             Clear transcript
                \\  /copy              Copy last response
                \\  /export [path]     Export to markdown
                \\  /share             Share as gist
                \\  /name <name>       Name session
                \\  /new               New session
                \\  /resume [id]       Resume session
                \\  /tree              List sessions
                \\  /fork [id]         Fork session
                \\  /compact           Compact session
                \\  /reload            Reload context files
                \\  /login             Login (OAuth/API key)
                \\  /logout            Logout
                \\  /changelog         What's new
                \\  /hotkeys           Keyboard shortcuts
                \\  /quit              Exit
                \\
            );
        },
        .quit, .exit => return .quit,
        .session => {
            const stats = try sessionStats(alloc, session_dir_path, sid.*, no_session);
            defer if (stats.path_owned) |path| alloc.free(path);
            const total = stats.user_msgs + stats.asst_msgs + stats.tool_calls + stats.tool_results;
            const info = try std.fmt.allocPrint(
                alloc,
                "Session Info\n\nFile: {s}\nID:   {s}\n\nMessages\n" ++
                    "  User:         {d}\n  Assistant:    {d}\n  Tool Calls:   {d}\n" ++
                    "  Tool Results: {d}\n  Total:        {d}\n",
                .{ stats.path, sid.*, stats.user_msgs, stats.asst_msgs, stats.tool_calls, stats.tool_results, total },
            );
            defer alloc.free(info);
            try out.writeAll(info);
        },
        .model => {
            if (arg.len == 0) return .select_model;
            const argv: core.audit.Str = .{ .text = arg, .vis = .@"pub" };
            try runtimeCtlStart(ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &.{});
            try replaceOwnedText(alloc, model, model_owned, arg);
            const attrs = [_]core.audit.Attr{
                .{
                    .key = "provider",
                    .vis = .@"pub",
                    .val = .{ .str = provider.* },
                },
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "model", .cfg, runtimeCfgResName(), argv, &attrs);
            try writeTextLine(alloc, out, "model set to {s}\n", .{model.*});
        },
        .provider => {
            if (arg.len == 0) {
                try writeTextLine(alloc, out, "provider {s}\n", .{provider.*});
                return .handled;
            }
            const argv: core.audit.Str = .{ .text = arg, .vis = .@"pub" };
            try runtimeCtlStart(ctl_audit, alloc, "provider", .cfg, runtimeCfgResName(), argv, &.{});
            try replaceOwnedText(alloc, provider, provider_owned, arg);
            try runtimeCtlSuccess(ctl_audit, alloc, "provider", .cfg, runtimeCfgResName(), argv, &.{});
            try writeTextLine(alloc, out, "provider set to {s}\n", .{provider.*});
        },
        .tools => {
            if (arg.len != 0) {
                const argv: core.audit.Str = .{ .text = arg, .vis = .@"pub" };
                try runtimeCtlStart(ctl_audit, alloc, "tools", .cfg, runtimeCfgResName(), argv, &.{});
                const mask = parseCmdToolMask(arg) catch {
                    try runtimeCtlFail(
                        ctl_audit,
                        alloc,
                        "tools",
                        .cfg,
                        runtimeCfgResName(),
                        argv,
                        .{ .text = "invalid tools value", .vis = .mask },
                        &.{},
                    );
                    try out.writeAll("error: invalid tools value; use all, none, or comma list of read,write,bash,edit,grep,find,ls,ask,skill\n");
                    return .handled;
                };
                tools_rt.tool_mask = mask;
                const tool_csv = try toolMaskCsvAlloc(alloc, tools_rt.tool_mask);
                defer alloc.free(tool_csv);
                const attrs = [_]core.audit.Attr{
                    .{
                        .key = "tools",
                        .vis = .@"pub",
                        .val = .{ .str = tool_csv },
                    },
                };
                try runtimeCtlSuccess(ctl_audit, alloc, "tools", .cfg, runtimeCfgResName(), argv, &attrs);
                try writeTextLine(alloc, out, "tools set to {s}\n", .{tool_csv});
                return .handled;
            }
            const tool_csv = try toolMaskCsvAlloc(alloc, tools_rt.tool_mask);
            defer alloc.free(tool_csv);
            try writeTextLine(alloc, out, "tools {s}\n", .{tool_csv});
        },
        .bg => {
            if (arg.len == 0) {
                const usage =
                    \\usage:
                    \\  /bg run <cmd>
                    \\  /bg list
                    \\  /bg show <id>
                    \\  /bg stop <id>
                    \\
                ;
                try out.writeAll(usage);
                return .handled;
            }
            const bg_out = try runBgCommand(alloc, bg_mgr, arg);
            defer alloc.free(bg_out);
            try out.writeAll(bg_out);
        },
        .upgrade => {
            try runtimeCtlStart(ctl_audit, alloc, "upgrade", .cmd, runtimeUpgradeResName(), null, &.{});
            const outcome = audit_hooks.run_upgrade(alloc, updateAuditHooks(audit_hooks)) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "upgrade",
                    .cmd,
                    runtimeUpgradeResName(),
                    null,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                return err;
            };
            defer outcome.deinit(alloc);
            if (outcome.ok) {
                try runtimeCtlSuccess(ctl_audit, alloc, "upgrade", .cmd, runtimeUpgradeResName(), null, &.{});
            } else {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "upgrade",
                    .cmd,
                    runtimeUpgradeResName(),
                    null,
                    .{ .text = outcome.msg, .vis = .mask },
                    &.{},
                );
            }
            try out.writeAll(outcome.msg);
        },
        .new => {
            try runtimeCtlStart(ctl_audit, alloc, "new", .sess, runtimeSessResName(), null, &.{});
            const next_sid = try newSid(alloc);
            alloc.free(sid.*);
            sid.* = next_sid;
            try runtimeCtlSuccess(ctl_audit, alloc, "new", .sess, runtimeSessResName(), null, &.{});
            try writeTextLine(alloc, out, "new session {s}\n", .{sid.*});
        },
        .@"resume" => {
            if (arg.len == 0) return .select_session;
            const argv: core.audit.Str = .{ .text = arg, .vis = .mask };
            try runtimeCtlStart(ctl_audit, alloc, "resume", .sess, runtimeSessResName(), argv, &.{});
            applyResumeSid(alloc, sid, session_dir_path, no_session, arg) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "resume",
                    .sess,
                    runtimeSessResName(),
                    argv,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "resume session", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "resume", .sess, runtimeSessResName(), argv, &.{});
            try writeTextLine(alloc, out, "resumed session {s}\n", .{sid.*});
            return .resumed;
        },
        .tree => {
            const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                const em = try report.cli(alloc, "list sessions", error.SessionDisabled);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            const tree = try listSessionsAlloc(alloc, session_dir);
            defer alloc.free(tree);
            try out.writeAll(tree);
            if (tree.len == 0 or tree[tree.len - 1] != '\n') try out.writeAll("\n");
        },
        .fork => {
            if (arg.len == 0) return .select_fork;
            const argv: core.audit.Str = .{ .text = arg, .vis = .mask };
            try runtimeCtlStart(ctl_audit, alloc, "fork", .sess, runtimeSessResName(), argv, &.{});
            applyForkSid(alloc, sid, session_dir_path, no_session, arg) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "fork",
                    .sess,
                    runtimeSessResName(),
                    argv,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "fork session", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "fork", .sess, runtimeSessResName(), argv, &.{});
            try writeTextLine(alloc, out, "forked session {s}\n", .{sid.*});
        },
        .compact => {
            try runtimeCtlStart(ctl_audit, alloc, "compact", .sess, runtimeSessResName(), null, &.{});
            const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "compact",
                    .sess,
                    runtimeSessResName(),
                    null,
                    .{ .text = @errorName(error.SessionDisabled), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "compact session", error.SessionDisabled);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            var dir = try std.fs.cwd().openDir(session_dir, .{});
            defer dir.close();
            const ck = core.session.compactSession(alloc, dir, sid.*, audit_hooks.now_ms()) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "compact",
                    .sess,
                    runtimeSessResName(),
                    null,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                return err;
            };
            const attrs = [_]core.audit.Attr{
                .{
                    .key = "in_lines",
                    .vis = .@"pub",
                    .val = .{ .uint = @intCast(ck.in_lines) },
                },
                .{
                    .key = "out_lines",
                    .vis = .@"pub",
                    .val = .{ .uint = @intCast(ck.out_lines) },
                },
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "compact", .sess, runtimeSessResName(), null, &attrs);
            try writeTextLine(alloc, out, "compacted in={d} out={d}\n", .{ ck.in_lines, ck.out_lines });
            return .compacted;
        },
        .@"export" => {
            const argv = if (arg.len > 0) core.audit.Str{ .text = arg, .vis = .mask } else null;
            try runtimeCtlStart(ctl_audit, alloc, "export", .file, runtimeExportResName(), argv, &.{});
            const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "export",
                    .file,
                    runtimeExportResName(),
                    argv,
                    .{ .text = @errorName(error.SessionDisabled), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "export session", error.SessionDisabled);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            var dir = try std.fs.cwd().openDir(session_dir, .{});
            defer dir.close();
            const out_path = if (arg.len > 0) arg else null;
            const path = core.session.@"export".toMarkdownAudited(alloc, dir, sid.*, out_path, exportAuditHooks(audit_hooks)) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "export",
                    .file,
                    runtimeExportResName(),
                    argv,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "export session", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            defer alloc.free(path);
            const attrs = [_]core.audit.Attr{
                .{
                    .key = "path",
                    .vis = .mask,
                    .val = .{ .str = path },
                },
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "export", .file, runtimeExportResName(), argv, &attrs);
            try writeTextLine(alloc, out, "exported to {s}\n", .{path});
        },
        .settings => return .select_settings,
        .hotkeys => {
            try out.writeAll(
                \\Keyboard shortcuts:
                \\  Enter          Submit message (steer while running)
                \\  ESC            Clear input / Cancel
                \\  Ctrl+C         Clear input / Quit
                \\  Ctrl+D         Quit (when input empty)
                \\  Ctrl+Z         Undo
                \\  Ctrl+Shift+Z   Redo
                \\  Up/Down        Input history
                \\  Ctrl+A         Move to start
                \\  Ctrl+E         Move to end
                \\  Ctrl+J         Insert newline
                \\  Ctrl+K         Delete to end of line
                \\  Ctrl+U         Delete whole line
                \\  Ctrl+W         Delete word backward
                \\  Alt+D          Delete word forward
                \\  Ctrl+Y         Yank (paste from kill ring)
                \\  Alt+Y          Yank-pop (cycle kill ring)
                \\  Ctrl+]         Jump to character
                \\  Alt+B/Ctrl+←   Move word left
                \\  Alt+F/Ctrl+→   Move word right
                \\  Shift+Tab      Cycle thinking level
                \\  Ctrl+P         Cycle model
                \\  Shift+Ctrl+P   Reverse cycle model
                \\  Ctrl+L         Select model
                \\  Ctrl+O         Toggle tool output
                \\  Ctrl+T         Toggle thinking blocks
                \\  Ctrl+G         External editor
                \\  Ctrl+V         Paste image
                \\  Alt+Enter      Queue follow-up message
                \\  Alt+Up         Restore queued messages to editor
                \\  Page Up/Down   Scroll transcript (half page)
                \\  Scroll Up/Down Scroll transcript
                \\  Shift+Drag     Select text
                \\  !cmd           Run bash (include)
                \\  !!cmd          Run bash (exclude)
                \\  /              Commands
                \\
            );
        },
        .clear => return .clear,
        .cost => return .cost,
        .copy => return .copy,
        .name => {
            if (arg.len == 0) {
                try out.writeAll("usage: /name <display name>\n");
                return .handled;
            }
            // Store name as a session event
            if (!no_session and session_dir_path != null) {
                try writeTextLine(alloc, out, "session named: {s}\n", .{arg});
            } else {
                const em = try report.cli(alloc, "name session", error.SessionDisabled);
                defer alloc.free(em);
                try out.writeAll(em);
            }
        },
        .login => {
            if (arg.len == 0) return .select_login;
            const req = parseAuthReq(arg, null) catch {
                const prov_name = if (std.mem.indexOfAny(u8, arg, " \t")) |i| arg[0..i] else arg;
                try writeTextLine(alloc, out, "unknown provider: {s}\n", .{prov_name});
                return .handled;
            };
            runLoginFlow(alloc, out, req, audit_hooks.auth()) catch |err| {
                const em = try report.cli(alloc, "login", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            return .handled;
        },
        .logout => {
            if (arg.len != 0) {
                const prov = parseAuthProvider(arg) orelse {
                    try writeTextLine(alloc, out, "unknown provider: {s}\n", .{arg});
                    return .handled;
                };
                core.providers.auth.logoutWithHooks(alloc, prov, audit_hooks.auth()) catch |err| {
                    const em = try report.cli(alloc, "logout", err);
                    defer alloc.free(em);
                    try out.writeAll(em);
                    return .handled;
                };
                try writeTextLine(alloc, out, "logged out of {s}\n", .{core.providers.auth.providerName(prov)});
                return .handled;
            }

            const logged_in = core.providers.auth.listLoggedIn(alloc) catch try alloc.alloc(core.providers.auth.Provider, 0);
            defer alloc.free(logged_in);
            if (logged_in.len == 0) {
                try out.writeAll("no providers logged in\n");
                return .handled;
            }

            const active_name = resolveDefaultProvider(provider.*);
            if (chooseLogoutProvider(active_name, logged_in)) |prov| {
                core.providers.auth.logoutWithHooks(alloc, prov, audit_hooks.auth()) catch |err| {
                    const em = try report.cli(alloc, "logout", err);
                    defer alloc.free(em);
                    try out.writeAll(em);
                    return .handled;
                };
                try writeTextLine(alloc, out, "logged out of {s}\n", .{core.providers.auth.providerName(prov)});
                return .handled;
            }
            return .select_logout;
        },
        .reload => return .reload,
        .share => {
            try runtimeCtlStart(ctl_audit, alloc, "share", .net, runtimeShareResName(), null, &.{});
            const session_dir = requireSessionDir(session_dir_path, no_session) catch {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "share",
                    .net,
                    runtimeShareResName(),
                    null,
                    .{ .text = @errorName(error.SessionDisabled), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "share session", error.SessionDisabled);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            var dir = try std.fs.cwd().openDir(session_dir, .{});
            defer dir.close();
            const md_path = core.session.@"export".toMarkdownAudited(alloc, dir, sid.*, null, exportAuditHooks(audit_hooks)) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "share",
                    .net,
                    runtimeShareResName(),
                    null,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "share session", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            defer alloc.free(md_path);
            const gist_url = audit_hooks.share_gist(alloc, md_path) catch |err| {
                try runtimeCtlFail(
                    ctl_audit,
                    alloc,
                    "share",
                    .net,
                    runtimeShareResName(),
                    null,
                    .{ .text = @errorName(err), .vis = .mask },
                    &.{},
                );
                const em = try report.cli(alloc, "publish gist", err);
                defer alloc.free(em);
                try out.writeAll(em);
                return .handled;
            };
            defer alloc.free(gist_url);
            const attrs = [_]core.audit.Attr{
                .{
                    .key = "url",
                    .vis = .mask,
                    .val = .{ .str = gist_url },
                },
            };
            try runtimeCtlSuccess(ctl_audit, alloc, "share", .net, runtimeShareResName(), null, &attrs);
            try writeTextLine(alloc, out, "shared: {s}\n", .{gist_url});
        },
        .changelog => {
            const cl = try changelog.formatForDisplay(alloc, 50);
            defer alloc.free(cl);
            try out.writeAll("[What's New]\n");
            try out.writeAll(cl);
            try out.writeAll("\n");
        },
    }
    return .handled;
}

fn runBgCommand(alloc: std.mem.Allocator, bg_mgr: *bg.Mgr, arg: []const u8) ![]u8 {
    const body = std.mem.trim(u8, arg, " \t");
    if (body.len == 0) {
        return alloc.dupe(u8, bg_usage);
    }

    const sp = std.mem.indexOfAny(u8, body, " \t");
    const sub = if (sp) |i| body[0..i] else body;
    const rest = if (sp) |i| std.mem.trim(u8, body[i + 1 ..], " \t") else "";

    switch (bg_sub_map.get(sub) orelse return alloc.dupe(u8, bg_usage)) {
        .run => {
            if (rest.len == 0) {
                return alloc.dupe(u8, "usage: /bg run <cmd>\n");
            }
            const id = try bg_mgr.start(rest, null);
            const v = (try bg_mgr.view(alloc, id)) orelse return error.InternalError;
            defer bg.deinitView(alloc, v);
            return std.fmt.allocPrint(alloc, "bg started id={d} pid={d} log={s}\n", .{
                v.id,
                v.pid,
                v.log_path,
            });
        },
        .list => {
            const jobs = try bg_mgr.list(alloc);
            defer bg.deinitViews(alloc, jobs);
            if (jobs.len == 0) return alloc.dupe(u8, "no background jobs\n");

            var out = std.ArrayList(u8).empty;
            errdefer out.deinit(alloc);
            try out.appendSlice(alloc, "id pid state code log cmd\n");
            for (jobs) |j| {
                const code = j.code orelse -1;
                const line = try std.fmt.allocPrint(alloc, "{d} {d} {s} {d} {s} {s}\n", .{
                    j.id,
                    j.pid,
                    bg.stateName(j.state),
                    code,
                    j.log_path,
                    j.cmd,
                });
                defer alloc.free(line);
                try out.appendSlice(alloc, line);
            }
            return out.toOwnedSlice(alloc);
        },
        .show => {
            const id = parseBgId(rest) catch return alloc.dupe(u8, "usage: /bg show <id>\n");
            const v = (try bg_mgr.view(alloc, id)) orelse return alloc.dupe(u8, "bg: not found\n");
            defer bg.deinitView(alloc, v);

            return std.fmt.allocPrint(alloc, "id={d}\npid={d}\nstate={s}\ncode={?d}\nstarted_ms={d}\nended_ms={?d}\nlog={s}\ncmd={s}\n", .{
                v.id,
                v.pid,
                bg.stateName(v.state),
                v.code,
                v.started_at_ms,
                v.ended_at_ms,
                v.log_path,
                v.cmd,
            });
        },
        .stop => {
            const id = parseBgId(rest) catch return alloc.dupe(u8, "usage: /bg stop <id>\n");
            const stop = try bg_mgr.stop(id);
            return switch (stop) {
                .sent => std.fmt.allocPrint(alloc, "bg stop sent id={d}\n", .{id}),
                .already_done => std.fmt.allocPrint(alloc, "bg already done id={d}\n", .{id}),
                .not_found => std.fmt.allocPrint(alloc, "bg not found id={d}\n", .{id}),
            };
        },
    }
}

fn parseBgId(text: []const u8) !u64 {
    const tok = std.mem.trim(u8, text, " \t");
    if (tok.len == 0) return error.InvalidId;
    return std.fmt.parseInt(u64, tok, 10);
}

fn flushBgDone(alloc: std.mem.Allocator, ui: *tui_harness.Ui, bg_mgr: *bg.Mgr) !void {
    const done = try bg_mgr.drainDone(alloc);
    defer bg.deinitViews(alloc, done);

    for (done) |job| {
        const msg = if (job.state == .wait_err)
            try std.fmt.allocPrint(alloc, "[bg {d} {s} err={s} log={s}]", .{
                job.id,
                bg.stateName(job.state),
                job.err_name orelse "",
                job.log_path,
            })
        else
            try std.fmt.allocPrint(alloc, "[bg {d} {s} code={?d} log={s}]", .{
                job.id,
                bg.stateName(job.state),
                job.code,
                job.log_path,
            });
        defer alloc.free(msg);
        try ui.tr.infoText(msg);
    }
    if (done.len > 0) ui.tr.scrollToBottom();
}

fn syncBgFooter(alloc: std.mem.Allocator, ui: *tui_harness.Ui, bg_mgr: *bg.Mgr) !void {
    const jobs = try bg_mgr.list(alloc);
    defer bg.deinitViews(alloc, jobs);

    const launched: u32 = @intCast(jobs.len);
    var running: u32 = 0;
    for (jobs) |job| {
        if (job.state == .running) running +%= 1;
    }
    const done: u32 = launched -| running;
    ui.panels.setBgStatus(launched, running, done);
}

fn maybeShowVersionUpdate(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    check: *version_check.Checker,
    done: *bool,
    out: std.Io.AnyWriter,
) !void {
    if (done.*) return;
    if (check.poll()) |new_ver| {
        const t = tui_theme.get();
        const ver_msg = try std.fmt.allocPrint(alloc, "Update available: {s}", .{new_ver});
        defer alloc.free(ver_msg);
        try ui.tr.styledText(ver_msg, .{ .fg = t.accent });
        try ui.tr.infoText("  /upgrade or pz --upgrade");
        try ui.tr.infoText("  https://github.com/joelreymont/pz/releases");
        try ui.draw(out);
        done.* = true;
        return;
    }
    if (check.isDone()) done.* = true;
}

fn shareGist(alloc: std.mem.Allocator, md_path: []const u8) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = alloc,
        .argv = &.{ "gh", "gist", "create", "--public=false", md_path },
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (result.term.Exited != 0) return error.GistFailed;
    const url = std.mem.trim(u8, result.stdout, " \t\n\r");
    if (url.len == 0) return error.GistFailed;
    return try alloc.dupe(u8, url);
}

fn writeJsonLine(
    alloc: std.mem.Allocator,
    out: std.Io.AnyWriter,
    value: anytype,
) !void {
    const raw = try std.json.Stringify.valueAlloc(alloc, value, .{});
    defer alloc.free(raw);
    try out.writeAll(raw);
    try out.writeAll("\n");
}

fn writeTextLine(
    alloc: std.mem.Allocator,
    out: std.Io.AnyWriter,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const raw = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(raw);
    try out.writeAll(raw);
}

fn listUserMessages(alloc: std.mem.Allocator, session_dir: []const u8, sid: []const u8) ![][]u8 {
    var dir = try std.fs.cwd().openDir(session_dir, .{});
    defer dir.close();

    var rdr = core.session.reader.ReplayReader.init(alloc, dir, sid, .{}) catch return try alloc.alloc([]u8, 0);
    defer rdr.deinit();

    var msgs = std.ArrayList([]u8).empty;
    errdefer {
        for (msgs.items) |m| alloc.free(m);
        msgs.deinit(alloc);
    }

    while (rdr.next() catch null) |ev| {
        if (ev.data == .prompt) {
            const text = ev.data.prompt.text;
            // Truncate to single line, max 80 chars for display
            const nl = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
            const end = @min(nl, 80);
            const display = if (end < text.len) blk: {
                const trimmed = try std.fmt.allocPrint(alloc, "{s}...", .{text[0..end]});
                break :blk trimmed;
            } else try alloc.dupe(u8, text);
            errdefer alloc.free(display);
            try msgs.append(alloc, display);
        }
    }
    return try msgs.toOwnedSlice(alloc);
}

fn applySettingsToggle(ui: *tui_harness.Ui, idx: usize, val: bool, auto_compact_on: *bool) void {
    const si: SettingIdx = @enumFromInt(idx);
    switch (si) {
        .show_tools => ui.tr.show_tools = val,
        .show_thinking => ui.tr.show_thinking = val,
        .auto_compact => auto_compact_on.* = val,
    }
}

const SettingIdx = enum(u8) {
    show_tools = 0,
    show_thinking = 1,
    auto_compact = 2,
};
const setting_labels = [_][]const u8{
    "Show tool output",
    "Show thinking",
    "Auto-compact",
};

fn buildSettingsOverlay(alloc: std.mem.Allocator, ui: *const tui_harness.Ui, auto_compact_on: bool) !tui_overlay.Overlay {
    const toggles = try alloc.alloc(bool, setting_labels.len);
    toggles[@intFromEnum(SettingIdx.show_tools)] = ui.tr.show_tools;
    toggles[@intFromEnum(SettingIdx.show_thinking)] = ui.tr.show_thinking;
    toggles[@intFromEnum(SettingIdx.auto_compact)] = auto_compact_on;
    return .{
        .items = &setting_labels,
        .title = "Settings",
        .kind = .settings,
        .toggles = toggles,
    };
}

fn startLiveTurnWithPrompt(
    live_turn: *LiveTurn,
    live_tctx: *const TurnCtx,
    ui: *tui_harness.Ui,
    sid: []const u8,
    prompt: []const u8,
    model: []const u8,
    provider_label: []const u8,
    popts: core.providers.Opts,
    sys_prompt: ?[]const u8,
    retried_overflow: *bool,
) !void {
    try live_turn.start(live_tctx, .{
        .sid = sid,
        .prompt = prompt,
        .model = model,
        .provider_label = provider_label,
        .provider_opts = popts,
        .system_prompt = sys_prompt,
    });
    retried_overflow.* = false;
    ui.panels.run_state = .streaming;
}

fn normalizeRpcCmd(raw: []const u8) []const u8 {
    const map = std.StaticStringMap([]const u8).initComptime(.{
        .{ "new_session", "new" },
        .{ "get_state", "session" },
        .{ "get_commands", "commands" },
        .{ "set_model", "model" },
        .{ "switch_session", "resume" },
        .{ "follow_up", "prompt" },
        .{ "steer", "prompt" },
    });
    return map.get(raw) orelse raw;
}

fn isSetModelAlias(raw: []const u8) bool {
    return set_model_alias_map.get(raw) != null;
}

const SessStats = struct {
    path: []const u8,
    path_owned: ?[]u8 = null,
    bytes: u64,
    lines: usize,
    user_msgs: u32 = 0,
    asst_msgs: u32 = 0,
    tool_calls: u32 = 0,
    tool_results: u32 = 0,
};

fn sessionStats(
    alloc: std.mem.Allocator,
    session_dir_path: ?[]const u8,
    sid: []const u8,
    no_session: bool,
) !SessStats {
    if (no_session or session_dir_path == null) {
        return .{
            .path = "",
            .bytes = 0,
            .lines = 0,
        };
    }

    const rel = try core.session.path.sidJsonlAlloc(alloc, sid);
    defer alloc.free(rel);
    const abs = try std.fs.path.join(alloc, &.{ session_dir_path.?, rel });
    errdefer alloc.free(abs);

    const f = std.fs.openFileAbsolute(abs, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => {
            return .{
                .path = abs,
                .path_owned = abs,
                .bytes = 0,
                .lines = 0,
            };
        },
        else => return err,
    };
    defer f.close();

    const st = try f.stat();
    var lines: usize = 0;
    var user_msgs: u32 = 0;
    var asst_msgs: u32 = 0;
    var tool_calls: u32 = 0;
    var tool_results: u32 = 0;
    // Replay once to count lines and message types.
    if (session_dir_path) |sdp| {
        var dir = std.fs.cwd().openDir(sdp, .{}) catch return .{
            .path = abs,
            .path_owned = abs,
            .bytes = st.size,
            .lines = lines,
        };
        defer dir.close();
        var rdr = core.session.ReplayReader.init(alloc, dir, sid, .{}) catch return .{
            .path = abs,
            .path_owned = abs,
            .bytes = st.size,
            .lines = lines,
        };
        defer rdr.deinit();
        while (true) {
            const ev = rdr.next() catch break;
            lines = rdr.line();
            const item = ev orelse break;
            switch (item.data) {
                .prompt => user_msgs += 1,
                .text => asst_msgs += 1,
                .tool_call => tool_calls += 1,
                .tool_result => tool_results += 1,
                else => {},
            }
        }
        lines = rdr.line();
    }

    return .{
        .path = abs,
        .path_owned = abs,
        .bytes = st.size,
        .lines = lines,
        .user_msgs = user_msgs,
        .asst_msgs = asst_msgs,
        .tool_calls = tool_calls,
        .tool_results = tool_results,
    };
}

fn parseCmdToolMask(raw: []const u8) !u16 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidToolMask;
    const special = std.StaticStringMap(u16).initComptime(.{
        .{ "all", core.tools.builtin.mask_all },
        .{ "none", 0 },
    });
    if (special.get(trimmed)) |m| return m;

    var mask: u16 = 0;
    var it = std.mem.splitScalar(u8, trimmed, ',');
    while (it.next()) |part_raw| {
        const part = std.mem.trim(u8, part_raw, " \t\r\n");
        if (part.len == 0) return error.InvalidToolMask;
        const bit = core.tools.builtin.maskForName(part) orelse return error.InvalidToolMask;
        if ((mask & bit) != 0) return error.InvalidToolMask;
        mask |= bit;
    }
    return mask;
}

const tui_cmdpicker = @import("../modes/tui/cmdpicker.zig");

fn completeSlashCmd(ed: *tui_harness.editor.Editor) void {
    const text = ed.text();
    if (text.len == 0 or text[0] != '/') return;
    const prefix = text[1..];
    var match: ?[]const u8 = null;
    var count: usize = 0;
    for (tui_cmdpicker.cmds) |cmd| {
        if (prefix.len <= cmd.name.len and std.mem.startsWith(u8, cmd.name, prefix)) {
            if (match == null) match = cmd.name;
            count += 1;
        }
    }
    if (count == 1) {
        if (match) |m| {
            const old_len = ed.buf.items.len;
            const old_cur = ed.cur;
            ed.buf.items.len = 0;
            ed.buf.appendSlice(ed.alloc, "/") catch {
                ed.buf.items.len = old_len;
                ed.cur = old_cur;
                return;
            };
            ed.buf.appendSlice(ed.alloc, m) catch {
                ed.buf.items.len = old_len;
                ed.cur = old_cur;
                return;
            };
            ed.buf.appendSlice(ed.alloc, " ") catch {
                ed.buf.items.len = old_len;
                ed.cur = old_cur;
                return;
            };
            ed.cur = ed.buf.items.len;
        }
    }
}

fn completeFilePath(alloc: std.mem.Allocator, ui: *tui_harness.Ui) !void {
    const text = ui.ed.text();
    const cur = ui.ed.cursor();
    if (cur == 0) return;

    const ws = ui.ed.wordStart(cur);
    const word = text[ws..cur];
    if (word.len == 0) return;

    // Strip @ prefix
    const has_at = word[0] == '@';
    const prefix = if (has_at) word[1..] else word;

    const items = tui_path_complete.list(alloc, prefix) orelse return;
    defer tui_path_complete.freeList(alloc, items);

    const repl: []const u8 = if (items.len == 1)
        items[0]
    else blk: {
        const cp = tui_path_complete.commonPrefix(tui_path_complete.asConst(items));
        if (cp.len <= prefix.len) return; // no progress
        break :blk cp;
    };

    // Build new text: before + [@] + replacement + after
    const at_s: []const u8 = if (has_at) "@" else "";
    const new_text = try std.fmt.allocPrint(alloc, "{s}{s}{s}{s}", .{
        text[0..ws], at_s, repl, text[cur..],
    });
    defer alloc.free(new_text);

    const new_cur = ws + at_s.len + repl.len;
    ui.ed.buf.items.len = 0;
    try ui.ed.buf.appendSlice(ui.ed.alloc, new_text);
    ui.ed.cur = new_cur;
}

fn toolMaskCsvAlloc(alloc: std.mem.Allocator, mask: u16) ![]u8 {
    if (mask == 0) return alloc.dupe(u8, "none");

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    const names = [_][]const u8{
        "read",
        "write",
        "bash",
        "edit",
        "grep",
        "find",
        "ls",
        "agent",
        "ask",
        "skill",
    };
    const bits = [_]u16{
        core.tools.builtin.mask_read,
        core.tools.builtin.mask_write,
        core.tools.builtin.mask_bash,
        core.tools.builtin.mask_edit,
        core.tools.builtin.mask_grep,
        core.tools.builtin.mask_find,
        core.tools.builtin.mask_ls,
        core.tools.builtin.mask_agent,
        core.tools.builtin.mask_ask,
        core.tools.builtin.mask_skill,
    };

    var need_sep = false;
    for (names, bits) |name, bit| {
        if ((mask & bit) == 0) continue;
        if (need_sep) try out.append(alloc, ',');
        try out.appendSlice(alloc, name);
        need_sep = true;
    }
    if (!need_sep) try out.appendSlice(alloc, "none");
    return try out.toOwnedSlice(alloc);
}

fn resolveResumeSid(
    alloc: std.mem.Allocator,
    session_dir: []const u8,
    token: ?[]const u8,
) ![]u8 {
    const plan = if (token) |tok|
        try core.session.selector.fromIdOrPrefix(alloc, session_dir, tok)
    else
        try core.session.selector.latestInDir(alloc, session_dir);
    defer alloc.free(plan.dir_path);
    return plan.sid;
}

const SessionOpErr = error{SessionDisabled};

fn requireSessionDir(session_dir_path: ?[]const u8, no_session: bool) SessionOpErr![]const u8 {
    if (no_session or session_dir_path == null) return error.SessionDisabled;
    return session_dir_path.?;
}

fn applyResumeSid(
    alloc: std.mem.Allocator,
    sid: *([]u8),
    session_dir_path: ?[]const u8,
    no_session: bool,
    token: ?[]const u8,
) (SessionOpErr || anyerror)!void {
    const dir = try requireSessionDir(session_dir_path, no_session);
    const next_sid = try resolveResumeSid(alloc, dir, token);
    alloc.free(sid.*);
    sid.* = next_sid;
}

fn mapSessionStopReason(reason: core.session.Event.StopReason) core.providers.StopReason {
    return switch (reason) {
        .done => .done,
        .max_out => .max_out,
        .tool => .tool,
        .canceled => .canceled,
        .err => .err,
    };
}

fn restoreSessionIntoUi(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    session_dir_path: ?[]const u8,
    no_session: bool,
    sid: []const u8,
) !void {
    const dir_path = try requireSessionDir(session_dir_path, no_session);
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();

    var rdr = try core.session.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    ui.clearTranscript();
    ui.panels.resetSessionView();

    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .noop => {},
            .prompt => |p| try ui.tr.userText(p.text),
            .text => |t| try ui.onProvider(.{ .text = t.text }),
            .thinking => |t| try ui.onProvider(.{ .thinking = t.text }),
            .tool_call => |tc| try ui.onProvider(.{ .tool_call = .{
                .id = tc.id,
                .name = tc.name,
                .args = tc.args,
            } }),
            .tool_result => |tr| try ui.onProvider(.{ .tool_result = .{
                .id = tr.id,
                .out = tr.out,
                .is_err = tr.is_err,
            } }),
            .usage => |u| try ui.onProvider(.{ .usage = .{
                .in_tok = u.in_tok,
                .out_tok = u.out_tok,
                .tot_tok = u.tot_tok,
                .cache_read = u.cache_read,
                .cache_write = u.cache_write,
            } }),
            .stop => |stop| try ui.onProvider(.{ .stop = .{
                .reason = mapSessionStopReason(stop.reason),
            } }),
            .err => |msg| try ui.onProvider(.{ .err = msg.text }),
        }
    }

    ui.panels.run_state = .idle;
    ui.tr.scrollToBottom();
}

fn tryRestoreSessionIntoUi(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    session_dir_path: ?[]const u8,
    no_session: bool,
    sid: []const u8,
) !bool {
    restoreSessionIntoUi(alloc, ui, session_dir_path, no_session, sid) catch |err| {
        const detail = try report.inlineMsg(alloc, err);
        defer alloc.free(detail);
        const msg = try std.fmt.allocPrint(alloc, "[resume restore failed: {s}]", .{detail});
        defer alloc.free(msg);
        try ui.tr.infoText(msg);
        return false;
    };
    return true;
}

fn applyForkSid(
    alloc: std.mem.Allocator,
    sid: *([]u8),
    session_dir_path: ?[]const u8,
    no_session: bool,
    token: ?[]const u8,
) (SessionOpErr || anyerror)!void {
    const dir = try requireSessionDir(session_dir_path, no_session);
    const next_sid = if (token) |raw| blk: {
        try core.session.path.validateSid(raw);
        break :blk try alloc.dupe(u8, raw);
    } else try newSid(alloc);
    errdefer alloc.free(next_sid);
    try forkSessionFile(dir, sid.*, next_sid);
    alloc.free(sid.*);
    sid.* = next_sid;
}

fn listSessionsAlloc(alloc: std.mem.Allocator, session_dir: []const u8) ![]u8 {
    var dir = try std.fs.cwd().openDir(session_dir, .{ .iterate = true });
    defer dir.close();

    var names = std.ArrayList([]u8).empty;
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var it = dir.iterate();
    while (try it.next()) |ent| {
        if (ent.kind != .file) continue;
        const sid = fileSidFromName(ent.name) orelse continue;
        const dup = try alloc.dupe(u8, sid);
        errdefer alloc.free(dup);
        try names.append(alloc, dup);
    }

    std.sort.pdq([]u8, names.items, {}, lessSid);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    for (names.items) |sid| {
        try out.appendSlice(alloc, sid);
        try out.append(alloc, '\n');
    }
    return try out.toOwnedSlice(alloc);
}

fn listSessionRows(alloc: std.mem.Allocator, session_dir: []const u8) ![]tui_overlay.Overlay.SessionRow {
    var dir = try std.fs.cwd().openDir(session_dir, .{ .iterate = true });
    defer dir.close();

    var names = std.ArrayList([]u8).empty;
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var it = dir.iterate();
    while (try it.next()) |ent| {
        if (ent.kind != .file) continue;
        const sid = fileSidFromName(ent.name) orelse continue;
        const dup = try alloc.dupe(u8, sid);
        errdefer alloc.free(dup);
        try names.append(alloc, dup);
    }

    std.sort.pdq([]u8, names.items, {}, lessSid);

    const rows = try alloc.alloc(tui_overlay.Overlay.SessionRow, names.items.len);
    errdefer {
        for (rows) |row| {
            if (row.sid.len > 0) alloc.free(row.sid);
            if (row.title.len > 0) alloc.free(row.title);
            if (row.time.len > 0) alloc.free(row.time);
            if (row.tokens.len > 0) alloc.free(row.tokens);
        }
        alloc.free(rows);
    }
    @memset(rows, .{
        .sid = &.{},
        .title = &.{},
        .time = &.{},
        .tokens = &.{},
    });

    const now_ms = std.time.milliTimestamp();
    for (names.items, 0..) |sid, idx| {
        rows[idx] = try buildSessionRow(alloc, dir, sid, now_ms);
    }
    return rows;
}

fn listSessionSids(alloc: std.mem.Allocator, session_dir: []const u8) ![][]u8 {
    var dir = try std.fs.cwd().openDir(session_dir, .{ .iterate = true });
    defer dir.close();

    var names = std.ArrayList([]u8).empty;
    errdefer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    var it = dir.iterate();
    while (try it.next()) |ent| {
        if (ent.kind != .file) continue;
        const sid = fileSidFromName(ent.name) orelse continue;
        const dup = try alloc.dupe(u8, sid);
        errdefer alloc.free(dup);
        try names.append(alloc, dup);
    }

    std.sort.pdq([]u8, names.items, {}, lessSid);
    return try names.toOwnedSlice(alloc);
}

fn lessSid(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn buildSessionRow(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    now_ms: i64,
) !tui_overlay.Overlay.SessionRow {
    var title: ?[]u8 = null;
    errdefer if (title) |t| alloc.free(t);
    var last_ms: i64 = 0;
    var tot_tok: u64 = 0;

    const path = try core.session.path.sidJsonlAlloc(alloc, sid);
    defer alloc.free(path);
    const st = try dir.statFile(path);
    if (st.size > 0) {
        var rdr = try core.session.ReplayReader.init(alloc, dir, sid, .{});
        defer rdr.deinit();

        while (try rdr.next()) |ev| {
            if (ev.at_ms > last_ms) last_ms = ev.at_ms;
            switch (ev.data) {
                .prompt => |p| {
                    if (title == null) title = try sessionTitleAlloc(alloc, p.text);
                },
                .usage => |u| tot_tok +|= u.tot_tok,
                else => {},
            }
        }
    }

    const sid_dup = try alloc.dupe(u8, sid);
    errdefer alloc.free(sid_dup);
    const row_title = if (title) |t| t else try alloc.dupe(u8, sid);
    errdefer if (title == null) alloc.free(row_title);
    const time = try formatSessionAgeAlloc(alloc, now_ms, last_ms);
    errdefer alloc.free(time);
    const tokens = try formatSessionTokensAlloc(alloc, tot_tok);
    errdefer alloc.free(tokens);

    return .{
        .sid = sid_dup,
        .title = row_title,
        .time = time,
        .tokens = tokens,
    };
}

fn sessionTitleAlloc(alloc: std.mem.Allocator, text: []const u8) !?[]u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return null;
    const line = if (std.mem.indexOfScalar(u8, trimmed, '\n')) |nl| trimmed[0..nl] else trimmed;
    const one = std.mem.trim(u8, line, " \t\r");
    if (one.len == 0) return null;
    return try alloc.dupe(u8, one);
}

fn formatSessionAgeAlloc(alloc: std.mem.Allocator, now_ms: i64, last_ms: i64) ![]u8 {
    if (last_ms <= 0 or last_ms >= now_ms) return alloc.dupe(u8, "now");

    const diff_ms: u64 = @intCast(now_ms - last_ms);
    const diff_min = diff_ms / (60 * std.time.ms_per_s);
    const diff_hour = diff_ms / (60 * 60 * std.time.ms_per_s);
    const diff_day = diff_ms / (24 * 60 * 60 * std.time.ms_per_s);

    if (diff_min < 1) return alloc.dupe(u8, "now");
    if (diff_min < 60) return std.fmt.allocPrint(alloc, "{d}m", .{diff_min});
    if (diff_hour < 24) return std.fmt.allocPrint(alloc, "{d}h", .{diff_hour});
    if (diff_day < 7) return std.fmt.allocPrint(alloc, "{d}d", .{diff_day});
    if (diff_day < 30) return std.fmt.allocPrint(alloc, "{d}w", .{diff_day / 7});
    if (diff_day < 365) return std.fmt.allocPrint(alloc, "{d}mo", .{diff_day / 30});
    return std.fmt.allocPrint(alloc, "{d}y", .{diff_day / 365});
}

fn formatSessionTokensAlloc(alloc: std.mem.Allocator, tot_tok: u64) ![]u8 {
    if (tot_tok >= 1_000_000) {
        return std.fmt.allocPrint(alloc, "{d}.{d}M tok", .{ tot_tok / 1_000_000, (tot_tok % 1_000_000) / 100_000 });
    }
    if (tot_tok >= 1000) {
        return std.fmt.allocPrint(alloc, "{d}.{d}k tok", .{ tot_tok / 1000, (tot_tok % 1000) / 100 });
    }
    return std.fmt.allocPrint(alloc, "{d} tok", .{tot_tok});
}

fn fileSidFromName(name: []const u8) ?[]const u8 {
    if (!std.mem.endsWith(u8, name, ".jsonl")) return null;
    if (name.len <= ".jsonl".len) return null;
    return name[0 .. name.len - ".jsonl".len];
}

fn forkSessionFile(session_dir: []const u8, src_sid: []const u8, dst_sid: []const u8) !void {
    var dir = try std.fs.cwd().openDir(session_dir, .{});
    defer dir.close();

    var src_buf: [256]u8 = undefined;
    const src_path = std.fmt.bufPrint(&src_buf, "{s}.jsonl", .{src_sid}) catch return error.NameTooLong;
    var dst_buf: [256]u8 = undefined;
    const dst_path = std.fmt.bufPrint(&dst_buf, "{s}.jsonl", .{dst_sid}) catch return error.NameTooLong;

    var dst = try dir.createFile(dst_path, .{
        .truncate = true,
    });
    defer dst.close();

    var src = dir.openFile(src_path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer src.close();

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try src.read(&buf);
        if (n == 0) break;
        try dst.writeAll(buf[0..n]);
    }
    try dst.sync();
}

fn newSid(alloc: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(alloc, "{d}", .{std.time.microTimestamp()});
}

fn resolveSessionPlan(alloc: std.mem.Allocator, run_cmd: cli.Run) !core.session.selector.Plan {
    return switch (run_cmd.session) {
        .auto => .{
            .sid = try newSid(alloc),
            .dir_path = try alloc.dupe(u8, run_cmd.cfg.session_dir),
        },
        .cont, .resm => core.session.selector.latestInDir(alloc, run_cmd.cfg.session_dir),
        .explicit => |raw| {
            if (isPathLike(raw)) return core.session.selector.fromPath(alloc, raw);
            return core.session.selector.fromIdOrPrefix(alloc, run_cmd.cfg.session_dir, raw);
        },
    };
}

fn getApprovalLocAlloc(alloc: std.mem.Allocator) !core.loop.CmdCache.Loc {
    if (runCmdTrimAlloc(alloc, &.{ "jj", "root" }, 4096)) |root| {
        return .{ .repo_root = root };
    }
    if (runCmdTrimAlloc(alloc, &.{ "git", "rev-parse", "--show-toplevel" }, 4096)) |root| {
        return .{ .repo_root = root };
    }
    return .{ .cwd = try std.fs.cwd().realpathAlloc(alloc, ".") };
}

fn freeApprovalLoc(alloc: std.mem.Allocator, loc: core.loop.CmdCache.Loc) void {
    switch (loc) {
        .cwd => |cwd| alloc.free(cwd),
        .repo_root => |root| alloc.free(root),
    }
}

fn loadApprovalBindAlloc(alloc: std.mem.Allocator) !core.policy.ApprovalBind {
    const cwd = try std.fs.cwd().realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    return core.policy.loadApprovalBind(alloc, cwd, std.posix.getenv("HOME"));
}

fn getProjectPath(alloc: std.mem.Allocator) ![]u8 {
    const loc = try getApprovalLocAlloc(alloc);
    defer freeApprovalLoc(alloc, loc);
    switch (loc) {
        .cwd => |cwd| return shortenHomePath(alloc, cwd),
        .repo_root => |root| return shortenHomePath(alloc, root),
    }
}

fn shortenHomePath(alloc: std.mem.Allocator, full: []const u8) ![]u8 {
    const home = std.posix.getenv("HOME") orelse "";
    if (home.len > 0 and std.mem.startsWith(u8, full, home)) {
        return std.fmt.allocPrint(alloc, "~{s}", .{full[home.len..]});
    }
    return alloc.dupe(u8, full);
}

fn getGitBranch(alloc: std.mem.Allocator) ![]u8 {
    if (getJjBranch(alloc)) |b| return b;

    if (runCmdTrimAlloc(alloc, &.{ "git", "branch", "--show-current" }, 512)) |branch| {
        return branch;
    }
    if (runCmdTrimAlloc(alloc, &.{ "git", "rev-parse", "--abbrev-ref", "HEAD" }, 512)) |branch| {
        if (!std.mem.eql(u8, branch, "HEAD")) return branch;
        alloc.free(branch);
    }

    const head = std.fs.cwd().readFileAlloc(alloc, ".git/HEAD", 256) catch return error.NotFound;
    defer alloc.free(head);
    const prefix = "ref: refs/heads/";
    if (std.mem.startsWith(u8, head, prefix)) {
        const rest = std.mem.trimRight(u8, head[prefix.len..], "\n\r ");
        return try alloc.dupe(u8, rest);
    }
    // Detached HEAD — show "detached" like pi
    return try alloc.dupe(u8, "detached");
}

fn getJjBranch(alloc: std.mem.Allocator) ?[]u8 {
    const current = runCmdTrimAlloc(alloc, &.{ "jj", "log", "--no-graph", "-r", "@", "-T", "bookmarks" }, 4096);
    if (current) |raw| {
        defer alloc.free(raw);
        if (parseJjBookmark(raw)) |name| {
            return alloc.dupe(u8, name) catch null;
        }
    }

    const parent = runCmdTrimAlloc(alloc, &.{ "jj", "log", "--no-graph", "-r", "@-", "-T", "bookmarks" }, 4096);
    if (parent) |raw| {
        defer alloc.free(raw);
        if (parseJjBookmark(raw)) |name| {
            return alloc.dupe(u8, name) catch null;
        }
    }

    return null;
}

fn parseJjBookmark(raw: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return null;

    var it = std.mem.splitScalar(u8, trimmed, ' ');
    const first = it.next() orelse return null;
    const name = if (first.len > 0 and first[first.len - 1] == '*')
        first[0 .. first.len - 1]
    else
        first;
    if (name.len == 0) return null;
    if (looksLikeHexCommit(name)) return null;
    return name;
}

fn looksLikeHexCommit(text: []const u8) bool {
    if (text.len < 12) return false;
    for (text) |c| {
        if ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')) {
            continue;
        }
        return false;
    }
    return true;
}

fn runCmdTrimAlloc(alloc: std.mem.Allocator, argv: []const []const u8, max_bytes: usize) ?[]u8 {
    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv,
        .max_output_bytes = max_bytes,
    }) catch return null;
    defer alloc.free(result.stderr);
    defer alloc.free(result.stdout);
    if (result.term.Exited != 0) return null;
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) return null;
    return alloc.dupe(u8, trimmed) catch null;
}

test "parseJjBookmark extracts first bookmark" {
    const got = parseJjBookmark("main feature") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("main", got);
}

test "parseJjBookmark strips working-copy marker" {
    const got = parseJjBookmark("trunk*") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("trunk", got);
}

test "parseJjBookmark rejects detached hash" {
    try std.testing.expect(parseJjBookmark("44693e6218c0b15a85acf5d2af52149b09dc4c76") == null);
}

test "parseNativeProviderKind resolves known native providers" {
    try std.testing.expectEqual(NativeProviderKind.anthropic, parseNativeProviderKind("anthropic").?);
    try std.testing.expectEqual(NativeProviderKind.openai, parseNativeProviderKind("openai").?);
    try std.testing.expect(parseNativeProviderKind("google") == null);
}

test "missingProviderMsgForInitErr is provider-specific" {
    try std.testing.expect(std.mem.indexOf(u8, missingProviderMsgForInitErr(.anthropic, error.AuthNotFound), "ANTHROPIC_API_KEY") != null);
    try std.testing.expect(std.mem.indexOf(u8, missingProviderMsgForInitErr(.openai, error.AuthNotFound), "OPENAI_API_KEY") != null);
}

const default_model = "claude-opus-4-6";
const default_provider = "anthropic";

fn resolveDefault(model: []const u8) []const u8 {
    return if (std.mem.eql(u8, model, "default")) default_model else model;
}

fn resolveDefaultProvider(provider: []const u8) []const u8 {
    return if (std.mem.eql(u8, provider, "default")) default_provider else provider;
}

fn modelCtxWindow(model: []const u8) u64 {
    const table = .{
        .{ "opus-4", 200000 },
        .{ "sonnet-4", 200000 },
        .{ "haiku-4", 200000 },
        .{ "claude-3-5", 200000 },
        .{ "claude-3.5", 200000 },
        .{ "claude-3-7", 200000 },
        .{ "claude-3.7", 200000 },
    };
    inline for (table) |entry| {
        if (std.mem.indexOf(u8, model, entry[0]) != null) return entry[1];
    }
    return 200000; // sensible default
}

fn isPathLike(raw: []const u8) bool {
    if (std.mem.endsWith(u8, raw, ".jsonl")) return true;
    if (std.mem.indexOfScalar(u8, raw, '/')) |_| return true;
    if (std.mem.indexOfScalar(u8, raw, '\\')) |_| return true;
    return false;
}

fn buildSystemPrompt(alloc: std.mem.Allocator, run_cmd: cli.Run) !?[]u8 {
    if (run_cmd.cfg.policy_lock.system_prompt and
        (run_cmd.system_prompt != null or run_cmd.append_system_prompt != null))
    {
        return error.PolicyLockedSystemPrompt;
    }
    if (run_cmd.cfg.policy_lock.context) {
        const paths = try core.context.discoverPaths(alloc);
        defer {
            for (paths) |p| alloc.free(p);
            alloc.free(paths);
        }
        if (paths.len > 0) return error.PolicyLockedContext;
    }
    if (run_cmd.system_prompt) |sp| {
        if (run_cmd.append_system_prompt) |ap| {
            return try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ sp, ap });
        }
        return try alloc.dupe(u8, sp);
    }

    const ctx = try core.context.load(alloc);
    if (run_cmd.append_system_prompt) |ap| {
        if (ctx) |c| {
            defer alloc.free(c);
            return try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ c, ap });
        }
        return try alloc.dupe(u8, ap);
    }
    return ctx;
}

const model_cycle = [_][]const u8{
    "claude-opus-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5-20251001",
};

const provider_args = [_][]const u8{ "anthropic", "openai", "google" };
const tool_args = [_][]const u8{ "all", "none", "read", "write", "bash", "edit", "grep", "find", "ls", "agent", "ask", "skill" };
const bg_args = [_][]const u8{ "run", "list", "show", "stop" };
const bg_usage = "usage: /bg run <cmd>|list|show <id>|stop <id>\n";
const BgSub = enum {
    run,
    list,
    show,
    stop,
};
const bg_sub_map = std.StaticStringMap(BgSub).initComptime(.{
    .{ "run", .run },
    .{ "list", .list },
    .{ "show", .show },
    .{ "stop", .stop },
});
const set_model_alias_map = std.StaticStringMap(void).initComptime(.{
    .{
        "set_model",
        {},
    },
});

const arg_src_kind_map = std.StaticStringMap(enum {
    model,
    provider,
    tools,
    bg,
    auth_provider,
}).initComptime(.{
    .{ "model", .model },
    .{ "provider", .provider },
    .{ "tools", .tools },
    .{ "bg", .bg },
    .{ "login", .auth_provider },
    .{ "logout", .auth_provider },
});

const provider_env_map = std.StaticStringMap([]const u8).initComptime(.{
    .{ "anthropic", "ANTHROPIC_API_KEY" },
    .{ "openai", "OPENAI_API_KEY" },
    .{ "google", "GOOGLE_API_KEY" },
});
const auth_provider_map = std.StaticStringMap(core.providers.auth.Provider).initComptime(.{
    .{ "anthropic", .anthropic },
    .{ "openai", .openai },
    .{ "google", .google },
});

fn parseAuthProvider(name: []const u8) ?core.providers.auth.Provider {
    return auth_provider_map.get(name);
}

const LoginInputKind = enum {
    api_key,
    oauth_start,
    oauth_complete,
};

fn classifyLoginInput(prov: core.providers.auth.Provider, key: []const u8) LoginInputKind {
    if (!core.providers.auth.oauthCapable(prov)) return .api_key;
    if (key.len == 0) return .oauth_start;
    if (core.providers.auth.looksLikeApiKey(prov, key)) return .api_key;
    return .oauth_complete;
}

fn hasLoggedInProvider(
    logged_in: []const core.providers.auth.Provider,
    provider: core.providers.auth.Provider,
) bool {
    for (logged_in) |p| if (p == provider) return true;
    return false;
}

fn chooseLogoutProvider(
    active_name: []const u8,
    logged_in: []const core.providers.auth.Provider,
) ?core.providers.auth.Provider {
    if (parseAuthProvider(active_name)) |active| {
        if (hasLoggedInProvider(logged_in, active)) return active;
    }
    if (logged_in.len == 1) return logged_in[0];
    return null;
}

/// Resolve arg completion source based on current editor text.
fn resolveArgSrc(text: []const u8, models: []const []const u8) ?[]const []const u8 {
    if (text.len == 0 or text[0] != '/') return null;
    const body = text[1..];
    const sp = std.mem.indexOfScalar(u8, body, ' ') orelse return null;
    const cmd = body[0..sp];
    const kind = arg_src_kind_map.get(cmd) orelse return null;
    return switch (kind) {
        .model => models,
        .provider, .auth_provider => &provider_args,
        .tools => &tool_args,
        .bg => &bg_args,
    };
}

fn cycleModel(alloc: std.mem.Allocator, cur: []const u8, model_owned: *?[]u8, cycle: []const []const u8) ![]const u8 {
    if (cycle.len == 0) return cur;
    var next_idx: usize = 0;
    for (cycle, 0..) |m, i| {
        if (std.mem.eql(u8, cur, m)) {
            next_idx = (i + 1) % cycle.len;
            break;
        }
    } else {
        next_idx = 0;
    }
    const new = try alloc.dupe(u8, cycle[next_idx]);
    if (model_owned.*) |old| alloc.free(old);
    model_owned.* = new;
    return new;
}

fn reverseCycleModel(alloc: std.mem.Allocator, cur: []const u8, model_owned: *?[]u8, cycle: []const []const u8) ![]const u8 {
    if (cycle.len == 0) return cur;
    var next_idx: usize = cycle.len - 1;
    for (cycle, 0..) |m, i| {
        if (std.mem.eql(u8, cur, m)) {
            next_idx = if (i == 0) cycle.len - 1 else i - 1;
            break;
        }
    }
    const new = try alloc.dupe(u8, cycle[next_idx]);
    if (model_owned.*) |old| alloc.free(old);
    model_owned.* = new;
    return new;
}

fn cycleThinking(cur: args_mod.ThinkingLevel) args_mod.ThinkingLevel {
    return switch (cur) {
        .adaptive => .off,
        .off => .minimal,
        .minimal => .low,
        .low => .medium,
        .medium => .high,
        .high => .xhigh,
        .xhigh => .adaptive,
    };
}

fn thinkingLabel(level: args_mod.ThinkingLevel) []const u8 {
    return @tagName(level);
}

fn thinkingBorderFg(level: args_mod.ThinkingLevel) @import("../modes/tui/frame.zig").Color {
    const t = tui_theme.get();
    return switch (level) {
        .off => t.thinking_off,
        .minimal => t.thinking_min,
        .low => t.thinking_low,
        .medium => t.thinking_med,
        .high => t.thinking_high,
        .xhigh => t.thinking_xhigh,
        .adaptive => t.thinking_med,
    };
}

fn showStartup(alloc: std.mem.Allocator, ui: *tui_harness.Ui, is_resumed: bool) !void {
    const t = tui_theme.get();

    // Version banner (matching pi's "pi v0.52.12")
    const ver_line = " pz v" ++ cli.version ++ " (" ++ cli.git_hash ++ ")";
    try ui.tr.styledText(ver_line, .{ .fg = t.dim });

    // Hotkeys — key in dim, description in muted
    const keys = [_][2][]const u8{
        .{ "escape", "to interrupt" },
        .{ "ctrl+c", "to clear" },
        .{ "ctrl+c twice", "to exit" },
        .{ "ctrl+d", "to exit (empty)" },
        .{ "ctrl+z", "to undo" },
        .{ "up/down", "for input history" },
        .{ "ctrl+a/e", "to start/end of line" },
        .{ "ctrl+j", "to insert newline" },
        .{ "ctrl+k/u", "to delete to end/all" },
        .{ "ctrl+w", "to delete word" },
        .{ "alt+b/f", "to move by word" },
        .{ "shift+tab", "to cycle thinking level" },
        .{ "ctrl+p/shift+ctrl+p", "to cycle models" },
        .{ "ctrl+l", "to select model" },
        .{ "ctrl+o", "to expand tools" },
        .{ "ctrl+t", "to expand thinking" },
        .{ "ctrl+g", "for external editor" },
        .{ "/", "for commands" },
        .{ "!", "to run bash" },
        .{ "!!", "to run bash (no context)" },
        .{ "alt+enter", "to queue follow-up" },
        .{ "alt+up", "to restore queued messages" },
        .{ "ctrl+v", "to paste image" },
        .{ "shift+drag", "to select text" },
        .{ "drop files", "to attach" },
    };
    for (keys) |kv| {
        // key in dim, description in muted (matching pi)
        const line = try std.fmt.allocPrint(alloc, " \x1b[38;2;102;102;102m{s}\x1b[38;2;128;128;128m {s}\x1b[0m", .{ kv[0], kv[1] });
        defer alloc.free(line);
        try ui.tr.pushAnsiText(line);
    }

    // Context section
    const ctx_paths = try core.context.discoverPaths(alloc);
    defer {
        for (ctx_paths) |p| alloc.free(p);
        alloc.free(ctx_paths);
    }
    if (ctx_paths.len > 0) {
        try ui.tr.styledText("", .{}); // blank line
        try ui.tr.styledText("", .{}); // blank line (pi has 2)
        try ui.tr.styledText("[Context]", .{ .fg = t.md_heading });
        const home = std.posix.getenv("HOME") orelse "";
        for (ctx_paths) |p| {
            // Shorten home prefix to ~/
            const display = if (home.len > 0 and std.mem.startsWith(u8, p, home))
                try std.fmt.allocPrint(alloc, "  ~{s}", .{p[home.len..]})
            else
                try std.fmt.allocPrint(alloc, "  {s}", .{p});
            defer alloc.free(display);
            try ui.tr.infoText(display);
        }
    }

    // Skills section
    const skills = try discoverSkills(alloc);
    defer core_skill.freeSkills(alloc, skills);
    if (skills.len > 0) {
        try ui.tr.styledText("", .{}); // blank line
        try ui.tr.styledText("[Skills]", .{ .fg = t.md_heading });
        for (skills) |skill| {
            const display = if (skill.meta.description.len > 0)
                try std.fmt.allocPrint(alloc, "  {s} [{s}] - {s}", .{
                    skill.dir_name,
                    skillSourceName(skill.source),
                    skill.meta.description,
                })
            else
                try std.fmt.allocPrint(alloc, "  {s} [{s}]", .{
                    skill.dir_name,
                    skillSourceName(skill.source),
                });
            defer alloc.free(display);
            try ui.tr.infoText(display);
        }
    }

    // What's New section (only on fresh sessions)
    if (!is_resumed) {
        var state = config.PzState.load(alloc) orelse config.PzState{};
        defer state.deinit(alloc);

        const new_entries = changelog.entriesSince(state.last_hash);
        if (new_entries.len > 0) {
            const formatted = try changelog.formatRaw(alloc, new_entries, 10);
            defer alloc.free(formatted);
            try ui.tr.styledText("", .{}); // blank line
            try ui.tr.styledText("[What's New]", .{ .fg = t.md_heading });
            // Split and display each line
            var off: usize = 0;
            while (off < formatted.len) {
                const eol = std.mem.indexOfScalarPos(u8, formatted, off, '\n') orelse formatted.len;
                try ui.tr.infoText(formatted[off..eol]);
                off = eol + 1;
            }
        }

        // Update state with current git hash
        const new_state = config.PzState{ .last_hash = cli.git_hash };
        new_state.save(alloc);
    }

    // Trailing blank lines before prompt (matching pi's spacing)
    try ui.tr.styledText("", .{});
    try ui.tr.styledText("", .{});
}

fn discoverSkills(alloc: std.mem.Allocator) ![]core_skill.SkillInfo {
    const skills = try core_skill.discoverAndRead(alloc);
    std.mem.sort(core_skill.SkillInfo, skills, {}, struct {
        fn lt(_: void, a: core_skill.SkillInfo, b: core_skill.SkillInfo) bool {
            return std.mem.lessThan(u8, a.dir_name, b.dir_name);
        }
    }.lt);
    return skills;
}

fn skillSourceName(source: core_skill.Source) []const u8 {
    return switch (source) {
        .global => "global",
        .project => "project",
    };
}

fn infoTextSafe(alloc: std.mem.Allocator, ui: *tui_harness.Ui, text: []const u8) !void {
    ui.tr.infoText(text) catch |err| switch (err) {
        error.InvalidUtf8 => {
            const safe = try sanitizeUtf8LossyAlloc(alloc, text);
            defer alloc.free(safe);
            try ui.tr.infoText(safe);
        },
        else => return err,
    };
}

fn sanitizeUtf8LossyAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (std.unicode.Utf8View.init(raw)) |_| {
        return alloc.dupe(u8, raw);
    } else |_| {}

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var i: usize = 0;
    while (i < raw.len) {
        const n = std.unicode.utf8ByteSequenceLength(raw[i]) catch {
            try out.append(alloc, '?');
            i += 1;
            continue;
        };
        if (i + n > raw.len) {
            try out.append(alloc, '?');
            break;
        }
        _ = std.unicode.utf8Decode(raw[i .. i + n]) catch {
            try out.append(alloc, '?');
            i += 1;
            continue;
        };
        try out.appendSlice(alloc, raw[i .. i + n]);
        i += n;
    }
    return out.toOwnedSlice(alloc);
}

fn showCost(_: std.mem.Allocator, ui: *tui_harness.Ui) !void {
    const u = ui.panels.usage;
    const mc = ui.panels.cost_micents;

    // Format cost as $N.NNN
    var cost_buf: [24]u8 = undefined;
    const cost_str = if (mc > 0)
        std.fmt.bufPrint(&cost_buf, "${d}.{d:0>3}", .{ mc / 100_000, (mc % 100_000) / 100 }) catch "?"
    else
        "$0.000";

    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const w = fbs.writer();
    try w.print("Tokens  in: {d}  out: {d}  total: {d}", .{ u.in_tok, u.out_tok, u.tot_tok });
    if (u.cache_read > 0 or u.cache_write > 0)
        try w.print("\nCache   read: {d}  write: {d}", .{ u.cache_read, u.cache_write });
    try w.print("\nCost    {s}", .{cost_str});
    try ui.tr.infoText(fbs.getWritten());
}

fn copyLastResponse(alloc: std.mem.Allocator, ui: *tui_harness.Ui) !void {
    const text = ui.lastResponseText() orelse {
        try ui.tr.infoText("[nothing to copy]");
        return;
    };
    const clip_cmds = [_][]const u8{ "pbcopy", "xclip", "xsel", "wl-copy" };
    for (clip_cmds) |cmd| {
        if (try pipeToCmd(alloc, cmd, text)) {
            try ui.tr.infoText("[copied to clipboard]");
            return;
        }
    }
    try ui.tr.infoText("[copy failed: no clipboard tool found]");
}

fn pipeToCmd(alloc: std.mem.Allocator, cmd: []const u8, text: []const u8) !bool {
    const argv = [_][]const u8{cmd};
    var child = std.process.Child.init(argv[0..], alloc);
    child.stdin_behavior = .Pipe;
    child.spawn() catch return false;
    if (child.stdin) |*stdin| {
        try stdin.writeAll(text);
        stdin.close();
        child.stdin = null;
    }
    const term = child.wait() catch return false;
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

const compact_threshold_pct: u32 = 80;

fn shouldRetryOverflow(
    alloc: std.mem.Allocator,
    live: *const LiveTurn,
    model: []const u8,
    retried: bool,
) bool {
    return shouldRetryOverflowState(alloc, live.last_model, live.last_stop, live.last_err, model, retried);
}

fn shouldRetryOverflowState(
    alloc: std.mem.Allocator,
    last_model: ?[]const u8,
    last_stop: ?core.providers.StopReason,
    last_err: ?[]const u8,
    model: []const u8,
    retried: bool,
) bool {
    if (retried) return false;
    if (last_model) |prev_model| {
        if (!std.mem.eql(u8, prev_model, model)) return false;
    } else return false;
    if (last_stop == .max_out) return true;
    if (last_err) |err_text| {
        return core.providers.types.isOverflowError(alloc, err_text);
    }
    return false;
}

const CompactRun = union(enum) {
    compacted,
    stopped: prov_contract.SummaryMeta,
};

const AutoCompactOutcome = enum {
    skipped,
    compacted,
    stopped,
    failed,
};

const CompactFn = *const fn (
    ctx: ?*anyopaque,
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    now: i64,
) anyerror!CompactRun;

fn compactNow(
    _: ?*anyopaque,
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    now: i64,
) !CompactRun {
    _ = try core.session.compactSession(alloc, dir, sid, now);
    return .compacted;
}

fn formatCompactStopAlloc(alloc: std.mem.Allocator, meta: prov_contract.SummaryMeta) ![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "[auto-compact stopped: summary input over budget bytes={d}/{d} tokens={d}/{d} kept={d} dropped={d}]",
        .{
            meta.input_bytes,
            meta.max_bytes,
            meta.input_tokens,
            meta.max_input_tokens,
            meta.kept_events,
            meta.dropped_events,
        },
    );
}

fn autoCompact(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    out: std.Io.AnyWriter,
    sid: []const u8,
    session_dir_path: ?[]const u8,
    no_session: bool,
    force: bool,
) !AutoCompactOutcome {
    return autoCompactWith(alloc, ui, out, sid, session_dir_path, no_session, force, null, compactNow);
}

fn autoCompactWith(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    out: std.Io.AnyWriter,
    sid: []const u8,
    session_dir_path: ?[]const u8,
    no_session: bool,
    force: bool,
    compact_ctx: ?*anyopaque,
    compact_fn: CompactFn,
) !AutoCompactOutcome {
    if (no_session or session_dir_path == null) return .skipped;
    if (!force) {
        if (ui.panels.ctx_limit == 0) return .skipped;
        if (!ui.panels.has_usage) return .skipped;
        const pct = ui.panels.cum_tok *| 100 / ui.panels.ctx_limit;
        if (pct < compact_threshold_pct) return .skipped;
    }

    try ui.tr.infoText("[compacting...]");
    try ui.draw(out);

    var dir = try std.fs.cwd().openDir(session_dir_path.?, .{});
    defer dir.close();
    const now = std.time.milliTimestamp();
    const res = compact_fn(compact_ctx, alloc, dir, sid, now) catch |err| {
        const detail = try report.inlineMsg(alloc, err);
        defer alloc.free(detail);
        const msg = try std.fmt.allocPrint(alloc, "[auto-compact failed: {s}]", .{detail});
        defer alloc.free(msg);
        try ui.tr.infoText(msg);
        return .failed;
    };
    switch (res) {
        .compacted => {
            ui.panels.noteCompaction();
            try ui.tr.infoText("[session compacted]");
            return .compacted;
        },
        .stopped => |meta| {
            const msg = try formatCompactStopAlloc(alloc, meta);
            defer alloc.free(msg);
            try ui.tr.infoText(msg);
            return .stopped;
        },
    }
}

fn syncInputFooter(ui: *tui_harness.Ui, mode: tui_panels.InputMode, queued_len: usize) void {
    const max_u32 = std.math.maxInt(u32);
    const queued: u32 = if (queued_len > max_u32) max_u32 else @intCast(queued_len);
    ui.panels.setInputStatus(mode, queued);
}

const PendingKind = enum {
    steering,
    follow_up,
};

const PendingTurn = struct {
    kind: PendingKind,
    text: []u8,
};

const PendingQueue = struct {
    steering: std.ArrayListUnmanaged([]u8) = .empty,
    follow_up: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *PendingQueue, alloc: std.mem.Allocator) void {
        clearQueueSlice(alloc, &self.steering);
        clearQueueSlice(alloc, &self.follow_up);
        self.steering.deinit(alloc);
        self.follow_up.deinit(alloc);
    }

    fn total(self: *const PendingQueue) usize {
        return self.steering.items.len + self.follow_up.items.len;
    }

    fn pushSteering(self: *PendingQueue, alloc: std.mem.Allocator, text: []const u8) !void {
        try queueMessage(alloc, &self.steering, text);
    }

    fn pushFollowUp(self: *PendingQueue, alloc: std.mem.Allocator, text: []const u8) !void {
        try queueMessage(alloc, &self.follow_up, text);
    }

    fn popNext(self: *PendingQueue) ?PendingTurn {
        if (self.steering.items.len > 0) {
            return .{
                .kind = .steering,
                .text = self.steering.orderedRemove(0),
            };
        }
        if (self.follow_up.items.len > 0) {
            return .{
                .kind = .follow_up,
                .text = self.follow_up.orderedRemove(0),
            };
        }
        return null;
    }

    fn restoreToEditor(self: *PendingQueue, alloc: std.mem.Allocator, ui: *tui_harness.Ui) !usize {
        const queued_ct = self.total();
        if (queued_ct == 0) return 0;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(alloc);

        var first = true;
        for (self.steering.items) |msg| {
            if (!first) try out.appendSlice(alloc, "\n\n");
            first = false;
            try out.appendSlice(alloc, msg);
        }
        for (self.follow_up.items) |msg| {
            if (!first) try out.appendSlice(alloc, "\n\n");
            first = false;
            try out.appendSlice(alloc, msg);
        }
        const cur = ui.editorText();
        if (cur.len > 0) {
            if (!first) try out.appendSlice(alloc, "\n\n");
            try out.appendSlice(alloc, cur);
        }

        try ui.ed.setText(out.items);
        ui.updatePreview();
        clearQueueSlice(alloc, &self.steering);
        clearQueueSlice(alloc, &self.follow_up);
        return queued_ct;
    }
};

fn queueMessage(
    alloc: std.mem.Allocator,
    queue: *std.ArrayListUnmanaged([]u8),
    text: []const u8,
) !void {
    if (text.len == 0) return;
    const queued = try alloc.dupe(u8, text);
    errdefer alloc.free(queued);
    try queue.append(alloc, queued);
}

fn queueFollowup(
    alloc: std.mem.Allocator,
    queue: *std.ArrayListUnmanaged([]u8),
    text: []const u8,
) !void {
    try queueMessage(alloc, queue, text);
}

fn clearQueueSlice(alloc: std.mem.Allocator, queue: *std.ArrayListUnmanaged([]u8)) void {
    for (queue.items) |item| alloc.free(item);
    queue.items.len = 0;
}

fn showLogoutOverlay(alloc: std.mem.Allocator, ui: *tui_harness.Ui, providers: []const core.providers.auth.Provider) !bool {
    if (providers.len == 0) return false;
    const names = try alloc.alloc([]u8, providers.len);
    for (names) |*n| n.len = 0;
    errdefer {
        for (names) |n| if (n.len > 0) alloc.free(n);
        alloc.free(names);
    }
    for (providers, 0..) |p, i| {
        names[i] = try alloc.dupe(u8, core.providers.auth.providerName(p));
    }
    ui.ov = tui_overlay.Overlay.initDyn(alloc, names, "Logout", .logout);
    return true;
}

fn showResumeOverlay(alloc: std.mem.Allocator, ui: *tui_harness.Ui, session_dir_path: ?[]const u8) !bool {
    const sdp = session_dir_path orelse return false;
    const rows = listSessionRows(alloc, sdp) catch return false;
    if (rows.len == 0) {
        alloc.free(rows);
        return false;
    }
    ui.ov = tui_overlay.Overlay.initSession(rows, "Resume Session");
    return true;
}

fn shouldQueueSubmit(text: []const u8) bool {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (trimmed[0] == '/') return false;
    return parseBashCmd(trimmed) == null;
}

fn showQueueOverlay(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    queue: []const []const u8,
) !bool {
    if (queue.len == 0) return false;

    const items = try alloc.alloc([]u8, queue.len);
    errdefer alloc.free(items);
    var filled: usize = 0;
    errdefer {
        for (items[0..filled]) |it| alloc.free(it);
    }

    for (queue, 0..) |msg, idx| {
        items[idx] = try queueItemLabel(alloc, idx, msg);
        filled = idx + 1;
    }

    var ov = tui_overlay.Overlay.initDyn(alloc, items, "Queued Messages", .queue);
    ov.hint = "Up/Down select, Enter edit, Esc close";
    ui.ov = ov;
    return true;
}

fn dequeueQueuedIntoEditor(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    queue: *std.ArrayListUnmanaged([]u8),
    idx: usize,
) !bool {
    if (idx >= queue.items.len) return false;
    const msg = queue.orderedRemove(idx);
    defer alloc.free(msg);
    try ui.ed.setText(msg);
    ui.updatePreview();
    return true;
}

fn queueItemLabel(alloc: std.mem.Allocator, idx: usize, msg: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, msg, " \t\r\n");
    const source = if (trimmed.len > 0) trimmed else msg;
    var one_line = source;
    var has_more = false;
    if (std.mem.indexOfScalar(u8, source, '\n')) |nl| {
        one_line = source[0..nl];
        has_more = true;
    }
    const clip = utf8Prefix(one_line, 56);
    if (clip.truncated) has_more = true;
    const suffix = if (has_more) " ..." else "";
    if (clip.text.len == 0) {
        return std.fmt.allocPrint(alloc, "#{d} (empty)", .{idx + 1});
    }
    return std.fmt.allocPrint(alloc, "#{d} {s}{s}", .{ idx + 1, clip.text, suffix });
}

const Utf8Clip = struct {
    text: []const u8,
    truncated: bool,
};

fn utf8Prefix(text: []const u8, max_cp: usize) Utf8Clip {
    if (max_cp == 0 or text.len == 0) return .{ .text = text[0..0], .truncated = text.len > 0 };
    var i: usize = 0;
    var count: usize = 0;
    while (i < text.len and count < max_cp) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch break;
        if (i + n > text.len) break;
        _ = std.unicode.utf8Decode(text[i .. i + n]) catch break;
        i += n;
        count += 1;
    }
    return .{
        .text = text[0..i],
        .truncated = i < text.len,
    };
}

const BashCmd = struct {
    cmd: []const u8,
    include: bool, // true = !cmd (include in context), false = !!cmd (exclude)
};

fn noteSessionWriteErr(ui: *tui_harness.Ui, msg: []const u8) !void {
    const note = try std.fmt.allocPrint(ui.alloc, "[session write failed: {s}]", .{msg});
    defer ui.alloc.free(note);
    try ui.tr.infoText(note);
}

fn appendSessionOrNote(
    ui: *tui_harness.Ui,
    sid: []const u8,
    store: core.session.SessionStore,
    ev: core.session.Event,
) !bool {
    store.append(sid, ev) catch |append_err| {
        try noteSessionWriteErr(ui, @errorName(append_err));
        return false;
    };
    return true;
}

fn parseBashCmd(text: []const u8) ?BashCmd {
    if (text.len < 2 or text[0] != '!') return null;
    if (text[1] == '!') {
        const cmd = std.mem.trim(u8, text[2..], " \t");
        if (cmd.len == 0) return null;
        return .{ .cmd = cmd, .include = false };
    }
    const cmd = std.mem.trim(u8, text[1..], " \t");
    if (cmd.len == 0) return null;
    return .{ .cmd = cmd, .include = true };
}

fn runBashMode(
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    bcmd: BashCmd,
    sid: []const u8,
    store: core.session.SessionStore,
) !void {
    if (try core.tools.bash.deniesProtectedCmd(alloc, bcmd.cmd)) {
        try ui.tr.append(.{ .tool_call = .{
            .id = "bash",
            .name = "bash",
            .args = bcmd.cmd,
        } });
        try ui.tr.append(.{ .tool_result = .{
            .id = "bash",
            .out = "bash denied: protected path",
            .is_err = true,
        } });

        if (bcmd.include) {
            _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .prompt = .{ .text = bcmd.cmd } } });
            _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .tool_call = .{
                .id = "bash",
                .name = "bash",
                .args = bcmd.cmd,
            } } });
            _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .tool_result = .{
                .id = "bash",
                .out = "bash denied: protected path",
                .is_err = true,
            } } });
        }
        return;
    }

    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = &.{ "/bin/bash", "-lc", bcmd.cmd },
        .max_output_bytes = 256 * 1024,
    }) catch |err| {
        const detail = try report.inlineMsg(alloc, err);
        defer alloc.free(detail);
        const msg = try std.fmt.allocPrint(alloc, "bash error: {s}", .{detail});
        defer alloc.free(msg);
        try ui.tr.append(.{ .err = msg });
        return;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    const output = if (result.stdout.len > 0) result.stdout else result.stderr;
    const is_err = switch (result.term) {
        .Exited => |code| code != 0,
        else => true,
    };

    // Show in transcript
    try ui.tr.append(.{ .tool_call = .{
        .id = "bash",
        .name = "bash",
        .args = bcmd.cmd,
    } });
    try ui.tr.append(.{ .tool_result = .{
        .id = "bash",
        .out = if (output.len > 0) output else "(no output)",
        .is_err = is_err,
    } });

    // Save to session if include mode
    if (bcmd.include) {
        _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .prompt = .{ .text = bcmd.cmd } } });
        _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .tool_call = .{
            .id = "bash",
            .name = "bash",
            .args = bcmd.cmd,
        } } });
        _ = try appendSessionOrNote(ui, sid, store, .{ .data = .{ .tool_result = .{
            .id = "bash",
            .out = if (output.len > 0) output else "(no output)",
            .is_err = is_err,
        } } });
    }
}

fn openExtEditor(alloc: std.mem.Allocator, current: []const u8) !?[]u8 {
    const ed = std.posix.getenv("EDITOR") orelse std.posix.getenv("VISUAL") orelse "vi";

    // Write current text to unique temp file
    var tmp_buf: [64]u8 = undefined;
    const ts: u64 = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())));
    const tmp = try std.fmt.bufPrint(&tmp_buf, "/tmp/pz-edit-{d}.txt", .{ts});
    defer std.fs.deleteFileAbsolute(tmp) catch |err| {
        std.debug.print("warning: temp file cleanup failed: {s}\n", .{@errorName(err)});
    };
    {
        const f = try std.fs.createFileAbsolute(tmp, .{});
        defer f.close();
        try f.writeAll(current);
    }

    const argv = [_][]const u8{ ed, tmp };
    var child = std.process.Child.init(argv[0..], alloc);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    _ = try child.wait();

    // Read back
    const f = try std.fs.openFileAbsolute(tmp, .{});
    defer f.close();
    const content = try f.readToEndAlloc(alloc, 1024 * 1024);
    // Trim trailing newline
    var len = content.len;
    while (len > 0 and (content[len - 1] == '\n' or content[len - 1] == '\r')) len -= 1;
    if (len == 0) {
        alloc.free(content);
        return null;
    }
    if (len < content.len) {
        const trimmed = try alloc.dupe(u8, content[0..len]);
        alloc.free(content);
        return trimmed;
    }
    return content;
}

fn pasteImage(alloc: std.mem.Allocator, ui: *tui_harness.Ui) !void {
    // macOS: check clipboard for image via osascript
    const argv = [_][]const u8{
        "osascript",                                                                                                     "-e",
        "try\nset theType to (clipboard info for «class PNGf»)\nreturn \"image\"\non error\nreturn \"none\"\nend try",
    };
    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv[0..],
        .max_output_bytes = 256,
    }) catch {
        try ui.tr.infoText("[paste: clipboard check failed]");
        return;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (!std.mem.eql(u8, trimmed, "image")) {
        try pasteText(alloc, ui);
        return;
    }

    // Save clipboard image to temp file
    const save_argv = [_][]const u8{
        "osascript",                                                                                                                                                              "-e",
        "set imgData to the clipboard as «class PNGf»\nset fp to open for access POSIX file \"/tmp/pz-paste.png\" with write permission\nwrite imgData to fp\nclose access fp",
    };
    const save_result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = save_argv[0..],
        .max_output_bytes = 256,
    }) catch {
        try ui.tr.infoText("[paste: save failed]");
        return;
    };
    defer alloc.free(save_result.stdout);
    defer alloc.free(save_result.stderr);

    ui.tr.imageBlock("/tmp/pz-paste.png") catch |err| {
        ui.tr.infoText("[pasted image: /tmp/pz-paste.png]") catch return err;
    };
}

fn pasteText(alloc: std.mem.Allocator, ui: *tui_harness.Ui) !void {
    const argv = [_][]const u8{"pbpaste"};
    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv[0..],
        .max_output_bytes = 256 * 1024,
    }) catch {
        try ui.tr.infoText("[paste failed]");
        return;
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    if (result.stdout.len > 0) {
        ui.ed.insertSlice(result.stdout) catch |err| {
            ui.tr.infoText("[paste: invalid UTF-8]") catch return err;
        };
    }
}

const TurnCtx = struct {
    alloc: std.mem.Allocator,
    provider: core.providers.Provider,
    store: core.session.SessionStore,
    pol: *const RuntimePolicy,
    tools_rt: *core.tools.builtin.Runtime,
    mode: core.loop.ModeSink,
    max_turns: u16 = 0,
    cancel: ?core.loop.CancelSrc = null,
    abort_slot: ?*core.providers.AbortSlot = null,
    cmd_cache: ?*core.loop.CmdCache = null,
    approval_bind: core.policy.ApprovalBind = .{ .version = core.policy.ver_current },
    approval_loc: ?core.loop.CmdCache.Loc = null,
    approver: ?core.loop.Approver = null,
    audit_hooks: AuditHooks = .{},

    const TurnOpts = struct {
        sid: []const u8,
        prompt: []const u8,
        model: []const u8,
        provider_label: []const u8 = "",
        provider_opts: core.providers.Opts = .{},
        system_prompt: ?[]const u8 = null,
    };

    fn run(self: *const TurnCtx, opts: TurnOpts) !void {
        const prompt_hint = if (needsAskHint(opts.prompt))
            try std.fmt.allocPrint(
                self.alloc,
                "{s}\n\nUse the `ask` tool for clarifying questions (1-3 concise questions with options) before final planning output.",
                .{opts.prompt},
            )
        else
            null;
        defer if (prompt_hint) |p| self.alloc.free(p);

        var reg: PolicyToolRegistry = undefined;
        var tool_audit_seq: u64 = 1;
        const tool_audit = PolicyToolAudit{
            .alloc = self.alloc,
            .hooks = self.audit_hooks,
            .sid = opts.sid,
            .seq = &tool_audit_seq,
        };
        reg.init(self.pol, self.tools_rt.registry(), tool_audit);
        var tool_auth_impl = PolicyToolAuth{
            .alloc = self.alloc,
            .pol = self.pol,
            .sid = opts.sid,
            .emit_audit_ctx = self.audit_hooks.emit_audit_ctx,
            .emit_audit = self.audit_hooks.emit_audit,
            .now_ms = self.audit_hooks.now_ms,
            .seq = &tool_audit_seq,
        };

        _ = try core.loop.run(.{
            .alloc = self.alloc,
            .sid = opts.sid,
            .prompt = prompt_hint orelse opts.prompt,
            .model = opts.model,
            .provider_label = opts.provider_label,
            .provider = self.provider,
            .store = self.store,
            .reg = reg.registry(),
            .tool_auth = core.loop.ToolAuth.from(PolicyToolAuth, &tool_auth_impl, PolicyToolAuth.check),
            .mode = self.mode,
            .system_prompt = opts.system_prompt,
            .provider_opts = opts.provider_opts,
            .max_turns = self.max_turns,
            .cancel = self.cancel,
            .abort_slot = self.abort_slot,
            .cmd_cache = self.cmd_cache,
            .approval = if (self.approval_loc) |loc| .{
                .loc = loc,
                .policy = self.approval_bind,
            } else null,
            .approver = self.approver,
        });
    }
};

fn needsAskHint(prompt: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(prompt, "ask me questions") != null or
        std.ascii.indexOfIgnoreCase(prompt, "ask questions") != null;
}

test "buildAskRows includes type-something-else and next navigation" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B", .description = "desc" },
    };
    const q: core.tools.Call.AskArgs.Question = .{
        .id = "scope",
        .question = "Pick scope",
        .options = opts[0..],
        .allow_other = true,
    };
    var rows = try buildAskRows(std.testing.allocator, q, .{}, true, false);
    defer rows.deinit(std.testing.allocator);

    const Snap = struct {
        row0: []const u8,
        row1: []const u8,
        row2: []const u8,
        row3: []const u8,
    };
    const snap = Snap{
        .row0 = rows.items[0],
        .row1 = rows.items[1],
        .row2 = rows.items[2],
        .row3 = rows.items[3],
    };
    try oh.snap(@src(),
        \\app.runtime.test.buildAskRows includes type-something-else and next navigation.Snap
        \\  .row0: []const u8
        \\    "[ ] A"
        \\  .row1: []const u8
        \\    "[ ] B - desc"
        \\  .row2: []const u8
        \\    "[ ] Type something else"
        \\  .row3: []const u8
        \\    "Next question"
    ).expectEqual(snap);
}

test "buildAskRows renders custom answer selection and submit controls" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const q: core.tools.Call.AskArgs.Question = .{
        .id = "scope",
        .question = "Pick scope",
        .options = opts[0..],
        .allow_other = true,
    };
    const custom = try std.testing.allocator.dupe(u8, "My custom answer");
    defer std.testing.allocator.free(custom);

    var rows = try buildAskRows(std.testing.allocator, q, .{
        .answer = custom,
        .index = 2,
    }, false, true);
    defer rows.deinit(std.testing.allocator);

    const Snap = struct {
        row0: []const u8,
        row1: []const u8,
        row2: []const u8,
        row3: []const u8,
        row4: []const u8,
    };
    const snap = Snap{
        .row0 = rows.items[0],
        .row1 = rows.items[1],
        .row2 = rows.items[2],
        .row3 = rows.items[3],
        .row4 = rows.items[4],
    };
    try oh.snap(@src(),
        \\app.runtime.test.buildAskRows renders custom answer selection and submit controls.Snap
        \\  .row0: []const u8
        \\    "[ ] A"
        \\  .row1: []const u8
        \\    "[ ] B"
        \\  .row2: []const u8
        \\    "[x] Type something else: My custom answer"
        \\  .row3: []const u8
        \\    "Previous question"
        \\  .row4: []const u8
        \\    "Submit answers"
    ).expectEqual(snap);
}

test "firstUnanswered returns first missing answer index" {
    const a0 = try std.testing.allocator.dupe(u8, "one");
    defer std.testing.allocator.free(a0);
    const a2 = try std.testing.allocator.dupe(u8, "three");
    defer std.testing.allocator.free(a2);

    const stored = [_]AskUiCtx.StoredAnswer{
        .{ .answer = a0, .index = 0 },
        .{},
        .{ .answer = a2, .index = 2 },
    };
    try std.testing.expectEqual(@as(?usize, 1), firstUnanswered(stored[0..]));
}

test "collectAskAnswers builds expected ask JSON payload" {
    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]core.tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick scope",
            .options = opts[0..],
            .allow_other = true,
        },
        .{
            .id = "detail",
            .question = "Add detail",
            .options = opts[0..],
            .allow_other = true,
        },
    };

    var stored = [_]AskUiCtx.StoredAnswer{
        .{},
        .{},
    };
    stored[0].answer = try std.testing.allocator.dupe(u8, "A");
    stored[0].index = 0;
    stored[1].answer = try std.testing.allocator.dupe(u8, "custom");
    stored[1].index = 2;
    defer {
        if (stored[0].answer) |a| std.testing.allocator.free(a);
        if (stored[1].answer) |a| std.testing.allocator.free(a);
    }

    const out_answers = try collectAskAnswers(std.testing.allocator, qs[0..], stored[0..]);
    defer std.testing.allocator.free(out_answers);
    const payload = try buildAskResult(std.testing.allocator, false, out_answers);
    defer std.testing.allocator.free(payload);

    try std.testing.expectEqualStrings(
        "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"A\",\"index\":0},{\"id\":\"detail\",\"answer\":\"custom\",\"index\":2}]}",
        payload,
    );
}

fn waitForAskTxn(live: *LiveTurn) !*LiveTurn.AskTxn {
    var ask_txn: ?*LiveTurn.AskTxn = null;
    var spins: usize = 0;
    while (ask_txn == null and spins < 1000) : (spins += 1) {
        ask_txn = live.takeAsk();
        if (ask_txn == null) std.Thread.sleep(std.time.ns_per_ms);
    }
    return ask_txn orelse error.TestUnexpectedResult;
}

test "live turn ask bridge waits for main-thread answer" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var live = try LiveTurn.init(std.testing.allocator);
    defer live.deinit();

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
    };
    const qs = [_]core.tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick scope",
            .options = opts[0..],
            .allow_other = true,
        },
    };

    const Ctx = struct {
        live: *LiveTurn,
        out: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.out = self.live.ask(.{ .questions = qs[0..] }) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var ctx = Ctx{ .live = &live };
    const thr = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    const tx = try waitForAskTxn(&live);
    const q = tx.args.questions[0];
    const q_id = try std.testing.allocator.dupe(u8, q.id);
    defer std.testing.allocator.free(q_id);
    const q_text = try std.testing.allocator.dupe(u8, q.question);
    defer std.testing.allocator.free(q_text);
    const q_allow_other = q.allow_other;
    const q_opt = try std.testing.allocator.dupe(u8, q.options[0].label);
    defer std.testing.allocator.free(q_opt);

    const out = try std.testing.allocator.dupe(
        u8,
        "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"A\",\"index\":0}]}",
    );
    live.finishAsk(tx, out);
    thr.join();

    if (ctx.err) |err| return err;
    defer std.testing.allocator.free(ctx.out.?);
    const snap = try std.fmt.allocPrint(
        std.testing.allocator,
        "q0 id={s} text={s} allow_other={} opt0={s}\nout={s}",
        .{ q_id, q_text, q_allow_other, q_opt, ctx.out.? },
    );
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "q0 id=scope text=Pick scope allow_other=true opt0=A
        \\out={"cancelled":false,"answers":[{"id":"scope","answer":"A","index":0}]}"
    ).expectEqual(snap);
}

test "live turn ask handoff keeps editor input isolated and cannot deadlock" {
    var live = try LiveTurn.init(std.testing.allocator);
    defer live.deinit();

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
    };
    const qs = [_]core.tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick scope",
            .options = opts[0..],
            .allow_other = false,
        },
    };

    const Ctx = struct {
        live: *LiveTurn,
        out: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.out = self.live.ask(.{ .questions = qs[0..] }) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();
    try ui.ed.setText("draft");

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer std.posix.close(pipe[0]);
    defer std.posix.close(pipe[1]);
    var watcher = try InputWatcher.init(pipe[0]);
    defer watcher.deinit();
    var ask_ui_ctx = AskUiCtx{
        .alloc = std.testing.allocator,
        .ui = &ui,
        .out = out_fbs.writer().any(),
        .watcher = &watcher,
    };
    _ = try std.posix.write(pipe[1], "\r\x1b[B\r");
    var reader = tui_input.Reader.init(watcher.fd);

    var ctx = Ctx{ .live = &live };
    const thr = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    const tx = try waitForAskTxn(&live);

    live.finishAsk(tx, ask_ui_ctx.runOnMain(&reader, tx.args.view()));
    thr.join();

    if (ctx.err) |err| return err;
    defer std.testing.allocator.free(ctx.out.?);
    try std.testing.expectEqualStrings(
        "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"A\",\"index\":0}]}",
        ctx.out.?,
    );
    try std.testing.expectEqualStrings("draft", ui.ed.text());
    try std.testing.expect(!watcher.isPaused());
    try std.testing.expect(ui.ov == null);
}

test "live turn ask handoff frees custom other answers cleanly" {
    var live = try LiveTurn.init(std.testing.allocator);
    defer live.deinit();

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
    };
    const qs = [_]core.tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick scope",
            .options = opts[0..],
            .allow_other = true,
        },
    };

    const Ctx = struct {
        live: *LiveTurn,
        out: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.out = self.live.ask(.{ .questions = qs[0..] }) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();
    try ui.ed.setText("draft");

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer std.posix.close(pipe[0]);
    defer std.posix.close(pipe[1]);
    var watcher = try InputWatcher.init(pipe[0]);
    defer watcher.deinit();
    var ask_ui_ctx = AskUiCtx{
        .alloc = std.testing.allocator,
        .ui = &ui,
        .out = out_fbs.writer().any(),
        .watcher = &watcher,
    };
    _ = try std.posix.write(pipe[1], "\x1b[B\rZ\r\x1b[B\r");
    var reader = tui_input.Reader.init(watcher.fd);

    var ctx = Ctx{ .live = &live };
    const thr = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    const tx = try waitForAskTxn(&live);

    live.finishAsk(tx, ask_ui_ctx.runOnMain(&reader, tx.args.view()));
    thr.join();

    if (ctx.err) |err| return err;
    defer std.testing.allocator.free(ctx.out.?);
    try std.testing.expectEqualStrings(
        "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"Z\",\"index\":1}]}",
        ctx.out.?,
    );
    try std.testing.expectEqualStrings("draft", ui.ed.text());
    try std.testing.expect(!watcher.isPaused());
    try std.testing.expect(ui.ov == null);
}

test "ask ui cancel frees temporary state and overlay" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var live = try LiveTurn.init(std.testing.allocator);
    defer live.deinit();

    const opts = [_]core.tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]core.tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick scope",
            .options = opts[0..],
            .allow_other = true,
        },
    };

    const Ctx = struct {
        live: *LiveTurn,
        out: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.out = self.live.ask(.{ .questions = qs[0..] }) catch |err| {
                self.err = err;
                return;
            };
        }
    };

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();
    try ui.ed.setText("draft");

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    const pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer std.posix.close(pipe[0]);
    defer std.posix.close(pipe[1]);
    var watcher = try InputWatcher.init(pipe[0]);
    defer watcher.deinit();
    var ask_ui_ctx = AskUiCtx{
        .alloc = std.testing.allocator,
        .ui = &ui,
        .out = out_fbs.writer().any(),
        .watcher = &watcher,
    };
    _ = try std.posix.write(pipe[1], "\x03");
    var reader = tui_input.Reader.init(watcher.fd);

    var ctx = Ctx{ .live = &live };
    const thr = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    const tx = try waitForAskTxn(&live);

    live.finishAsk(tx, ask_ui_ctx.runOnMain(&reader, tx.args.view()));
    thr.join();

    if (ctx.err) |err| return err;
    defer std.testing.allocator.free(ctx.out.?);

    try oh.snap(@src(),
        \\[]u8
        \\  "{"cancelled":true,"answers":[]}"
    ).expectEqual(ctx.out.?);
    try std.testing.expectEqualStrings("draft", ui.ed.text());
    try std.testing.expect(!watcher.isPaused());
    try std.testing.expect(ui.ov == null);
}

test "input watcher join wakes promptly while paused" {
    const in_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer std.posix.close(in_pipe[0]);
    defer std.posix.close(in_pipe[1]);

    var watcher = try InputWatcher.init(in_pipe[0]);
    defer watcher.deinit();
    try std.testing.expect(watcher.start());
    watcher.setPaused(true);

    const done_pipe = try std.posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer std.posix.close(done_pipe[0]);
    defer std.posix.close(done_pipe[1]);

    const Ctx = struct {
        watcher: *InputWatcher,
        fd: std.posix.fd_t,

        fn run(self: *@This()) void {
            self.watcher.join(null);
            _ = std.posix.write(self.fd, "\x01") catch {};
        }
    };
    var ctx = Ctx{ .watcher = &watcher, .fd = done_pipe[1] };
    const thr = try std.Thread.spawn(.{}, Ctx.run, .{&ctx});
    defer thr.join();

    var fds = [1]std.posix.pollfd{.{
        .fd = done_pipe[0],
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&fds, 20);
    try std.testing.expectEqual(@as(usize, 1), ready);
}

test "parseBashCmd single bang" {
    const r = parseBashCmd("!ls -la").?;
    try std.testing.expectEqualStrings("ls -la", r.cmd);
    try std.testing.expect(r.include);
}

test "parseBashCmd double bang excludes" {
    const r = parseBashCmd("!!echo hi").?;
    try std.testing.expectEqualStrings("echo hi", r.cmd);
    try std.testing.expect(!r.include);
}

test "parseBashCmd empty cmd returns null" {
    try std.testing.expect(parseBashCmd("!") == null);
    try std.testing.expect(parseBashCmd("! ") == null);
    try std.testing.expect(parseBashCmd("!!") == null);
    try std.testing.expect(parseBashCmd("!! ") == null);
}

test "parseBashCmd no bang returns null" {
    try std.testing.expect(parseBashCmd("hello") == null);
    try std.testing.expect(parseBashCmd("/quit") == null);
}

test "shouldQueueSubmit excludes commands and includes prompts" {
    try std.testing.expect(!shouldQueueSubmit(""));
    try std.testing.expect(!shouldQueueSubmit("   \t\n"));
    try std.testing.expect(!shouldQueueSubmit("/help"));
    try std.testing.expect(!shouldQueueSubmit(" /help"));
    try std.testing.expect(!shouldQueueSubmit("!ls -la"));
    try std.testing.expect(!shouldQueueSubmit("!!echo hi"));
    try std.testing.expect(shouldQueueSubmit("explain this bug"));
}

test "pending queue pops steering before follow-up" {
    var pending = PendingQueue{};
    defer pending.deinit(std.testing.allocator);

    try pending.pushFollowUp(std.testing.allocator, "follow-1");
    try pending.pushSteering(std.testing.allocator, "steer-1");
    try pending.pushFollowUp(std.testing.allocator, "follow-2");

    const one = pending.popNext() orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(one.text);
    try std.testing.expect(one.kind == .steering);
    try std.testing.expectEqualStrings("steer-1", one.text);

    const two = pending.popNext() orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(two.text);
    try std.testing.expect(two.kind == .follow_up);
    try std.testing.expectEqualStrings("follow-1", two.text);

    const three = pending.popNext() orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(three.text);
    try std.testing.expect(three.kind == .follow_up);
    try std.testing.expectEqualStrings("follow-2", three.text);

    try std.testing.expect(pending.popNext() == null);
}

test "pending queue restore merges steering follow-up and editor text" {
    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    var pending = PendingQueue{};
    defer pending.deinit(std.testing.allocator);

    try pending.pushSteering(std.testing.allocator, "steer one");
    try pending.pushSteering(std.testing.allocator, "steer two");
    try pending.pushFollowUp(std.testing.allocator, "follow one");
    try ui.ed.setText("existing draft");

    const restored = try pending.restoreToEditor(std.testing.allocator, &ui);
    try std.testing.expectEqual(@as(usize, 3), restored);
    try std.testing.expectEqualStrings("steer one\n\nsteer two\n\nfollow one\n\nexisting draft", ui.ed.text());
    try std.testing.expectEqual(@as(usize, 0), pending.total());
}

test "queueItemLabel snapshots preview formatting" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const one = try queueItemLabel(std.testing.allocator, 0, "first line\nsecond line");
    defer std.testing.allocator.free(one);

    const two = try queueItemLabel(std.testing.allocator, 1, "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz");
    defer std.testing.allocator.free(two);

    const three = try queueItemLabel(std.testing.allocator, 2, "   ");
    defer std.testing.allocator.free(three);

    const Snap = struct {
        one: []const u8,
        two: []const u8,
        three: []const u8,
    };
    try oh.snap(@src(),
        \\app.runtime.test.queueItemLabel snapshots preview formatting.Snap
        \\  .one: []const u8
        \\    "#1 first line ..."
        \\  .two: []const u8
        \\    "#2 abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcd ..."
        \\  .three: []const u8
        \\    "#3    "
    ).expectEqual(Snap{
        .one = one,
        .two = two,
        .three = three,
    });
}

test "showQueueOverlay and dequeueQueuedIntoEditor edit selected message" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    var queue: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (queue.items) |q| std.testing.allocator.free(q);
        queue.deinit(std.testing.allocator);
    }
    try queueFollowup(std.testing.allocator, &queue, "one");
    try queueFollowup(std.testing.allocator, &queue, "two");
    try queueFollowup(std.testing.allocator, &queue, "three");

    try std.testing.expect(try showQueueOverlay(std.testing.allocator, &ui, queue.items));
    try std.testing.expect(ui.ov != null);
    try std.testing.expect(ui.ov.?.kind == .queue);
    try std.testing.expect(ui.ov.?.dyn_items != null);
    try std.testing.expectEqual(@as(usize, 3), ui.ov.?.dyn_items.?.len);

    ui.ov.?.sel = 1;
    try std.testing.expect(try dequeueQueuedIntoEditor(std.testing.allocator, &ui, &queue, ui.ov.?.sel));
    const Snap = struct {
        ov_len: usize,
        editor: []const u8,
        q0: []const u8,
        q1: []const u8,
    };
    try oh.snap(@src(),
        \\app.runtime.test.showQueueOverlay and dequeueQueuedIntoEditor edit selected message.Snap
        \\  .ov_len: usize = 3
        \\  .editor: []const u8
        \\    "two"
        \\  .q0: []const u8
        \\    "one"
        \\  .q1: []const u8
        \\    "three"
    ).expectEqual(Snap{
        .ov_len = ui.ov.?.dyn_items.?.len,
        .editor = ui.ed.text(),
        .q0 = queue.items[0],
        .q1 = queue.items[1],
    });

    ui.ov.?.deinit(std.testing.allocator);
    ui.ov = null;
}

fn writeSessionEventsFile(tmp: std.testing.TmpDir, sub_path: []const u8, events: []const core.session.Event) !void {
    const file = try tmp.dir.createFile(sub_path, .{});
    defer file.close();
    for (events) |ev| {
        const raw = try core.session.encodeEventAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw);
        try file.writeAll("\n");
    }
}

fn frameRowBoxAlloc(alloc: std.mem.Allocator, frm: *const tui_frame.Frame, y: usize) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    try out.append(alloc, '|');
    for (0..frm.w) |x| {
        const cell = try frm.cell(x, y);
        if (cell.cp == tui_frame.Frame.wide_pad) continue;
        if (cell.cp <= 0x7f) {
            try out.append(alloc, @intCast(cell.cp));
            continue;
        }
        var buf: [4]u8 = undefined;
        const n = try std.unicode.utf8Encode(cell.cp, &buf);
        try out.appendSlice(alloc, buf[0..n]);
    }
    try out.append(alloc, '|');
    return out.toOwnedSlice(alloc);
}

test "showResumeOverlay lists sessions and supports arrow navigation" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");
    try tmp.dir.writeFile(.{
        .sub_path = "sess/200.jsonl",
        .data = "",
    });
    try tmp.dir.writeFile(.{
        .sub_path = "sess/100.jsonl",
        .data = "",
    });

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try std.testing.expect(try showResumeOverlay(std.testing.allocator, &ui, sess_abs));
    try std.testing.expect(ui.ov != null);
    try std.testing.expect(ui.ov.?.kind == .session);
    try std.testing.expect(ui.ov.?.session_rows != null);
    const rows = ui.ov.?.session_rows.?;
    const RowSnap = struct {
        sid: []const u8,
        title: []const u8,
        time: []const u8,
        tokens: []const u8,
    };
    const Snap = struct {
        title: []const u8,
        selected: []const u8,
        rows: [2]RowSnap,
    };
    try oh.snap(@src(),
        \\app.runtime.test.showResumeOverlay lists sessions and supports arrow navigation.Snap
        \\  .title: []const u8
        \\    "Resume Session"
        \\  .selected: []const u8
        \\    "100"
        \\  .rows: [2]app.runtime.test.showResumeOverlay lists sessions and supports arrow navigation.RowSnap
        \\    [0]: app.runtime.test.showResumeOverlay lists sessions and supports arrow navigation.RowSnap
        \\      .sid: []const u8
        \\        "100"
        \\      .title: []const u8
        \\        "100"
        \\      .time: []const u8
        \\        "now"
        \\      .tokens: []const u8
        \\        "0 tok"
        \\    [1]: app.runtime.test.showResumeOverlay lists sessions and supports arrow navigation.RowSnap
        \\      .sid: []const u8
        \\        "200"
        \\      .title: []const u8
        \\        "200"
        \\      .time: []const u8
        \\        "now"
        \\      .tokens: []const u8
        \\        "0 tok"
    ).expectEqual(Snap{
        .title = ui.ov.?.title,
        .selected = ui.ov.?.selected().?,
        .rows = .{
            .{ .sid = rows[0].sid, .title = rows[0].title, .time = rows[0].time, .tokens = rows[0].tokens },
            .{ .sid = rows[1].sid, .title = rows[1].title, .time = rows[1].time, .tokens = rows[1].tokens },
        },
    });

    ui.ov.?.down();
    try std.testing.expectEqualStrings("200", ui.ov.?.selected().?);
    ui.ov.?.down();
    try std.testing.expectEqualStrings("100", ui.ov.?.selected().?);
    ui.ov.?.up();
    try std.testing.expectEqualStrings("200", ui.ov.?.selected().?);

    ui.ov.?.deinit(std.testing.allocator);
    ui.ov = null;
}

test "showResumeOverlay fixed-width snapshot aligns age and token columns" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");

    const now = std.time.milliTimestamp();
    const long_events = [_]core.session.Event{
        .{
            .at_ms = now - (2 * 60 * 60 * std.time.ms_per_s),
            .data = .{ .prompt = .{ .text = "A very long session title that should ellipsize before the right-aligned columns" } },
        },
        .{
            .at_ms = now - (2 * 60 * 60 * std.time.ms_per_s),
            .data = .{ .usage = .{ .tot_tok = 1345 } },
        },
    };
    try writeSessionEventsFile(tmp, "sess/100.jsonl", &long_events);

    const short_events = [_]core.session.Event{
        .{
            .at_ms = now - (45 * 60 * std.time.ms_per_s),
            .data = .{ .prompt = .{ .text = "Short title" } },
        },
        .{
            .at_ms = now - (45 * 60 * std.time.ms_per_s),
            .data = .{ .usage = .{ .tot_tok = 46 } },
        },
    };
    try writeSessionEventsFile(tmp, "sess/200.jsonl", &short_events);

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 48, 8, "m", "p");
    defer ui.deinit();
    try std.testing.expect(try showResumeOverlay(std.testing.allocator, &ui, sess_abs));

    var frm = try tui_frame.Frame.init(std.testing.allocator, 48, 8);
    defer frm.deinit(std.testing.allocator);
    try ui.ov.?.render(&frm);

    const row2 = try frameRowBoxAlloc(std.testing.allocator, &frm, 2);
    defer std.testing.allocator.free(row2);
    const row3 = try frameRowBoxAlloc(std.testing.allocator, &frm, 3);
    defer std.testing.allocator.free(row3);
    const row4 = try frameRowBoxAlloc(std.testing.allocator, &frm, 4);
    defer std.testing.allocator.free(row4);
    const row5 = try frameRowBoxAlloc(std.testing.allocator, &frm, 5);
    defer std.testing.allocator.free(row5);

    const Snap = struct {
        row2: []const u8,
        row3: []const u8,
        row4: []const u8,
        row5: []const u8,
    };
    try oh.snap(@src(),
        \\app.runtime.test.showResumeOverlay fixed-width snapshot aligns age and token columns.Snap
        \\  .row2: []const u8
        \\    "|┌────────────────Resume Session────────────────┐|"
        \\  .row3: []const u8
        \\    "|│ > A very long session titl...   2h  1.3k tok │|"
        \\  .row4: []const u8
        \\    "|│   Short title                  45m    46 tok │|"
        \\  .row5: []const u8
        \\    "|└──────────────────────────────────────────────┘|"
    ).expectEqual(Snap{
        .row2 = row2,
        .row3 = row3,
        .row4 = row4,
        .row5 = row5,
    });
}

test "showResumeOverlay returns false when no sessions exist" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try std.testing.expect(!(try showResumeOverlay(std.testing.allocator, &ui, sess_abs)));
    try std.testing.expect(ui.ov == null);
}

test "restoreSessionIntoUi replays session history and resets stale ui state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");

    const file = try tmp.dir.createFile("sess/100.jsonl", .{});
    defer file.close();
    const events = [_]core.session.Event{
        .{
            .at_ms = 1,
            .data = .{ .prompt = .{ .text = "old prompt" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .text = .{ .text = "old answer" } },
        },
        .{
            .at_ms = 3,
            .data = .{ .tool_call = .{ .id = "call-1", .name = "read", .args = "{\"path\":\"a.txt\"}" } },
        },
        .{
            .at_ms = 4,
            .data = .{ .tool_result = .{ .id = "call-1", .out = "ok", .is_err = false } },
        },
        .{
            .at_ms = 5,
            .data = .{ .usage = .{ .in_tok = 12, .out_tok = 34, .tot_tok = 46, .cache_read = 1, .cache_write = 2 } },
        },
        .{
            .at_ms = 6,
            .data = .{ .stop = .{ .reason = .done } },
        },
    };
    for (events) |ev| {
        const raw = try core.session.encodeEventAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw);
        try file.writeAll("\n");
    }

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try ui.tr.infoText("stale");
    try ui.onProvider(.{ .tool_call = .{ .id = "stale-1", .name = "ls", .args = "{}" } });
    ui.panels.cum_tok = 999;
    ui.panels.has_usage = true;
    ui.panels.run_state = .failed;

    try restoreSessionIntoUi(std.testing.allocator, &ui, sess_abs, false, "100");

    var saw_stale = false;
    var saw_prompt = false;
    var saw_answer = false;
    for (ui.tr.blocks.items) |blk| {
        if (std.mem.eql(u8, blk.buf.items, "stale")) saw_stale = true;
        if (std.mem.eql(u8, blk.buf.items, "old prompt")) saw_prompt = true;
        if (std.mem.eql(u8, blk.buf.items, "old answer")) saw_answer = true;
    }
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const row = ui.panels.tool(0);
    const snap = try std.fmt.allocPrint(
        std.testing.allocator,
        "stale={} prompt={} answer={} usage={} tok={} state={s} count={} row={s}|{s}|{s}",
        .{
            saw_stale,
            saw_prompt,
            saw_answer,
            ui.panels.has_usage,
            ui.panels.cum_tok,
            @tagName(ui.panels.state()),
            ui.panels.count(),
            row.id,
            row.name,
            @tagName(row.state),
        },
    );
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "stale=false prompt=true answer=true usage=true tok=46 state=idle count=1 row=call-1|read|ok"
    ).expectEqual(snap);
}

test "restoreSessionIntoUi ignores empty blocks when rendering bottom row" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");

    const file = try tmp.dir.createFile("sess/100.jsonl", .{});
    defer file.close();
    const events = [_]core.session.Event{
        .{
            .at_ms = 1,
            .data = .{ .text = .{ .text = "" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .tool_call = .{ .id = "call-1", .name = "bash", .args = "{\"cmd\":\"printf ok\"}" } },
        },
        .{
            .at_ms = 3,
            .data = .{ .tool_result = .{ .id = "call-1", .out = "", .is_err = false } },
        },
        .{
            .at_ms = 4,
            .data = .{ .text = .{ .text = "tail line" } },
        },
    };
    for (events) |ev| {
        const raw = try core.session.encodeEventAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw);
        try file.writeAll("\n");
    }

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 24, 4, "m", "p");
    defer ui.deinit();

    try restoreSessionIntoUi(std.testing.allocator, &ui, sess_abs, false, "100");

    var frm = try tui_frame.Frame.init(std.testing.allocator, 24, 1);
    defer frm.deinit(std.testing.allocator);
    try ui.tr.render(&frm, .{ .x = 0, .y = 0, .w = 24, .h = 1 });

    var raw: [24]u8 = undefined;
    var x: usize = 0;
    while (x < frm.w) : (x += 1) {
        const c = try frm.cell(x, 0);
        raw[x] = if (c.cp <= 0x7f) @intCast(c.cp) else '?';
    }
    try std.testing.expect(std.mem.indexOf(u8, raw[0..], "tail line") != null);
}

test "runtime tui non-tty /resume restores session without running provider turn" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const file = try tmp.dir.createFile("sess/100.jsonl", .{});
    defer file.close();
    const events = [_]core.session.Event{
        .{
            .at_ms = 1,
            .data = .{ .prompt = .{ .text = "old prompt" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .text = .{ .text = "old answer" } },
        },
        .{
            .at_ms = 3,
            .data = .{ .stop = .{ .reason = .done } },
        },
    };
    for (events) |ev| {
        const raw = try core.session.encodeEventAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw);
        try file.writeAll("\n");
    }

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:MODEL-RAN\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/resume 100\n");
    var out_buf: [65536]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);
    try std.testing.expectEqualStrings("100", sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "resumed session 100") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "MODEL-RAN") == null);

    var session_dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer session_dir.close();
    var rdr = try core.session.ReplayReader.init(std.testing.allocator, session_dir, "100", .{});
    defer rdr.deinit();

    var prompt_ct: usize = 0;
    var saw_resume_prompt = false;
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| {
                prompt_ct += 1;
                if (std.mem.eql(u8, p.text, "/resume 100")) saw_resume_prompt = true;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 1), prompt_ct);
    try std.testing.expect(!saw_resume_prompt);
}

test "syncInputFooter tracks mode and clamps queue size" {
    var ui = try tui_harness.Ui.init(std.testing.allocator, 60, 10, "m", "p");
    defer ui.deinit();

    syncInputFooter(&ui, .queue, 12);
    try std.testing.expect(ui.panels.input_mode == .queue);
    try std.testing.expectEqual(@as(u32, 12), ui.panels.queued_msgs);

    syncInputFooter(&ui, .steering, @as(usize, std.math.maxInt(u32)) + 10);
    try std.testing.expect(ui.panels.input_mode == .steering);
    try std.testing.expectEqual(std.math.maxInt(u32), ui.panels.queued_msgs);
}

test "needsAskHint detects ask-question prompts" {
    try std.testing.expect(needsAskHint("ask me questions before planning"));
    try std.testing.expect(needsAskHint("Please ASK QUESTIONS first."));
}

test "needsAskHint ignores regular prompts" {
    try std.testing.expect(!needsAskHint("build a parser for this input"));
    try std.testing.expect(!needsAskHint("summarize the codebase"));
}

test "sanitizeUtf8LossyAlloc preserves valid utf8" {
    const in = "upgrade ok ✓";
    const out = try sanitizeUtf8LossyAlloc(std.testing.allocator, in);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings(in, out);
}

test "sanitizeUtf8LossyAlloc replaces invalid bytes" {
    const bad = [_]u8{ 'o', 0xff, 'k', 0xc3 };
    const out = try sanitizeUtf8LossyAlloc(std.testing.allocator, bad[0..]);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("o?k?", out);
}

test "sanitizeUtf8LossyAlloc truncates incomplete multibyte suffix lossy" {
    const bad = [_]u8{ 'a', 0xe2, 0x82 };
    const out = try sanitizeUtf8LossyAlloc(std.testing.allocator, bad[0..]);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("a?", out);
}

test "sanitizeUtf8LossyAlloc property: output is valid utf8" {
    const pbt = @import("../core/prop_test.zig");
    try pbt.expectSanValid(sanitizeUtf8LossyAlloc, 64, .{ .iterations = 200 });
}

test "sanitizeUtf8LossyAlloc property: valid utf8 is preserved" {
    const pbt = @import("../core/prop_test.zig");
    try pbt.expectSanPreserves(sanitizeUtf8LossyAlloc, 24, .{ .iterations = 200 });
}

test "infoTextSafe accepts invalid utf8 command output" {
    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    const bad = [_]u8{ 'u', 0xff, 'p' };
    try infoTextSafe(std.testing.allocator, &ui, bad[0..]);
    try std.testing.expectEqual(@as(usize, 1), ui.tr.count());
}

fn eofReader() std.Io.AnyReader {
    const S = struct {
        fn read(_: *const anyopaque, buf: []u8) anyerror!usize {
            _ = buf;
            return 0; // EOF
        }
    };
    return .{ .context = undefined, .readFn = &S.read };
}

fn runtimeTestPolicyKeyPair() !core.signing.KeyPair {
    const seed = try core.signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    return core.signing.KeyPair.fromSeed(seed);
}

fn writeRuntimePolicy(dir: std.fs.Dir, doc: core.policy.Doc) !void {
    try dir.makePath(".pz");
    const kp = try runtimeTestPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, doc, kp);
    defer std.testing.allocator.free(raw);
    try dir.writeFile(.{ .sub_path = config.policy_rel_path, .data = raw });
}

const AuditRows = struct {
    rows: std.ArrayList([]u8) = .empty,

    fn deinit(self: *AuditRows, alloc: std.mem.Allocator) void {
        for (self.rows.items) |row| alloc.free(row);
        self.rows.deinit(alloc);
    }

    fn emit(ctx: *anyopaque, alloc: std.mem.Allocator, ent: core.audit.Entry) !void {
        const self: *AuditRows = @ptrCast(@alignCast(ctx));
        const raw = try core.audit.encodeAlloc(alloc, ent);
        errdefer alloc.free(raw);
        try self.rows.append(alloc, raw);
    }
};

const AuditAttrSnap = struct {
    key: []const u8,
    vis: core.audit.Vis,
    ty: []const u8,
};

const AuditEntrySnap = struct {
    sid: []const u8,
    seq: u64,
    kind: core.audit.EventKind,
    sev: core.audit.Severity,
    out: core.audit.Outcome,
    res_kind: ?core.audit.ResKind = null,
    res_name: ?[]const u8 = null,
    op: ?[]const u8 = null,
    msg: ?[]const u8 = null,
    data_name: ?[]const u8 = null,
    call_id: ?[]const u8 = null,
    auth_mech: ?[]const u8 = null,
    attrs: []const AuditAttrSnap = &.{},
};

fn auditTraceSnap(alloc: std.mem.Allocator, rows: []const []const u8) ![]AuditEntrySnap {
    const out = try alloc.alloc(AuditEntrySnap, rows.len);
    for (rows, 0..) |row, i| {
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, row, .{});
        const root = parsed.value;
        if (root != .object) return error.UnexpectedToken;

        const kind_txt = jsonStr(root.object, "kind") orelse return error.UnexpectedToken;
        const sev_txt = jsonStr(root.object, "sev") orelse return error.UnexpectedToken;
        const out_txt = jsonStr(root.object, "out") orelse return error.UnexpectedToken;
        const kind = std.meta.stringToEnum(core.audit.EventKind, kind_txt) orelse return error.UnexpectedToken;
        const sev = std.meta.stringToEnum(core.audit.Severity, sev_txt) orelse return error.UnexpectedToken;
        const out_tag = std.meta.stringToEnum(core.audit.Outcome, out_txt) orelse return error.UnexpectedToken;

        const attrs_val = root.object.get("attrs") orelse return error.UnexpectedToken;
        if (attrs_val != .array) return error.UnexpectedToken;
        const attrs = try alloc.alloc(AuditAttrSnap, attrs_val.array.items.len);
        for (attrs_val.array.items, 0..) |attr, j| {
            if (attr != .object) return error.UnexpectedToken;
            attrs[j] = .{
                .key = jsonStr(attr.object, "key") orelse return error.UnexpectedToken,
                .vis = std.meta.stringToEnum(core.audit.Vis, jsonStr(attr.object, "vis") orelse return error.UnexpectedToken) orelse return error.UnexpectedToken,
                .ty = jsonStr(attr.object, "ty") orelse return error.UnexpectedToken,
            };
        }

        const res_obj = jsonObj(root.object, "res");
        const msg_obj = jsonObj(root.object, "msg");
        const data_obj = jsonObj(root.object, "data") orelse return error.UnexpectedToken;
        out[i] = .{
            .sid = jsonStr(root.object, "sid") orelse return error.UnexpectedToken,
            .seq = jsonU64(root.object, "seq") orelse return error.UnexpectedToken,
            .kind = kind,
            .sev = sev,
            .out = out_tag,
            .res_kind = if (res_obj) |obj| std.meta.stringToEnum(core.audit.ResKind, jsonStr(obj, "kind") orelse return error.UnexpectedToken) else null,
            .res_name = if (res_obj) |obj| jsonVisText(obj, "name") else null,
            .op = if (res_obj) |obj| jsonStr(obj, "op") else null,
            .msg = if (msg_obj) |obj| jsonVisText(obj, null) else null,
            .data_name = switch (kind) {
                .tool, .forward => jsonVisText(data_obj, "name"),
                else => null,
            },
            .call_id = switch (kind) {
                .tool => jsonStr(data_obj, "call_id"),
                else => null,
            },
            .auth_mech = switch (kind) {
                .auth => jsonStr(data_obj, "mech"),
                else => null,
            },
            .attrs = attrs,
        };
    }
    return out;
}

fn jsonObj(obj: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const v = obj.get(key) orelse return null;
    return if (v == .object) v.object else null;
}

fn jsonStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn jsonU64(obj: std.json.ObjectMap, key: []const u8) ?u64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |n| @intCast(n),
        else => null,
    };
}

fn jsonVisText(obj: std.json.ObjectMap, key: ?[]const u8) ?[]const u8 {
    const txt = if (key) |k| blk: {
        const v = obj.get(k) orelse return null;
        if (v != .object) return null;
        break :blk v.object;
    } else obj;
    const text = jsonStr(txt, "text") orelse return null;
    const vis_txt = jsonStr(txt, "vis") orelse return null;
    const vis = std.meta.stringToEnum(core.audit.Vis, vis_txt) orelse return null;
    return switch (vis) {
        .@"pub" => text,
        .mask, .hash, .secret => "[mask]",
    };
}

test "runtime executes print mode and persists session events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    var session_dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer session_dir.close();

    var rdr = try core.session.ReplayReader.init(std.testing.allocator, session_dir, sid, .{});
    defer rdr.deinit();

    const ev0 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev0.data) {
        .prompt => |out| try std.testing.expectEqualStrings("ping", out.text),
        else => return error.TestUnexpectedResult,
    }

    const ev1 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev1.data) {
        .text => |out| try std.testing.expectEqualStrings("pong", out.text),
        else => return error.TestUnexpectedResult,
    }

    const ev2 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev2.data) {
        .stop => |out| try std.testing.expect(out.reason == .done),
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect((try rdr.next()) == null);
    // Non-verbose: only text output, no stop metadata
    try std.testing.expectEqualStrings("pong\n", out_fbs.getWritten());
}

test "runtime executes tool calls through loop registry in print mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"tool_result\"'; then " ++
        "printf 'text:done\\nstop:done\\n'; " ++
        "else " ++
        "printf 'tool_call:call-1|bash|{\"cmd\":\"printf hi\"}\\nstop:tool\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ship",
        .verbose = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "done") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "stop reason=done") != null);
}

test "runtime blocks tool dispatch under verified policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    try writeRuntimePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/tool/bash", .effect = .deny, .tool = "bash" },
            .{ .pattern = "*", .effect = .allow },
        },
    });

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    const root_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_abs);
    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"tool_result\"'; then " ++
        "printf 'text:done\\nstop:done\\n'; " ++
        "else " ++
        "printf 'tool_call:call-1|bash|{\"cmd\":\"printf hi\"}\\nstop:tool\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ship",
        .verbose = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "tool_result id=\"call-1\" is_err=true out=\"blocked by policy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "stop reason=done") != null);

    const sess_dir = try tmp.dir.openDir("sess", .{});
    var fs_store = try core.session.fs_store.Store.init(.{
        .alloc = std.testing.allocator,
        .dir = sess_dir,
    });
    defer fs_store.deinit();

    var rdr = try fs_store.asSessionStore().replay(sid);
    defer rdr.deinit();
    var saw_blocked = false;
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .tool_result => |tr| {
                if (std.mem.eql(u8, tr.id, "call-1") and tr.is_err and std.mem.eql(u8, tr.out, "blocked by policy")) {
                    saw_blocked = true;
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_blocked);
}

fn verifyDeniedBashAuditSyslog(transport: core.syslog.Transport) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    try writeRuntimePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/tool/bash", .effect = .deny, .tool = "bash" },
            .{ .pattern = "*", .effect = .allow },
        },
    });

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"tool_result\"'; then " ++
        "printf 'text:done\\nstop:done\\n'; " ++
        "else " ++
        "printf 'tool_call:call-1|bash|{\"cmd\":\"rm -rf /tmp/bash-secret/.env\"}\\nstop:tool\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ship",
        .verbose = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        eofReader(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 141;
                }
            }.f,
        },
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "tool_result id=\"call-1\" is_err=true out=\"blocked by policy\"") != null);
    try std.testing.expect(rows.rows.items.len != 0);

    switch (transport) {
        .udp => {
            var collector = try syslog_mock.UdpCollector.init();
            defer collector.deinit();
            const t = try collector.spawnCount(rows.rows.items.len);

            var sender = try core.syslog.Sender.init(std.testing.allocator, .{
                .transport = .udp,
                .host = "127.0.0.1",
                .port = collector.port(),
            });
            defer sender.deinit();

            try audit_e2e.shipAuditRows(std.testing.allocator, &sender, rows.rows.items);
            t.join();
            try audit_e2e.verifyRoundTrip(&collector, rows.rows.items);
        },
        .tcp => {
            var collector = try syslog_mock.TcpCollector.init();
            defer collector.deinit();
            const t = try collector.spawnCount(rows.rows.items.len);

            var sender = try core.syslog.Sender.init(std.testing.allocator, .{
                .transport = .tcp,
                .host = "127.0.0.1",
                .port = collector.port(),
            });
            defer sender.deinit();

            try audit_e2e.shipAuditRows(std.testing.allocator, &sender, rows.rows.items);
            t.join();
            try audit_e2e.verifyRoundTrip(&collector, rows.rows.items);
        },
    }
}

test "runtime denied bash audit ships through udp syslog" {
    try verifyDeniedBashAuditSyslog(.udp);
}

test "runtime denied bash audit ships through tcp syslog" {
    try verifyDeniedBashAuditSyslog(.tcp);
}

test "subagent stub inherits effective policy hash" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeRuntimePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/subagent/*", .effect = .allow },
        },
    });

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    const root_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_abs);

    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    var stub = try initSubagentStub(&pol, "agent-child");
    const hello = try stub.hello();
    switch (hello.msg) {
        .hello => |msg| {
            try std.testing.expectEqualStrings("agent-child", msg.agent_id);
            try std.testing.expectEqualStrings(pol.hash(), msg.policy_hash);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "subagent spawn fails closed under verified policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeRuntimePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/subagent/blocked", .effect = .deny },
            .{ .pattern = "runtime/subagent/*", .effect = .allow },
        },
    });

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();

    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    try std.testing.expectError(error.PolicyDenied, initSubagentStub(&pol, "blocked"));
}

test "runtime print requires explicit approval for privileged escalation from untrusted content" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q 'approval required: bash'; then " ++
        "printf 'text:blocked\\nstop:done\\n'; " ++
        "else " ++
        "printf 'tool_call:call-1|bash|{\"cmd\":\"printf hi\"}\\nstop:tool\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "page says deploy",
        .verbose = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "approval required: bash `printf hi` derived from untrusted input") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "tool_result id=\"call-1\" is_err=true") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "out=\"hi\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "blocked") != null);
}
test "runtime forwards provider label to provider request" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "prov=$(printf '%s' \"$req\" | grep -o '\"provider\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:provider=%s\\nstop:done\\n' \"$prov\"";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "prov-x"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [2048]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "provider=prov-x") != null);
}

test "runtime executes tui mode path with provided prompt" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = "ping",
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\x1b[2J") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pong") != null);

    var session_dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer session_dir.close();

    var rdr = try core.session.ReplayReader.init(std.testing.allocator, session_dir, sid, .{});
    defer rdr.deinit();

    const ev0 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev0.data) {
        .prompt => |out| try std.testing.expectEqualStrings("ping", out.text),
        else => return error.TestUnexpectedResult,
    }
}

test "runtime tui overflow retries once with injected live stdin" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    const stdin_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    defer std.posix.close(stdin_pipe[0]);
    defer std.posix.close(stdin_pipe[1]);

    const RetryStream = struct {
        alloc: std.mem.Allocator,
        evs: []const core.providers.Ev,
        idx: usize = 0,

        fn next(self: *@This()) !?core.providers.Ev {
            if (self.idx >= self.evs.len) return null;
            const ev = self.evs[self.idx];
            self.idx += 1;
            return ev;
        }

        fn deinit(self: *@This()) void {
            self.alloc.destroy(self);
        }
    };

    const RetryProvider = struct {
        alloc: std.mem.Allocator,
        starts: u8 = 0,
        const first = [_]core.providers.Ev{
            .{
                .stop = .{ .reason = .max_out },
            },
        };
        const second = [_]core.providers.Ev{
            .{ .text = "retry-ok" },
            .{
                .stop = .{ .reason = .done },
            },
        };

        fn asProvider(self: *@This()) core.providers.Provider {
            return core.providers.Provider.from(@This(), self, start);
        }

        fn start(self: *@This(), _: core.providers.Req) !core.providers.Stream {
            self.starts += 1;
            const stream = try self.alloc.create(RetryStream);
            stream.* = .{
                .alloc = self.alloc,
                .evs = if (self.starts == 1) &first else &second,
            };
            return core.providers.Stream.from(RetryStream, stream, RetryStream.next, RetryStream.deinit);
        }
    };
    var provider_impl = RetryProvider{ .alloc = std.testing.allocator };

    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();
    var tools_rt = core.tools.builtin.Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = core.tools.builtin.mask_all,
    });
    const dir = try tmp.dir.openDir("sess", .{ .iterate = true });
    var fs_store = try core.session.fs_store.Store.init(.{
        .alloc = std.testing.allocator,
        .dir = dir,
        .flush = .{
            .always = {},
        },
        .replay = .{},
    });
    defer fs_store.deinit();
    var sid = try std.testing.allocator.dupe(u8, "s1");
    defer std.testing.allocator.free(sid);

    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    try runTui(
        std.testing.allocator,
        cfg,
        &sid,
        provider_impl.asProvider(),
        fs_store.asSessionStore(),
        &pol,
        &tools_rt,
        eofReader(),
        out_fbs.writer().any(),
        "sess",
        false,
        null,
        false,
        .{},
        .{
            .stdin_fd = stdin_pipe[0],
            .live = true,
            .raw_mode = false,
            .stop_after_completions = 1,
            .submit_text = "ping",
        },
    );

    var session_dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer session_dir.close();
    var rdr = try core.session.ReplayReader.init(std.testing.allocator, session_dir, sid, .{});
    defer rdr.deinit();

    var events = std.ArrayList(u8).empty;
    defer events.deinit(std.testing.allocator);
    const w = events.writer(std.testing.allocator);
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| try w.print("prompt:{s}\n", .{p.text}),
            .text => |t| try w.print("text:{s}\n", .{t.text}),
            else => {},
        }
    }
    const plain_out = try tui_transcript.stripAnsi(std.testing.allocator, out_fbs.getWritten());
    defer std.testing.allocator.free(plain_out);

    const Snap = struct {
        retry_ct: u8,
        saw_notice: bool,
        saw_retry_text: bool,
        events: []const u8,
    };
    try oh.snap(@src(),
        \\app.runtime.test.runtime tui overflow retries once with injected live stdin.Snap
        \\  .retry_ct: u8 = 2
        \\  .saw_notice: bool = true
        \\  .saw_retry_text: bool = true
        \\  .events: []const u8
        \\    "prompt:ping
        \\prompt:ping
        \\text:retry-ok
        \\"
    ).expectEqual(Snap{
        .retry_ct = provider_impl.starts,
        .saw_notice = std.mem.indexOf(u8, plain_out, "overflow detected:") != null and
            std.mem.indexOf(u8, plain_out, "retrying") != null,
        .saw_retry_text = std.mem.indexOf(u8, events.items, "text:retry-ok\n") != null,
        .events = events.items,
    });
}

test "runtime tui reports error when no provider available" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = "ping",
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = null,
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "provider unavailable") != null);
}

test "runtime print reports unsupported native provider without provider_cmd" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "google"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = null,
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    try std.testing.expectError(
        error.ProviderStopped,
        execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any()),
    );

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "native provider unavailable") != null);
}

test "runtime tui consumes multiple prompts from input stream" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "users=$(printf '%s' \"$req\" | grep -o '\"role\":\"user\"' | wc -l | tr -d '[:space:]'); " ++
        "printf 'text:u%s\\nstop:done\\n' \"$users\"";

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("first\nsecond\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "u1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "u2") != null);

    var session_dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer session_dir.close();
    var rdr = try core.session.ReplayReader.init(std.testing.allocator, session_dir, sid, .{});
    defer rdr.deinit();

    var prompt_ct: usize = 0;
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| {
                if (prompt_ct == 0) try std.testing.expectEqualStrings("first", p.text);
                if (prompt_ct == 1) try std.testing.expectEqualStrings("second", p.text);
                prompt_ct += 1;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), prompt_ct);
}

test "runtime tui rejects blank-only stdin input" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("\n\r\n\n");
    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    try std.testing.expectError(
        error.EmptyPrompt,
        execWithIo(
            std.testing.allocator,
            cfg,
            in_fbs.reader().any(),
            out_fbs.writer().any(),
        ),
    );
}

fn expectLatestSessionReused(session_sel: anytype) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    {
        const old_file = try tmp.dir.createFile("sess/100.jsonl", .{});
        defer old_file.close();
        const old_ev = try core.session.encodeEventAlloc(std.testing.allocator, .{
            .at_ms = 1,
            .data = .{
                .prompt = .{ .text = "old-100" },
            },
        });
        defer std.testing.allocator.free(old_ev);
        try old_file.writeAll(old_ev);
        try old_file.writeAll("\n");
    }
    {
        const old_file = try tmp.dir.createFile("sess/200.jsonl", .{});
        defer old_file.close();
        const old_ev = try core.session.encodeEventAlloc(std.testing.allocator, .{
            .at_ms = 1,
            .data = .{
                .prompt = .{ .text = "old-200" },
            },
        });
        defer std.testing.allocator.free(old_ev);
        try old_file.writeAll(old_ev);
        try old_file.writeAll("\n");
    }

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "new-turn",
        .session = session_sel,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:ok\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);
    try std.testing.expectEqualStrings("200", sid);

    var dir = try std.fs.openDirAbsolute(sess_abs, .{});
    defer dir.close();
    var rdr = try core.session.ReplayReader.init(std.testing.allocator, dir, "200", .{});
    defer rdr.deinit();

    const ev0 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev0.data) {
        .prompt => |p| try std.testing.expectEqualStrings("old-200", p.text),
        else => return error.TestUnexpectedResult,
    }
    var saw_new = false;
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| {
                if (std.mem.eql(u8, p.text, "new-turn")) saw_new = true;
            },
            else => {},
        }
    }
    try std.testing.expect(saw_new);
}

test "runtime continue reuses latest session id and appends new turn" {
    try expectLatestSessionReused(.cont);
}

test "runtime resume (-r) reuses latest session id and appends new turn" {
    try expectLatestSessionReused(.resm);
}

test "runtime explicit session path resumes that session id" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    {
        const old_file = try tmp.dir.createFile("sess/sid-1.jsonl", .{});
        defer old_file.close();
        const old_ev = try core.session.encodeEventAlloc(std.testing.allocator, .{
            .at_ms = 1,
            .data = .{
                .prompt = .{ .text = "old" },
            },
        });
        defer std.testing.allocator.free(old_ev);
        try old_file.writeAll(old_ev);
        try old_file.writeAll("\n");
    }

    const sid_path = try tmp.dir.realpathAlloc(std.testing.allocator, "sess/sid-1.jsonl");
    defer std.testing.allocator.free(sid_path);

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "new",
        .session = .{ .explicit = sid_path },
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:ok\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);
    try std.testing.expectEqualStrings("sid-1", sid);
}

test "runtime no session mode does not persist jsonl files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .no_session = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    var sess_dir = try std.fs.openDirAbsolute(sess_abs, .{ .iterate = true });
    defer sess_dir.close();
    var it = sess_dir.iterate();
    try std.testing.expect((try it.next()) == null);
}

test "runtime tool mask filters builtins used by loop registry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"tool_result\"'; then " ++
        "printf 'text:done\\nstop:done\\n'; " ++
        "else " ++
        "printf 'tool_call:call-1|bash|{\"cmd\":\"printf hi\"}\\nstop:tool\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ship",
        .tool_mask = core.tools.builtin.mask_read,
        .verbose = true,
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        null,
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "tool_result id=\"call-1\" is_err=true") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "tool-not-found:bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "stop reason=done") != null);
}

test "runtime json mode emits JSON lines for loop events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .json,
        .prompt = "ping",
        .cfg = .{
            .mode = .json,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"session\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"provider\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "pong") != null);
}

test "runtime print mode uses configured model and provider" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "model=$(printf '%s' \"$req\" | grep -o '\"model\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "prov=$(printf '%s' \"$req\" | grep -o '\"provider\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:model=%s provider=%s\\nstop:done\\n' \"$model\" \"$prov\"";

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "cfg-model"),
            .provider = try std.testing.allocator.dupe(u8, "cfg-provider"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [2048]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "model=cfg-model provider=cfg-provider") != null);
}

test "runtime json mode uses configured model and stdin prompts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "model=$(printf '%s' \"$req\" | grep -o '\"model\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "prov=$(printf '%s' \"$req\" | grep -o '\"provider\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:model=%s provider=%s\\nstop:done\\n' \"$model\" \"$prov\"";

    var cfg = cli.Run{
        .mode = .json,
        .prompt = null,
        .cfg = .{
            .mode = .json,
            .model = try std.testing.allocator.dupe(u8, "cfg-json-model"),
            .provider = try std.testing.allocator.dupe(u8, "cfg-json-provider"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("from-stdin\n");
    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "model=cfg-json-model provider=cfg-json-provider") != null);
}

test "runtime json mode errors on empty stdin when no prompt is supplied" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .json,
        .prompt = null,
        .cfg = .{
            .mode = .json,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    try std.testing.expectError(
        error.EmptyPrompt,
        execWithIo(
            std.testing.allocator,
            cfg,
            eofReader(),
            out_fbs.writer().any(),
        ),
    );
}

test "execWithIo cleans orphan compact temp files on startup" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    {
        var f = try tmp.dir.createFile("sess/orphan.jsonl.compact.tmp", .{});
        f.close();
    }
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .print,
        .prompt = "ping",
        .cfg = .{
            .mode = .print,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var out_buf: [2048]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    const sid = try execWithIo(std.testing.allocator, cfg, eofReader(), out_fbs.writer().any());
    defer std.testing.allocator.free(sid);

    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("sess/orphan.jsonl.compact.tmp"));
}

test "PrintSink surfaces session write errors non-fatally" {
    var out_buf: [512]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var sink = PrintSink.init(std.testing.allocator, out_fbs.writer().any());
    defer sink.deinit();

    try sink.push(.{ .provider = .{ .text = "hello" } });
    try sink.push(.{ .session_write_err = "DiskFull" });
    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "hello\n[session write failed: DiskFull]") != null);
}

test "TuiSink surfaces session write errors in transcript" {
    var ui = try tui_harness.Ui.init(std.testing.allocator, 60, 10, "m", "p");
    defer ui.deinit();

    var out_buf: [4096]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var sink = TuiSink{
        .ui = &ui,
        .out = out_fbs.writer().any(),
    };

    try sink.push(.{ .session_write_err = "DiskFull" });

    var found = false;
    for (ui.tr.blocks.items) |blk| {
        if (std.mem.indexOf(u8, blk.buf.items, "session write failed: DiskFull") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "runBashMode include write failure is non-fatal for denied bash" {
    const StoreImpl = struct {
        fn append(_: *@This(), _: []const u8, _: core.session.Event) !void {
            return error.DiskFull;
        }
        fn replay(_: *@This(), _: []const u8) !core.session.Reader {
            return error.Unexpected;
        }
        fn deinit(_: *@This()) void {}
    };

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(StoreImpl, &store_impl, StoreImpl.append, StoreImpl.replay, StoreImpl.deinit);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try runBashMode(std.testing.allocator, &ui, .{
        .cmd = "cat ~/.pz/settings.json",
        .include = true,
    }, "sid-1", store);

    var saw_deny = false;
    var saw_write_err = false;
    for (ui.tr.blocks.items) |blk| {
        if (std.mem.indexOf(u8, blk.buf.items, "bash denied: protected path") != null) saw_deny = true;
        if (std.mem.indexOf(u8, blk.buf.items, "session write failed: DiskFull") != null) saw_write_err = true;
    }
    try std.testing.expect(saw_deny);
    try std.testing.expect(saw_write_err);
}

test "runBashMode include write failure is non-fatal for bash output" {
    const StoreImpl = struct {
        fn append(_: *@This(), _: []const u8, _: core.session.Event) !void {
            return error.DiskFull;
        }
        fn replay(_: *@This(), _: []const u8) !core.session.Reader {
            return error.Unexpected;
        }
        fn deinit(_: *@This()) void {}
    };

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(StoreImpl, &store_impl, StoreImpl.append, StoreImpl.replay, StoreImpl.deinit);

    var ui = try tui_harness.Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try runBashMode(std.testing.allocator, &ui, .{
        .cmd = "printf ok",
        .include = true,
    }, "sid-1", store);

    var saw_ok = false;
    var saw_write_err = false;
    for (ui.tr.blocks.items) |blk| {
        if (std.mem.indexOf(u8, blk.buf.items, "ok") != null) saw_ok = true;
        if (std.mem.indexOf(u8, blk.buf.items, "session write failed: DiskFull") != null) saw_write_err = true;
    }
    try std.testing.expect(saw_ok);
    try std.testing.expect(saw_write_err);
}

test "runtime rpc mode handles session model prompt and quit commands" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"cmd\":\"session\"}\n" ++
            "{\"cmd\":\"tools\",\"arg\":\"read,write\"}\n" ++
            "{\"cmd\":\"model\",\"arg\":\"m2\"}\n" ++
            "{\"cmd\":\"provider\",\"arg\":\"p2\"}\n" ++
            "{\"cmd\":\"prompt\",\"text\":\"ping\"}\n" ++
            "{\"cmd\":\"session\"}\n" ++
            "{\"cmd\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"rpc_session\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"session_file\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"session_lines\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"tools\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"tools\":\"read,write\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"model\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"provider\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"provider\":\"p2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"prompt\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"quit\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"provider\"") != null);
}

test "runtime tui slash commands execute without prompt turns" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/help\n/session\n/provider p2\n/tools read\n/settings\n/new\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "/help") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "/session") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "/model") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "/tools") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "provider set to p2") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "tools set to read") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "File:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "ID:") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Messages") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "new session") != null);
}

test "discoverSkills returns skill metadata with source" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pi/skills/review-plan");
    var skill = try tmp.dir.createFile(".pi/skills/review-plan/SKILL.md", .{});
    defer skill.close();
    try skill.writeAll(
        \\---
        \\name: review-plan
        \\description: review
        \\user_invocable: true
        \\---
        \\Body
        \\
    );

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    const skills = try discoverSkills(std.testing.allocator);
    defer core_skill.freeSkills(std.testing.allocator, skills);

    const info = core_skill.findByDirName(skills, "review-plan") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("review", info.meta.description);
    try std.testing.expectEqual(core_skill.Source.project, info.source);
}

test "handleSlashCommand falls through for user-invocable skills" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pi/skills/review-plan");
    var skill = try tmp.dir.createFile(".pi/skills/review-plan/SKILL.md", .{});
    defer skill.close();
    try skill.writeAll(
        \\---
        \\name: review-plan
        \\description: review
        \\user_invocable: true
        \\---
        \\Body
        \\
    );

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    var sid = try std.testing.allocator.dupe(u8, "sid");
    defer std.testing.allocator.free(sid);
    var model: []const u8 = "m";
    var provider: []const u8 = "p";
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |buf| std.testing.allocator.free(buf);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |buf| std.testing.allocator.free(buf);
    var tools_rt = core.tools.builtin.Runtime.init(.{ .alloc = std.testing.allocator });
    defer tools_rt.deinit();
    var bg_mgr = try bg.Mgr.init(std.testing.allocator);
    defer bg_mgr.deinit();
    var ctl_audit = RuntimeCtlAudit{ .hooks = .{} };
    var out_buf: [256]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const got = try handleSlashCommand(
        std.testing.allocator,
        "/review-plan",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        null,
        true,
        null,
        out_fbs.writer().any(),
        .{},
        &ctl_audit,
    );

    try std.testing.expectEqual(CmdRes.unhandled, got);
    try std.testing.expectEqual(@as(usize, 0), out_fbs.getWritten().len);
}

test "handleSlashCommand blocks non-user-invocable skills" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pi/skills/review-plan");
    var skill = try tmp.dir.createFile(".pi/skills/review-plan/SKILL.md", .{});
    defer skill.close();
    try skill.writeAll(
        \\---
        \\name: review-plan
        \\description: review
        \\user_invocable: false
        \\---
        \\Body
        \\
    );

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    var sid = try std.testing.allocator.dupe(u8, "sid");
    defer std.testing.allocator.free(sid);
    var model: []const u8 = "m";
    var provider: []const u8 = "p";
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |buf| std.testing.allocator.free(buf);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |buf| std.testing.allocator.free(buf);
    var tools_rt = core.tools.builtin.Runtime.init(.{ .alloc = std.testing.allocator });
    defer tools_rt.deinit();
    var bg_mgr = try bg.Mgr.init(std.testing.allocator);
    defer bg_mgr.deinit();
    var ctl_audit = RuntimeCtlAudit{ .hooks = .{} };
    var out_buf: [256]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const got = try handleSlashCommand(
        std.testing.allocator,
        "/review-plan",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        null,
        true,
        null,
        out_fbs.writer().any(),
        .{},
        &ctl_audit,
    );

    try std.testing.expectEqual(CmdRes.handled, got);
    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "skill blocked: /review-plan") != null);
}

test "TurnCtx.run binds approval context for destructive tools" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();
    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    const cwd = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd);

    const steps = [_]provider_mock.Step{
        .{
            .ev = .{ .tool_call = .{
                .id = "call-write",
                .name = "write",
                .args = "{\"path\":\"out.txt\",\"text\":\"hello\"}",
            } },
        },
        .{
            .ev = .{ .stop = .{ .reason = .done } },
        },
    };
    var scripted = try provider_mock.ScriptedProvider.init(steps[0..]);
    defer scripted.deinit();

    const ReaderImpl = struct {
        fn next(_: *@This()) !?core.session.Event {
            return null;
        }

        fn deinit(_: *@This()) void {}
    };

    const StoreImpl = struct {
        rdr: ReaderImpl = .{},

        fn append(_: *@This(), _: []const u8, _: core.session.Event) !void {}

        fn replay(self: *@This(), _: []const u8) !core.session.Reader {
            return core.session.Reader.from(ReaderImpl, &self.rdr, ReaderImpl.next, ReaderImpl.deinit);
        }

        fn deinit(_: *@This()) void {}
    };

    const ModeImpl = struct {
        fn push(_: *@This(), _: core.loop.ModeEv) !void {}
    };

    const ApproverImpl = struct {
        cached: bool = true,
        sid: []const u8 = "",
        cwd: []const u8 = "",
        policy_hash: []const u8 = "",

        fn check(self: *@This(), key: core.loop.CmdCache.Key, cached: bool) !void {
            self.cached = cached;
            self.sid = switch (key.life) {
                .session => |sid| sid,
                .expires_at_ms => return error.TestUnexpectedResult,
            };
            self.cwd = switch (key.loc) {
                .cwd => |loc| loc,
                .repo_root => return error.TestUnexpectedResult,
            };
            self.policy_hash = switch (key.policy) {
                .hash => |hash| hash,
                .version => return error.TestUnexpectedResult,
            };
        }
    };

    var store_impl = StoreImpl{};
    const store = core.session.SessionStore.from(StoreImpl, &store_impl, StoreImpl.append, StoreImpl.replay, StoreImpl.deinit);
    var mode_impl = ModeImpl{};
    const mode = core.loop.ModeSink.from(ModeImpl, &mode_impl, ModeImpl.push);
    var tools_rt = core.tools.builtin.Runtime.init(.{ .alloc = std.testing.allocator });
    defer tools_rt.deinit();
    var cmd_cache = core.loop.CmdCache.init(std.testing.allocator);
    defer cmd_cache.deinit();
    try cmd_cache.add(.{
        .tool = .write,
        .cmd = "{\"path\":\"out.txt\",\"text\":\"hello\"}",
        .loc = .{ .cwd = cwd },
        .policy = .{ .hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        .life = .{ .session = "sid-rt" },
    });
    var approver_impl = ApproverImpl{};
    const approver = core.loop.Approver.from(ApproverImpl, &approver_impl, ApproverImpl.check);

    const tctx = TurnCtx{
        .alloc = std.testing.allocator,
        .provider = scripted.asProvider(),
        .store = store,
        .pol = &pol,
        .tools_rt = &tools_rt,
        .mode = mode,
        .max_turns = 1,
        .cmd_cache = &cmd_cache,
        .approval_bind = .{ .hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
        .approval_loc = .{ .cwd = cwd },
        .approver = approver,
    };

    try tctx.run(.{
        .sid = "sid-rt",
        .prompt = "test",
        .model = "m",
    });
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const snap = try std.fmt.allocPrint(
        std.testing.allocator,
        "cached={} sid={s} cwd_match={} policy_hash={s}",
        .{
            approver_impl.cached,
            approver_impl.sid,
            std.mem.eql(u8, cwd, approver_impl.cwd),
            approver_impl.policy_hash,
        },
    );
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "cached=false sid=sid-rt cwd_match=true policy_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    ).expectEqual(snap);
}

test "handleSlashCommand blocks builtins under verified policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeRuntimePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/cmd/share", .effect = .deny },
            .{ .pattern = "runtime/cmd/*", .effect = .allow },
        },
    });

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();

    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    var sid = try std.testing.allocator.dupe(u8, "sid");
    defer std.testing.allocator.free(sid);
    var model: []const u8 = "m";
    var provider: []const u8 = "p";
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |buf| std.testing.allocator.free(buf);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |buf| std.testing.allocator.free(buf);
    var tools_rt = core.tools.builtin.Runtime.init(.{ .alloc = std.testing.allocator });
    defer tools_rt.deinit();
    var bg_mgr = try bg.Mgr.init(std.testing.allocator);
    defer bg_mgr.deinit();
    var ctl_audit = RuntimeCtlAudit{ .hooks = .{} };
    var out_buf: [256]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const got = try handleSlashCommand(
        std.testing.allocator,
        "/share",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        null,
        true,
        null,
        out_fbs.writer().any(),
        .{},
        &ctl_audit,
    );

    try std.testing.expectEqual(CmdRes.handled, got);
    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "blocked by policy: /share") != null);
}

test "handleSlashCommand export share and upgrade emit audited redacted records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const events = [_]core.session.Event{
        .{
            .at_ms = 1,
            .data = .{ .prompt = .{ .text = "authorization: bearer sk-live-secret" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .text = .{ .text = "<script>alert(1)</script>" } },
        },
        .{
            .at_ms = 3,
            .data = .{ .stop = .{ .reason = .done } },
        },
    };
    try writeSessionEventsFile(tmp, "sess/100.jsonl", &events);

    var root = try tmp.dir.openDir(".", .{});
    defer root.close();
    var guard = try path_guard.CwdGuard.enter(root);
    defer guard.deinit();

    var pol = try RuntimePolicy.load(std.testing.allocator);
    defer pol.deinit();

    const root_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_abs);
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var sid = try std.testing.allocator.dupe(u8, "100");
    defer std.testing.allocator.free(sid);
    var model: []const u8 = "m";
    var provider: []const u8 = "p";
    var model_owned: ?[]u8 = null;
    defer if (model_owned) |buf| std.testing.allocator.free(buf);
    var provider_owned: ?[]u8 = null;
    defer if (provider_owned) |buf| std.testing.allocator.free(buf);
    var tools_rt = core.tools.builtin.Runtime.init(.{ .alloc = std.testing.allocator });
    defer tools_rt.deinit();
    var bg_mgr = try bg.Mgr.init(std.testing.allocator);
    defer bg_mgr.deinit();
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    var ctl_audit = RuntimeCtlAudit{ .hooks = .{
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 999;
            }
        }.f,
        .share_gist = struct {
            fn ok(alloc: std.mem.Allocator, _: []const u8) ![]u8 {
                return try alloc.dupe(u8, "https://gist.github.test/private/secret-url");
            }
        }.ok,
        .run_upgrade = struct {
            fn ok(alloc: std.mem.Allocator, _: update_mod.AuditHooks) !update_mod.Outcome {
                return .{
                    .ok = true,
                    .msg = try alloc.dupe(u8, "already up to date\n"),
                };
            }
        }.ok,
    } };
    var out_buf: [1024]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    _ = try handleSlashCommand(
        std.testing.allocator,
        "/export team.md",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        sess_abs,
        false,
        null,
        out_fbs.writer().any(),
        ctl_audit.hooks,
        &ctl_audit,
    );

    ctl_audit.hooks.share_gist = struct {
        fn fail(_: std.mem.Allocator, _: []const u8) ![]u8 {
            return error.GistFailed;
        }
    }.fail;

    _ = try handleSlashCommand(
        std.testing.allocator,
        "/share",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        sess_abs,
        false,
        null,
        out_fbs.writer().any(),
        ctl_audit.hooks,
        &ctl_audit,
    );

    _ = try handleSlashCommand(
        std.testing.allocator,
        "/upgrade",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        sess_abs,
        false,
        null,
        out_fbs.writer().any(),
        ctl_audit.hooks,
        &ctl_audit,
    );

    ctl_audit.hooks.run_upgrade = struct {
        fn fail(alloc: std.mem.Allocator, _: update_mod.AuditHooks) !update_mod.Outcome {
            return .{
                .ok = false,
                .msg = try alloc.dupe(u8, "upgrade blocked by policy\n"),
            };
        }
    }.fail;

    _ = try handleSlashCommand(
        std.testing.allocator,
        "/upgrade",
        &sid,
        &model,
        &model_owned,
        &provider,
        &provider_owned,
        &pol,
        &tools_rt,
        &bg_mgr,
        sess_abs,
        false,
        null,
        out_fbs.writer().any(),
        ctl_audit.hooks,
        &ctl_audit,
    );

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    const export_abs = try std.fs.path.join(std.testing.allocator, &.{ root_abs, "team.md" });
    defer std.testing.allocator.free(export_abs);
    const share_abs = try std.fs.path.join(std.testing.allocator, &.{ sess_abs, "100.md" });
    defer std.testing.allocator.free(share_abs);
    const export_tag = try core.audit.redactTextAlloc(std.testing.allocator, export_abs, .mask);
    defer std.testing.allocator.free(export_tag);
    const share_tag = try core.audit.redactTextAlloc(std.testing.allocator, share_abs, .mask);
    defer std.testing.allocator.free(share_tag);
    const norm_export = try std.mem.replaceOwned(u8, std.testing.allocator, joined, export_tag, "[mask:EXPORT_PATH]");
    defer std.testing.allocator.free(norm_export);
    const norm = try std.mem.replaceOwned(u8, std.testing.allocator, norm_export, share_tag, "[mask:SHARE_PATH]");
    defer std.testing.allocator.free(norm);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":999,"sid":"runtime","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"session-export","vis":"pub"},"op":"export"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"export","argv":{"text":"[mask:96832bf7da08afc9]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"100","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:EXPORT_PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export start","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"100","argv":{"text":"[mask:EXPORT_PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"100","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:EXPORT_PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export complete","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"100","argv":{"text":"[mask:EXPORT_PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":2,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"session-export","vis":"pub"},"op":"export"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"export","argv":{"text":"[mask:96832bf7da08afc9]","vis":"mask"}},"attrs":[{"key":"path","vis":"mask","ty":"str","val":"[mask:EXPORT_PATH]"}]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":3,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"net","name":{"text":"gist","vis":"pub"},"op":"share"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"share"},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"100","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:SHARE_PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export start","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"100","argv":{"text":"[mask:SHARE_PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"100","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:SHARE_PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export complete","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"100","argv":{"text":"[mask:SHARE_PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":4,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"net","name":{"text":"gist","vis":"pub"},"op":"share"},"msg":{"text":"[mask:f32272af783cb16f]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"share"},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":5,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":6,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":7,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":999,"sid":"runtime","seq":8,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"[mask:6570e9c86ff68452]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}"
    ).expectEqual(norm);
}

test "runtime tui bg command starts and lists background jobs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/bg run sleep 1\n/bg list\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "bg started id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "id pid state code log cmd") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "bg L1 R1 D0") != null);
}

test "runtime snapshot for slash + bg flow" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/help\n/tools all\n/bg run sleep 1\n/bg list\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    const Snap = struct {
        has_help: bool,
        has_tools_set: bool,
        has_bg_started: bool,
        has_bg_list_header: bool,
        has_bg_footer: bool,
    };
    try oh.snap(@src(),
        \\app.runtime.test.runtime snapshot for slash + bg flow.Snap
        \\  .has_help: bool = true
        \\  .has_tools_set: bool = true
        \\  .has_bg_started: bool = true
        \\  .has_bg_list_header: bool = true
        \\  .has_bg_footer: bool = true
    ).expectEqual(Snap{
        .has_help = std.mem.indexOf(u8, written, "/help") != null,
        .has_tools_set = std.mem.indexOf(u8, written, "tools set to read,write,bash,edit,grep,find,ls,agent,ask,skill") != null,
        .has_bg_started = std.mem.indexOf(u8, written, "bg started id=1") != null,
        .has_bg_list_header = std.mem.indexOf(u8, written, "id pid state code log cmd") != null,
        .has_bg_footer = std.mem.indexOf(u8, written, "bg L1 R1 D0") != null,
    });
}

test "runtime rpc accepts type envelope aliases and echoes ids" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:pong\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"1\",\"type\":\"get_state\"}\n" ++
            "{\"id\":\"2\",\"type\":\"set_model\",\"provider\":\"p2\",\"model_id\":\"m2\"}\n" ++
            "{\"id\":\"3\",\"type\":\"get_commands\"}\n" ++
            "{\"id\":\"4\",\"type\":\"new_session\"}\n" ++
            "{\"id\":\"5\",\"type\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"id\":\"1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"id\":\"2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"id\":\"3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"id\":\"4\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"id\":\"5\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"set_model\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"provider\":\"p2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"rpc_commands\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"new_session\"") != null);
}

test "runtime rpc bg command starts lists and stops jobs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"1\",\"cmd\":\"bg\",\"arg\":\"run sleep 1\"}\n" ++
            "{\"id\":\"2\",\"cmd\":\"bg\",\"arg\":\"list\"}\n" ++
            "{\"id\":\"3\",\"cmd\":\"bg\",\"arg\":\"stop 1\"}\n" ++
            "{\"id\":\"4\",\"cmd\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"rpc_bg\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "bg started id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "id pid state code log cmd") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, written, "bg stop sent id=1") != null or
            std.mem.indexOf(u8, written, "bg already done id=1") != null,
    );
}

test "runtime rpc auth commands emit audited success and failure records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    try tmp.dir.makePath("home");
    {
        var bad = try tmp.dir.createFile("home-bad", .{});
        bad.close();
    }
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const bad_home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home-bad");
    defer std.testing.allocator.free(bad_home_abs);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "openai"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"1\",\"cmd\":\"login\",\"provider\":\"openai\",\"arg\":\"sk-openai-secret\"}\n" ++
            "{\"id\":\"2\",\"cmd\":\"logout\",\"provider\":\"openai\"}\n" ++
            "{\"id\":\"3\",\"cmd\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 321;
                }
            }.f,
            .auth_home = home_abs,
        },
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"rpc_auth\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "API key saved for openai") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "logged out of openai") != null);

    var fail_cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "openai"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer fail_cfg.cfg.deinit(std.testing.allocator);

    var fail_in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"4\",\"cmd\":\"login\",\"provider\":\"openai\",\"arg\":\"sk-openai-secret\"}\n" ++
            "{\"id\":\"5\",\"cmd\":\"quit\"}\n",
    );
    var fail_out_buf: [32768]u8 = undefined;
    var fail_out_fbs = std.io.fixedBufferStream(&fail_out_buf);

    const fail_sid = try execWithIoHooks(
        std.testing.allocator,
        fail_cfg,
        fail_in_fbs.reader().any(),
        fail_out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 321;
                }
            }.f,
            .auth_home = bad_home_abs,
        },
    );
    defer std.testing.allocator.free(fail_sid);

    const fail_written = fail_out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, fail_written, "\"type\":\"rpc_error\"") != null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const trace = try auditTraceSnap(arena.allocator(), rows.rows.items);
    try oh.snap(@src(),
        \\[]app.runtime.AuditEntrySnap
        \\  [0]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [1]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [2]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [3]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .notice
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save complete"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [4]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [5]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [6]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "logout"
        \\    .msg: ?[]const u8
        \\      "logout start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "stored"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [7]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .notice
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "logout"
        \\    .msg: ?[]const u8
        \\      "logout complete"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "stored"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [8]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 5
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [9]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 6
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [10]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [11]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [12]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [13]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .err
        \\    .out: core.audit.Outcome
        \\      .fail
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "[mask]"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [14]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [15]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
    ).expectEqual(trace);
}

test "runtime rpc bg commands emit audited redacted control records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"1\",\"cmd\":\"bg\",\"arg\":\"run printf done\"}\n" ++
            "{\"id\":\"2\",\"cmd\":\"bg\",\"arg\":\"list\"}\n" ++
            "{\"id\":\"3\",\"cmd\":\"bg\",\"arg\":\"stop 42\"}\n" ++
            "{\"id\":\"4\",\"cmd\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 654;
                }
            }.f,
        },
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"type\":\"rpc_bg\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "bg started id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "bg not found id=42") != null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const trace = try auditTraceSnap(arena.allocator(), rows.rows.items);
    try oh.snap(@src(),
        \\[]app.runtime.AuditEntrySnap
        \\  [0]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [1]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [2]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "start"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "start"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "cwd"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\  [3]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "start"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "start"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [1]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "pid"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [2]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "cwd"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\      [3]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "log_path"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\  [4]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 5
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [5]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 6
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [6]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 7
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [7]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 8
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [8]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 9
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [9]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 10
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [10]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 11
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "stop"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "stop"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [11]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 12
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .err
        \\    .out: core.audit.Outcome
        \\      .fail
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "stop"
        \\    .msg: ?[]const u8
        \\      "bg not found"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "stop"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [1]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "status"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "str"
        \\  [12]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 13
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [13]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 14
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "drain"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "drain"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
    ).expectEqual(trace);
}

test "runtime tui auth commands emit audited success and failure records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    try tmp.dir.makePath("home");
    {
        var bad = try tmp.dir.createFile("home-bad", .{});
        bad.close();
    }
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const bad_home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home-bad");
    defer std.testing.allocator.free(bad_home_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "openai"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/login openai sk-openai-secret\n/logout openai\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 432;
                }
            }.f,
            .auth_home = home_abs,
        },
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "API key saved for openai") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "logged out of openai") != null);

    var fail_cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "openai"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer fail_cfg.cfg.deinit(std.testing.allocator);

    var fail_in_fbs = std.io.fixedBufferStream("/login openai sk-openai-secret\n/quit\n");
    var fail_out_buf: [32768]u8 = undefined;
    var fail_out_fbs = std.io.fixedBufferStream(&fail_out_buf);

    const fail_sid = try execWithIoHooks(
        std.testing.allocator,
        fail_cfg,
        fail_in_fbs.reader().any(),
        fail_out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 432;
                }
            }.f,
            .auth_home = bad_home_abs,
        },
    );
    defer std.testing.allocator.free(fail_sid);

    const fail_written = fail_out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, fail_written, "error: login failed") != null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const trace = try auditTraceSnap(arena.allocator(), rows.rows.items);
    try oh.snap(@src(),
        \\[]app.runtime.AuditEntrySnap
        \\  [0]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [1]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [2]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [3]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .notice
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save complete"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [4]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [5]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [6]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "logout"
        \\    .msg: ?[]const u8
        \\      "logout start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "stored"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [7]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .notice
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "logout"
        \\    .msg: ?[]const u8
        \\      "logout complete"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "stored"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [8]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 5
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [9]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 6
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [10]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [11]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [12]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "api key save start"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [13]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "auth"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .auth
        \\    .sev: core.audit.Severity
        \\      .err
        \\    .out: core.audit.Outcome
        \\      .fail
        \\    .res_kind: ?core.audit.ResKind
        \\      .auth
        \\    .res_name: ?[]const u8
        \\      "openai"
        \\    .op: ?[]const u8
        \\      "save_api_key"
        \\    .msg: ?[]const u8
        \\      "[mask]"
        \\    .data_name: ?[]const u8
        \\      null
        \\    .call_id: ?[]const u8
        \\      null
        \\    .auth_mech: ?[]const u8
        \\      "api_key"
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [14]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [15]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
    ).expectEqual(trace);
}

test "runtime tui bg commands emit audited redacted control records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/bg run printf done\n/bg list\n/bg stop 42\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 765;
                }
            }.f,
        },
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "bg started id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "bg not found id=42") != null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const trace = try auditTraceSnap(arena.allocator(), rows.rows.items);
    try oh.snap(@src(),
        \\[]app.runtime.AuditEntrySnap
        \\  [0]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 1
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [1]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 2
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [2]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 3
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "start"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "start"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "cwd"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\  [3]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 4
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "start"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "start"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [1]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "pid"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [2]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "cwd"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\      [3]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "log_path"
        \\        .vis: core.audit.Vis
        \\          .mask
        \\        .ty: []const u8
        \\          "str"
        \\  [4]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 5
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [5]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 6
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [6]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 7
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [7]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 8
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [8]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 9
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [9]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 10
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [10]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 11
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "stop"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "stop"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\  [11]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 12
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .err
        \\    .out: core.audit.Outcome
        \\      .fail
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "stop"
        \\    .msg: ?[]const u8
        \\      "bg not found"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "stop"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "job_id"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
        \\      [1]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "status"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "str"
        \\  [12]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 13
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control start"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      (empty)
        \\  [13]: app.runtime.AuditEntrySnap
        \\    .sid: []const u8
        \\      "bg"
        \\    .seq: u64 = 14
        \\    .kind: core.audit.EventKind
        \\      .tool
        \\    .sev: core.audit.Severity
        \\      .info
        \\    .out: core.audit.Outcome
        \\      .ok
        \\    .res_kind: ?core.audit.ResKind
        \\      .cmd
        \\    .res_name: ?[]const u8
        \\      "bg"
        \\    .op: ?[]const u8
        \\      "list"
        \\    .msg: ?[]const u8
        \\      "bg control success"
        \\    .data_name: ?[]const u8
        \\      "bg"
        \\    .call_id: ?[]const u8
        \\      "list"
        \\    .auth_mech: ?[]const u8
        \\      null
        \\    .attrs: []const app.runtime.AuditAttrSnap
        \\      [0]: app.runtime.AuditAttrSnap
        \\        .key: []const u8
        \\          "count"
        \\        .vis: core.audit.Vis
        \\          .pub
        \\        .ty: []const u8
        \\          "uint"
    ).expectEqual(trace);
}
test "runtime reload audit snapshots start success and failure" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    var ctl_audit = RuntimeCtlAudit{ .hooks = .{
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 777;
            }
        }.f,
    } };
    var sys_prompt: ?[]const u8 = null;
    var sys_prompt_owned: ?[]u8 = null;
    defer if (sys_prompt_owned) |buf| std.testing.allocator.free(buf);

    const loaded = try reloadContextWithAudit(
        std.testing.allocator,
        &sys_prompt,
        &sys_prompt_owned,
        &ctl_audit,
        struct {
            fn f(alloc: std.mem.Allocator) !?[]u8 {
                return try alloc.dupe(u8, "ctx a");
            }
        }.f,
    );
    try std.testing.expectEqual(ReloadRes.loaded, loaded);

    const empty = try reloadContextWithAudit(
        std.testing.allocator,
        &sys_prompt,
        &sys_prompt_owned,
        &ctl_audit,
        struct {
            fn f(_: std.mem.Allocator) !?[]u8 {
                return null;
            }
        }.f,
    );
    try std.testing.expectEqual(ReloadRes.empty, empty);

    try std.testing.expectError(
        error.AccessDenied,
        reloadContextWithAudit(
            std.testing.allocator,
            &sys_prompt,
            &sys_prompt_owned,
            &ctl_audit,
            struct {
                fn f(_: std.mem.Allocator) !?[]u8 {
                    return error.AccessDenied;
                }
            }.f,
        ),
    );

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":777,"sid":"runtime","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[]}
        \\{"v":1,"ts_ms":777,"sid":"runtime","seq":2,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[{"key":"loaded","vis":"pub","ty":"bool","val":true}]}
        \\{"v":1,"ts_ms":777,"sid":"runtime","seq":3,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[]}
        \\{"v":1,"ts_ms":777,"sid":"runtime","seq":4,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[{"key":"loaded","vis":"pub","ty":"bool","val":false}]}
        \\{"v":1,"ts_ms":777,"sid":"runtime","seq":5,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[]}
        \\{"v":1,"ts_ms":777,"sid":"runtime","seq":6,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"reload"},"msg":{"text":"[mask:ce3db9ab7a88d359]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"reload"},"attrs":[]}"
    ).expectEqual(joined);
}

test "runtime rpc control commands emit audited redacted control records" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const events = [_]core.session.Event{
        .{
            .at_ms = 1,
            .data = .{ .prompt = .{ .text = "old prompt" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .text = .{ .text = "old answer" } },
        },
        .{
            .at_ms = 3,
            .data = .{ .stop = .{ .reason = .done } },
        },
    };
    try writeSessionEventsFile(tmp, "sess/100.jsonl", &events);

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"id\":\"1\",\"cmd\":\"provider\",\"arg\":\"p2\"}\n" ++
            "{\"id\":\"2\",\"type\":\"set_model\",\"provider\":\"p3\",\"model_id\":\"m2\"}\n" ++
            "{\"id\":\"3\",\"cmd\":\"tools\",\"arg\":\"bogus\"}\n" ++
            "{\"id\":\"4\",\"cmd\":\"tools\",\"arg\":\"read,skill\"}\n" ++
            "{\"id\":\"5\",\"cmd\":\"resume\",\"arg\":\"100\"}\n" ++
            "{\"id\":\"6\",\"cmd\":\"fork\",\"arg\":\"200\"}\n" ++
            "{\"id\":\"7\",\"cmd\":\"compact\"}\n" ++
            "{\"id\":\"8\",\"cmd\":\"new\"}\n" ++
            "{\"id\":\"9\",\"cmd\":\"resume\",\"arg\":\"404\"}\n" ++
            "{\"id\":\"10\",\"cmd\":\"upgrade\"}\n" ++
            "{\"id\":\"11\",\"cmd\":\"upgrade\"}\n" ++
            "{\"id\":\"12\",\"cmd\":\"quit\"}\n",
    );
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);
    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .emit_audit_ctx = &rows,
            .emit_audit = AuditRows.emit,
            .now_ms = struct {
                fn f() i64 {
                    return 888;
                }
            }.f,
            .run_upgrade = struct {
                var n: usize = 0;

                fn f(alloc: std.mem.Allocator, _: update_mod.AuditHooks) !update_mod.Outcome {
                    defer n += 1;
                    if (n == 0) {
                        return .{
                            .ok = true,
                            .msg = try alloc.dupe(u8, "already up to date\n"),
                        };
                    }
                    return .{
                        .ok = false,
                        .msg = try alloc.dupe(u8, "upgrade blocked by policy\n"),
                    };
                }
            }.f,
        },
    );
    defer std.testing.allocator.free(sid);

    var filtered = std.ArrayList([]const u8).empty;
    defer filtered.deinit(std.testing.allocator);
    for (rows.rows.items) |row| {
        if (std.mem.indexOf(u8, row, "\"sid\":\"runtime\"") == null) continue;
        try filtered.append(std.testing.allocator, row);
    }
    const joined = try std.mem.join(std.testing.allocator, "\n", filtered.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":888,"sid":"runtime","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"provider"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"provider","argv":{"text":"p2","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":2,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"provider"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"provider","argv":{"text":"p2","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":3,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"model"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"model","argv":{"text":"m2","vis":"pub"}},"attrs":[{"key":"provider","vis":"pub","ty":"str","val":"p3"}]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":4,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"model"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"model","argv":{"text":"m2","vis":"pub"}},"attrs":[{"key":"provider","vis":"pub","ty":"str","val":"p3"}]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":5,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"tools"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"tools","argv":{"text":"bogus","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":6,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"tools"},"msg":{"text":"[mask:fa8bbdf6c4af830c]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"tools","argv":{"text":"bogus","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":7,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"tools"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"tools","argv":{"text":"read,skill","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":8,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"tools"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"tools","argv":{"text":"read,skill","vis":"pub"}},"attrs":[{"key":"tools","vis":"pub","ty":"str","val":"read,skill"}]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":9,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:37774687180645c4]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":10,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:37774687180645c4]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":11,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"fork"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"fork","argv":{"text":"[mask:c0807a979f88a933]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":12,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"fork"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"fork","argv":{"text":"[mask:c0807a979f88a933]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":13,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"compact"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"compact"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":14,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"compact"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"compact"},"attrs":[{"key":"in_lines","vis":"pub","ty":"uint","val":3},{"key":"out_lines","vis":"pub","ty":"uint","val":3}]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":15,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"new"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"new"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":16,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"new"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"new"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":17,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:91910081c6428103]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":18,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"[mask:bd710b2156a1699e]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:91910081c6428103]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":19,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":20,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":21,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"runtime control start","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":888,"sid":"runtime","seq":22,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"upgrade"},"msg":{"text":"[mask:6570e9c86ff68452]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"upgrade"},"attrs":[]}"
    ).expectEqual(joined);
}

test "runtime bg command validates usage and missing ids" {
    var mgr = try bg.Mgr.init(std.testing.allocator);
    defer mgr.deinit();

    const usage = try runBgCommand(std.testing.allocator, &mgr, "");
    defer std.testing.allocator.free(usage);
    try std.testing.expectEqualStrings("usage: /bg run <cmd>|list|show <id>|stop <id>\n", usage);

    const run_usage = try runBgCommand(std.testing.allocator, &mgr, "run");
    defer std.testing.allocator.free(run_usage);
    try std.testing.expectEqualStrings("usage: /bg run <cmd>\n", run_usage);

    const show_usage = try runBgCommand(std.testing.allocator, &mgr, "show nope");
    defer std.testing.allocator.free(show_usage);
    try std.testing.expectEqualStrings("usage: /bg show <id>\n", show_usage);

    const stop_usage = try runBgCommand(std.testing.allocator, &mgr, "stop nope");
    defer std.testing.allocator.free(stop_usage);
    try std.testing.expectEqualStrings("usage: /bg stop <id>\n", stop_usage);

    const not_found = try runBgCommand(std.testing.allocator, &mgr, "show 42");
    defer std.testing.allocator.free(not_found);
    try std.testing.expectEqualStrings("bg: not found\n", not_found);

    const stop_not_found = try runBgCommand(std.testing.allocator, &mgr, "stop 42");
    defer std.testing.allocator.free(stop_not_found);
    try std.testing.expectEqualStrings("bg not found id=42\n", stop_not_found);

    const bad_sub = try runBgCommand(std.testing.allocator, &mgr, "wat");
    defer std.testing.allocator.free(bad_sub);
    try std.testing.expectEqualStrings("usage: /bg run <cmd>|list|show <id>|stop <id>\n", bad_sub);
}

test "parseCmdToolMask fuzz smoke does not panic" {
    var prng = std.Random.DefaultPrng.init(0x5EED_F00D);
    const rnd = prng.random();

    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < 2000) : (i += 1) {
        const n = rnd.intRangeAtMost(usize, 0, buf.len);
        var j: usize = 0;
        while (j < n) : (j += 1) {
            const pick = rnd.intRangeAtMost(u8, 0, 9);
            buf[j] = switch (pick) {
                0 => ',',
                1 => ' ',
                2 => 'r',
                3 => 'w',
                4 => 'b',
                5 => 'a',
                6 => 's',
                7 => 'l',
                8 => 'g',
                else => 'x',
            };
        }
        _ = parseCmdToolMask(buf[0..n]) catch {};
    }
}

test "parseCmdToolMask accepts skill" {
    const got = try parseCmdToolMask("read,skill");
    try std.testing.expectEqual(core.tools.builtin.mask_read | core.tools.builtin.mask_skill, got);
}

test "toolMaskCsvAlloc includes skill" {
    const got = try toolMaskCsvAlloc(
        std.testing.allocator,
        core.tools.builtin.mask_read | core.tools.builtin.mask_skill,
    );
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("read,skill", got);
}

test "chooseLogoutProvider picks active provider when available" {
    const logged_in = [_]core.providers.auth.Provider{ .anthropic, .openai };
    const picked = chooseLogoutProvider("anthropic", &logged_in) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(core.providers.auth.Provider.anthropic, picked);
}

test "chooseLogoutProvider falls back to single logged-in provider" {
    const logged_in = [_]core.providers.auth.Provider{.openai};
    const picked = chooseLogoutProvider("anthropic", &logged_in) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(core.providers.auth.Provider.openai, picked);
}

test "chooseLogoutProvider returns null when ambiguous" {
    const logged_in = [_]core.providers.auth.Provider{ .openai, .google };
    try std.testing.expect(chooseLogoutProvider("anthropic", &logged_in) == null);
}

test "classifyLoginInput treats anthropic empty arg as oauth start" {
    const got = classifyLoginInput(.anthropic, "");
    try std.testing.expectEqual(LoginInputKind.oauth_start, got);
}

test "classifyLoginInput keeps anthropic api key flow" {
    const got = classifyLoginInput(.anthropic, "sk-ant-api03-123");
    try std.testing.expectEqual(LoginInputKind.api_key, got);
}

test "classifyLoginInput treats anthropic callback payload as oauth complete" {
    const got = classifyLoginInput(.anthropic, "http://localhost:64915/callback?code=abc&state=def");
    try std.testing.expectEqual(LoginInputKind.oauth_complete, got);
}

test "classifyLoginInput treats openai empty arg as oauth start" {
    const got = classifyLoginInput(.openai, "");
    try std.testing.expectEqual(LoginInputKind.oauth_start, got);
}

test "classifyLoginInput keeps openai api key flow" {
    const got = classifyLoginInput(.openai, "sk-proj-123");
    try std.testing.expectEqual(LoginInputKind.api_key, got);
}

test "classifyLoginInput treats openai callback payload as oauth complete" {
    const got = classifyLoginInput(.openai, "http://localhost:1455/auth/callback?code=abc&state=def");
    try std.testing.expectEqual(LoginInputKind.oauth_complete, got);
}

test "classifyLoginInput treats openai raw query payload as oauth complete" {
    const got = classifyLoginInput(.openai, "code=abc&state=def");
    try std.testing.expectEqual(LoginInputKind.oauth_complete, got);
}

test "classifyLoginInput keeps google in api key mode" {
    const got = classifyLoginInput(.google, "");
    try std.testing.expectEqual(LoginInputKind.api_key, got);
}

test "classifyLoginInput keeps google key input in api key mode" {
    const got = classifyLoginInput(.google, "ya29-token");
    try std.testing.expectEqual(LoginInputKind.api_key, got);
}

test "resolveArgSrc maps slash command names to completion sources" {
    const models = [_][]const u8{ "m1", "m2" };

    const model_src = resolveArgSrc("/model ", &models) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("m1", model_src[0]);

    const provider_src = resolveArgSrc("/provider ", &models) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("anthropic", provider_src[0]);

    const login_src = resolveArgSrc("/login ", &models) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("openai", login_src[1]);

    const bg_src = resolveArgSrc("/bg ", &models) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("run", bg_src[0]);

    try std.testing.expect(resolveArgSrc("/unknown ", &models) == null);
    try std.testing.expect(resolveArgSrc("plain", &models) == null);
}

test "runtime bg command run show list workflow" {
    var mgr = try bg.Mgr.init(std.testing.allocator);
    defer mgr.deinit();

    const started = try runBgCommand(std.testing.allocator, &mgr, "run sleep 1");
    defer std.testing.allocator.free(started);
    try std.testing.expect(std.mem.indexOf(u8, started, "bg started id=1") != null);
    try std.testing.expect(std.mem.indexOf(u8, started, "pid=") != null);
    try std.testing.expect(std.mem.indexOf(u8, started, "log=/tmp/pz-bg-") != null);

    const shown = try runBgCommand(std.testing.allocator, &mgr, "show 1");
    defer std.testing.allocator.free(shown);
    try std.testing.expect(std.mem.indexOf(u8, shown, "id=1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, shown, "pid=") != null);
    try std.testing.expect(std.mem.indexOf(u8, shown, "state=") != null);
    try std.testing.expect(std.mem.indexOf(u8, shown, "cmd=sleep 1\n") != null);

    const listed = try runBgCommand(std.testing.allocator, &mgr, "list");
    defer std.testing.allocator.free(listed);
    try std.testing.expect(std.mem.indexOf(u8, listed, "id pid state code log cmd\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, listed, " sleep 1\n") != null);

    const stopped = try runBgCommand(std.testing.allocator, &mgr, "stop 1");
    defer std.testing.allocator.free(stopped);
    try std.testing.expect(
        std.mem.indexOf(u8, stopped, "bg stop sent id=1\n") != null or
            std.mem.indexOf(u8, stopped, "bg already done id=1\n") != null,
    );
}

test "runtime tui tools command updates tool availability per turn" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"name\":\"bash\"'; then " ++
        "printf 'text:has-bash\\nstop:done\\n'; " ++
        "else " ++
        "printf 'text:no-bash\\nstop:done\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/tools read\none\n/tools all\ntwo\n/quit\n");
    var out_buf: [65536]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "tools set to read") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "no-bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "has-bash") != null);
}

test "runtime rpc tools command updates tool availability per turn" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q '\"name\":\"bash\"'; then " ++
        "printf 'text:has-bash\\nstop:done\\n'; " ++
        "else " ++
        "printf 'text:no-bash\\nstop:done\\n'; " ++
        "fi";

    var cfg = cli.Run{
        .mode = .rpc,
        .prompt = null,
        .cfg = .{
            .mode = .rpc,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "p"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, provider_cmd),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream(
        "{\"cmd\":\"tools\",\"arg\":\"read\"}\n" ++
            "{\"cmd\":\"prompt\",\"text\":\"one\"}\n" ++
            "{\"cmd\":\"tools\",\"arg\":\"all\"}\n" ++
            "{\"cmd\":\"prompt\",\"text\":\"two\"}\n" ++
            "{\"cmd\":\"quit\"}\n",
    );
    var out_buf: [65536]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIo(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
    );
    defer std.testing.allocator.free(sid);

    const written = out_fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, written, "\"cmd\":\"tools\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "no-bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "has-bash") != null);
}

test "showLogoutOverlay builds overlay and frees on deinit" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var ui = try tui_harness.Ui.init(alloc, 80, 12, "m", "p");
    defer ui.deinit();

    // Empty providers: no overlay created, no leak.
    {
        const provs = try alloc.alloc(core.providers.auth.Provider, 0);
        defer alloc.free(provs);
        try std.testing.expect(!try showLogoutOverlay(alloc, &ui, provs));
        try std.testing.expect(ui.ov == null);
    }

    // Two providers: overlay created with dyn_items.
    {
        var provs = try alloc.alloc(core.providers.auth.Provider, 2);
        defer alloc.free(provs);
        provs[0] = .anthropic;
        provs[1] = .openai;
        try std.testing.expect(try showLogoutOverlay(alloc, &ui, provs));
        try std.testing.expect(ui.ov != null);
        try std.testing.expect(ui.ov.?.dyn_items != null);
        try oh.snap(@src(),
            \\[][]u8
            \\  [0]: []u8
            \\    "anthropic"
            \\  [1]: []u8
            \\    "openai"
        ).expectEqual(ui.ov.?.dyn_items.?);
        ui.ov.?.deinit(alloc);
        ui.ov = null;
    }
}

test "slash logout without explicit provider frees logged-in list cleanly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("sess");
    try tmp.dir.makePath("home");

    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var cfg = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, "m"),
            .provider = try std.testing.allocator.dupe(u8, "openai"),
            .session_dir = try std.testing.allocator.dupe(u8, sess_abs),
            .provider_cmd = try std.testing.allocator.dupe(u8, "cat >/dev/null; printf 'text:noop\\nstop:done\\n'"),
        },
    };
    defer cfg.cfg.deinit(std.testing.allocator);

    var in_fbs = std.io.fixedBufferStream("/login openai sk-openai-secret\n/logout\n/quit\n");
    var out_buf: [32768]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const sid = try execWithIoHooks(
        std.testing.allocator,
        cfg,
        in_fbs.reader().any(),
        out_fbs.writer().any(),
        .{
            .auth_home = home_abs,
        },
    );
    defer std.testing.allocator.free(sid);

    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "API key saved for openai") != null);
}

test "LiveTurn tracks last_stop last_err and last_model" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var lt = try LiveTurn.init(alloc);
    defer lt.deinit();

    // Enqueue stop event
    try lt.enqueueProvider(.{ .stop = .{ .reason = .max_out } });

    // Enqueue err event
    try lt.enqueueProvider(.{ .err = "bad request" });

    // Drain events
    const ev1 = lt.popProvider().?;
    defer freeProviderEv(alloc, ev1.ev);
    const ev2 = lt.popProvider().?;
    defer freeProviderEv(alloc, ev2.ev);
    try std.testing.expect(lt.popProvider() == null);

    // Overwrite err
    try lt.enqueueProvider(.{ .err = "timeout" });
    const ev3 = lt.popProvider().?;
    defer freeProviderEv(alloc, ev3.ev);
    const first = try std.fmt.allocPrint(
        alloc,
        "last_stop={s} last_err={?s} last_model={?s} seqs={},{},{}",
        .{ @tagName(lt.last_stop.?), lt.last_err, lt.last_model, ev1.seq, ev2.seq, ev3.seq },
    );
    defer alloc.free(first);
    try oh.snap(@src(),
        \\[]u8
        \\  "last_stop=max_out last_err=timeout last_model=null seqs=1,2,3"
    ).expectEqual(first);

    // Simulate turn reset
    lt.mu.lock();
    lt.last_stop = null;
    if (lt.last_err) |e| {
        alloc.free(e);
        lt.last_err = null;
    }
    if (lt.last_model) |m| {
        alloc.free(m);
        lt.last_model = null;
    }
    lt.last_model = try alloc.dupe(u8, "claude-opus-4-20250918");
    lt.mu.unlock();
    const second = try std.fmt.allocPrint(
        alloc,
        "last_stop={s} last_err={?s} last_model={?s} seqs={},{},{}",
        .{ "null", lt.last_err, lt.last_model, ev1.seq, ev2.seq, ev3.seq },
    );
    defer alloc.free(second);
    try oh.snap(@src(),
        \\[]u8
        \\  "last_stop=null last_err=null last_model=claude-opus-4-20250918 seqs=1,2,3"
    ).expectEqual(second);
}

test "LiveTurn cloneReq duplicates retained request" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var lt = try LiveTurn.init(alloc);
    defer lt.deinit();

    lt.last_req = .{
        .sid = try alloc.dupe(u8, "sess-1"),
        .prompt = try alloc.dupe(u8, "hello"),
        .model = try alloc.dupe(u8, "m-1"),
        .provider_label = try alloc.dupe(u8, "p-1"),
        .provider_opts = .{ .temp = 0.2, .max_out = 42 },
        .system_prompt = try alloc.dupe(u8, "sys"),
    };

    const dup = (try lt.cloneReq(alloc)) orelse return error.TestUnexpectedResult;
    defer {
        var req = dup;
        req.deinit(alloc);
    }
    const snap = try std.fmt.allocPrint(
        alloc,
        "sid={s} prompt={s} model={s} provider={s} temp={d} max_out={} system={s}",
        .{
            dup.sid,
            dup.prompt,
            dup.model,
            dup.provider_label,
            dup.provider_opts.temp.?,
            dup.provider_opts.max_out.?,
            dup.system_prompt.?,
        },
    );
    defer alloc.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "sid=sess-1 prompt=hello model=m-1 provider=p-1 temp=0.2 max_out=42 system=sys"
    ).expectEqual(snap);
}

test "buildSystemPrompt rejects explicit prompt under policy lock" {
    var run = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, config.model_default),
            .provider = try std.testing.allocator.dupe(u8, config.provider_default),
            .session_dir = try std.testing.allocator.dupe(u8, config.session_dir_default),
            .policy_lock = .{ .system_prompt = true },
        },
        .system_prompt = "sys",
    };
    defer run.cfg.deinit(std.testing.allocator);

    try std.testing.expectError(error.PolicyLockedSystemPrompt, buildSystemPrompt(std.testing.allocator, run));
}

test "buildSystemPrompt rejects context under policy lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "AGENTS.md", .data = "ctx" });
    const old = try std.process.getCwdAlloc(std.testing.allocator);
    defer std.testing.allocator.free(old);
    const cwd = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd);
    try std.posix.chdir(cwd);
    defer std.posix.chdir(old) catch {};

    var run = cli.Run{
        .mode = .tui,
        .prompt = null,
        .cfg = .{
            .mode = .tui,
            .model = try std.testing.allocator.dupe(u8, config.model_default),
            .provider = try std.testing.allocator.dupe(u8, config.provider_default),
            .session_dir = try std.testing.allocator.dupe(u8, config.session_dir_default),
            .policy_lock = .{ .context = true },
        },
    };
    defer run.cfg.deinit(std.testing.allocator);

    try std.testing.expectError(error.PolicyLockedContext, buildSystemPrompt(std.testing.allocator, run));
}

test "shouldRetryOverflow gates retry to real overflow in same model once" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var lt = try LiveTurn.init(alloc);
    defer lt.deinit();

    lt.last_model = try alloc.dupe(u8, "m-1");
    lt.last_stop = .max_out;
    const a = shouldRetryOverflow(alloc, &lt, "m-1", false);
    const b = shouldRetryOverflow(alloc, &lt, "m-2", false);
    const c = shouldRetryOverflow(alloc, &lt, "m-1", true);

    lt.last_stop = null;
    lt.last_err = try alloc.dupe(u8, "{\"error\":{\"code\":\"context_length_exceeded\"}}");
    const d = shouldRetryOverflow(alloc, &lt, "m-1", false);

    alloc.free(lt.last_err.?);
    lt.last_err = try alloc.dupe(u8, "400 Bad Request");
    const e = shouldRetryOverflow(alloc, &lt, "m-1", false);

    const snap = try std.fmt.allocPrint(alloc, "{any}\n{any}\n{any}\n{any}\n{any}\n", .{ a, b, c, d, e });
    defer alloc.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "true
        \\false
        \\false
        \\true
        \\false
        \\"
    ).expectEqual(snap);
}

test "shouldRetryOverflowState property: retried disables retry" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            err_text: zc.String,
            stop_max_out: bool,
        }) bool {
            return !shouldRetryOverflowState(
                std.testing.allocator,
                "m",
                if (args.stop_max_out) .max_out else null,
                args.err_text.slice(),
                "m",
                true,
            );
        }
    }.prop, .{ .iterations = 300 });
}

test "shouldRetryOverflowState property: model mismatch disables retry" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            err_text: zc.String,
            stop_max_out: bool,
        }) bool {
            return !shouldRetryOverflowState(
                std.testing.allocator,
                "model-a",
                if (args.stop_max_out) .max_out else null,
                args.err_text.slice(),
                "model-b",
                false,
            );
        }
    }.prop, .{ .iterations = 300 });
}

test "shouldRetryOverflowState property: max_out forces retry in same model" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { err_text: zc.String }) bool {
            return shouldRetryOverflowState(
                std.testing.allocator,
                "m",
                .max_out,
                args.err_text.slice(),
                "m",
                false,
            );
        }
    }.prop, .{ .iterations = 300 });
}

test "autoCompact draws compacting notice before compactor runs" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(alloc, "sess");
    defer alloc.free(sess_abs);

    var ui = try tui_harness.Ui.init(alloc, 80, 12, "m", "p");
    defer ui.deinit();
    ui.panels.ctx_limit = 100;
    ui.panels.cum_tok = 90;
    ui.panels.has_usage = true;

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const Ctx = struct {
        ui: *tui_harness.Ui,
        saw_notice: bool = false,

        fn run(raw: ?*anyopaque, _: std.mem.Allocator, _: std.fs.Dir, _: []const u8, _: i64) !CompactRun {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            for (self.ui.tr.blocks.items) |blk| {
                if (std.mem.eql(u8, blk.buf.items, "[compacting...]")) {
                    self.saw_notice = true;
                    return .compacted;
                }
            }
            return error.TestUnexpectedResult;
        }
    };

    var ctx = Ctx{ .ui = &ui };
    try std.testing.expectEqual(AutoCompactOutcome.compacted, try autoCompactWith(
        alloc,
        &ui,
        out_fbs.writer().any(),
        "sess-1",
        sess_abs,
        false,
        false,
        &ctx,
        Ctx.run,
    ));
    try std.testing.expect(ctx.saw_notice);

    var snap: std.ArrayListUnmanaged(u8) = .empty;
    defer snap.deinit(alloc);
    for (ui.tr.blocks.items, 0..) |blk, i| {
        if (i != 0) try snap.append(alloc, '\n');
        try snap.appendSlice(alloc, blk.buf.items);
    }
    const snap_txt = try snap.toOwnedSlice(alloc);
    defer alloc.free(snap_txt);

    try oh.snap(@src(),
        \\[]u8
        \\  "[compacting...]
        \\[session compacted]"
    ).expectEqual(snap_txt);
    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "[compacting...]") != null);
}

test "autoCompact reports summary budget stop metadata" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sess");
    const sess_abs = try tmp.dir.realpathAlloc(alloc, "sess");
    defer alloc.free(sess_abs);

    var ui = try tui_harness.Ui.init(alloc, 80, 12, "m", "p");
    defer ui.deinit();
    ui.panels.ctx_limit = 100;
    ui.panels.cum_tok = 90;
    ui.panels.has_usage = true;

    var out_buf: [16384]u8 = undefined;
    var out_fbs = std.io.fixedBufferStream(&out_buf);

    const Ctx = struct {
        fn run(_: ?*anyopaque, _: std.mem.Allocator, _: std.fs.Dir, _: []const u8, _: i64) !CompactRun {
            return .{ .stopped = .{
                .outcome = .over_budget,
                .input_bytes = 90210,
                .input_tokens = 8192,
                .max_bytes = 65536,
                .max_input_tokens = 4096,
                .kept_events = 3,
                .dropped_events = 17,
            } };
        }
    };

    try std.testing.expectEqual(AutoCompactOutcome.stopped, try autoCompactWith(
        alloc,
        &ui,
        out_fbs.writer().any(),
        "sess-1",
        sess_abs,
        false,
        false,
        null,
        Ctx.run,
    ));

    var snap: std.ArrayListUnmanaged(u8) = .empty;
    defer snap.deinit(alloc);
    for (ui.tr.blocks.items, 0..) |blk, i| {
        if (i != 0) try snap.append(alloc, '\n');
        try snap.appendSlice(alloc, blk.buf.items);
    }
    const snap_txt = try snap.toOwnedSlice(alloc);
    defer alloc.free(snap_txt);

    try oh.snap(@src(),
        \\[]u8
        \\  "[compacting...]
        \\[auto-compact stopped: summary input over budget bytes=90210/65536 tokens=8192/4096 kept=3 dropped=17]"
    ).expectEqual(snap_txt);
    try std.testing.expect(std.mem.indexOf(u8, out_fbs.getWritten(), "[compacting...]") != null);
}
