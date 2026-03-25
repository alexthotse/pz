const std = @import("std");
const core = @import("../../core.zig");
const tui_harness = @import("harness.zig");
const tui_input = @import("input.zig");
const tui_editor = @import("editor.zig");
const tui_overlay = @import("overlay.zig");
const tui_term = @import("term.zig");

pub const PauseCtl = struct {
    vt: *const Vt,

    pub const Vt = struct {
        set_paused: *const fn (self: *PauseCtl, paused: bool) void,
    };

    pub fn setPaused(self: *PauseCtl, paused: bool) void {
        self.vt.set_paused(self, paused);
    }

    pub fn Bind(comptime T: type, comptime method: fn (*T, bool) void) type {
        return struct {
            pub const vt = Vt{
                .set_paused = setPausedFn,
            };
            fn setPausedFn(pc: *PauseCtl, paused: bool) void {
                const self: *T = @fieldParentPtr("pause_ctl", pc);
                method(self, paused);
            }
        };
    }
};

pub const AskUiCtx = struct {
    alloc: std.mem.Allocator,
    ui: *tui_harness.Ui,
    out: std.Io.AnyWriter,
    pause: *PauseCtl,

    pub const Answer = struct {
        id: []const u8,
        answer: []const u8,
        index: usize,
    };

    pub const StoredAnswer = struct {
        answer: ?[]u8 = null,
        index: ?usize = null,
    };

    pub const RowKind = union(enum) {
        option: usize,
        other: void,
        prev: void,
        next: void,
        submit: void,
    };

    pub const RowSet = struct {
        items: [][]u8,
        kinds: []RowKind,

        pub fn deinit(self: *RowSet, alloc: std.mem.Allocator) void {
            if (self.items.len > 0) {
                for (self.items) |item| alloc.free(item);
                alloc.free(self.items);
            }
            if (self.kinds.len > 0) alloc.free(self.kinds);
            self.items = &.{};
            self.kinds = &.{};
        }

        pub fn releaseItems(self: *RowSet) [][]u8 {
            const out = self.items;
            self.items = &.{};
            return out;
        }
    };

    pub fn runOnMain(self: *AskUiCtx, reader: *tui_input.Reader, args: core.tools.Call.AskArgs) anyerror![]u8 {
        if (args.questions.len == 0) return error.InvalidArgs;

        self.pause.setPaused(true);
        defer self.pause.setPaused(false);
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
                self.ui.draw(self.out) catch {}; // cleanup: propagation impossible
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
                        else => {}, // other keys fall through to navigation/selection below
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
                            else => {}, // .none, .cancel, .interrupt, .cycle_*, .toggle_*, .kill_to_eol, .suspend: no-op in text input
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
                        else => {}, // other keys (ctrl_*, alt_*, home, end, etc.) ignored in ask selection
                    }
                },
                .resize => {
                    if (tui_term.size(std.posix.STDOUT_FILENO)) |sz| {
                        try self.ui.resize(sz.w, sz.h);
                    }
                },
                .none => continue,
                .err => return error.TerminalSetupFailed,
                else => {}, // .mouse, .paste, .notify not used in ask UI
            }
        }
    }

    fn setStoredAnswer(self: *AskUiCtx, dst: *StoredAnswer, text: []const u8, index: usize) !void {
        if (dst.answer) |old| self.alloc.free(old);
        dst.answer = try self.alloc.dupe(u8, text);
        dst.index = index;
    }
};

pub fn collectAskAnswers(
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

pub fn firstUnanswered(stored: []const AskUiCtx.StoredAnswer) ?usize {
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

pub fn buildAskRows(
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

pub fn buildAskResult(alloc: std.mem.Allocator, cancelled: bool, answers: []const AskUiCtx.Answer) ![]u8 {
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
