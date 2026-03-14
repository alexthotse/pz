//! Conversation transcript: scrollable message history panel.
const std = @import("std");
const core = @import("../../core.zig");
const frame = @import("frame.zig");
const tool_display = @import("tool_display.zig");
const markdown = @import("markdown.zig");
const theme = @import("theme.zig");
const wc = @import("wcwidth.zig");

pub const Rect = struct {
    x: usize,
    y: usize,
    w: usize,
    h: usize,
};

const image = @import("image.zig");

const Kind = enum { text, user, thinking, tool, err, meta, image };

const ToolPhase = enum { none, call, result };

const LineMode = enum { wrap, ellipsis };

const Span = struct {
    start: usize, // byte offset in buf
    end: usize, // byte offset in buf
    st: frame.Style,
};

const Block = struct {
    seq: u64 = 0,
    kind: Kind,
    buf: std.ArrayListUnmanaged(u8),
    st: frame.Style,
    spans: std.ArrayListUnmanaged(Span) = .empty,
    tool_gid: u64 = 0,
    tool_phase: ToolPhase = .none,
    line_mode: LineMode = .wrap,

    pub fn deinit(self: *Block, alloc: std.mem.Allocator) void {
        self.spans.deinit(alloc);
        self.buf.deinit(alloc);
    }

    pub fn text(self: *const Block) []const u8 {
        return self.buf.items;
    }

    fn styleAt(self: *const Block, pos: usize) frame.Style {
        for (self.spans.items) |s| {
            if (s.start > pos) break; // spans sorted by start
            if (pos >= s.start and pos < s.end) return s.st;
        }
        return self.st;
    }

    fn hasSpans(self: *const Block) bool {
        return self.spans.items.len > 0;
    }
};

pub const ImageRef = struct {
    path: []const u8, // borrowed from block
    y: usize, // screen row
    w: usize, // available width
};

pub const Transcript = struct {
    alloc: std.mem.Allocator,
    blocks: std.ArrayListUnmanaged(Block) = .empty,
    next_seq: u64 = 1,
    md: markdown.Renderer = .{},
    scroll_off: usize = 0,
    show_tools: bool = true,
    show_thinking: bool = true,
    img_refs: [8]ImageRef = undefined,
    img_ref_n: u8 = 0,

    pub fn scrollUp(self: *Transcript, n: usize) void {
        self.scroll_off +|= n;
    }

    pub fn scrollDown(self: *Transcript, n: usize) void {
        if (n >= self.scroll_off) {
            self.scroll_off = 0;
        } else {
            self.scroll_off -= n;
        }
    }

    pub fn scrollToBottom(self: *Transcript) void {
        self.scroll_off = 0;
    }

    pub const AppendError = std.mem.Allocator.Error || error{InvalidUtf8};
    pub const RenderError = frame.Frame.PosError || error{InvalidUtf8};

    pub fn init(alloc: std.mem.Allocator) Transcript {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Transcript) void {
        for (self.blocks.items) |*b| b.deinit(self.alloc);
        self.blocks.deinit(self.alloc);
        self.* = undefined;
    }

    pub fn count(self: *const Transcript) usize {
        return self.blocks.items.len;
    }

    pub fn append(self: *Transcript, ev: core.providers.Event) AppendError!void {
        return self.appendSeq(self.takeSeq(), ev);
    }

    pub fn appendSeq(self: *Transcript, seq: u64, ev: core.providers.Event) AppendError!void {
        switch (ev) {
            .text => |t| {
                // Coalesce consecutive text events
                if (self.blocks.items.len > 0) {
                    const last = &self.blocks.items[self.blocks.items.len - 1];
                    if (last.kind == .text and last.seq <= seq) {
                        try ensureUtf8(t);
                        try last.buf.appendSlice(self.alloc, t);
                        return;
                    }
                }
                _ = try self.pushBlock(seq, .text, t, .{});
            },
            .thinking => |t| {
                // Coalesce consecutive thinking events
                if (self.blocks.items.len > 0) {
                    const last = &self.blocks.items[self.blocks.items.len - 1];
                    if (last.kind == .thinking and last.seq <= seq) {
                        try ensureUtf8(t);
                        try last.buf.appendSlice(self.alloc, t);
                        return;
                    }
                }
                _ = try self.pushBlock(seq, .thinking, t, .{
                    .fg = theme.get().thinking_fg,
                    .italic = true,
                });
            },
            .tool_call => |tc| {
                // Format like pi: " $ command args" for bash,
                // " $ tool_name path" for file tools, etc.
                const display = fmtToolCall(self.alloc, tc.name, tc.args) catch
                    try std.fmt.allocPrint(self.alloc, " $ {s}", .{tc.name});
                defer self.alloc.free(display);
                const idx = try self.pushBlock(seq, .tool, display, .{
                    .fg = theme.get().dim,
                    .bg = theme.get().tool_pending_bg,
                });
                if (std.mem.eql(u8, tc.name, "bash")) {
                    self.blocks.items[idx].line_mode = .ellipsis;
                }
                self.tagToolAt(idx, toolGroup(tc.id), .call);
            },
            .tool_result => |tr| {
                const gid = toolGroup(tr.id);
                self.setToolCallStatus(gid, tr.is_err);
                if (tr.is_err) {
                    const idx = try self.pushAnsi(seq, .err, "", .{}, tr.out, .{
                        .fg = theme.get().err,
                        .bg = theme.get().tool_error_bg,
                    });
                    self.tagToolAt(idx, gid, .result);
                } else {
                    // Show result with collapsing like pi
                    const idx = try self.pushToolResult(seq, tr.out);
                    self.tagToolAt(idx, gid, .result);
                }
            },
            .err => |t| _ = try self.pushFmt(seq, .err, "[err] {s}", .{t}, .{
                .fg = theme.get().err,
                .bold = true,
                .bg = theme.get().tool_error_bg,
            }),
            // Usage and stop are tracked in panels, not shown in transcript
            .usage => {},
            .stop => {},
        }
    }

    pub fn userText(self: *Transcript, t: []const u8) AppendError!void {
        _ = try self.pushBlock(self.takeSeq(), .user, t, .{ .bg = theme.get().user_msg_bg });
    }

    pub fn infoText(self: *Transcript, t: []const u8) AppendError!void {
        _ = try self.pushBlock(self.takeSeq(), .meta, t, .{ .fg = theme.get().dim });
    }

    pub fn styledText(self: *Transcript, t: []const u8, st: frame.Style) AppendError!void {
        _ = try self.pushBlock(self.takeSeq(), .meta, t, st);
    }

    pub fn imageBlock(self: *Transcript, path: []const u8) AppendError!void {
        _ = try self.pushBlock(self.takeSeq(), .image, path, .{ .fg = theme.get().dim });
    }

    pub fn pushAnsiText(self: *Transcript, ansi_text: []const u8) AppendError!void {
        _ = try self.pushAnsi(self.takeSeq(), .meta, "", .{}, ansi_text, .{});
    }

    pub fn render(self: *Transcript, frm: *frame.Frame, rect: Rect) RenderError!void {
        self.img_ref_n = 0;
        if (rect.w == 0 or rect.h == 0) return;

        _ = try rectEndX(frm, rect);
        _ = try rectEndY(frm, rect);
        // 1-col left padding matching pi
        const pad: usize = if (rect.w > 2) 1 else 0;
        const content_x = rect.x + pad;
        const avail_w = rect.w - pad;

        // Count total display lines at scrollbar-reserved width (single pass).
        // Using avail_w - 1 means: if overflow, count is already correct;
        // if no overflow, we use full avail_w for rendering (the slightly
        // wider width can only reduce line count, so no-overflow is stable).
        const bar_w: usize = if (avail_w >= 2) 1 else 0;
        const count_w = avail_w - bar_w;
        var total: usize = 0;
        var prev_vis: ?*Block = null;
        for (self.blocks.items) |*b| {
            if (!self.blockVisible(b)) continue;
            const blk_rows = blockLineCount(b, count_w);
            if (blk_rows == 0) continue;
            if (prev_vis) |prev| {
                if (needsGap(prev, b)) total += 1;
            }
            total += blk_rows;
            prev_vis = b;
        }
        if (total == 0) return;

        const has_bar = total > rect.h and bar_w > 0;
        const text_w = if (has_bar) count_w else avail_w;

        // Auto-scroll when scroll_off == 0, otherwise respect manual offset
        const max_skip = if (total > rect.h) total - rect.h else 0;
        const clamped_off = @min(self.scroll_off, max_skip);
        var skip = if (self.scroll_off == 0)
            max_skip
        else if (max_skip > clamped_off)
            max_skip - clamped_off
        else
            0;
        var total_rows = total;
        render_again: while (true) {
            self.img_ref_n = 0;
            try clearRect(frm, rect);
            var skipped: usize = 0;
            var row: usize = 0;

            var md = markdown.Renderer{};
            var first_vis = true;
            var prev_rendered: ?*Block = null;
            for (self.blocks.items) |*b| {
                if (!self.blockVisible(b)) continue;
                if (blockLineCount(b, text_w) == 0) continue;

                // 1-line gap between blocks
                if (!first_vis and (prev_rendered == null or needsGap(prev_rendered.?, b))) {
                    if (skipped < skip) {
                        skipped += 1;
                    } else if (row < rect.h) {
                        row += 1;
                    }
                }
                first_vis = false;
                prev_rendered = b;

                // Image blocks: header line + reserved rows
                if (b.kind == .image) {
                    const blk_h = image.img_rows;
                    var img_skipped: usize = 0;
                    var ir: usize = 0;
                    while (ir < blk_h) : (ir += 1) {
                        if (skipped < skip) {
                            skipped += 1;
                            img_skipped += 1;
                            continue;
                        }
                        if (row >= rect.h) break;
                        const y = rect.y + row;
                        if (ir == 0) {
                            // First visible row: show header
                            _ = try frm.write(content_x, y, b.text(), b.st);
                        }
                        // Record image position (first displayed row)
                        if (ir == img_skipped and self.img_ref_n < self.img_refs.len) {
                            self.img_refs[self.img_ref_n] = .{
                                .path = b.text(),
                                .y = y,
                                .w = text_w,
                            };
                            self.img_ref_n += 1;
                        }
                        row += 1;
                    }
                    continue;
                }

                const txt = self.blockDisplayText(b);
                const use_md = b.kind == .text or b.kind == .user;
                if (use_md) {
                    md = .{};
                    var md_wit = mdWrapIter(txt, text_w);
                    var pending_md: ?[]const u8 = null;
                    while (true) {
                        const line = if (pending_md) |p| blk: {
                            pending_md = null;
                            break :blk p;
                        } else md_wit.next() orelse break;

                        // Detect a markdown table block (header + separator + rows)
                        if (isMdTableLine(line)) {
                            if (md_wit.next()) |sep_line| {
                                if (isMdTableSepLine(sep_line)) {
                                    var table_lines_buf: [64][]const u8 = undefined;
                                    var table_n: usize = 0;
                                    table_lines_buf[table_n] = line;
                                    table_n += 1;
                                    table_lines_buf[table_n] = sep_line;
                                    table_n += 1;

                                    while (md_wit.next()) |tbl_line| {
                                        if (!isMdTableLine(tbl_line)) {
                                            pending_md = tbl_line;
                                            break;
                                        }
                                        if (table_n < table_lines_buf.len) {
                                            table_lines_buf[table_n] = tbl_line;
                                            table_n += 1;
                                        }
                                    }

                                    const table_lines = table_lines_buf[0..table_n];
                                    const layout = computeMdTableLayout(table_lines, text_w);
                                    const data_n: usize = if (table_lines.len > 2) table_lines.len - 2 else 0;

                                    // top border
                                    if (skipped < skip) {
                                        skipped += 1;
                                    } else if (row < rect.h) {
                                        const y = rect.y + row;
                                        if (!b.st.bg.isDefault()) {
                                            var x: usize = rect.x;
                                            while (x < rect.x + rect.w) : (x += 1) {
                                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                            }
                                        }
                                        try renderMdTableRule(frm, content_x, y, text_w, layout, b.st, .top);
                                        row += 1;
                                    }

                                    // header row
                                    const header_line = table_lines[0];
                                    if (skipped < skip) {
                                        skipped += 1;
                                        md.advanceSkipped(header_line);
                                    } else if (row < rect.h) {
                                        const y = rect.y + row;
                                        if (!b.st.bg.isDefault()) {
                                            var x: usize = rect.x;
                                            while (x < rect.x + rect.w) : (x += 1) {
                                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                            }
                                        }
                                        try renderMdTableRowAligned(frm, content_x, y, text_w, header_line, layout, b.st, true);
                                        row += 1;
                                    }

                                    // header/data separator
                                    if (skipped < skip) {
                                        skipped += 1;
                                    } else if (row < rect.h) {
                                        const y = rect.y + row;
                                        if (!b.st.bg.isDefault()) {
                                            var x: usize = rect.x;
                                            while (x < rect.x + rect.w) : (x += 1) {
                                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                            }
                                        }
                                        try renderMdTableRule(frm, content_x, y, text_w, layout, b.st, .mid);
                                        row += 1;
                                    }

                                    var di: usize = 0;
                                    while (di < data_n) : (di += 1) {
                                        const data_line = table_lines[2 + di];
                                        if (skipped < skip) {
                                            skipped += 1;
                                            md.advanceSkipped(data_line);
                                        } else if (row < rect.h) {
                                            const y = rect.y + row;
                                            if (!b.st.bg.isDefault()) {
                                                var x: usize = rect.x;
                                                while (x < rect.x + rect.w) : (x += 1) {
                                                    try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                                }
                                            }
                                            try renderMdTableRowAligned(frm, content_x, y, text_w, data_line, layout, b.st, false);
                                            row += 1;
                                        }

                                        if (di + 1 < data_n) {
                                            if (skipped < skip) {
                                                skipped += 1;
                                            } else if (row < rect.h) {
                                                const y = rect.y + row;
                                                if (!b.st.bg.isDefault()) {
                                                    var x: usize = rect.x;
                                                    while (x < rect.x + rect.w) : (x += 1) {
                                                        try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                                    }
                                                }
                                                try renderMdTableRule(frm, content_x, y, text_w, layout, b.st, .mid);
                                                row += 1;
                                            }
                                        }
                                    }

                                    // bottom border
                                    if (skipped < skip) {
                                        skipped += 1;
                                    } else if (row < rect.h) {
                                        const y = rect.y + row;
                                        if (!b.st.bg.isDefault()) {
                                            var x: usize = rect.x;
                                            while (x < rect.x + rect.w) : (x += 1) {
                                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                                            }
                                        }
                                        try renderMdTableRule(frm, content_x, y, text_w, layout, b.st, .bottom);
                                        row += 1;
                                    }
                                    continue;
                                }
                                pending_md = sep_line;
                            }
                        }

                        if (skipped < skip) {
                            skipped += 1;
                            md.advanceSkipped(line);
                            continue;
                        }
                        if (row >= rect.h) break;

                        const y = rect.y + row;

                        if (!b.st.bg.isDefault()) {
                            var x: usize = rect.x;
                            while (x < rect.x + rect.w) : (x += 1) {
                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                            }
                        }

                        _ = try md.renderLine(frm, content_x, y, line, text_w, b.st);
                        row += 1;
                    }
                } else if (b.line_mode == .ellipsis) {
                    if (skipped < skip) {
                        skipped += 1;
                        continue;
                    }
                    if (row >= rect.h) break;

                    const y = rect.y + row;

                    if (!b.st.bg.isDefault()) {
                        var x = rect.x;
                        while (x < rect.x + rect.w) : (x += 1) {
                            try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                        }
                    }

                    _ = try writeEllipsisUtf8(frm, content_x, y, text_w, txt, b.st);
                    row += 1;
                } else {
                    var wit = wrapIter(txt, text_w);
                    while (wit.next()) |line| {
                        if (skipped < skip) {
                            skipped += 1;
                            continue;
                        }
                        if (row >= rect.h) break;

                        const y = rect.y + row;

                        // Fill bg across full width (including padding) if non-default
                        if (!b.st.bg.isDefault()) {
                            var x = rect.x;
                            while (x < rect.x + rect.w) : (x += 1) {
                                try frm.set(x, y, ' ', .{ .bg = b.st.bg });
                            }
                        }

                        if (b.hasSpans()) {
                            const base_off = @intFromPtr(line.ptr) - @intFromPtr(txt.ptr);
                            _ = try writeStyled(frm, content_x, y, line, base_off, b);
                        } else {
                            _ = try frm.write(content_x, y, line, b.st);
                        }

                        row += 1;
                    }
                }
            }

            if (row < rect.h) {
                total_rows = skipped + row;
                const exact_max_skip = total_rows -| rect.h;
                if (exact_max_skip < skip) {
                    skip = exact_max_skip;
                    continue :render_again;
                }
            }
            break :render_again;
        }

        // Scroll indicator
        if (has_bar and total_rows > rect.h) {
            const bar_x = rect.x + rect.w - 1;
            const bar_st = frame.Style{ .fg = theme.get().border_muted };
            const track_st = frame.Style{ .fg = theme.get().dim };

            const thumb_h = @max(@as(usize, 1), rect.h * rect.h / total_rows);
            const scroll_range = total_rows - rect.h;
            const track_range = if (rect.h > thumb_h) rect.h - thumb_h else 0;
            const thumb_y = if (scroll_range > 0) skip * track_range / scroll_range else 0;

            var sy: usize = 0;
            while (sy < rect.h) : (sy += 1) {
                const is_thumb = sy >= thumb_y and sy < thumb_y + thumb_h;
                const cp: u21 = if (is_thumb) 0x2588 else 0x2591;
                const st = if (is_thumb) bar_st else track_st;
                try frm.set(bar_x, rect.y + sy, cp, st);
            }
        }
    }

    fn blockVisible(self: *const Transcript, b: *const Block) bool {
        if (!self.show_tools and b.kind == .tool) return false;
        if (!self.show_thinking and b.kind == .thinking) return false;
        return true;
    }

    fn blockDisplayText(_: *const Transcript, b: *const Block) []const u8 {
        return b.text();
    }

    fn blockLineCount(b: *const Block, w: usize) usize {
        if (b.kind == .image) return image.img_rows;
        if (b.line_mode == .ellipsis) return if (w == 0) 0 else 1;
        if (b.kind == .text or b.kind == .user) return countMdLines(b.text(), w);
        return countLines(b.text(), w);
    }

    fn takeSeq(self: *Transcript) u64 {
        const seq = self.next_seq;
        self.next_seq += 1;
        return seq;
    }

    fn insertBlock(self: *Transcript, blk: Block) AppendError!usize {
        if (self.blocks.items.len == 0 or self.blocks.items[self.blocks.items.len - 1].seq <= blk.seq) {
            try self.blocks.append(self.alloc, blk);
            return self.blocks.items.len - 1;
        }
        var idx: usize = 0;
        while (idx < self.blocks.items.len and self.blocks.items[idx].seq <= blk.seq) : (idx += 1) {}
        try self.blocks.insert(self.alloc, idx, blk);
        return idx;
    }

    fn pushBlock(self: *Transcript, seq: u64, kind: Kind, t: []const u8, st: frame.Style) AppendError!usize {
        try ensureUtf8(t);
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        try buf.appendSlice(self.alloc, t);
        errdefer buf.deinit(self.alloc);
        return self.insertBlock(.{
            .seq = seq,
            .kind = kind,
            .buf = buf,
            .st = st,
        });
    }

    fn pushFmt(
        self: *Transcript,
        seq: u64,
        kind: Kind,
        comptime fmt: []const u8,
        args: anytype,
        st: frame.Style,
    ) AppendError!usize {
        const txt = try std.fmt.allocPrint(self.alloc, fmt, args);
        ensureUtf8(txt) catch {
            self.alloc.free(txt);
            return error.InvalidUtf8;
        };
        var buf: std.ArrayListUnmanaged(u8) = .{
            .items = txt,
            .capacity = txt.len,
        };
        errdefer buf.deinit(self.alloc);
        return self.insertBlock(.{
            .seq = seq,
            .kind = kind,
            .buf = buf,
            .st = st,
        });
    }

    fn pushAnsi(
        self: *Transcript,
        seq: u64,
        kind: Kind,
        comptime prefix_fmt: []const u8,
        prefix_args: anytype,
        ansi_text: []const u8,
        base_st: frame.Style,
    ) AppendError!usize {
        const prefix = try std.fmt.allocPrint(self.alloc, prefix_fmt, prefix_args);
        defer self.alloc.free(prefix);

        var parsed = try parseAnsi(self.alloc, ansi_text, base_st);
        errdefer {
            parsed.spans.deinit(self.alloc);
            parsed.buf.deinit(self.alloc);
        }

        // Shift span offsets by prefix length
        const off = prefix.len;
        for (parsed.spans.items) |*s| {
            s.start += off;
            s.end += off;
        }

        // Build final buf: prefix + parsed text
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        try buf.ensureTotalCapacity(self.alloc, off + parsed.buf.items.len);
        errdefer buf.deinit(self.alloc);
        buf.appendSliceAssumeCapacity(prefix);
        buf.appendSliceAssumeCapacity(parsed.buf.items);
        parsed.buf.deinit(self.alloc);
        parsed.buf = .empty; // prevent double-free via errdefer

        try ensureUtf8(buf.items);

        return self.insertBlock(.{
            .seq = seq,
            .kind = kind,
            .buf = buf,
            .st = base_st,
            .spans = parsed.spans,
        });
    }

    /// Show tool result, collapsing long output like pi does:
    /// "... (N earlier lines, ctrl+o to expand)"
    fn pushToolResult(self: *Transcript, seq: u64, out: []const u8) AppendError!usize {
        var shown = out;
        var shown_owned: ?[]u8 = null;
        defer if (shown_owned) |buf| self.alloc.free(buf);

        if (try formatAskResultAlloc(self.alloc, out)) |pretty| {
            shown_owned = pretty;
            shown = pretty;
        }

        const max_tail = 6; // show last N lines
        var lines: usize = 0;
        for (shown) |c| {
            if (c == '\n') lines += 1;
        }
        if (shown.len > 0 and shown[shown.len - 1] != '\n') lines += 1;

        if (lines <= max_tail + 1) {
            // Short enough: show all
            return self.pushAnsi(seq, .tool, "", .{}, shown, .{
                .fg = theme.get().tool_output,
                .bg = theme.get().tool_success_bg,
            });
        }

        // Find where the tail starts
        const hidden = lines - max_tail;
        var skip: usize = 0;
        var nl_count: usize = 0;
        for (shown, 0..) |c, idx| {
            if (c == '\n') {
                nl_count += 1;
                if (nl_count == hidden) {
                    skip = idx + 1;
                    break;
                }
            }
        }

        return self.pushAnsi(seq, .tool, " ... ({d} earlier lines, ctrl+o to expand)\n", .{hidden}, shown[skip..], .{
            .fg = theme.get().tool_output,
            .bg = theme.get().tool_success_bg,
        });
    }

    fn setToolCallStatus(self: *Transcript, gid: u64, is_err: bool) void {
        if (gid == 0) return;
        var i = self.blocks.items.len;
        while (i > 0) {
            i -= 1;
            var b = &self.blocks.items[i];
            if (b.tool_gid != gid or b.tool_phase != .call) continue;
            b.st.bg = if (is_err) theme.get().tool_error_bg else theme.get().tool_success_bg;
            return;
        }
    }

    fn tagToolAt(self: *Transcript, idx: usize, gid: u64, phase: ToolPhase) void {
        if (idx >= self.blocks.items.len) return;
        var b = &self.blocks.items[idx];
        b.tool_gid = gid;
        b.tool_phase = phase;
    }
};

fn toolGroup(id: []const u8) u64 {
    if (id.len == 0) return 0;
    return std.hash.Wyhash.hash(0, id);
}

fn needsGap(prev: *const Block, cur: *const Block) bool {
    if (prev.tool_gid != 0 and prev.tool_gid == cur.tool_gid) return false;
    return true;
}

// -- Tool call formatting --

fn fmtToolCall(alloc: std.mem.Allocator, name: []const u8, args: []const u8) ![]u8 {
    const disp = try tool_display.makeAlloc(alloc, name, args, 160);
    defer alloc.free(disp);
    return std.fmt.allocPrint(alloc, " $ {s}", .{disp});
}

const AskResult = struct {
    cancelled: bool,
    answers: []const AskAnswer,
};

const AskAnswer = struct {
    id: []const u8,
    answer: []const u8,
    index: usize,
};

fn formatAskResultAlloc(alloc: std.mem.Allocator, out: []const u8) std.mem.Allocator.Error!?[]u8 {
    const trimmed = std.mem.trim(u8, out, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '{') return null;

    const parsed = std.json.parseFromSlice(AskResult, alloc, trimmed, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    defer parsed.deinit();

    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(alloc);

    if (parsed.value.cancelled) {
        try buf.appendSlice(alloc, "ask: cancelled");
        return try buf.toOwnedSlice(alloc);
    }
    if (parsed.value.answers.len == 0) {
        try buf.appendSlice(alloc, "ask: no answers");
        return try buf.toOwnedSlice(alloc);
    }

    const noun = if (parsed.value.answers.len == 1) "answer" else "answers";
    try std.fmt.format(buf.writer(alloc), "ask: {d} {s}\n", .{ parsed.value.answers.len, noun });
    for (parsed.value.answers, 0..) |ans, i| {
        _ = ans.index;
        try std.fmt.format(buf.writer(alloc), "  - {s}: {s}", .{ ans.id, ans.answer });
        if (i + 1 < parsed.value.answers.len) try buf.append(alloc, '\n');
    }
    return try buf.toOwnedSlice(alloc);
}

// -- Word wrap --

pub const WrapIter = struct {
    text: []const u8,
    pos: usize,
    w: usize,

    pub fn next(self: *WrapIter) ?[]const u8 {
        if (self.w == 0) return null;
        if (self.pos >= self.text.len) return null;

        // Check for trailing position after final \n
        const start = self.pos;
        var i = start;
        var cols: usize = 0;

        while (i < self.text.len) {
            // Check for newline
            if (self.text[i] == '\n') {
                const line = self.text[start..i];
                self.pos = i + 1;
                // If this \n is the last char, and we haven't seen content,
                // need to check if we're at end
                return line;
            }

            // Decode codepoint
            const n = std.unicode.utf8ByteSequenceLength(self.text[i]) catch 1;
            const cp_end = @min(i + n, self.text.len);
            const cp = std.unicode.utf8Decode(self.text[i..cp_end]) catch 0xFFFD;

            const cw: usize = if (cp == '\t') 1 else wc.wcwidth(cp);
            cols += cw;
            if (cols > self.w) {
                // Need to break - look backward for space
                var brk = i;
                var scan = i;
                var found_space = false;
                while (scan > start) {
                    scan -= 1;
                    if (self.text[scan] == ' ' or self.text[scan] == '\t') {
                        brk = scan;
                        found_space = true;
                        break;
                    }
                }
                if (found_space) {
                    const line = self.text[start..brk];
                    self.pos = brk + 1; // skip the space
                    return line;
                } else {
                    // Hard break — must advance at least one codepoint
                    const end = if (i == start) cp_end else i;
                    const line = self.text[start..end];
                    self.pos = end;
                    return line;
                }
            }

            i = cp_end;
        }

        // Remaining text (no newline at end)
        if (start < self.text.len) {
            self.pos = self.text.len;
            return self.text[start..];
        }

        return null;
    }
};

pub fn wrapIter(text: []const u8, w: usize) WrapIter {
    return .{ .text = text, .pos = 0, .w = w };
}

pub const MdWrapIter = struct {
    text: []const u8,
    pos: usize,
    w: usize,
    line_wit: ?WrapIter = null,

    pub fn next(self: *MdWrapIter) ?[]const u8 {
        if (self.w == 0) return null;
        while (true) {
            if (self.line_wit) |*wit| {
                if (wit.next()) |seg| return seg;
                self.line_wit = null;
            }
            if (self.pos >= self.text.len) return null;

            const start = self.pos;
            var i = start;
            while (i < self.text.len and self.text[i] != '\n') : (i += 1) {}
            const line = self.text[start..i];
            self.pos = if (i < self.text.len) i + 1 else i;

            if (line.len == 0) return line;
            if (isMdTableLine(line)) return line;

            self.line_wit = wrapIter(line, self.w);
        }
    }
};

pub fn mdWrapIter(text: []const u8, w: usize) MdWrapIter {
    return .{ .text = text, .pos = 0, .w = w };
}

fn isMdTableLine(line: []const u8) bool {
    const t = std.mem.trimLeft(u8, line, " \t");
    return t.len > 0 and t[0] == '|';
}

fn isMdTableSepLine(line: []const u8) bool {
    const t = std.mem.trimLeft(u8, line, " \t");
    if (t.len < 3 or t[0] != '|') return false;
    for (t) |c| {
        switch (c) {
            '|', '-', ':', ' ', '\t' => {},
            else => return false,
        }
    }
    return std.mem.indexOfScalar(u8, t, '-') != null;
}

const table_max_cols: usize = 32;
const MdTableLayout = struct {
    ncols: usize,
    widths: [table_max_cols]usize,
};

fn splitMdTableCells(line: []const u8, buf: *[table_max_cols][]const u8) usize {
    const t = std.mem.trimLeft(u8, line, " \t");
    var rest = t;
    if (rest.len > 0 and rest[0] == '|') rest = rest[1..];
    if (rest.len > 0 and rest[rest.len - 1] == '|') rest = rest[0 .. rest.len - 1];

    var n: usize = 0;
    while (rest.len > 0 and n < buf.len) {
        if (std.mem.indexOfScalar(u8, rest, '|')) |pipe| {
            buf[n] = std.mem.trim(u8, rest[0..pipe], " \t");
            n += 1;
            rest = rest[pipe + 1 ..];
        } else {
            buf[n] = std.mem.trim(u8, rest, " \t");
            n += 1;
            break;
        }
    }
    return n;
}

fn computeMdTableLayout(lines: []const []const u8, max_w: usize) MdTableLayout {
    var layout = MdTableLayout{
        .ncols = 0,
        .widths = std.mem.zeroes([table_max_cols]usize),
    };
    var cells_buf: [table_max_cols][]const u8 = undefined;

    for (lines) |line| {
        const ncells = splitMdTableCells(line, &cells_buf);
        if (ncells > layout.ncols) layout.ncols = ncells;
        if (isMdTableSepLine(line)) continue;

        var i: usize = 0;
        while (i < ncells and i < layout.widths.len) : (i += 1) {
            const w = @max(@as(usize, 1), wc.strwidth(cells_buf[i]));
            if (w > layout.widths[i]) layout.widths[i] = w;
        }
    }

    if (layout.ncols == 0) return layout;

    var i: usize = 0;
    while (i < layout.ncols) : (i += 1) {
        if (layout.widths[i] == 0) layout.widths[i] = 1;
    }

    const overhead = 1 + 3 * layout.ncols; // "│" + per-cell " " + content + " " + "│"
    if (max_w <= overhead) {
        i = 0;
        while (i < layout.ncols) : (i += 1) layout.widths[i] = 1;
        return layout;
    }

    const avail_content = max_w - overhead;
    var total_content: usize = 0;
    i = 0;
    while (i < layout.ncols) : (i += 1) total_content += layout.widths[i];

    while (total_content > avail_content) {
        var widest_idx: ?usize = null;
        var widest: usize = 0;
        i = 0;
        while (i < layout.ncols) : (i += 1) {
            const w = layout.widths[i];
            if (w > widest and w > 1) {
                widest = w;
                widest_idx = i;
            }
        }
        if (widest_idx == null) break;
        layout.widths[widest_idx.?] -= 1;
        total_content -= 1;
    }

    return layout;
}

const MdTableRule = enum {
    top,
    mid,
    bottom,
};

fn renderMdTableRule(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    layout: MdTableLayout,
    base_st: frame.Style,
    rule: MdTableRule,
) frame.Frame.PosError!void {
    if (max_w == 0 or layout.ncols == 0) return;

    const border_st = frame.Style{
        .fg = theme.get().border_muted,
        .bg = base_st.bg,
    };

    const left_cp: u21 = switch (rule) {
        .top => 0x250C, // ┌
        .mid => 0x251C, // ├
        .bottom => 0x2514, // └
    };
    const mid_cp: u21 = switch (rule) {
        .top => 0x252C, // ┬
        .mid => 0x253C, // ┼
        .bottom => 0x2534, // ┴
    };
    const right_cp: u21 = switch (rule) {
        .top => 0x2510, // ┐
        .mid => 0x2524, // ┤
        .bottom => 0x2518, // ┘
    };

    var col: usize = 0;
    if (col < max_w) {
        try frm.set(x + col, y, left_cp, border_st);
        col += 1;
    }

    var ci: usize = 0;
    while (ci < layout.ncols) : (ci += 1) {
        const seg_w = layout.widths[ci] + 2; // left/right padding spaces around cell text
        var k: usize = 0;
        while (k < seg_w and col < max_w) : (k += 1) {
            try frm.set(x + col, y, 0x2500, border_st); // ─
            col += 1;
        }
        if (col < max_w) {
            const cp = if (ci + 1 < layout.ncols) mid_cp else right_cp;
            try frm.set(x + col, y, cp, border_st);
            col += 1;
        }
    }
}

fn renderMdTableRowAligned(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    line: []const u8,
    layout: MdTableLayout,
    base_st: frame.Style,
    is_header: bool,
) (frame.Frame.PosError || error{InvalidUtf8})!void {
    if (max_w == 0 or layout.ncols == 0) return;

    const border_st = frame.Style{
        .fg = theme.get().border_muted,
        .bg = base_st.bg,
    };

    var col: usize = 0;

    var cells_buf: [table_max_cols][]const u8 = undefined;
    const ncells = splitMdTableCells(line, &cells_buf);

    if (col < max_w) {
        try frm.set(x + col, y, 0x2502, border_st); // │
        col += 1;
    }

    var ci: usize = 0;
    while (ci < layout.ncols) : (ci += 1) {
        if (col < max_w) {
            try frm.set(x + col, y, ' ', base_st);
            col += 1;
        }

        const cell = if (ci < ncells) cells_buf[ci] else "";
        var cell_st = base_st;
        if (is_header) cell_st.bold = true;

        const written = try writeClippedUtf8Cols(frm, x + col, y, max_w - col, cell, layout.widths[ci], cell_st);
        col += written;

        var pad: usize = written;
        while (pad < layout.widths[ci] and col < max_w) : (pad += 1) {
            try frm.set(x + col, y, ' ', cell_st);
            col += 1;
        }

        if (col < max_w) {
            try frm.set(x + col, y, ' ', base_st);
            col += 1;
        }
        if (col < max_w) {
            try frm.set(x + col, y, 0x2502, border_st); // │
            col += 1;
        }
    }
}

fn writeClippedUtf8Cols(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    text: []const u8,
    col_limit: usize,
    st: frame.Style,
) (frame.Frame.PosError || error{InvalidUtf8})!usize {
    if (max_w == 0 or col_limit == 0 or text.len == 0) return 0;

    var col: usize = 0;
    var i: usize = 0;
    while (i < text.len and col < col_limit and col < max_w) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch return error.InvalidUtf8;
        if (i + n > text.len) return error.InvalidUtf8;
        const cp = std.unicode.utf8Decode(text[i .. i + n]) catch return error.InvalidUtf8;
        const cw = wc.wcwidth(cp);
        if (cw == 0) {
            i += n;
            continue;
        }
        if (col + cw > col_limit or col + cw > max_w) break;

        try frm.set(x + col, y, cp, st);
        if (cw == 2 and col + 1 < max_w) {
            try frm.set(x + col + 1, y, frame.Frame.wide_pad, st);
        }
        col += cw;
        i += n;
    }
    return col;
}

pub fn countLines(text: []const u8, w: usize) usize {
    if (w == 0) return 0;
    if (text.len == 0) return 0;
    var n: usize = 0;
    var it = wrapIter(text, w);
    while (it.next() != null) n += 1;
    return n;
}

fn countMdLines(text: []const u8, w: usize) usize {
    if (w == 0) return 0;
    if (text.len == 0) return 0;
    var n: usize = 0;
    var it = mdWrapIter(text, w);
    var pending: ?[]const u8 = null;
    while (true) {
        const line = if (pending) |p| blk: {
            pending = null;
            break :blk p;
        } else it.next() orelse break;

        if (isMdTableLine(line)) {
            if (it.next()) |sep_line| {
                if (isMdTableSepLine(sep_line)) {
                    var data_n: usize = 0;
                    while (it.next()) |tbl_line| {
                        if (!isMdTableLine(tbl_line)) {
                            pending = tbl_line;
                            break;
                        }
                        data_n += 1;
                    }
                    n += mdTableVisualRows(data_n);
                    continue;
                }
                pending = sep_line;
            }
        }

        n += 1;
    }
    return n;
}

fn mdTableVisualRows(data_n: usize) usize {
    // top + header + header-separator + bottom
    var out: usize = 4;
    // One visual row per data row
    out += data_n;
    // Pi-style separators between data rows
    if (data_n > 1) out += data_n - 1;
    return out;
}

// -- Per-span styled write --

fn writeStyled(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    line: []const u8,
    base_off: usize,
    blk: *const Block,
) (frame.Frame.PosError || error{InvalidUtf8})!usize {
    if (x >= frm.w or y >= frm.h) return error.OutOfBounds;
    const wcwidth = @import("wcwidth.zig").wcwidth;

    var col = x;
    var ct: usize = 0;
    var it = (std.unicode.Utf8View.init(line) catch return error.InvalidUtf8).iterator();
    var byte_pos: usize = 0;
    while (col < frm.w) {
        const cp = it.nextCodepoint() orelse break;
        const cp_len = std.unicode.utf8CodepointSequenceLength(cp) catch 1;
        const st = blk.styleAt(base_off + byte_pos);
        byte_pos += cp_len;
        // Skip control chars to prevent terminal escape leaking
        if (cp < 0x20 and cp != '\t') continue;
        if (cp == 0x7f) continue;
        // Render tab as space
        const rcp: u21 = if (cp == '\t') ' ' else cp;
        const w: usize = if (cp == '\t') 1 else wcwidth(cp);
        if (w == 0) continue;
        if (col + w > frm.w) break;
        frm.cells[y * frm.w + col] = .{ .cp = rcp, .style = st };
        if (w == 2) {
            frm.cells[y * frm.w + col + 1] = .{ .cp = frame.Frame.wide_pad, .style = st };
        }
        col += w;
        ct += 1;
    }
    return ct;
}

// -- ANSI parsing --

const ParseResult = struct {
    buf: std.ArrayListUnmanaged(u8),
    spans: std.ArrayListUnmanaged(Span),
};

pub fn parseAnsi(alloc: std.mem.Allocator, text: []const u8, base_st: frame.Style) !ParseResult {
    // Fast path: no ESC
    if (std.mem.indexOfScalar(u8, text, 0x1b) == null) {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        try buf.appendSlice(alloc, text);
        return .{ .buf = buf, .spans = .empty };
    }

    const State = enum { text, esc, csi, osc };

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    try buf.ensureTotalCapacity(alloc, text.len);
    errdefer buf.deinit(alloc);

    var spans: std.ArrayListUnmanaged(Span) = .empty;
    errdefer spans.deinit(alloc);

    var cur_st = base_st;
    var span_start: ?usize = null;
    var seq_start: usize = 0;

    var i: usize = 0;
    var state: State = .text;
    while (i < text.len) {
        state = sw: switch (state) {
            .text => {
                if (text[i] == 0x1b) {
                    i += 1;
                    continue :sw .esc;
                }
                buf.appendAssumeCapacity(text[i]);
                i += 1;
                break :sw .text; // re-enter while loop for bounds check
            },
            .esc => {
                if (i >= text.len) break :sw .text;
                switch (text[i]) {
                    '[' => {
                        i += 1;
                        seq_start = i;
                        continue :sw .csi;
                    },
                    ']' => {
                        i += 1;
                        continue :sw .osc;
                    },
                    else => {
                        // Simple ESC+char — skip
                        i += 1;
                        break :sw .text; // re-enter while loop for bounds check
                    },
                }
            },
            .csi => {
                while (i < text.len) {
                    if (text[i] >= 0x40 and text[i] <= 0x7e) {
                        const cmd = text[i];
                        i += 1;
                        if (cmd == 'm') {
                            // Close open span before style change
                            if (span_start) |ss| {
                                if (buf.items.len > ss) {
                                    try spans.append(alloc, .{
                                        .start = ss,
                                        .end = buf.items.len,
                                        .st = cur_st,
                                    });
                                }
                                span_start = null;
                            }
                            cur_st = applySgr(text[seq_start .. i - 1], base_st, cur_st);
                            if (!frame.Style.eql(cur_st, base_st)) {
                                span_start = buf.items.len;
                            }
                        }
                        break;
                    }
                    i += 1;
                }
                break :sw .text; // re-enter while loop for bounds check
            },
            .osc => {
                while (i < text.len) {
                    if (text[i] == 0x07) {
                        i += 1;
                        break;
                    }
                    if (text[i] == 0x1b and i + 1 < text.len and text[i + 1] == '\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                break :sw .text; // re-enter while loop for bounds check
            },
        };
    }

    // Close trailing span
    if (span_start) |ss| {
        if (buf.items.len > ss) {
            try spans.append(alloc, .{
                .start = ss,
                .end = buf.items.len,
                .st = cur_st,
            });
        }
    }

    return .{ .buf = buf, .spans = spans };
}

fn applySgr(params: []const u8, base: frame.Style, cur: frame.Style) frame.Style {
    var st = cur;
    var it = SgrIter{ .data = params };
    while (it.next()) |code| {
        switch (code) {
            0 => st = base,
            1 => st.bold = true,
            2 => st.dim = true,
            3 => st.italic = true,
            4 => st.underline = true,
            7 => st.inverse = true,
            22 => {
                st.bold = false;
                st.dim = false;
            },
            23 => st.italic = false,
            24 => st.underline = false,
            27 => st.inverse = false,
            30...37 => st.fg = .{ .idx = @intCast(code - 30) },
            38 => {
                if (parseExtColor(&it)) |c| st.fg = c;
            },
            39 => st.fg = base.fg,
            40...47 => st.bg = .{ .idx = @intCast(code - 40) },
            48 => {
                if (parseExtColor(&it)) |c| st.bg = c;
            },
            49 => st.bg = base.bg,
            90...97 => st.fg = .{ .idx = @intCast(code - 90 + 8) },
            100...107 => st.bg = .{ .idx = @intCast(code - 100 + 8) },
            else => {},
        }
    }
    return st;
}

fn parseExtColor(it: *SgrIter) ?frame.Color {
    const mode = it.next() orelse return null;
    switch (mode) {
        5 => {
            const n = it.next() orelse return null;
            return .{ .idx = @intCast(n & 0xff) };
        },
        2 => {
            const r = it.next() orelse return null;
            const g = it.next() orelse return null;
            const b = it.next() orelse return null;
            const rgb: u24 = (@as(u24, @intCast(r & 0xff)) << 16) |
                (@as(u24, @intCast(g & 0xff)) << 8) |
                @as(u24, @intCast(b & 0xff));
            return .{ .rgb = rgb };
        },
        else => return null,
    }
}

const SgrIter = struct {
    data: []const u8,
    pos: usize = 0,
    done: bool = false,

    fn next(self: *SgrIter) ?u16 {
        if (self.done) return null;
        if (self.pos >= self.data.len) {
            self.done = true;
            // Bare \x1b[m (empty params) => implicit reset (0)
            // Also handles trailing semicolon like "1;"
            return 0;
        }
        var val: u16 = 0;
        var found_digit = false;
        while (self.pos < self.data.len) {
            const c = self.data[self.pos];
            self.pos += 1;
            if (c == ';') return if (found_digit) val else 0;
            if (c >= '0' and c <= '9') {
                val = val *% 10 +% @as(u16, c - '0');
                found_digit = true;
            }
        }
        self.done = true;
        return if (found_digit) val else 0;
    }
};

// -- ANSI stripping (kept for non-tool blocks) --

pub fn stripAnsi(alloc: std.mem.Allocator, text: []const u8) ![]const u8 {
    // Quick check: no ESC → return original
    if (std.mem.indexOfScalar(u8, text, 0x1b) == null)
        return text;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.ensureTotalCapacity(alloc, text.len);
    errdefer out.deinit(alloc);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == 0x1b) {
            i += 1;
            if (i >= text.len) break;
            if (text[i] == '[') {
                // CSI sequence: skip until command byte (0x40-0x7e)
                i += 1;
                while (i < text.len) {
                    if (text[i] >= 0x40 and text[i] <= 0x7e) {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            } else {
                // Simple ESC+char
                i += 1;
            }
        } else {
            try out.append(alloc, text[i]);
            i += 1;
        }
    }

    return try out.toOwnedSlice(alloc);
}

// -- Utilities --

fn cpCount(text: []const u8) usize {
    return wc.strwidth(text);
}

fn ensureUtf8(text: []const u8) error{InvalidUtf8}!void {
    _ = std.unicode.Utf8View.init(text) catch return error.InvalidUtf8;
}

fn clipCols(text: []const u8, cols: usize) error{InvalidUtf8}![]const u8 {
    if (cols == 0 or text.len == 0) return text[0..0];

    var i: usize = 0;
    var used: usize = 0;
    while (i < text.len and used < cols) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch return error.InvalidUtf8;
        if (i + n > text.len) return error.InvalidUtf8;
        const cp = std.unicode.utf8Decode(text[i .. i + n]) catch return error.InvalidUtf8;
        const w = wc.wcwidth(cp);
        if (used + w > cols) break;
        i += n;
        used += w;
    }
    return text[0..i];
}

fn writeEllipsisUtf8(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    text: []const u8,
    st: frame.Style,
) (frame.Frame.PosError || error{InvalidUtf8})!usize {
    if (max_w == 0 or text.len == 0) return 0;

    const fit = try clipCols(text, max_w);
    if (fit.len == text.len or max_w <= 3) {
        if (max_w <= 3 and fit.len < text.len) {
            var i: usize = 0;
            while (i < max_w) : (i += 1) {
                try frm.set(x + i, y, '.', st);
            }
            return max_w;
        }
        return try frm.write(x, y, fit, st);
    }

    const base = try clipCols(text, max_w - 3);
    var col = try frm.write(x, y, base, st);
    var i: usize = 0;
    while (i < 3 and col < max_w) : (i += 1) {
        try frm.set(x + col, y, '.', st);
        col += 1;
    }
    return col;
}

fn rectEndX(frm: *const frame.Frame, rect: Rect) frame.Frame.PosError!usize {
    const x_end = std.math.add(usize, rect.x, rect.w) catch return error.OutOfBounds;
    if (x_end > frm.w) return error.OutOfBounds;
    return x_end;
}

fn rectEndY(frm: *const frame.Frame, rect: Rect) frame.Frame.PosError!usize {
    const y_end = std.math.add(usize, rect.y, rect.h) catch return error.OutOfBounds;
    if (y_end > frm.h) return error.OutOfBounds;
    return y_end;
}

fn clearRect(frm: *frame.Frame, rect: Rect) frame.Frame.PosError!void {
    var y: usize = 0;
    while (y < rect.h) : (y += 1) {
        var x: usize = 0;
        while (x < rect.w) : (x += 1) {
            try frm.set(rect.x + x, rect.y + y, ' ', .{});
        }
    }
}

fn rowAscii(frm: *const frame.Frame, y: usize, out: []u8) ![]const u8 {
    std.debug.assert(out.len >= frm.w);
    var x: usize = 0;
    while (x < frm.w) : (x += 1) {
        const c = try frm.cell(x, y);
        out[x] = if (c.cp <= 0x7f) @intCast(c.cp) else '?';
    }
    return out[0..frm.w];
}

fn frameRowsSnap(
    alloc: std.mem.Allocator,
    frm: *const frame.Frame,
    y0: usize,
    y1: usize,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    const raw = try alloc.alloc(u8, frm.w);
    defer alloc.free(raw);

    var y = y0;
    while (y <= y1) : (y += 1) {
        if (y != y0) try out.append(alloc, '\n');
        const row = try rowAscii(frm, y, raw);
        const trimmed = std.mem.trimRight(u8, row, " ");
        try std.fmt.format(out.writer(alloc), "{d}:{s}", .{ y, trimmed });
    }
    return out.toOwnedSlice(alloc);
}

fn allocBigMdTable(alloc: std.mem.Allocator, n: usize) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, "| H1 | H2 |\n");
    try buf.appendSlice(alloc, "| --- | --- |\n");
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try std.fmt.format(buf.writer(alloc), "| r{d} | v{d} |\n", .{ i + 1, i + 1 });
    }
    return buf.toOwnedSlice(alloc);
}

fn tableBorderCols(frm: *const frame.Frame, y: usize, out: []usize) !usize {
    var n: usize = 0;
    var x: usize = 0;
    while (x < frm.w) : (x += 1) {
        const c = try frm.cell(x, y);
        const is_border = c.cp == 0x2502 or // │
            c.cp == 0x251C or // ├
            c.cp == 0x253C or // ┼
            c.cp == 0x2524 or // ┤
            c.cp == 0x250C or // ┌
            c.cp == 0x252C or // ┬
            c.cp == 0x2510 or // ┐
            c.cp == 0x2514 or // └
            c.cp == 0x2534 or // ┴
            c.cp == 0x2518; // ┘
        if (!is_border) continue;
        if (n < out.len) out[n] = x;
        n += 1;
    }
    return n;
}

// ============================================================
// Tests
// ============================================================

fn expectSnapText(comptime src: std.builtin.SourceLocation, comptime body: []const u8, actual: anytype) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const snap = comptime std.fmt.comptimePrint("{s}\n  \"{s}\"", .{
        @typeName(@TypeOf(actual)),
        body,
    });
    try oh.snap(src, snap).expectEqual(actual);
}

test {
    _ = @import("ohsnap");
}

fn collectLines(alloc: std.mem.Allocator, it_ptr: anytype) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    var first = true;
    while (it_ptr.next()) |line| {
        if (!first) try out.append(alloc, '\n');
        first = false;
        try out.appendSlice(alloc, line);
    }
    return out.toOwnedSlice(alloc);
}

fn appendColor(out: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, c: frame.Color) !void {
    switch (c) {
        .default => try out.appendSlice(alloc, "default"),
        .idx => |idx| try std.fmt.format(out.writer(alloc), "idx:{d}", .{idx}),
        .rgb => |rgb| try std.fmt.format(out.writer(alloc), "rgb:{x:0>6}", .{rgb}),
    }
}

fn styledTextSnap(alloc: std.mem.Allocator, text: []const u8, spans: []const Span) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    try std.fmt.format(out.writer(alloc), "buf={s}", .{text});
    if (spans.len == 0) {
        try out.appendSlice(alloc, "\nspans=0");
        return out.toOwnedSlice(alloc);
    }

    for (spans) |span| {
        try std.fmt.format(out.writer(alloc), "\nspan {d}..{d} fg=", .{ span.start, span.end });
        try appendColor(&out, alloc, span.st.fg);
        try out.appendSlice(alloc, " bg=");
        try appendColor(&out, alloc, span.st.bg);
        try std.fmt.format(out.writer(alloc), " bold={d} dim={d} italic={d} underline={d} inverse={d}", .{
            @intFromBool(span.st.bold),
            @intFromBool(span.st.dim),
            @intFromBool(span.st.italic),
            @intFromBool(span.st.underline),
            @intFromBool(span.st.inverse),
        });
    }
    return out.toOwnedSlice(alloc);
}

test "transcript appends provider events and renders fixed-height tail" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "one" });
    try tr.append(.{ .thinking = "two" });
    try tr.append(.{ .tool_call = .{
        .id = "c1",
        .name = "read",
        .args = "{}",
    } });
    try tr.append(.{ .text = "three" });

    // 4 blocks: text("one"), thinking, tool, text("three")
    try std.testing.expectEqual(@as(usize, 4), tr.count());

    // 4 blocks + 3 gaps = 7 lines; show last 5 to see two, $ read, three
    var frm = try frame.Frame.init(std.testing.allocator, 24, 5);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{
        .x = 0,
        .y = 0,
        .w = 24,
        .h = 5,
    });

    // Lines: two(0), gap(1), $ read(2), gap(3), three(4)
    var raw: [24]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0, "two") != null);
    const r2 = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2, "$ read") != null);
    const r4 = try rowAscii(&frm, 4, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r4, "three") != null);
}

test "transcript tool call rows have dim fg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_call = .{
        .id = "x",
        .name = "ls",
        .args = "{\"path\":\".\"}",
    } });

    var frm = try frame.Frame.init(std.testing.allocator, 30, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 1 });

    // Tool calls now render as "$ ls ." in dim
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.fg, theme.get().dim));
}

test "transcript text lines have no background fill" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "hi" });

    var frm = try frame.Frame.init(std.testing.allocator, 10, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 10, .h = 1 });

    // Past text, bg should be default
    const c5 = try frm.cell(5, 0);
    try std.testing.expect(c5.style.bg.isDefault());
}

test "transcript rejects invalid utf8 and out-of-bounds render" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    const bad = [_]u8{0xff};
    try std.testing.expectError(error.InvalidUtf8, tr.append(.{ .text = bad[0..] }));

    var frm = try frame.Frame.init(std.testing.allocator, 2, 1);
    defer frm.deinit(std.testing.allocator);
    try std.testing.expectError(error.OutOfBounds, tr.render(&frm, .{
        .x = 1,
        .y = 0,
        .w = 2,
        .h = 1,
    }));
}

test "word wrap breaks at word boundary" {
    var it = wrapIter("hello world foo", 8);
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "hello\nworld\nfoo", got);
}

test "word wrap hard breaks long words" {
    var it = wrapIter("abcdefghij", 5);
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "abcde\nfghij", got);
}

test "word wrap wide char in narrow terminal does not hang" {
    // Wide CJK char (width=2) in width=1 terminal — must not infinite loop
    var it = wrapIter("中", 1);
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "中", got);
}

test "word wrap tabs count as width 1" {
    // Tab is whitespace → acts as a break point and counts as 1 col
    var it = wrapIter("a\tb\tc", 3);
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "a\nb\tc", got);
}

test "markdown wrap keeps table rows intact" {
    var it = mdWrapIter(
        "| Name | Description |\n| --- | --- |\n| A | a very long description that should not wrap |",
        12,
    );
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(
        @src(),
        "| Name | Description |\n| --- | --- |\n| A | a very long description that should not wrap |",
        got,
    );
}

test "markdown table keeps aligned padded columns and full enclosure" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "| Name | Value |\n" ++
        "| --- | --- |\n" ++
        "| a | 1 |\n" ++
        "| longer-name | 12345 |" });

    var frm = try frame.Frame.init(std.testing.allocator, 80, 10);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 80, .h = 10 });

    const rows = try frameRowsSnap(std.testing.allocator, &frm, 0, 6);
    defer std.testing.allocator.free(rows);
    try oh.snap(@src(),
        \\[]u8
        \\  "0: ???????????????????????
        \\1: ? Name        ? Value ?
        \\2: ???????????????????????
        \\3: ? a           ? 1     ?
        \\4: ???????????????????????
        \\5: ? longer-name ? 12345 ?
        \\6: ???????????????????????"
    ).expectEqual(rows);
}

test "markdown wrap still wraps non-table lines" {
    var it = mdWrapIter("alpha beta gamma", 8);
    const got = try collectLines(std.testing.allocator, &it);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "alpha\nbeta\ngamma", got);
}

test "transcript keeps markdown table state when top rows are skipped" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "| H1 | H2 |\n" ++
        "| --- | --- |\n" ++
        "| a1 | b1 |\n" ++
        "| a2 | b2 |" });

    var frm = try frame.Frame.init(std.testing.allocator, 30, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 2 });

    var a2_col: ?usize = null;
    var x: usize = 0;
    while (x < frm.w) : (x += 1) {
        const c = try frm.cell(x, 0);
        if (c.cp == 'a') {
            const n = if (x + 1 < frm.w) try frm.cell(x + 1, 0) else continue;
            if (n.cp == '2') {
                a2_col = x;
                break;
            }
        }
    }
    try std.testing.expect(a2_col != null);
    const c = try frm.cell(a2_col.?, 0);
    try std.testing.expect(!c.style.bold);
}

test "transcript clamps viewport within rendered table rows" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    const table = try allocBigMdTable(std.testing.allocator, 70);
    defer std.testing.allocator.free(table);
    try tr.append(.{ .text = table[0 .. table.len / 2] });
    try tr.append(.{ .text = table[table.len / 2 ..] });

    var frm = try frame.Frame.init(std.testing.allocator, 30, 3);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 3 });

    var raw: [30]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.trim(u8, r0, " ").len != 0);
    const r1 = try rowAscii(&frm, 1, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r1, "r62") != null);
    const r2 = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.trim(u8, r2, " ").len != 0);
}

test "transcript ignores empty blocks when auto-scrolling" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "" });
    try tr.append(.{ .tool_call = .{ .id = "empty", .name = "bash", .args = "{\"cmd\":\"printf ok\"}" } });
    try tr.append(.{ .tool_result = .{ .id = "empty", .out = "", .is_err = false } });
    try tr.append(.{ .text = "tail line" });

    var frm = try frame.Frame.init(std.testing.allocator, 24, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 24, .h = 1 });

    var raw: [24]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0, "tail line") != null);
}

test "text coalescing merges consecutive text events" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "a" });
    try tr.append(.{ .text = "b" });
    try std.testing.expectEqual(@as(usize, 1), tr.count());
    try expectSnapText(@src(), "ab", tr.blocks.items[0].text());
}

test "userText prevents coalescing" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "a" });
    try tr.userText("b");
    try std.testing.expectEqual(@as(usize, 2), tr.count());
}

test "stripAnsi removes CSI sequences" {
    const input = "\x1b[31mhello\x1b[0m";
    const result = try stripAnsi(std.testing.allocator, input);
    defer std.testing.allocator.free(result);
    try expectSnapText(@src(), "hello", result);
}

test "scroll indicator appears when content overflows" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "line1" });
    try tr.userText("line2");
    try tr.userText("line3");
    try tr.userText("line4");

    // 4 blocks, 2-row viewport → overflow → scrollbar at col 19
    var frm = try frame.Frame.init(std.testing.allocator, 20, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 20, .h = 2 });

    // Last column should have scroll indicator chars (non-space, non-default fg)
    const c0 = try frm.cell(19, 0);
    const c1 = try frm.cell(19, 1);
    try std.testing.expect(c0.cp == 0x2588 or c0.cp == 0x2591);
    try std.testing.expect(c1.cp == 0x2588 or c1.cp == 0x2591);

    // Text should not bleed into scrollbar column
    const c_text = try frm.cell(18, 1);
    try std.testing.expect(c_text.cp <= 0x7f); // ASCII text region
}

test "no scroll indicator when content fits" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "hi" });

    var frm = try frame.Frame.init(std.testing.allocator, 20, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 20, .h = 2 });

    // Last column should be space (no scrollbar)
    const c = try frm.cell(19, 0);
    try std.testing.expectEqual(@as(u21, ' '), c.cp);
}

test "parseAnsi red foreground" {
    const base: frame.Style = .{ .fg = .{ .rgb = 0xaabbcc } };
    var res = try parseAnsi(std.testing.allocator, "\x1b[31mhello\x1b[0m world", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=hello world\nspan 0..5 fg=idx:1 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi bold" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[1mbold\x1b[22mnot", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=boldnot\nspan 0..4 fg=default bg=default bold=1 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi 256-color" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[38;5;196mred\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=red\nspan 0..3 fg=idx:196 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi truecolor" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[38;2;255;128;0mtext\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=text\nspan 0..4 fg=rgb:ff8000 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi reset mid-stream" {
    const base: frame.Style = .{ .fg = .{ .rgb = 0x808080 } };
    var res = try parseAnsi(std.testing.allocator, "\x1b[31mA\x1b[0mB\x1b[32mC\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(
        @src(),
        "buf=ABC\nspan 0..1 fg=idx:1 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0\nspan 2..3 fg=idx:2 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0",
        got,
    );
}

test "parseAnsi no escapes returns original text" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "plain text", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=plain text\nspans=0", got);
}

test "parseAnsi nested attributes" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[1;31mboldred\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=boldred\nspan 0..7 fg=idx:1 bg=default bold=1 dim=0 italic=0 underline=0 inverse=0", got);
}

test "tool result preserves ANSI colors" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_result = .{
        .id = "t1",
        .out = "\x1b[31mfail\x1b[0m ok",
        .is_err = false,
    } });

    const blk = &tr.blocks.items[0];
    // Text should have ANSI stripped from buf but spans preserved
    try std.testing.expect(std.mem.indexOf(u8, blk.text(), "fail ok") != null);
    try std.testing.expect(blk.hasSpans());
    // The span should cover "fail" within the output portion
    try std.testing.expect(blk.spans.items.len >= 1);
}

test "tool result renders colored text to frame" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_result = .{
        .id = "t1",
        .out = "\x1b[31mERR\x1b[0m",
        .is_err = false,
    } });

    const blk = &tr.blocks.items[0];
    const txt = blk.text();

    // Find where "ERR" starts in the buf
    const err_pos = std.mem.indexOf(u8, txt, "ERR").?;

    var frm = try frame.Frame.init(std.testing.allocator, 80, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 80, .h = 1 });

    // +1 for left padding
    const c = try frm.cell(err_pos + 1, 0);
    try std.testing.expectEqual(@as(u21, 'E'), c.cp);
    try std.testing.expect(frame.Color.eql(c.style.fg, .{ .idx = 1 }));
}

test "SgrIter parses semicolon-separated params" {
    var it = SgrIter{ .data = "1;31" };
    try std.testing.expectEqual(@as(u16, 1), it.next().?);
    try std.testing.expectEqual(@as(u16, 31), it.next().?);
    try std.testing.expect(it.next() == null);
}

test "SgrIter empty params yields zero" {
    var it = SgrIter{ .data = "" };
    try std.testing.expectEqual(@as(u16, 0), it.next().?);
    try std.testing.expect(it.next() == null);
}

test "parseAnsi bright colors" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[91mhi\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=hi\nspan 0..2 fg=idx:9 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi bg color" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b[42mgreen\x1b[0m", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=green\nspan 0..5 fg=default bg=idx:2 bold=0 dim=0 italic=0 underline=0 inverse=0", got);
}

test "parseAnsi strips OSC terminated by BEL" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b]0;my title\x07hello", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=hello\nspans=0", got);
}

test "parseAnsi strips OSC terminated by ST" {
    const base: frame.Style = .{};
    var res = try parseAnsi(std.testing.allocator, "\x1b]0;my title\x1b\\world", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=world\nspans=0", got);
}

test "parseAnsi multi-sgr: bold red then reset then green" {
    const base: frame.Style = .{};
    // "\x1b[1;31mhello\x1b[0m \x1b[32mworld\x1b[0m"
    const input = "\x1b[1;31mhello\x1b[0m \x1b[32mworld\x1b[0m";
    var res = try parseAnsi(std.testing.allocator, input, base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(
        @src(),
        "buf=hello world\nspan 0..5 fg=idx:1 bg=default bold=1 dim=0 italic=0 underline=0 inverse=0\nspan 6..11 fg=idx:2 bg=default bold=0 dim=0 italic=0 underline=0 inverse=0",
        got,
    );
}

test "parseAnsi trailing ESC at end of input" {
    const base: frame.Style = .{};
    // Text ending with a lone ESC byte — should not crash
    var res = try parseAnsi(std.testing.allocator, "abc\x1b", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=abc\nspans=0", got);
}

test "parseAnsi CSI non-SGR sequence stripped" {
    const base: frame.Style = .{};
    // CSI cursor movement (ESC[2J = clear screen) should be stripped, not crash
    var res = try parseAnsi(std.testing.allocator, "before\x1b[2Jafter", base);
    defer {
        res.buf.deinit(std.testing.allocator);
        res.spans.deinit(std.testing.allocator);
    }
    const got = try styledTextSnap(std.testing.allocator, res.buf.items, res.spans.items);
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "buf=beforeafter\nspans=0", got);
}

test "scrollUp and scrollDown adjust offset" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try std.testing.expectEqual(@as(usize, 0), tr.scroll_off);
    tr.scrollUp(5);
    try std.testing.expectEqual(@as(usize, 5), tr.scroll_off);
    tr.scrollDown(3);
    try std.testing.expectEqual(@as(usize, 2), tr.scroll_off);
    tr.scrollDown(10);
    try std.testing.expectEqual(@as(usize, 0), tr.scroll_off);
}

test "scrollUp saturates" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    tr.scroll_off = std.math.maxInt(usize) - 1;
    tr.scrollUp(5);
    try std.testing.expectEqual(std.math.maxInt(usize), tr.scroll_off);
}

test "scrollToBottom resets offset" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    tr.scrollUp(100);
    tr.scrollToBottom();
    try std.testing.expectEqual(@as(usize, 0), tr.scroll_off);
}

test "render with scroll offset shows earlier content" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    // 4 single-line blocks + 3 gaps = 7 lines total
    try tr.append(.{ .text = "AAA" });
    try tr.userText("BBB");
    try tr.userText("CCC");
    try tr.userText("DDD");

    // At bottom (scroll_off=0) with 3-row viewport: gap, DDD (last 2 of 7)
    // Use 3 rows to see: CCC, gap, DDD
    var frm = try frame.Frame.init(std.testing.allocator, 20, 3);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 20, .h = 3 });

    var raw: [20]u8 = undefined;
    {
        const r0 = try rowAscii(&frm, 0, raw[0..]);
        try std.testing.expect(std.mem.indexOf(u8, r0, "CCC") != null);
    }
    {
        const r2 = try rowAscii(&frm, 2, raw[0..]);
        try std.testing.expect(std.mem.indexOf(u8, r2, "DDD") != null);
    }

    // Scroll up 4 lines: show AAA, gap, BBB from top
    tr.scrollUp(4);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 20, .h = 3 });

    {
        const r0 = try rowAscii(&frm, 0, raw[0..]);
        try std.testing.expect(std.mem.indexOf(u8, r0, "AAA") != null);
    }
    {
        const r2 = try rowAscii(&frm, 2, raw[0..]);
        try std.testing.expect(std.mem.indexOf(u8, r2, "BBB") != null);
    }
}

test "show_tools hides tool blocks" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "hello" });
    try tr.append(.{ .tool_call = .{ .id = "c1", .name = "read", .args = "{}" } });
    try tr.append(.{ .tool_result = .{ .id = "c1", .out = "ok", .is_err = false } });
    try tr.append(.{ .text = "bye" });

    // 4 blocks + 3 gaps = 7 lines visible by default
    var frm = try frame.Frame.init(std.testing.allocator, 30, 7);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 7 });
    var raw: [30]u8 = undefined;
    // hello, gap, $ read, gap, ok, gap, bye
    const r2 = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2, "$ read") != null);

    // Hide tools: 2 blocks (hello, bye) + 1 gap = 3 lines
    tr.show_tools = false;
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 7 });
    const r0h = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0h, "hello") != null);
    const r2h = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2h, "bye") != null);
}

test "transcript appendSeq keeps deny blocks in causal order" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.appendSeq(1, .{ .tool_call = .{ .id = "deny-1", .name = "bash", .args = "{\"cmd\":\"cat ~/.ssh/id_rsa\"}" } });
    try tr.appendSeq(3, .{ .text = "later provider text" });
    try tr.appendSeq(2, .{ .tool_result = .{ .id = "deny-1", .out = "permission denied", .is_err = true } });

    var frm = try frame.Frame.init(std.testing.allocator, 48, 10);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 48, .h = 10 });

    var raw: [48]u8 = undefined;
    var call_y: ?usize = null;
    var deny_y: ?usize = null;
    var later_y: ?usize = null;
    var y: usize = 0;
    while (y < frm.h) : (y += 1) {
        const row = try rowAscii(&frm, y, raw[0..]);
        if (call_y == null and std.mem.indexOf(u8, row, "$ cat ") != null) call_y = y;
        if (deny_y == null and std.mem.indexOf(u8, row, "permission denied") != null) deny_y = y;
        if (later_y == null and std.mem.indexOf(u8, row, "later provider text") != null) later_y = y;
    }
    try std.testing.expect(call_y != null);
    try std.testing.expect(deny_y != null);
    try std.testing.expect(later_y != null);
    try std.testing.expect(call_y.? < deny_y.?);
    try std.testing.expect(deny_y.? < later_y.?);
}

test "thinking visible by default, hidden when toggled" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "before" });
    try tr.append(.{ .thinking = "deep reasoning here" });
    try tr.append(.{ .text = "after" });

    // Default: show_thinking=true → 3 blocks + 2 gaps = 5 lines
    // h=5 shows all: before, gap, deep reasoning, gap, after
    var frm = try frame.Frame.init(std.testing.allocator, 40, 5);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 40, .h = 5 });
    var raw: [40]u8 = undefined;
    const r2v = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2v, "deep reasoning") != null);
    const t = theme.get();
    const c_exp = try frm.cell(1, 2);
    try std.testing.expect(c_exp.style.italic);
    try std.testing.expect(frame.Color.eql(c_exp.style.fg, t.thinking_fg));

    // Toggle off → 2 blocks + 1 gap = 3 lines: before, gap, after
    tr.show_thinking = false;
    var frm2 = try frame.Frame.init(std.testing.allocator, 20, 3);
    defer frm2.deinit(std.testing.allocator);
    try tr.render(&frm2, .{ .x = 0, .y = 0, .w = 20, .h = 3 });
    var raw2: [20]u8 = undefined;
    const r0 = try rowAscii(&frm2, 0, raw2[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0, "before") != null);
    const r2 = try rowAscii(&frm2, 2, raw2[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2, "after") != null);
}

test "error block renders with err fg, bold, and error bg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .err = "rate limit exceeded" });

    var frm = try frame.Frame.init(std.testing.allocator, 40, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 40, .h = 1 });

    const t = theme.get();
    // Col 0 = padding with bg fill
    const c0 = try frm.cell(0, 0);
    try std.testing.expect(frame.Color.eql(c0.style.bg, t.tool_error_bg));
    // Col 1 = first text char with err fg + bold + error bg
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.fg, t.err));
    try std.testing.expect(c1.style.bold);
    try std.testing.expect(frame.Color.eql(c1.style.bg, t.tool_error_bg));
    // Trailing cols also have error bg
    const c_last = try frm.cell(39, 0);
    try std.testing.expect(frame.Color.eql(c_last.style.bg, t.tool_error_bg));
}

test "user message has user_msg_bg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.userText("hello from user");

    var frm = try frame.Frame.init(std.testing.allocator, 30, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 1 });

    const t = theme.get();
    // Padding col and text col both have user_msg_bg
    const c0 = try frm.cell(0, 0);
    try std.testing.expect(frame.Color.eql(c0.style.bg, t.user_msg_bg));
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.bg, t.user_msg_bg));
    // Trailing fill
    const c_last = try frm.cell(29, 0);
    try std.testing.expect(frame.Color.eql(c_last.style.bg, t.user_msg_bg));
}

test "info text has dim fg and no bg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.infoText("loaded CLAUDE.md");

    var frm = try frame.Frame.init(std.testing.allocator, 30, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 1 });

    const t = theme.get();
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.fg, t.dim));
    // No bg fill for info text (default bg)
    try std.testing.expect(c1.style.bg.isDefault());
}

test "tool result success uses tool output fg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_result = .{
        .id = "r1",
        .out = "all good",
        .is_err = false,
    } });

    var frm = try frame.Frame.init(std.testing.allocator, 50, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 50, .h = 1 });

    const t = theme.get();
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.fg, t.tool_output));
    try std.testing.expect(frame.Color.eql(c1.style.bg, t.tool_success_bg));
}

test "tool result ask payload renders as readable lines" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_result = .{
        .id = "ask-1",
        .out = "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"Ship it\",\"index\":0},{\"id\":\"risk\",\"answer\":\"Low\",\"index\":1}]}",
        .is_err = false,
    } });

    try std.testing.expectEqual(@as(usize, 1), tr.count());
    const txt = tr.blocks.items[0].text();
    try std.testing.expect(std.mem.indexOf(u8, txt, "ask: 2 answers") != null);
    try std.testing.expect(std.mem.indexOf(u8, txt, "scope: Ship it") != null);
    try std.testing.expect(std.mem.indexOf(u8, txt, "risk: Low") != null);
    try std.testing.expect(std.mem.indexOfScalar(u8, txt, '{') == null);
}

test "tool result error has err fg and error bg" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_result = .{
        .id = "r2",
        .out = "not found",
        .is_err = true,
    } });

    var frm = try frame.Frame.init(std.testing.allocator, 50, 1);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 50, .h = 1 });

    const t = theme.get();
    const c1 = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(c1.style.fg, t.err));
    try std.testing.expect(frame.Color.eql(c1.style.bg, t.tool_error_bg));
}

test "tool call pending recolors to success and joins result block" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_call = .{ .id = "c9", .name = "read", .args = "{\"path\":\"a\"}" } });

    var frm = try frame.Frame.init(std.testing.allocator, 30, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 2 });

    const t = theme.get();
    const call_pending = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(call_pending.style.bg, t.tool_pending_bg));

    try tr.append(.{ .tool_result = .{ .id = "c9", .out = "ok", .is_err = false } });
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 2 });

    const call_done = try frm.cell(1, 0);
    try std.testing.expect(frame.Color.eql(call_done.style.bg, t.tool_success_bg));
    const result_row = try frm.cell(1, 1);
    try std.testing.expect(frame.Color.eql(result_row.style.bg, t.tool_success_bg));
}

test "bash tool call row truncates with ellipsis and stays single-line" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_call = .{
        .id = "bash-1",
        .name = "bash",
        .args = "{\"cmd\":\"echo abcdefghijklmnopqrstuvwxyz\"}",
    } });

    var frm = try frame.Frame.init(std.testing.allocator, 18, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 18, .h = 2 });

    var raw: [18]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0, "$ echo") != null);
    try std.testing.expect(std.mem.indexOf(u8, r0, "...") != null);
    try std.testing.expect(std.mem.indexOf(u8, r0, "$ bash") == null);

    const r1 = try rowAscii(&frm, 1, raw[0..]);
    try std.testing.expect(std.mem.trim(u8, r1, " ").len == 0);
}

test "bash tool call row redacts sensitive command fragments" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_call = .{
        .id = "bash-redact",
        .name = "bash",
        .args = "{\"cmd\":\"curl 'https://svc.local/x?token=secret' /Users/joel/.ssh/id_rsa\"}",
    } });

    var frm = try frame.Frame.init(std.testing.allocator, 64, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 64, .h = 2 });

    var raw: [64]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try oh.snap(@src(),
        \\[]const u8
        \\  "  $ curl '[secret:f46ae11f145e0f15]' [path:7bb914945c8f6207]    "
    ).expectEqual(r0);
}

test "tool call recolors to error with failed result" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .tool_call = .{ .id = "ce", .name = "bash", .args = "{\"cmd\":\"false\"}" } });
    try tr.append(.{ .tool_result = .{ .id = "ce", .out = "failed", .is_err = true } });

    var frm = try frame.Frame.init(std.testing.allocator, 30, 2);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 30, .h = 2 });

    const t = theme.get();
    const call_row = try frm.cell(1, 0);
    const result_row = try frm.cell(1, 1);
    var raw: [30]u8 = undefined;
    const row = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(frame.Color.eql(call_row.style.bg, t.tool_error_bg));
    try std.testing.expect(frame.Color.eql(result_row.style.bg, t.tool_error_bg));
    try std.testing.expect(frame.Color.eql(result_row.style.fg, t.err));
    try std.testing.expect(std.mem.indexOf(u8, row, "$ false") != null);
}

test "usage and stop produce no transcript blocks" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .usage = .{ .in_tok = 10, .out_tok = 20, .tot_tok = 30 } });
    try tr.append(.{ .stop = .{ .reason = .done } });

    // No blocks should be added for usage/stop events
    try std.testing.expectEqual(@as(usize, 0), tr.count());
}

test "scroll offset clamped to max" {
    var tr = Transcript.init(std.testing.allocator);
    defer tr.deinit();

    try tr.append(.{ .text = "A" });
    try tr.userText("B");
    try tr.userText("C");

    // 3 blocks + 2 gaps = 5 lines, viewport 3 => max_skip=2
    // Scrolling up 999 clamps to max, showing first 3: A, gap, B
    tr.scrollUp(999);

    var frm = try frame.Frame.init(std.testing.allocator, 10, 3);
    defer frm.deinit(std.testing.allocator);
    try tr.render(&frm, .{ .x = 0, .y = 0, .w = 10, .h = 3 });

    var raw: [10]u8 = undefined;
    const r0 = try rowAscii(&frm, 0, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r0, "A") != null);
    const r2 = try rowAscii(&frm, 2, raw[0..]);
    try std.testing.expect(std.mem.indexOf(u8, r2, "B") != null);
}
