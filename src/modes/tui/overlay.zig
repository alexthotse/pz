const std = @import("std");
const frame_mod = @import("frame.zig");
const theme_mod = @import("theme.zig");
const wc = @import("wcwidth.zig");

const Frame = frame_mod.Frame;
const Style = frame_mod.Style;
const Color = frame_mod.Color;

pub const Kind = enum { model, session, settings, fork, login, logout, queue };

pub const Overlay = struct {
    pub const SessionRow = struct {
        sid: []u8,
        title: []u8,
        time: []u8,
        tokens: []u8,
    };

    items: []const []const u8,
    dyn_items: ?[][]u8 = null, // owned items (freed on deinit)
    session_rows: ?[]SessionRow = null, // owned session rows
    toggles: ?[]bool = null, // toggle state per item (settings kind)
    sel: usize = 0,
    scroll: usize = 0,
    title: []const u8 = "Select Model",
    kind: Kind = .model,
    hint: ?[]const u8 = null,
    input_label: ?[]const u8 = null,
    input_text: ?[]const u8 = null,
    input_cursor: bool = false,

    const max_vis: usize = 12;

    pub fn init(items: []const []const u8, cur: usize) Overlay {
        return .{ .items = items, .sel = if (items.len > 0) @min(cur, items.len - 1) else 0 };
    }

    pub fn initDyn(alloc: std.mem.Allocator, dyn: [][]u8, title: []const u8, kind: Kind) Overlay {
        _ = alloc;
        return .{
            .items = &.{},
            .dyn_items = dyn,
            .title = title,
            .kind = kind,
        };
    }

    pub fn initSession(rows: []SessionRow, title: []const u8) Overlay {
        return .{
            .items = &.{},
            .session_rows = rows,
            .title = title,
            .kind = .session,
        };
    }

    pub fn deinit(self: *Overlay, alloc: std.mem.Allocator) void {
        if (self.dyn_items) |items| {
            for (items) |item| alloc.free(item);
            alloc.free(items);
            self.dyn_items = null;
        }
        if (self.session_rows) |rows| {
            for (rows) |row| {
                alloc.free(row.sid);
                alloc.free(row.title);
                alloc.free(row.time);
                alloc.free(row.tokens);
            }
            alloc.free(rows);
            self.session_rows = null;
        }
        if (self.toggles) |t| {
            alloc.free(t);
            self.toggles = null;
        }
    }

    pub fn toggle(self: *Overlay) void {
        if (self.toggles) |t| {
            if (self.sel < t.len) t[self.sel] = !t[self.sel];
        }
    }

    pub fn getToggle(self: *const Overlay, idx: usize) ?bool {
        if (self.toggles) |t| {
            if (idx < t.len) return t[idx];
        }
        return null;
    }

    fn itemSlice(self: *const Overlay) []const []const u8 {
        if (self.dyn_items) |d| {
            // Cast [][]u8 to []const []const u8
            const ptr: [*]const []const u8 = @ptrCast(d.ptr);
            return ptr[0..d.len];
        }
        return self.items;
    }

    fn itemCount(self: *const Overlay) usize {
        if (self.session_rows) |rows| return rows.len;
        if (self.dyn_items) |d| return d.len;
        return self.items.len;
    }

    pub fn up(self: *Overlay) void {
        const n = self.itemCount();
        if (n == 0) return;
        if (self.sel > 0) self.sel -= 1 else self.sel = n - 1;
        self.fixScroll();
    }

    pub fn down(self: *Overlay) void {
        const n = self.itemCount();
        if (n == 0) return;
        if (self.sel + 1 < n) self.sel += 1 else self.sel = 0;
        self.fixScroll();
    }

    pub fn fixScroll(self: *Overlay) void {
        if (self.sel < self.scroll) self.scroll = self.sel;
        if (self.sel >= self.scroll + max_vis) self.scroll = self.sel - max_vis + 1;
    }

    pub fn selected(self: *const Overlay) ?[]const u8 {
        if (self.session_rows) |rows| {
            if (rows.len == 0) return null;
            return rows[self.sel].sid;
        }
        const items = self.itemSlice();
        if (items.len == 0) return null;
        return items[self.sel];
    }

    pub fn render(self: *const Overlay, frm: *Frame) !void {
        const t = theme_mod.get();
        const items = self.itemSlice();
        const sess_rows = self.session_rows;
        const hint_text = self.hint;
        const has_hint = hint_text != null and hint_text.?.len > 0;
        const has_input = self.input_label != null and self.input_text != null;

        // Compute box dimensions
        var max_w: usize = wc.strwidth(self.title);
        var vis_n = @min(items.len, max_vis);
        var sess_time_w: usize = 0;
        var sess_tok_w: usize = 0;
        if (sess_rows) |rows| {
            vis_n = @min(rows.len, max_vis);
            for (rows) |row| {
                const title_w = wc.strwidth(row.title);
                const time_w = wc.strwidth(row.time);
                const tok_w = wc.strwidth(row.tokens);
                const row_w = title_w + 2 + time_w + 2 + tok_w;
                if (row_w + 4 > max_w) max_w = row_w + 4;
                if (time_w > sess_time_w) sess_time_w = time_w;
                if (tok_w > sess_tok_w) sess_tok_w = tok_w;
            }
        } else {
            for (items) |item| {
                const label = if (self.kind == .model) shortLabel(item) else item;
                const lw = wc.strwidth(label);
                if (lw + 4 > max_w) max_w = lw + 4;
            }
        }
        if (has_hint) {
            const hw = wc.strwidth(hint_text.?) + 4;
            if (hw > max_w) max_w = hw;
        }
        if (has_input) {
            const iw = wc.strwidth(self.input_label.?) + 2 + wc.strwidth(self.input_text.?) + if (self.input_cursor) @as(usize, 1) else @as(usize, 0);
            if (iw + 4 > max_w) max_w = iw + 4;
        }
        const extra_rows: usize = (if (has_hint) @as(usize, 1) else @as(usize, 0)) + (if (has_input) @as(usize, 1) else @as(usize, 0));
        const max_item_rows: usize = if (frm.h > 2 + extra_rows) frm.h - 2 - extra_rows else 0;
        vis_n = @min(vis_n, max_item_rows);
        const box_w = @min(max_w + 4, frm.w);
        const box_h = vis_n + 2 + extra_rows;

        if (box_w < 8 or box_h > frm.h) return;

        const x0 = (frm.w - box_w) / 2;
        const y0 = (frm.h - box_h) / 2;

        const border_rgb = switch (t.border_c) {
            .rgb => |v| v,
            else => 0x555555,
        };
        const heading_rgb = switch (t.md_heading) {
            .rgb => |v| v,
            else => 0xc5c8c6,
        };
        const border_st = Style{ .fg = .{ .rgb = border_rgb } };
        const title_st = Style{ .fg = .{ .rgb = heading_rgb }, .bold = true };
        const item_st = Style{ .fg = .{ .rgb = 0xc5c8c6 } };
        const sel_st = Style{ .fg = .{ .rgb = 0x81a1c1 }, .bold = true };
        const bg: Color = .{ .rgb = 0x1d1f21 };
        const sel_bg: Color = .{ .rgb = 0x2d2f31 };

        // Draw border and background
        // Top border: ┌─ title ─┐
        try frm.set(x0, y0, 0x250C, border_st); // ┌
        {
            var x = x0 + 1;
            const title_w = wc.strwidth(self.title);
            const pad_total = box_w -| 2 -| title_w;
            const pad_l = pad_total / 2;
            const pad_r = pad_total - pad_l;
            var pi: usize = 0;
            while (pi < pad_l) : (pi += 1) {
                try frm.set(x, y0, 0x2500, border_st); // ─
                x += 1;
            }
            var ti: usize = 0;
            while (ti < self.title.len) {
                const n = std.unicode.utf8ByteSequenceLength(self.title[ti]) catch break;
                if (ti + n > self.title.len) break;
                const cp = std.unicode.utf8Decode(self.title[ti .. ti + n]) catch break;
                if (x >= x0 + box_w - 1) break;
                try frm.set(x, y0, cp, title_st);
                x += wc.wcwidth(cp);
                ti += n;
            }
            pi = 0;
            while (pi < pad_r) : (pi += 1) {
                if (x >= x0 + box_w - 1) break;
                try frm.set(x, y0, 0x2500, border_st);
                x += 1;
            }
        }
        try frm.set(x0 + box_w - 1, y0, 0x2510, border_st); // ┐

        // Items (scrolled window)
        var row: usize = 0;
        const row_count = self.itemCount();
        while (row < vis_n) : (row += 1) {
            const idx = self.scroll + row;
            if (idx >= row_count) break;
            const y = y0 + 1 + row;
            const is_sel = idx == self.sel;
            const row_bg = if (is_sel) sel_bg else bg;
            const row_st = if (is_sel) sel_st else item_st;
            const prefix_st = Style{ .fg = if (is_sel) .{ .rgb = 0x81a1c1 } else .{ .default = {} } };

            try frm.set(x0, y, 0x2502, border_st); // │

            // Fill background
            var x = x0 + 1;
            while (x < x0 + box_w - 1) : (x += 1) {
                try frm.set(x, y, ' ', Style{ .bg = row_bg });
            }

            // Write prefix
            x = x0 + 2;
            if (is_sel) {
                try frm.set(x, y, '>', Style{ .fg = prefix_st.fg, .bg = row_bg, .bold = true });
                x += 1;
                try frm.set(x, y, ' ', Style{ .bg = row_bg });
                x += 1;
            } else {
                try frm.set(x, y, ' ', Style{ .bg = row_bg });
                x += 1;
                try frm.set(x, y, ' ', Style{ .bg = row_bg });
                x += 1;
            }

            if (sess_rows) |rows| {
                const row_data = rows[idx];
                const content_end = x0 + box_w - 2;
                const tok_x = content_end - sess_tok_w;
                const time_x = tok_x - 2 - sess_time_w;
                const title_end = if (time_x > x) time_x - 2 else x;
                try writeEllipsis(
                    frm,
                    x,
                    title_end,
                    y,
                    row_data.title,
                    Style{ .fg = row_st.fg, .bg = row_bg, .bold = row_st.bold },
                );
                try writeRight(
                    frm,
                    time_x,
                    sess_time_w,
                    y,
                    row_data.time,
                    Style{ .fg = item_st.fg, .bg = row_bg },
                );
                try writeRight(
                    frm,
                    tok_x,
                    sess_tok_w,
                    y,
                    row_data.tokens,
                    Style{ .fg = item_st.fg, .bg = row_bg },
                );
            } else {
                const item = items[idx];
                const label = if (self.kind == .model) shortLabel(item) else item;
                var li: usize = 0;
                while (li < label.len) {
                    if (x >= x0 + box_w - 2) break;
                    const n = std.unicode.utf8ByteSequenceLength(label[li]) catch break;
                    if (li + n > label.len) break;
                    const cp = std.unicode.utf8Decode(label[li .. li + n]) catch break;
                    const cw = wc.wcwidth(cp);
                    if (x + cw > x0 + box_w - 1) break;
                    try frm.set(x, y, cp, Style{
                        .fg = row_st.fg,
                        .bg = row_bg,
                        .bold = row_st.bold,
                    });
                    x += cw;
                    li += n;
                }
            }

            // Toggle indicator for settings
            if (self.kind == .settings) {
                if (self.getToggle(idx)) |on| {
                    // Right-align the indicator
                    const ind_x = x0 + box_w - 3;
                    if (ind_x > x) {
                        const ind_cp: u21 = if (on) 0x2713 else 0x2717; // ✓ or ✗
                        const ind_fg: Color = if (on) .{ .rgb = 0xa3be8c } else .{ .rgb = 0xbf616a };
                        try frm.set(ind_x, y, ind_cp, Style{ .fg = ind_fg, .bg = row_bg });
                    }
                }
            }

            try frm.set(x0 + box_w - 1, y, 0x2502, border_st); // │
        }

        var extra_y = y0 + 1 + vis_n;
        if (has_hint) {
            const hint_st = Style{ .fg = .{ .rgb = 0x969896 } };
            try frm.set(x0, extra_y, 0x2502, border_st); // │
            var x = x0 + 1;
            while (x < x0 + box_w - 1) : (x += 1) {
                try frm.set(x, extra_y, ' ', Style{ .bg = bg });
            }
            x = x0 + 2;
            const text = hint_text.?;
            var ti: usize = 0;
            while (ti < text.len) {
                if (x >= x0 + box_w - 2) break;
                const n = std.unicode.utf8ByteSequenceLength(text[ti]) catch break;
                if (ti + n > text.len) break;
                const cp = std.unicode.utf8Decode(text[ti .. ti + n]) catch break;
                const cw = wc.wcwidth(cp);
                if (x + cw > x0 + box_w - 1) break;
                try frm.set(x, extra_y, cp, Style{
                    .fg = hint_st.fg,
                    .bg = bg,
                });
                x += cw;
                ti += n;
            }
            try frm.set(x0 + box_w - 1, extra_y, 0x2502, border_st); // │
            extra_y += 1;
        }

        if (has_input) {
            const inp_bg: Color = .{ .rgb = 0x222426 };
            const label_st = Style{ .fg = .{ .rgb = 0x81a1c1 }, .bold = true };
            const text_st = Style{ .fg = .{ .rgb = 0xc5c8c6 } };

            try frm.set(x0, extra_y, 0x2502, border_st); // │
            var x = x0 + 1;
            while (x < x0 + box_w - 1) : (x += 1) {
                try frm.set(x, extra_y, ' ', Style{ .bg = inp_bg });
            }
            x = x0 + 2;

            const label = self.input_label.?;
            var li: usize = 0;
            while (li < label.len) {
                if (x >= x0 + box_w - 2) break;
                const n = std.unicode.utf8ByteSequenceLength(label[li]) catch break;
                if (li + n > label.len) break;
                const cp = std.unicode.utf8Decode(label[li .. li + n]) catch break;
                const cw = wc.wcwidth(cp);
                if (x + cw > x0 + box_w - 1) break;
                try frm.set(x, extra_y, cp, Style{ .fg = label_st.fg, .bg = inp_bg, .bold = true });
                x += cw;
                li += n;
            }
            if (x < x0 + box_w - 2) {
                try frm.set(x, extra_y, ':', Style{ .fg = label_st.fg, .bg = inp_bg, .bold = true });
                x += 1;
            }
            if (x < x0 + box_w - 2) {
                try frm.set(x, extra_y, ' ', Style{ .bg = inp_bg });
                x += 1;
            }

            const text = self.input_text.?;
            var ti: usize = 0;
            while (ti < text.len) {
                if (x >= x0 + box_w - 2) break;
                const n = std.unicode.utf8ByteSequenceLength(text[ti]) catch break;
                if (ti + n > text.len) break;
                const cp = std.unicode.utf8Decode(text[ti .. ti + n]) catch break;
                const cw = wc.wcwidth(cp);
                if (x + cw > x0 + box_w - 1) break;
                try frm.set(x, extra_y, cp, Style{
                    .fg = text_st.fg,
                    .bg = inp_bg,
                });
                x += cw;
                ti += n;
            }
            if (self.input_cursor and x < x0 + box_w - 2) {
                try frm.set(x, extra_y, 0x2588, Style{ .fg = .{ .rgb = 0x81a1c1 }, .bg = inp_bg });
            }
            try frm.set(x0 + box_w - 1, extra_y, 0x2502, border_st); // │
            extra_y += 1;
        }

        // Bottom border: └──────┘
        const yb = y0 + box_h - 1;
        try frm.set(x0, yb, 0x2514, border_st); // └
        {
            var x = x0 + 1;
            while (x < x0 + box_w - 1) : (x += 1) {
                try frm.set(x, yb, 0x2500, border_st);
            }
        }
        try frm.set(x0 + box_w - 1, yb, 0x2518, border_st); // ┘
    }
};

/// Extract short display name from full model ID.
/// "claude-opus-4-6-20250219" → "claude-opus-4-6"
fn shortLabel(model: []const u8) []const u8 {
    // Strip date suffix (-YYYYMMDD)
    if (model.len >= 9 and model[model.len - 9] == '-') {
        const suffix = model[model.len - 8 ..];
        // Check all digits
        for (suffix) |c| {
            if (c < '0' or c > '9') return model;
        }
        return model[0 .. model.len - 9];
    }
    return model;
}

fn clipCols(text: []const u8, cols: usize) []const u8 {
    if (cols == 0 or text.len == 0) return text[0..0];
    var i: usize = 0;
    var used: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch break;
        if (i + n > text.len) break;
        const cp = std.unicode.utf8Decode(text[i .. i + n]) catch break;
        const cw = wc.wcwidth(cp);
        if (used + cw > cols) break;
        used += cw;
        i += n;
    }
    return text[0..i];
}

fn writeRight(frm: *Frame, x: usize, cols: usize, y: usize, text: []const u8, st: Style) !void {
    if (cols == 0) return;
    const fit = clipCols(text, cols);
    const pad = cols - @min(cols, wc.strwidth(fit));
    _ = try frm.write(x + pad, y, fit, st);
}

fn writeEllipsis(frm: *Frame, x: usize, x_end: usize, y: usize, text: []const u8, st: Style) !void {
    if (x >= x_end) return;
    const cols = x_end - x;
    const fit = clipCols(text, cols);
    if (fit.len == text.len or cols <= 3) {
        if (cols <= 3 and fit.len < text.len) {
            var i: usize = 0;
            while (i < cols) : (i += 1) try frm.set(x + i, y, '.', st);
            return;
        }
        _ = try frm.write(x, y, fit, st);
        return;
    }

    const base = clipCols(text, cols - 3);
    var xpos = x;
    xpos += try frm.write(xpos, y, base, st);
    var i: usize = 0;
    while (i < 3 and xpos < x_end) : (i += 1) {
        try frm.set(xpos, y, '.', st);
        xpos += 1;
    }
}

fn expectSnapText(comptime src: std.builtin.SourceLocation, comptime body: []const u8, actual: anytype) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const snap = comptime std.fmt.comptimePrint("{s}\n  \"{s}\"", .{
        @typeName(@TypeOf(actual)),
        body,
    });
    try oh.snap(src, snap).expectEqual(actual);
}

fn rowAscii(frm: *const Frame, y: usize, out: []u8) ![]const u8 {
    var x: usize = 0;
    while (x < frm.w) : (x += 1) {
        const cp = (try frm.cell(x, y)).cp;
        out[x] = if (cp <= 0x7f) @intCast(cp) else '?';
    }
    return out[0..frm.w];
}

fn rowSegmentsAlloc(alloc: std.mem.Allocator, row: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    var x: usize = 0;
    var first = true;
    while (x < row.len) {
        if (row[x] == ' ') {
            x += 1;
            continue;
        }
        if (!first) try out.appendSlice(alloc, " | ");
        first = false;
        try std.fmt.format(out.writer(alloc), "@{d}:", .{x});
        const start = x;
        while (x < row.len and row[x] != ' ') : (x += 1) {}
        try out.appendSlice(alloc, row[start..x]);
    }
    return out.toOwnedSlice(alloc);
}

fn trimmedBoxSegmentsAlloc(alloc: std.mem.Allocator, frm: *const Frame) ![]u8 {
    var x0: ?usize = null;
    var y0: ?usize = null;
    var x1: usize = 0;
    var y1: usize = 0;

    var y: usize = 0;
    while (y < frm.h) : (y += 1) {
        var x: usize = 0;
        while (x < frm.w) : (x += 1) {
            const cp = (try frm.cell(x, y)).cp;
            if (cp == ' ' or cp == Frame.wide_pad) continue;
            x0 = if (x0) |cur| @min(cur, x) else x;
            y0 = if (y0) |cur| @min(cur, y) else y;
            x1 = @max(x1, x);
            y1 = @max(y1, y);
        }
    }

    if (x0 == null or y0 == null) return try alloc.dupe(u8, "");

    const buf = try alloc.alloc(u8, frm.w);
    defer alloc.free(buf);
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    y = y0.?;
    while (y <= y1) : (y += 1) {
        if (y > y0.?) try out.append(alloc, '\n');
        const row = try rowAscii(frm, y, buf);
        const segs = try rowSegmentsAlloc(alloc, row[x0.? .. x1 + 1]);
        defer alloc.free(segs);
        try std.fmt.format(out.writer(alloc), "row{d} {s}", .{ y - y0.?, segs });
    }
    return out.toOwnedSlice(alloc);
}

test {
    _ = @import("ohsnap");
}

test "overlay renders centered box" {
    const items = [_][]const u8{ "model-a", "model-b", "model-c" };
    const ov = Overlay.init(&items, 1);

    var frm = try Frame.init(std.testing.allocator, 30, 10);
    defer frm.deinit(std.testing.allocator);

    try ov.render(&frm);

    const x0 = (30 - (11 + 4)) / 2; // max_w=12("Select Model"), box_w=16
    const y0 = (10 - 5) / 2; // box_h = 3 items + 2 = 5
    var r0: [30]u8 = undefined;
    var r1: [30]u8 = undefined;
    var r2: [30]u8 = undefined;
    var r3: [30]u8 = undefined;
    var r4: [30]u8 = undefined;
    const actual = try std.fmt.allocPrint(std.testing.allocator, "{s}\n{s}\n{s}\n{s}\n{s}", .{
        (try rowAscii(&frm, y0 + 0, r0[0..]))[x0 .. x0 + 15],
        (try rowAscii(&frm, y0 + 1, r1[0..]))[x0 .. x0 + 15],
        (try rowAscii(&frm, y0 + 2, r2[0..]))[x0 .. x0 + 15],
        (try rowAscii(&frm, y0 + 3, r3[0..]))[x0 .. x0 + 15],
        (try rowAscii(&frm, y0 + 4, r4[0..]))[x0 .. x0 + 15],
    });
    defer std.testing.allocator.free(actual);
    try expectSnapText(
        @src(),
        "??Select Model?\n" ++
            "?   model-a    \n" ++
            "? > model-b    \n" ++
            "?   model-c    \n" ++
            "???????????????",
        actual,
    );
}

test "overlay navigation wraps" {
    const items = [_][]const u8{ "a", "b", "c" };
    var ov = Overlay.init(&items, 0);

    ov.up();
    const after_up = try std.fmt.allocPrint(std.testing.allocator, "sel={d} scroll={d}", .{ ov.sel, ov.scroll });
    defer std.testing.allocator.free(after_up);
    try expectSnapText(@src(), "sel=2 scroll=0", after_up);

    ov.down();
    const after_down = try std.fmt.allocPrint(std.testing.allocator, "sel={d} scroll={d}", .{ ov.sel, ov.scroll });
    defer std.testing.allocator.free(after_down);
    try expectSnapText(@src(), "sel=0 scroll=0", after_down);
}

test "overlay scrolls with many items" {
    // 25 items to ensure scrolling with max_vis=12
    const items = [_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y" };
    var ov = Overlay.init(&items, 0);
    var i: usize = 0;
    while (i < Overlay.max_vis + 2) : (i += 1) ov.down();
    const after_down = try std.fmt.allocPrint(std.testing.allocator, "sel={d} scroll={d}", .{ ov.sel, ov.scroll });
    defer std.testing.allocator.free(after_down);
    try expectSnapText(@src(), "sel=14 scroll=3", after_down);
    while (i > 0) : (i -= 1) ov.up();
    const after_up = try std.fmt.allocPrint(std.testing.allocator, "sel={d} scroll={d}", .{ ov.sel, ov.scroll });
    defer std.testing.allocator.free(after_up);
    try expectSnapText(@src(), "sel=0 scroll=0", after_up);
}

test "overlay session kind renders without shortLabel" {
    const rows = try std.testing.allocator.alloc(Overlay.SessionRow, 2);
    defer {
        for (rows) |row| {
            std.testing.allocator.free(row.sid);
            std.testing.allocator.free(row.title);
            std.testing.allocator.free(row.time);
            std.testing.allocator.free(row.tokens);
        }
        std.testing.allocator.free(rows);
    }
    rows[0] = .{
        .sid = try std.testing.allocator.dupe(u8, "sess-abc-123"),
        .title = try std.testing.allocator.dupe(u8, "sess-abc-123"),
        .time = try std.testing.allocator.dupe(u8, "2h"),
        .tokens = try std.testing.allocator.dupe(u8, "10 tok"),
    };
    rows[1] = .{
        .sid = try std.testing.allocator.dupe(u8, "sess-def-456"),
        .title = try std.testing.allocator.dupe(u8, "sess-def-456"),
        .time = try std.testing.allocator.dupe(u8, "5m"),
        .tokens = try std.testing.allocator.dupe(u8, "2 tok"),
    };
    var ov = Overlay.initSession(rows, "Resume Session");

    var frm = try Frame.init(std.testing.allocator, 40, 10);
    defer frm.deinit(std.testing.allocator);
    try ov.render(&frm);
    const actual = try trimmedBoxSegmentsAlloc(std.testing.allocator, &frm);
    defer std.testing.allocator.free(actual);
    try expectSnapText(
        @src(),
        "row0 @0:?????????Resume | @16:Session?????????\nrow1 @0:? | @2:> | @4:sess-abc-123 | @20:2h | @24:10 | @27:tok | @31:?\nrow2 @0:? | @4:sess-def-456 | @20:5m | @25:2 | @27:tok | @31:?\nrow3 @0:????????????????????????????????",
        actual,
    );
    try expectSnapText(@src(), "sess-abc-123", ov.selected().?);
}

test "settings overlay toggle and render" {
    const labels = [_][]const u8{ "Show tools", "Show thinking", "Auto-compact" };
    var toggles = [_]bool{ true, true, false };
    var ov = Overlay{
        .items = &labels,
        .title = "Settings",
        .kind = .settings,
        .toggles = &toggles,
    };

    // Toggle first item
    ov.toggle();
    const toggles_snap = try std.fmt.allocPrint(std.testing.allocator, "0={any}\n1={any}", .{
        ov.getToggle(0).?,
        ov.getToggle(1).?,
    });
    defer std.testing.allocator.free(toggles_snap);
    try expectSnapText(@src(), "0=false\n1=true", toggles_snap);

    // Render without crash
    var frm = try Frame.init(std.testing.allocator, 40, 10);
    defer frm.deinit(std.testing.allocator);
    try ov.render(&frm);
    const full = try trimmedBoxSegmentsAlloc(std.testing.allocator, &frm);
    defer std.testing.allocator.free(full);
    var it = std.mem.splitScalar(u8, full, '\n');
    _ = it.next().?;
    const row1 = it.next().?;
    const row2 = it.next().?;
    const row3 = it.next().?;
    const actual = try std.fmt.allocPrint(std.testing.allocator, "{s}\n{s}\n{s}", .{ row1, row2, row3 });
    defer std.testing.allocator.free(actual);
    try expectSnapText(
        @src(),
        "row1 @0:? | @2:> | @4:Show | @9:tools | @18:? | @20:?\nrow2 @0:? | @4:Show | @9:thinking | @18:? | @20:?\nrow3 @0:? | @4:Auto-compact | @18:? | @20:?",
        actual,
    );
}

test "shortLabel strips date suffix" {
    const got = try std.mem.join(std.testing.allocator, "\n", &.{
        shortLabel("claude-opus-4-6-20250219"),
        shortLabel("my-model"),
        shortLabel("model-with-abc"),
    });
    defer std.testing.allocator.free(got);
    try expectSnapText(@src(), "claude-opus-4-6\nmy-model\nmodel-with-abc", got);
}
