//! Markdown renderer: inline styles, code blocks, tables.
const std = @import("std");
const frame = @import("frame.zig");
const theme = @import("theme.zig");
const syntax = @import("syntax.zig");
const wc = @import("wcwidth.zig");
const tbl = @import("table_layout.zig");

pub const Renderer = struct {
    in_code_block: bool = false,
    code_lang: syntax.Lang = .unknown,
    in_table: bool = false,
    saw_table_sep: bool = false,

    pub const RenderError = frame.Frame.PosError || error{InvalidUtf8};

    /// Advance code-block state for a skipped line (scrolled past).
    pub fn advanceSkipped(self: *Renderer, line: []const u8) void {
        if (isFence(line)) {
            if (!self.in_code_block) {
                self.code_lang = syntax.Lang.detect(trimFence(line));
            } else {
                self.code_lang = .unknown;
            }
            self.in_code_block = !self.in_code_block;
            self.in_table = false;
            return;
        }
        // Track table state even for skipped lines
        if (!self.in_code_block) {
            if (tbl.isTableLine(line)) {
                if (tbl.isSepLine(line)) {
                    self.saw_table_sep = true;
                }
                self.in_table = true;
            } else {
                self.in_table = false;
                self.saw_table_sep = false;
            }
        }
    }

    /// Render one line of markdown to frame at (x, y).
    /// Returns number of display columns written.
    pub fn renderLine(self: *Renderer, frm: *frame.Frame, x: usize, y: usize, line: []const u8, max_w: usize, base_st: frame.Style) Renderer.RenderError!usize {
        if (max_w == 0) return 0;

        // Code fence toggle
        if (isFence(line)) {
            if (!self.in_code_block) {
                self.code_lang = syntax.Lang.detect(trimFence(line));
            } else {
                self.code_lang = .unknown;
            }
            self.in_code_block = !self.in_code_block;
            self.in_table = false;
            var st = base_st;
            st.fg = theme.get().md_code_border;
            const trimmed = trimFence(line);
            if (trimmed.len > 0) {
                return try writeStr(frm, x, y, trimmed, max_w, st);
            }
            // Render fence as thin line
            return try fillCh(frm, x, y, max_w, 0x2500, st); // ─
        }

        // Inside code block — syntax highlight
        if (self.in_code_block) {
            return try renderCodeLine(frm, x, y, line, max_w, base_st, self.code_lang);
        }

        // Table line (must be checked before hrule since "|---|" looks like hrule-ish)
        if (tbl.isTableLine(line)) {
            const is_sep = tbl.isSepLine(line);
            const is_header = self.in_table == false and !is_sep;
            self.in_table = true;
            if (is_sep) self.saw_table_sep = true;
            return try renderTableLine(frm, x, y, line, max_w, base_st, is_sep, is_header);
        }
        self.in_table = false;
        self.saw_table_sep = false;

        // Horizontal rule
        if (isHRule(line)) {
            var st = base_st;
            st.fg = theme.get().md_hr;
            return try fillCh(frm, x, y, max_w, 0x2500, st); // ─
        }

        // Heading
        if (headingLevel(line)) |lvl| {
            const rest = line[lvl + 1 ..]; // skip "# "
            var st = base_st;
            st.fg = theme.get().md_heading;
            st.bold = true;
            return try renderInline(frm, x, y, rest, max_w, st);
        }

        // Blockquote
        if (isBlockquote(line)) {
            var st = base_st;
            st.fg = theme.get().md_quote;
            var col: usize = 0;
            // Write "│ " prefix
            if (col < max_w) {
                try frm.set(x + col, y, 0x2502, st); // │
                col += 1;
            }
            if (col < max_w) {
                try frm.set(x + col, y, ' ', st);
                col += 1;
            }
            const rest = stripQuotePrefix(line);
            col += try renderInline(frm, x + col, y, rest, max_w - col, base_st);
            return col;
        }

        // Unordered list
        if (unorderedItem(line)) |rest| {
            var bst = base_st;
            bst.fg = theme.get().md_list_bullet;
            var col: usize = 0;
            if (col < max_w) {
                try frm.set(x + col, y, 0x2022, bst); // •
                col += 1;
            }
            if (col < max_w) {
                try frm.set(x + col, y, ' ', base_st);
                col += 1;
            }
            col += try renderInline(frm, x + col, y, rest, max_w - col, base_st);
            return col;
        }

        // Ordered list
        if (orderedItem(line)) |info| {
            var bst = base_st;
            bst.fg = theme.get().md_list_bullet;
            var col: usize = 0;
            // Write the number + ". "
            for (info.prefix) |ch| {
                if (col >= max_w) break;
                try frm.set(x + col, y, ch, bst);
                col += 1;
            }
            if (col < max_w) {
                try frm.set(x + col, y, ' ', base_st);
                col += 1;
            }
            col += try renderInline(frm, x + col, y, info.rest, max_w - col, base_st);
            return col;
        }

        // Plain text with inline formatting
        return try renderInline(frm, x, y, line, max_w, base_st);
    }
};

fn cellsSnapAlloc(alloc: std.mem.Allocator, n: usize, buf: []const []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    try std.fmt.format(out.writer(alloc), "n={}", .{n});
    for (buf[0..n], 0..) |cell, i| {
        try std.fmt.format(out.writer(alloc), "\n[{d}] {s}", .{ i, cell });
    }
    return out.toOwnedSlice(alloc);
}

fn renderTableLine(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    line: []const u8,
    max_w: usize,
    base_st: frame.Style,
    is_sep: bool,
    is_header: bool,
) Renderer.RenderError!usize {
    const t = theme.get();
    const border_st = frame.Style{ .fg = t.border_muted, .bg = base_st.bg };

    if (is_sep) {
        // Render separator as ─ fill with ┼ at pipe positions
        var col: usize = 0;
        const trimmed = trimLeadingSpaces(line);
        var i: usize = 0;
        while (i < trimmed.len and col < max_w) : (i += 1) {
            const ch: u21 = if (trimmed[i] == '|') 0x253C else 0x2500; // ┼ or ─
            try frm.set(x + col, y, ch, border_st);
            col += 1;
        }
        return col;
    }

    // Header or data row — render cells with │ borders
    var cell_buf: [tbl.max_cols][]const u8 = undefined;
    const ncells = tbl.splitCells(line, &cell_buf);
    const cells = cell_buf[0..ncells];

    var col: usize = 0;

    // Leading │
    if (col < max_w) {
        try frm.set(x + col, y, 0x2502, border_st); // │
        col += 1;
    }

    for (cells) |cell| {
        // Space before cell content
        if (col < max_w) {
            try frm.set(x + col, y, ' ', base_st);
            col += 1;
        }

        // Cell content
        if (is_header) {
            var hdr_st = base_st;
            hdr_st.bold = true;
            col += try renderInline(frm, x + col, y, cell, max_w -| col, hdr_st);
        } else {
            col += try renderInline(frm, x + col, y, cell, max_w -| col, base_st);
        }

        // Space after cell content
        if (col < max_w) {
            try frm.set(x + col, y, ' ', base_st);
            col += 1;
        }

        // │ separator
        if (col < max_w) {
            try frm.set(x + col, y, 0x2502, border_st); // │
            col += 1;
        }
    }

    return col;
}

fn renderCodeLine(frm: *frame.Frame, x: usize, y: usize, line: []const u8, max_w: usize, base_st: frame.Style, lang: syntax.Lang) Renderer.RenderError!usize {
    var tok_buf: [512]syntax.Token = undefined;
    const toks = syntax.tokenize(line, lang, &tok_buf);
    var col: usize = 0;
    for (toks) |tok| {
        if (col >= max_w) break;
        const text = line[tok.start..tok.end];
        const st = tok.kind.style(base_st);
        col += try writeStr(frm, x + col, y, text, max_w - col, st);
    }
    return col;
}

// -- Inline renderer --

fn renderInline(frm: *frame.Frame, x: usize, y: usize, text: []const u8, max_w: usize, base_st: frame.Style) Renderer.RenderError!usize {
    if (max_w == 0) return 0;

    var col: usize = 0;
    var i: usize = 0;

    while (i < text.len and col < max_w) {
        // Inline code: `...`
        if (text[i] == '`') {
            if (findInlineCode(text, i)) |span| {
                var st = base_st;
                st.fg = theme.get().md_code;
                const content = text[span.start..span.end];
                col += try writeStr(frm, x + col, y, content, max_w - col, st);
                i = span.after;
                continue;
            }
        }

        // Bold: **...** or __...__
        if (i + 1 < text.len and ((text[i] == '*' and text[i + 1] == '*') or (text[i] == '_' and text[i + 1] == '_'))) {
            if (findDelimited(text, i, 2)) |span| {
                var st = base_st;
                st.bold = true;
                const content = text[span.start..span.end];
                col += try writeStr(frm, x + col, y, content, max_w - col, st);
                i = span.after;
                continue;
            }
        }

        // Italic: *...* or _..._
        if ((text[i] == '*' or text[i] == '_') and !(i + 1 < text.len and text[i + 1] == text[i])) {
            if (findDelimited(text, i, 1)) |span| {
                var st = base_st;
                st.italic = true;
                const content = text[span.start..span.end];
                col += try writeStr(frm, x + col, y, content, max_w - col, st);
                i = span.after;
                continue;
            }
        }

        // Link: [text](url)
        if (text[i] == '[') {
            if (findLink(text, i)) |lnk| {
                var st = base_st;
                st.fg = theme.get().md_link;
                col += try writeStr(frm, x + col, y, lnk.label, max_w - col, st);
                i = lnk.after;
                continue;
            }
        }

        // Regular character
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch 1;
        const end = @min(i + n, text.len);
        const view = std.unicode.Utf8View.initUnchecked(text[i..end]);
        var it = view.iterator();
        if (it.nextCodepoint()) |cp| {
            const cw = wc.wcwidth(cp);
            if (col + cw > max_w) break;
            try frm.set(x + col, y, cp, base_st);
            col += cw;
        }
        i = end;
    }

    return col;
}

// -- Block detection helpers --

pub fn isFence(line: []const u8) bool {
    const t = trimLeadingSpaces(line);
    if (t.len < 3) return false;
    if (t[0] != '`') return false;
    if (t[1] != '`') return false;
    if (t[2] != '`') return false;
    return true;
}

fn trimFence(line: []const u8) []const u8 {
    const t = trimLeadingSpaces(line);
    // Skip backticks
    var i: usize = 0;
    while (i < t.len and t[i] == '`') : (i += 1) {}
    // Remaining is the language tag
    const rest = std.mem.trim(u8, t[i..], " \t");
    return rest;
}

fn isHRule(line: []const u8) bool {
    const t = trimLeadingSpaces(line);
    if (t.len < 3) return false;
    const ch = t[0];
    if (ch != '-' and ch != '*' and ch != '_') return false;
    for (t) |c| {
        if (c != ch and c != ' ' and c != '\t') return false;
    }
    // Count actual chars
    var n: usize = 0;
    for (t) |c| {
        if (c == ch) n += 1;
    }
    return n >= 3;
}

fn headingLevel(line: []const u8) ?usize {
    var lvl: usize = 0;
    while (lvl < line.len and line[lvl] == '#') : (lvl += 1) {}
    if (lvl == 0 or lvl > 6) return null;
    if (lvl >= line.len or line[lvl] != ' ') return null;
    return lvl;
}

fn isBlockquote(line: []const u8) bool {
    if (line.len < 2) return false;
    return line[0] == '>' and line[1] == ' ';
}

fn stripQuotePrefix(line: []const u8) []const u8 {
    if (line.len >= 2 and line[0] == '>' and line[1] == ' ')
        return line[2..];
    return line;
}

fn unorderedItem(line: []const u8) ?[]const u8 {
    if (line.len < 2) return null;
    if ((line[0] == '-' or line[0] == '*' or line[0] == '+') and line[1] == ' ')
        return line[2..];
    return null;
}

const OrdItem = struct {
    prefix: []const u8,
    rest: []const u8,
};

fn orderedItem(line: []const u8) ?OrdItem {
    var i: usize = 0;
    while (i < line.len and line[i] >= '0' and line[i] <= '9') : (i += 1) {}
    if (i == 0) return null;
    if (i >= line.len or line[i] != '.') return null;
    if (i + 1 >= line.len or line[i + 1] != ' ') return null;
    return .{
        .prefix = line[0 .. i + 1], // "1."
        .rest = line[i + 2 ..],
    };
}

// -- Inline span detection --

const Span = struct {
    start: usize,
    end: usize,
    after: usize,
};

fn findInlineCode(text: []const u8, pos: usize) ?Span {
    if (pos >= text.len or text[pos] != '`') return null;
    const start = pos + 1;
    if (start >= text.len) return null;
    var i = start;
    while (i < text.len) : (i += 1) {
        if (text[i] == '`') {
            if (i == start) return null; // empty ``
            return .{ .start = start, .end = i, .after = i + 1 };
        }
    }
    return null;
}

fn findDelimited(text: []const u8, pos: usize, delim_len: usize) ?Span {
    if (pos + delim_len >= text.len) return null;
    const ch = text[pos];
    // Verify opening delimiter
    var d: usize = 0;
    while (d < delim_len) : (d += 1) {
        if (pos + d >= text.len or text[pos + d] != ch) return null;
    }
    const start = pos + delim_len;
    if (start >= text.len) return null;
    // Don't match if opening delimiter is followed by space
    if (text[start] == ' ') return null;

    var i = start;
    while (i + delim_len <= text.len) : (i += 1) {
        var match = true;
        var j: usize = 0;
        while (j < delim_len) : (j += 1) {
            if (text[i + j] != ch) {
                match = false;
                break;
            }
        }
        if (match and i > start) {
            // Don't match if closing delimiter preceded by space
            if (text[i - 1] == ' ') continue;
            return .{ .start = start, .end = i, .after = i + delim_len };
        }
    }
    return null;
}

const Link = struct {
    label: []const u8,
    after: usize,
};

fn findLink(text: []const u8, pos: usize) ?Link {
    if (pos >= text.len or text[pos] != '[') return null;
    // Find ]
    var i = pos + 1;
    while (i < text.len and text[i] != ']') : (i += 1) {}
    if (i >= text.len) return null;
    const label = text[pos + 1 .. i];
    if (label.len == 0) return null;
    // Expect (
    i += 1;
    if (i >= text.len or text[i] != '(') return null;
    // Find )
    i += 1;
    while (i < text.len and text[i] != ')') : (i += 1) {}
    if (i >= text.len) return null;
    return .{ .label = label, .after = i + 1 };
}

// -- Utility --

fn trimLeadingSpaces(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len and (s[i] == ' ' or s[i] == '\t')) : (i += 1) {}
    return s[i..];
}

fn writeStr(frm: *frame.Frame, x: usize, y: usize, text: []const u8, max_w: usize, st: frame.Style) Renderer.RenderError!usize {
    if (max_w == 0 or text.len == 0) return 0;
    if (x >= frm.w or y >= frm.h) return error.OutOfBounds;

    var col: usize = 0;
    const view = std.unicode.Utf8View.initUnchecked(text);
    var it = view.iterator();
    while (col < max_w) {
        const cp = it.nextCodepoint() orelse break;
        const cw = wc.wcwidth(cp);
        if (col + cw > max_w) break;
        if (x + col >= frm.w) break;
        try frm.set(x + col, y, cp, st);
        col += cw;
    }
    return col;
}

fn fillCh(frm: *frame.Frame, x: usize, y: usize, w: usize, cp: u21, st: frame.Style) frame.Frame.PosError!usize {
    var i: usize = 0;
    while (i < w) : (i += 1) {
        if (x + i >= frm.w) break;
        try frm.set(x + i, y, cp, st);
    }
    return i;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn rowChars(frm: *const frame.Frame, y: usize, buf: []u21) ![]const u21 {
    var i: usize = 0;
    while (i < frm.w and i < buf.len) : (i += 1) {
        buf[i] = (try frm.cell(i, y)).cp;
    }
    return buf[0..i];
}

fn rowStyles(frm: *const frame.Frame, y: usize, buf: []frame.Style) ![]const frame.Style {
    var i: usize = 0;
    while (i < frm.w and i < buf.len) : (i += 1) {
        buf[i] = (try frm.cell(i, y)).style;
    }
    return buf[0..i];
}

fn u21Eql(a: []const u21, b: []const u21) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
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

fn appendColorName(out: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, c: frame.Color) !void {
    switch (c) {
        .default => try out.appendSlice(alloc, "default"),
        .idx => |idx| try std.fmt.format(out.writer(alloc), "idx:{d}", .{idx}),
        .rgb => |rgb| try std.fmt.format(out.writer(alloc), "rgb:{x:0>6}", .{rgb}),
    }
}

fn appendCodepoint(out: *std.ArrayListUnmanaged(u8), alloc: std.mem.Allocator, cp: u21) !void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch {
        try out.append(alloc, '?');
        return;
    };
    try out.appendSlice(alloc, buf[0..n]);
}

fn frameRowsStyleSnapAlloc(
    alloc: std.mem.Allocator,
    frm: *const frame.Frame,
    y0: usize,
    y1: usize,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    var y = y0;
    while (y <= y1) : (y += 1) {
        if (y != y0) try out.append(alloc, '\n');
        var last: usize = 0;
        var found = false;
        var x: usize = 0;
        while (x < frm.w) : (x += 1) {
            const c = try frm.cell(x, y);
            if (c.cp != ' ') {
                last = x + 1;
                found = true;
            }
        }
        try std.fmt.format(out.writer(alloc), "{d}:", .{y});
        if (found) {
            x = 0;
            while (x < last) : (x += 1) {
                const c = try frm.cell(x, y);
                try appendCodepoint(&out, alloc, c.cp);
            }
        }

        var any = false;
        x = 0;
        while (x < last) {
            const c = try frm.cell(x, y);
            if (c.style.isDefault()) {
                x += 1;
                continue;
            }
            any = true;
            const st = c.style;
            const x0 = x;
            x += 1;
            while (x < last) : (x += 1) {
                const next = try frm.cell(x, y);
                if (!frame.Style.eql(st, next.style)) break;
            }
            try std.fmt.format(out.writer(alloc), "\n  {d}..{d} fg=", .{ x0, x });
            try appendColorName(&out, alloc, st.fg);
            try out.appendSlice(alloc, " bg=");
            try appendColorName(&out, alloc, st.bg);
            try std.fmt.format(out.writer(alloc), " b={d} d={d} i={d} u={d} inv={d}", .{
                @intFromBool(st.bold),
                @intFromBool(st.dim),
                @intFromBool(st.italic),
                @intFromBool(st.underline),
                @intFromBool(st.inverse),
            });
        }
        if (!any) try out.appendSlice(alloc, "\n  styles=0");
    }
    return out.toOwnedSlice(alloc);
}

test "heading renders bold with md_heading color" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    const n = try md.renderLine(&frm, 0, 0, "## Hello", 20, .{});
    try testing.expectEqual(@as(usize, 5), n);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:Hello
        \\  0..5 fg=rgb:f0c674 bg=default b=1 d=0 i=0 u=0 inv=0
    , snap);
}

test "code fence toggles code block mode" {
    var frm = try frame.Frame.init(testing.allocator, 30, 3);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};

    // Opening fence
    _ = try md.renderLine(&frm, 0, 0, "```zig", 30, .{});
    try testing.expect(md.in_code_block);
    try testing.expectEqual(syntax.Lang.zig, md.code_lang);

    const n = try md.renderLine(&frm, 0, 1, "const x = 1;", 30, .{});
    try testing.expect(n > 0);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 1, 1);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\1:const x = 1;
        \\  0..5 fg=rgb:569cd6 bg=default b=1 d=0 i=0 u=0 inv=0
        \\  8..9 fg=rgb:d4d4d4 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  10..11 fg=rgb:b5cea8 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  11..12 fg=rgb:d4d4d4 bg=default b=0 d=1 i=0 u=0 inv=0
    , snap);

    _ = try md.renderLine(&frm, 0, 2, "```", 30, .{});
    try testing.expect(!md.in_code_block);
    try testing.expectEqual(syntax.Lang.unknown, md.code_lang);
}

test "code block without lang hint uses generic highlighting" {
    var frm = try frame.Frame.init(testing.allocator, 30, 3);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "```", 30, .{});
    try testing.expect(md.in_code_block);
    try testing.expectEqual(syntax.Lang.unknown, md.code_lang);

    const n = try md.renderLine(&frm, 0, 1, "x = \"hi\"", 30, .{});
    try testing.expect(n > 0);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 1, 1);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\1:x = "hi"
        \\  2..3 fg=rgb:d4d4d4 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  4..8 fg=rgb:ce9178 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "blockquote renders bar prefix" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "> quoted", 20, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:│ quoted
        \\  0..2 fg=rgb:808080 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "unordered list renders bullet" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "- item", 20, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:• item
        \\  0..1 fg=rgb:8abeb7 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "ordered list renders number" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "3. third", 20, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:3. third
        \\  0..2 fg=rgb:8abeb7 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "horizontal rule fills with line char" {
    var frm = try frame.Frame.init(testing.allocator, 10, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    const n = try md.renderLine(&frm, 0, 0, "---", 10, .{});
    try testing.expectEqual(@as(usize, 10), n);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:──────────
        \\  0..10 fg=rgb:808080 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "inline code gets md_code style" {
    var frm = try frame.Frame.init(testing.allocator, 30, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "use `foo` here", 30, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:use foo here
        \\  4..7 fg=rgb:8abeb7 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "bold text gets bold attribute" {
    var frm = try frame.Frame.init(testing.allocator, 30, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "a **bold** z", 30, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:a bold z
        \\  2..6 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
    , snap);
}

test "italic text gets italic attribute" {
    var frm = try frame.Frame.init(testing.allocator, 30, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "a *em* z", 30, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:a em z
        \\  2..4 fg=default bg=default b=0 d=0 i=1 u=0 inv=0
    , snap);
}

test "link renders label in md_link color" {
    var frm = try frame.Frame.init(testing.allocator, 30, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "[click](http://x.com)", 30, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:click
        \\  0..5 fg=rgb:81a2be bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "fence lang tag rendered in code_border color" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "```python", 20, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:python
        \\  0..6 fg=rgb:808080 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "plain text renders unchanged" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    const n = try md.renderLine(&frm, 0, 0, "hello", 20, .{});
    try testing.expectEqual(@as(usize, 5), n);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:hello
        \\  styles=0
    , snap);
}

test "max_w clips output" {
    var frm = try frame.Frame.init(testing.allocator, 20, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    const n = try md.renderLine(&frm, 0, 0, "abcdefghij", 3, .{});
    try testing.expectEqual(@as(usize, 3), n);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:abc
        \\  styles=0
    , snap);
}

test "table header renders bold with borders" {
    var frm = try frame.Frame.init(testing.allocator, 40, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    const n = try md.renderLine(&frm, 0, 0, "| Name | Age |", 40, .{});
    try testing.expect(n > 0);
    try testing.expect(md.in_table);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 0);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:│ Name │ Age │
        \\  0..1 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  2..6 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  7..8 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  9..12 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  13..14 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "table separator renders as box-drawing" {
    var frm = try frame.Frame.init(testing.allocator, 40, 2);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    // First line starts table
    _ = try md.renderLine(&frm, 0, 0, "| A | B |", 40, .{});
    // Separator line
    const n = try md.renderLine(&frm, 0, 1, "|---|---|", 40, .{});
    try testing.expect(n > 0);
    try testing.expect(md.saw_table_sep);
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 1);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:│ A │ B │
        \\  0..1 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  2..3 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  4..5 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  6..7 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  8..9 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\1:┼───┼───┼
        \\  0..9 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "table data row renders normal text with borders" {
    var frm = try frame.Frame.init(testing.allocator, 40, 3);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "| H1 | H2 |", 40, .{});
    _ = try md.renderLine(&frm, 0, 1, "|-----|-----|", 40, .{});
    _ = try md.renderLine(&frm, 0, 2, "| foo | bar |", 40, .{});
    const snap = try frameRowsStyleSnapAlloc(testing.allocator, &frm, 0, 2);
    defer testing.allocator.free(snap);
    try expectSnapText(@src(),
        \\0:│ H1 │ H2 │
        \\  0..1 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  2..4 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  5..6 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  7..9 fg=default bg=default b=1 d=0 i=0 u=0 inv=0
        \\  10..11 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\1:┼─────┼─────┼
        \\  0..13 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\2:│ foo │ bar │
        \\  0..1 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  6..7 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
        \\  12..13 fg=rgb:505050 bg=default b=0 d=0 i=0 u=0 inv=0
    , snap);
}

test "table state resets on non-table line" {
    var frm = try frame.Frame.init(testing.allocator, 40, 1);
    defer frm.deinit(testing.allocator);

    var md = Renderer{};
    _ = try md.renderLine(&frm, 0, 0, "| A |", 40, .{});
    try testing.expect(md.in_table);
    md.advanceSkipped("not a table");
    try testing.expect(!md.in_table);
}

test "isTableSep detects separator lines" {
    try testing.expect(tbl.isSepLine("|---|---|"));
    try testing.expect(tbl.isSepLine("| --- | :---: |"));
    try testing.expect(tbl.isSepLine("|:---|---:|"));
    try testing.expect(!tbl.isSepLine("| data | here |"));
    try testing.expect(!tbl.isSepLine("---"));
}

test "splitCells parses pipe-delimited cells" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var buf: [tbl.max_cols][]const u8 = undefined;
    const n = tbl.splitCells("| hello | world | 42 |", &buf);
    const snap = try cellsSnapAlloc(testing.allocator, n, buf[0..]);
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "n=3
        \\[0] hello
        \\[1] world
        \\[2] 42"
    ).expectEqual(snap);
}

test "splitCells handles no trailing pipe" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var buf: [tbl.max_cols][]const u8 = undefined;
    const n = tbl.splitCells("| a | b", &buf);
    const snap = try cellsSnapAlloc(testing.allocator, n, buf[0..]);
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "n=2
        \\[0] a
        \\[1] b"
    ).expectEqual(snap);
}
