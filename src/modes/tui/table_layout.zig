//! Shared markdown table detection, layout computation, and rendering.
const std = @import("std");
const frame = @import("frame.zig");
const theme = @import("theme.zig");
const wc = @import("wcwidth.zig");

pub const max_cols: usize = 32;

pub const Layout = struct {
    ncols: usize,
    widths: [max_cols]usize,
};

pub const Rule = enum {
    top,
    mid,
    bottom,
};

// -- Detection --

pub fn isTableLine(line: []const u8) bool {
    const t = std.mem.trimLeft(u8, line, " \t");
    return t.len > 0 and t[0] == '|';
}

pub fn isSepLine(line: []const u8) bool {
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

// -- Cell splitting --

pub fn splitCells(line: []const u8, buf: *[max_cols][]const u8) usize {
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

// -- Layout computation --

pub fn computeLayout(lines: []const []const u8, max_w: usize) Layout {
    var layout = Layout{
        .ncols = 0,
        .widths = std.mem.zeroes([max_cols]usize),
    };
    var cells_buf: [max_cols][]const u8 = undefined;

    for (lines) |line| {
        const ncells = splitCells(line, &cells_buf);
        if (ncells > layout.ncols) layout.ncols = ncells;
        if (isSepLine(line)) continue;

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

    const overhead = 1 + 3 * layout.ncols;
    if (max_w <= overhead) {
        i = 0;
        while (i < layout.ncols) : (i += 1) layout.widths[i] = 1;
        return layout;
    }

    const avail = max_w - overhead;
    var total: usize = 0;
    i = 0;
    while (i < layout.ncols) : (i += 1) total += layout.widths[i];

    while (total > avail) {
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
        total -= 1;
    }

    return layout;
}

// -- Rendering --

pub fn renderRule(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    layout: Layout,
    base_st: frame.Style,
    rule: Rule,
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
        const seg_w = layout.widths[ci] + 2;
        var k: usize = 0;
        while (k < seg_w and col < max_w) : (k += 1) {
            try frm.set(x + col, y, 0x2500, border_st);
            col += 1;
        }
        if (col < max_w) {
            const cp = if (ci + 1 < layout.ncols) mid_cp else right_cp;
            try frm.set(x + col, y, cp, border_st);
            col += 1;
        }
    }
}

pub fn renderRowAligned(
    frm: *frame.Frame,
    x: usize,
    y: usize,
    max_w: usize,
    line: []const u8,
    layout: Layout,
    base_st: frame.Style,
    is_header: bool,
) (frame.Frame.PosError || error{InvalidUtf8})!void {
    if (max_w == 0 or layout.ncols == 0) return;

    const border_st = frame.Style{
        .fg = theme.get().border_muted,
        .bg = base_st.bg,
    };

    var col: usize = 0;

    var cells_buf: [max_cols][]const u8 = undefined;
    const ncells = splitCells(line, &cells_buf);

    if (col < max_w) {
        try frm.set(x + col, y, 0x2502, border_st);
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

        const written = try writeClippedCols(frm, x + col, y, max_w - col, cell, layout.widths[ci], cell_st);
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
            try frm.set(x + col, y, 0x2502, border_st);
            col += 1;
        }
    }
}

fn writeClippedCols(
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

// -- Visual row counting --

pub fn visualRows(data_n: usize) usize {
    // top + header + header-separator + bottom
    var out: usize = 4;
    out += data_n;
    if (data_n > 1) out += data_n - 1;
    return out;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

test "isTableLine detects pipe-prefixed lines" {
    try testing.expect(isTableLine("| foo |"));
    try testing.expect(isTableLine("  | bar |"));
    try testing.expect(!isTableLine("no pipe"));
    try testing.expect(!isTableLine(""));
}

test "isSepLine detects separator lines" {
    try testing.expect(isSepLine("|---|---|"));
    try testing.expect(isSepLine("| --- | :---: |"));
    try testing.expect(isSepLine("|:---|---:|"));
    try testing.expect(!isSepLine("| data | here |"));
    try testing.expect(!isSepLine("---"));
}

test "splitCells parses pipe-delimited cells" {
    var buf: [max_cols][]const u8 = undefined;
    const n = splitCells("| hello | world | 42 |", &buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualStrings("hello", buf[0]);
    try testing.expectEqualStrings("world", buf[1]);
    try testing.expectEqualStrings("42", buf[2]);
}

test "splitCells handles no trailing pipe" {
    var buf: [max_cols][]const u8 = undefined;
    const n = splitCells("| a | b", &buf);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("a", buf[0]);
    try testing.expectEqualStrings("b", buf[1]);
}

test "computeLayout distributes widths" {
    const lines = [_][]const u8{
        "| Name | V |",
        "| --- | --- |",
        "| abcde | 1 |",
    };
    const layout = computeLayout(&lines, 40);
    try testing.expectEqual(@as(usize, 2), layout.ncols);
    try testing.expect(layout.widths[0] >= 5);
    try testing.expect(layout.widths[1] >= 1);
}

test "visualRows counts correctly" {
    try testing.expectEqual(@as(usize, 4), visualRows(0));
    try testing.expectEqual(@as(usize, 5), visualRows(1));
    try testing.expectEqual(@as(usize, 7), visualRows(2));
}
