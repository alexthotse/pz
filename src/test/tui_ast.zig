//! TUI AST: semantic extraction from VScreen for test assertions.
//!
//! Given a 120x40 VScreen after a TUI draw, extracts transcript blocks,
//! editor text, footer fields, and overlay structure.
const std = @import("std");
const vscreen = @import("../modes/tui/vscreen.zig");
const frame = @import("../modes/tui/frame.zig");
const theme = @import("../modes/tui/theme.zig");

const VScreen = vscreen.VScreen;
const Color = frame.Color;

pub const TuiAst = struct {
    blocks: []Block,
    footer: Footer,
    editor: []const u8,
    overlay: ?Overlay,
    alloc: std.mem.Allocator,

    pub const Block = struct {
        kind: Kind,
        text: []const u8,
        pub const Kind = enum { user, assistant, tool, info, err, agent };
    };

    pub const Footer = struct {
        row0: []const u8,
        row1: []const u8,
        model: ?[]const u8,
        has_tokens: bool,
        has_cost: bool,
    };

    pub const Overlay = struct {
        title: []const u8,
        items: []const []const u8,
    };

    pub fn deinit(self: *TuiAst) void {
        const a = self.alloc;
        for (self.blocks) |b| a.free(b.text);
        a.free(self.blocks);
        a.free(self.footer.row0);
        a.free(self.footer.row1);
        if (self.footer.model) |m| a.free(m);
        a.free(self.editor);
        if (self.overlay) |ov| {
            a.free(ov.title);
            for (ov.items) |it| a.free(it);
            a.free(ov.items);
        }
        self.* = undefined;
    }
};

/// Extract semantic TUI structure from a vscreen snapshot.
pub fn extract(alloc: std.mem.Allocator, vs: *const VScreen) !TuiAst {
    // Step 1: Find border rows (full-width ─ 0x2500).
    var border1: ?usize = null; // first border (above editor)
    var border2: ?usize = null; // second border (below editor)
    {
        var r: usize = 0;
        while (r < vs.h) : (r += 1) {
            if (isBorderRow(vs, r)) {
                if (border1 == null) {
                    border1 = r;
                } else {
                    border2 = r;
                }
            }
        }
    }

    // Step 2: Determine regions.
    const tx_end = border1 orelse vs.h;
    const ed_start = if (border1) |b1| b1 + 1 else vs.h;
    const ed_end = border2 orelse vs.h;
    const footer_start = if (border2) |b2| b2 + 1 else vs.h;

    // Step 3: Extract transcript blocks.
    const blocks = try extractBlocks(alloc, vs, 0, tx_end);
    errdefer {
        for (blocks) |b| alloc.free(b.text);
        alloc.free(blocks);
    }

    // Step 4: Extract editor text.
    const editor = try extractRegionText(alloc, vs, ed_start, ed_end);
    errdefer alloc.free(editor);

    // Step 5: Extract footer.
    const footer = try extractFooter(alloc, vs, footer_start);

    // Step 6: Detect overlay.
    const overlay = try detectOverlay(alloc, vs);

    return .{
        .blocks = blocks,
        .footer = footer,
        .editor = editor,
        .overlay = overlay,
        .alloc = alloc,
    };
}

/// A row is a border if every non-space cell is ─ (0x2500) and at least half
/// the width is ─. Text labels embedded in the border (e.g. " streaming ◒ ")
/// don't disqualify it — we check that the majority is ─.
fn isBorderRow(vs: *const VScreen, r: usize) bool {
    if (r >= vs.h) return false;
    var dash_count: usize = 0;
    var c: usize = 0;
    while (c < vs.w) : (c += 1) {
        const cp = vs.cellAt(r, c).cp;
        if (cp == 0x2500) dash_count += 1;
    }
    // Require at least 60% ─ characters for border detection.
    return dash_count * 10 >= vs.w * 6;
}

fn extractBlocks(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    start: usize,
    end: usize,
) ![]TuiAst.Block {
    var blocks = std.ArrayListUnmanaged(TuiAst.Block).empty;
    errdefer {
        for (blocks.items) |b| alloc.free(b.text);
        blocks.deinit(alloc);
    }

    if (start >= end) return try blocks.toOwnedSlice(alloc);

    var cur_bg: ?Color = null;
    var block_start: usize = start;

    var r = start;
    while (r < end) : (r += 1) {
        const row_bg = vs.cellAt(r, 0).style.bg;
        const row_empty = isRowEmpty(vs, r);

        if (row_empty) {
            // Empty rows end current block.
            if (cur_bg != null and r > block_start) {
                const blk = try makeBlock(alloc, vs, block_start, r, cur_bg.?);
                try blocks.append(alloc, blk);
            }
            cur_bg = null;
            block_start = r + 1;
            continue;
        }

        if (cur_bg == null) {
            // Start new block.
            cur_bg = row_bg;
            block_start = r;
        } else if (!Color.eql(row_bg, cur_bg.?)) {
            // Background change — flush previous block.
            const blk = try makeBlock(alloc, vs, block_start, r, cur_bg.?);
            try blocks.append(alloc, blk);
            cur_bg = row_bg;
            block_start = r;
        }
    }

    // Flush trailing block.
    if (cur_bg != null and block_start < end) {
        const blk = try makeBlock(alloc, vs, block_start, end, cur_bg.?);
        try blocks.append(alloc, blk);
    }

    return try blocks.toOwnedSlice(alloc);
}

fn makeBlock(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    start: usize,
    end: usize,
    bg: Color,
) !TuiAst.Block {
    const text = try extractRegionText(alloc, vs, start, end);
    const kind = classifyBlock(bg, text);
    return .{ .kind = kind, .text = text };
}

fn classifyBlock(bg: Color, text: []const u8) TuiAst.Block.Kind {
    const t = theme.get();

    // Check background color first.
    if (Color.eql(bg, t.user_msg_bg)) return .user;
    if (Color.eql(bg, t.tool_pending_bg) or
        Color.eql(bg, t.tool_success_bg) or
        Color.eql(bg, t.tool_error_bg))
        return .tool;

    // Text-prefix heuristics for default-bg blocks.
    if (std.mem.startsWith(u8, text, "$ ")) return .tool;
    if (std.mem.startsWith(u8, text, "[err]") or std.mem.startsWith(u8, text, "[error]")) return .err;
    if (std.mem.startsWith(u8, text, "~ agent:")) return .agent;

    // Non-default bg without a recognized color → info.
    if (!bg.isDefault() and
        !Color.eql(bg, t.user_msg_bg))
    {
        return .info;
    }

    return .assistant;
}

fn isRowEmpty(vs: *const VScreen, r: usize) bool {
    var c: usize = 0;
    while (c < vs.w) : (c += 1) {
        if (vs.cellAt(r, c).cp != ' ') return false;
    }
    return true;
}

fn extractRegionText(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    start: usize,
    end: usize,
) ![]const u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(alloc);

    var r = start;
    while (r < end) : (r += 1) {
        const row = try vs.rowText(alloc, r);
        defer alloc.free(row);
        if (buf.items.len > 0 and row.len > 0) {
            try buf.append(alloc, '\n');
        }
        if (row.len > 0) {
            try buf.appendSlice(alloc, row);
        }
    }

    return try buf.toOwnedSlice(alloc);
}

fn extractFooter(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    start: usize,
) !TuiAst.Footer {
    const row0 = if (start < vs.h)
        try vs.rowText(alloc, start)
    else
        try alloc.alloc(u8, 0);
    errdefer alloc.free(row0);

    const row1 = if (start + 1 < vs.h)
        try vs.rowText(alloc, start + 1)
    else
        try alloc.alloc(u8, 0);
    errdefer alloc.free(row1);

    // Parse model: right-aligned on row1, after last multi-space gap.
    const model = extractModel(alloc, row1);

    // Token indicators: ↓ (0xE2 0x86 0x93) or ↑ (0xE2 0x86 0x91).
    const has_tokens = std.mem.indexOf(u8, row1, "\xe2\x86\x93") != null or
        std.mem.indexOf(u8, row1, "\xe2\x86\x91") != null;

    // Cost: $ sign.
    const has_cost = std.mem.indexOfScalar(u8, row1, '$') != null;

    return .{
        .row0 = row0,
        .row1 = row1,
        .model = model,
        .has_tokens = has_tokens,
        .has_cost = has_cost,
    };
}

/// Extract model name from footer row1. The model is right-aligned,
/// separated from stats by spaces. We find the rightmost non-space
/// segment preceded by at least 2 spaces.
fn extractModel(alloc: std.mem.Allocator, row1: []const u8) ?[]const u8 {
    // Find last non-space char.
    var end = row1.len;
    while (end > 0 and row1[end - 1] == ' ') end -= 1;
    if (end == 0) return null;

    // Walk backward to find start of model token (after space gap).
    var start = end;
    while (start > 0 and row1[start - 1] != ' ') start -= 1;

    // Require at least one space before the model.
    if (start == 0) return null;

    const dup = alloc.dupe(u8, row1[start..end]) catch return null;
    return dup;
}

fn detectOverlay(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
) !?TuiAst.Overlay {
    // Scan for ┌ (0x250C) not at column 0 (centered overlay).
    var ov_row: ?usize = null;
    var ov_col: usize = 0;
    {
        var r: usize = 0;
        while (r < vs.h) : (r += 1) {
            var c: usize = 1; // skip col 0 — borders live there
            while (c < vs.w) : (c += 1) {
                if (vs.cellAt(r, c).cp == 0x250C) {
                    ov_row = r;
                    ov_col = c;
                    break;
                }
            }
            if (ov_row != null) break;
        }
    }

    const top_row = ov_row orelse return null;

    // Find ┐ (0x2510) on same row to get box width.
    var ov_right: usize = ov_col + 1;
    while (ov_right < vs.w) : (ov_right += 1) {
        if (vs.cellAt(top_row, ov_right).cp == 0x2510) break;
    }

    // Extract title from top border between ┌ and ┐.
    const title = try extractOverlayTitle(alloc, vs, top_row, ov_col, ov_right);
    errdefer alloc.free(title);

    // Extract items from interior rows (between │ characters).
    var items = std.ArrayListUnmanaged([]const u8).empty;
    errdefer {
        for (items.items) |it| alloc.free(it);
        items.deinit(alloc);
    }

    var r = top_row + 1;
    while (r < vs.h) : (r += 1) {
        const left_cp = vs.cellAt(r, ov_col).cp;
        // └ (0x2514) = bottom border, stop.
        if (left_cp == 0x2514) break;
        // │ (0x2502) = interior row.
        if (left_cp != 0x2502) break;

        const item_text = try extractRowRange(alloc, vs, r, ov_col + 1, ov_right);
        try items.append(alloc, item_text);
    }

    return .{
        .title = title,
        .items = try items.toOwnedSlice(alloc),
    };
}

fn extractOverlayTitle(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    r: usize,
    left: usize,
    right: usize,
) ![]const u8 {
    // Title sits between ─ characters on the top border row.
    // Find first non-─ character after ┌.
    var start = left + 1;
    while (start < right) : (start += 1) {
        const cp = vs.cellAt(r, start).cp;
        if (cp != 0x2500 and cp != ' ') break;
    }
    var end = right;
    while (end > start) : (end -= 1) {
        const cp = vs.cellAt(r, end - 1).cp;
        if (cp != 0x2500 and cp != ' ') break;
    }

    return try extractRowRange(alloc, vs, r, start, end);
}

fn extractRowRange(
    alloc: std.mem.Allocator,
    vs: *const VScreen,
    r: usize,
    col_start: usize,
    col_end: usize,
) ![]const u8 {
    var buf = std.ArrayListUnmanaged(u8).empty;
    errdefer buf.deinit(alloc);
    var c = col_start;
    while (c < col_end) : (c += 1) {
        const cp = vs.cellAt(r, c).cp;
        var enc: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &enc) catch 1;
        try buf.appendSlice(alloc, enc[0..n]);
    }
    // Trim trailing spaces.
    var end = buf.items.len;
    while (end > 0 and buf.items[end - 1] == ' ') end -= 1;
    // Trim leading spaces.
    var start: usize = 0;
    while (start < end and buf.items[start] == ' ') start += 1;
    if (start > 0) {
        std.mem.copyForwards(u8, buf.items[0 .. end - start], buf.items[start..end]);
    }
    buf.items.len = end - start;
    return try buf.toOwnedSlice(alloc);
}

// ── Tests ──

const testing = std.testing;

fn makeSgr(comptime params: []const u8) []const u8 {
    return "\x1b[" ++ params ++ "m";
}

fn bgRgb(r: u8, g: u8, b: u8) []const u8 {
    return std.fmt.comptimePrint("\x1b[48;2;{};{};{}m", .{ r, g, b });
}

fn fgRgb(comptime r: u8, comptime g: u8, comptime b: u8) []const u8 {
    return std.fmt.comptimePrint("\x1b[38;2;{};{};{}m", .{ r, g, b });
}

fn fillBorder(vs: *VScreen, r: usize) void {
    var c: usize = 0;
    while (c < vs.w) : (c += 1) {
        vs.cells[r * vs.w + c] = .{
            .cp = 0x2500,
            .style = .{ .fg = .{ .rgb = 0x5f87ff } },
        };
    }
}

fn fillRow(vs: *VScreen, r: usize, text: []const u8, bg: Color) void {
    // Position cursor at row start with background.
    vs.row = r;
    vs.col = 0;
    vs.style = .{ .bg = bg };
    // Write text.
    var i: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch {
            i += 1;
            continue;
        };
        if (i + n > text.len) break;
        const cp = std.unicode.utf8Decode(text[i .. i + n]) catch {
            i += n;
            continue;
        };
        if (vs.col < vs.w) {
            vs.cells[r * vs.w + vs.col] = .{ .cp = cp, .style = vs.style };
            vs.col += 1;
        }
        i += n;
    }
    // Fill rest of row with bg.
    while (vs.col < vs.w) : (vs.col += 1) {
        vs.cells[r * vs.w + vs.col] = .{ .cp = ' ', .style = vs.style };
    }
}

test "extract startup screen" {
    // Simulate a minimal 30x10 startup screen:
    //   rows 0-5: transcript (one assistant block)
    //   row 6: border
    //   row 7: editor (empty)
    //   row 8: border
    //   row 9-10: footer (2 rows) → but we only have 10 rows total, so 9 is footer row0 and we skip row1
    // Actually let's use 30x12 for cleaner layout.
    const alloc = testing.allocator;
    var vs = try VScreen.init(alloc, 30, 12);
    defer vs.deinit();

    // Transcript: assistant message on rows 0-1 (default bg).
    fillRow(&vs, 0, "Hello! How can I help?", .{ .default = {} });
    fillRow(&vs, 1, "Ask me anything.", .{ .default = {} });
    // Rows 2-6 empty (default = space, default bg).

    // Border at row 7.
    fillBorder(&vs, 7);
    // Editor at row 8 (empty — spaces with default bg, already default).

    // Border at row 9.
    fillBorder(&vs, 9);

    // Footer row 0 at row 10.
    fillRow(&vs, 10, "~/Work/pz (main)", .{ .default = {} });
    // Footer row 1 at row 11.
    fillRow(&vs, 11, "  claude-sonnet-4-20250514", .{ .default = {} });

    var ast = try extract(alloc, &vs);
    defer ast.deinit();

    // One assistant block.
    try testing.expectEqual(@as(usize, 1), ast.blocks.len);
    try testing.expectEqual(TuiAst.Block.Kind.assistant, ast.blocks[0].kind);
    try testing.expectEqualStrings("Hello! How can I help?\nAsk me anything.", ast.blocks[0].text);

    // Editor is empty.
    try testing.expectEqualStrings("", ast.editor);

    // Footer.
    try testing.expectEqualStrings("~/Work/pz (main)", ast.footer.row0);
    try testing.expect(ast.footer.model != null);
    try testing.expectEqualStrings("claude-sonnet-4-20250514", ast.footer.model.?);
}

test "extract prompt and response with user block" {
    const alloc = testing.allocator;
    var vs = try VScreen.init(alloc, 40, 14);
    defer vs.deinit();

    const t = theme.get();
    const user_bg = t.user_msg_bg;

    // Row 0-1: user message (user_msg_bg).
    fillRow(&vs, 0, "What is 2+2?", user_bg);

    // Row 1: empty separator.

    // Row 2-3: assistant response (default bg).
    fillRow(&vs, 2, "The answer is 4.", .{ .default = {} });

    // Rows 4-8 empty.

    // Border at row 9.
    fillBorder(&vs, 9);
    // Editor at row 10.
    fillRow(&vs, 10, "next question", .{ .default = {} });
    // Border at row 11.
    fillBorder(&vs, 11);
    // Footer at rows 12-13.
    fillRow(&vs, 12, "/home/user (dev)", .{ .default = {} });

    // Build footer row1 with tokens + cost + model.
    {
        const row1_text = "\xe2\x86\x93" ++ "1.2k" ++ " \xe2\x86\x91" ++ "340" ++ " $0.02" ++ "           opus-4";
        fillRow(&vs, 13, row1_text, .{ .default = {} });
    }

    var ast = try extract(alloc, &vs);
    defer ast.deinit();

    // Two blocks: user + assistant.
    try testing.expectEqual(@as(usize, 2), ast.blocks.len);
    try testing.expectEqual(TuiAst.Block.Kind.user, ast.blocks[0].kind);
    try testing.expectEqualStrings("What is 2+2?", ast.blocks[0].text);
    try testing.expectEqual(TuiAst.Block.Kind.assistant, ast.blocks[1].kind);
    try testing.expectEqualStrings("The answer is 4.", ast.blocks[1].text);

    // Editor has text.
    try testing.expectEqualStrings("next question", ast.editor);

    // Footer tokens and cost.
    try testing.expect(ast.footer.has_tokens);
    try testing.expect(ast.footer.has_cost);
    try testing.expect(ast.footer.model != null);
    try testing.expectEqualStrings("opus-4", ast.footer.model.?);
}

test "detect overlay box" {
    const alloc = testing.allocator;
    var vs = try VScreen.init(alloc, 30, 10);
    defer vs.deinit();

    // Draw a small overlay box centered at col 10.
    //   row 2: ┌── Select Model ──┐
    //   row 3: │  opus-4           │
    //   row 4: │  sonnet-4         │
    //   row 5: └──────────────────┘
    const x0: usize = 5;
    const x1: usize = 25; // box width = 20

    // Top border.
    vs.cells[2 * vs.w + x0] = .{ .cp = 0x250C }; // ┌
    {
        var c = x0 + 1;
        while (c < x1) : (c += 1) {
            vs.cells[2 * vs.w + c] = .{ .cp = 0x2500 }; // ─
        }
    }
    vs.cells[2 * vs.w + x1] = .{ .cp = 0x2510 }; // ┐

    // Write title centered in top border.
    {
        const title = "Select Model";
        var col: usize = x0 + 4;
        for (title) |ch| {
            vs.cells[2 * vs.w + col] = .{ .cp = ch };
            col += 1;
        }
    }

    // Interior rows.
    vs.cells[3 * vs.w + x0] = .{ .cp = 0x2502 }; // │
    {
        const item = "opus-4";
        var col: usize = x0 + 2;
        for (item) |ch| {
            vs.cells[3 * vs.w + col] = .{ .cp = ch };
            col += 1;
        }
    }
    vs.cells[3 * vs.w + x1] = .{ .cp = 0x2502 };

    vs.cells[4 * vs.w + x0] = .{ .cp = 0x2502 };
    {
        const item = "sonnet-4";
        var col: usize = x0 + 2;
        for (item) |ch| {
            vs.cells[4 * vs.w + col] = .{ .cp = ch };
            col += 1;
        }
    }
    vs.cells[4 * vs.w + x1] = .{ .cp = 0x2502 };

    // Bottom border.
    vs.cells[5 * vs.w + x0] = .{ .cp = 0x2514 }; // └
    {
        var c = x0 + 1;
        while (c < x1) : (c += 1) {
            vs.cells[5 * vs.w + c] = .{ .cp = 0x2500 };
        }
    }
    vs.cells[5 * vs.w + x1] = .{ .cp = 0x2518 }; // ┘

    var ast = try extract(alloc, &vs);
    defer ast.deinit();

    try testing.expect(ast.overlay != null);
    const ov = ast.overlay.?;
    try testing.expectEqualStrings("Select Model", ov.title);
    try testing.expectEqual(@as(usize, 2), ov.items.len);
    try testing.expectEqualStrings("opus-4", ov.items[0]);
    try testing.expectEqualStrings("sonnet-4", ov.items[1]);
}
