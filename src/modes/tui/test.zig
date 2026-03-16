//! TUI test fixtures: harness setup for snapshot tests.
const std = @import("std");
const core = @import("../../core.zig");
const frame = @import("frame.zig");
const harness = @import("harness.zig");
const render = @import("render.zig");
const theme = @import("theme.zig");
const vscreen = @import("vscreen.zig");

const Event = core.providers.Event;
const VScreen = vscreen.VScreen;
const Ui = harness.Ui;
const FrameSnap = struct {
    row0: []const u8,
    row1: []const u8,
    row8: []const u8,
    row9: []const u8,
};

const TableSnap = struct {
    counts: [5]usize,
    top: [3]usize,
    hdr: [3]usize,
    row1: [3]usize,
    row2: [3]usize,
    bot: [3]usize,
    corners: [9]u21,
    padding: [6]u21,
};

/// Render a Ui into a VScreen via the renderer.
fn renderToVs(ui: *Ui, vs: *VScreen) !void {
    var buf: [16384]u8 = undefined;
    var out = BufWriter.init(&buf);
    try ui.draw(&out);
    vs.feed(out.view());
}

const BufWriter = @import("test_buf.zig").TestBuf;

// Layout helper: reserved = 5 (border + editor + border + 2 footer)
// tx_h = h - 5 for h >= 6

// ── Scenarios ──

test "e2e simple text response" {
    var ui = try Ui.init(std.testing.allocator, 60, 10, "gpt-4", "openai");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "Hello, how can I help?" });
    try ui.onProvider(.{ .usage = .{ .in_tok = 10, .out_tok = 20, .tot_tok = 30 } });
    try ui.onProvider(.{ .stop = .{ .reason = .done } });

    var vs = try VScreen.init(std.testing.allocator, 60, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=10: tx_h=5 (rows 0..4), border 5, editor 6, border 7, footer 8-9
    // Usage/stop no longer shown in transcript
    var found_text = false;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "Hello, how can I help?") != null) found_text = true;
    }
    try std.testing.expect(found_text);
}

test "e2e text + thinking + text" {
    // h=10: tx_h=5, enough for 3 blocks + 2 gaps
    var ui = try Ui.init(std.testing.allocator, 40, 10, "claude", "anthropic");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "Let me think..." });
    try ui.onProvider(.{ .thinking = "analyzing the problem" });
    try ui.onProvider(.{ .text = "Here is my answer." });

    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // tx_h=5: Let me think (0), gap (1), analyzing (2), gap (3), Here is (4)
    {
        const row = try vs.rowText(std.testing.allocator, 0);
        defer std.testing.allocator.free(row);
        try std.testing.expect(std.mem.indexOf(u8, row, "Let me think") != null);
    }
    {
        const row = try vs.rowText(std.testing.allocator, 2);
        defer std.testing.allocator.free(row);
        try std.testing.expect(std.mem.indexOf(u8, row, "analyzing the problem") != null);
    }
    {
        const row = try vs.rowText(std.testing.allocator, 4);
        defer std.testing.allocator.free(row);
        try std.testing.expect(std.mem.indexOf(u8, row, "Here is my answer") != null);
    }
}

test "e2e tool call and result" {
    var ui = try Ui.init(std.testing.allocator, 50, 10, "gpt-4", "openai");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "I'll read the file." });
    try ui.onProvider(.{ .tool_call = .{
        .id = "c1",
        .name = "read",
        .args = "{\"path\":\"main.zig\"}",
    } });
    try ui.onProvider(.{ .tool_result = .{
        .id = "c1",
        .output = "const std = @import(\"std\");",
        .is_err = false,
    } });
    try ui.onProvider(.{ .text = "The file imports std." });

    var vs = try VScreen.init(std.testing.allocator, 50, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=10: tx_h=5 (rows 0..4)
    // Tool call now shows as "$ read main.zig" in dim
    var found_tool = false;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "$ read main.zig") != null) {
            try vs.expectFg(r, 1, .{ .rgb = 0x666666 }); // theme.dim
            found_tool = true;
            break;
        }
    }
    try std.testing.expect(found_tool);

    // Find tool result row
    var found_result = false;
    r = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "const std") != null) {
            found_result = true;
            break;
        }
    }
    try std.testing.expect(found_result);
}

test "e2e error response" {
    // Use larger terminal so error fits in transcript area
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .err = "rate limit exceeded" });

    var vs = try VScreen.init(std.testing.allocator, 40, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=8: tx_h=3 (rows 0..2)
    var found_err = false;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "[err] rate limit exceeded") != null) {
            try vs.expectFg(r, 1, .{ .rgb = 0xcc6666 }); // theme.err
            try vs.expectBold(r, 1, true);
            try vs.expectBg(r, 0, .{ .rgb = 0x3c2828 }); // theme.tool_error_bg
            found_err = true;
            break;
        }
    }
    try std.testing.expect(found_err);
}

test "e2e tool result with ANSI is stripped" {
    var ui = try Ui.init(std.testing.allocator, 50, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .tool_result = .{
        .id = "c1",
        .output = "\x1b[31mred text\x1b[0m normal",
        .is_err = false,
    } });

    var vs = try VScreen.init(std.testing.allocator, 50, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=8: tx_h=3 (rows 0..2)
    var found_stripped = false;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        // Should not contain raw ESC byte
        try std.testing.expect(std.mem.indexOfScalar(u8, row, 0x1b) == null);
        // Check for stripped content (may be word-wrapped across lines)
        if (std.mem.indexOf(u8, row, "red text") != null or
            std.mem.indexOf(u8, row, "text normal") != null)
            found_stripped = true;
    }
    try std.testing.expect(found_stripped);
}

test "e2e word wrap in narrow terminal" {
    var ui = try Ui.init(std.testing.allocator, 20, 10, "m", "p");
    defer ui.deinit();

    // Text wider than transcript area should wrap
    try ui.onProvider(.{ .text = "hello world this is a long response" });

    var vs = try VScreen.init(std.testing.allocator, 20, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=10: tx_h=5 (rows 0..4)
    // w=20, 1-col pad → 19 cols for text. "hello world this is a long response" wraps.
    var non_empty: usize = 0;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (row.len > 0) non_empty += 1;
    }
    try std.testing.expect(non_empty >= 2);
}

test "e2e markdown table draws aligned separators" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var ui = try Ui.init(std.testing.allocator, 80, 12, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "| Name | Value |\n" ++
        "| --- | --- |\n" ++
        "| a | 1 |\n" ++
        "| longer-name | 12345 |" });

    var vs = try VScreen.init(std.testing.allocator, 80, 12);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    const S = struct {
        fn borderCols(vs_: *const VScreen, r: usize, out: *[8]usize) usize {
            var n: usize = 0;
            var c: usize = 0;
            while (c < vs_.w) : (c += 1) {
                const cp = vs_.cellAt(r, c).cp;
                const is_border = cp == 0x2502 or // │
                    cp == 0x251C or // ├
                    cp == 0x253C or // ┼
                    cp == 0x2524 or // ┤
                    cp == 0x250C or // ┌
                    cp == 0x252C or // ┬
                    cp == 0x2510 or // ┐
                    cp == 0x2514 or // └
                    cp == 0x2534 or // ┴
                    cp == 0x2518; // ┘
                if (!is_border) continue;
                if (n < out.len) out[n] = c;
                n += 1;
            }
            return n;
        }
    };

    var hcols: [8]usize = undefined;
    var hdr_cols: [8]usize = undefined;
    var d1cols: [8]usize = undefined;
    var d2cols: [8]usize = undefined;
    var bot_cols: [8]usize = undefined;
    const top_n = S.borderCols(&vs, 0, &hcols);
    const hdr_n = S.borderCols(&vs, 1, &hdr_cols);
    const d1n = S.borderCols(&vs, 3, &d1cols);
    const d2n = S.borderCols(&vs, 5, &d2cols);
    const bot_n = S.borderCols(&vs, 6, &bot_cols);

    const snap = TableSnap{
        .counts = .{ top_n, hdr_n, d1n, d2n, bot_n },
        .top = .{ hcols[0], hcols[1], hcols[2] },
        .hdr = .{ hdr_cols[0], hdr_cols[1], hdr_cols[2] },
        .row1 = .{ d1cols[0], d1cols[1], d1cols[2] },
        .row2 = .{ d2cols[0], d2cols[1], d2cols[2] },
        .bot = .{ bot_cols[0], bot_cols[1], bot_cols[2] },
        .corners = .{
            vs.cellAt(0, hcols[0]).cp,
            vs.cellAt(0, hcols[1]).cp,
            vs.cellAt(0, hcols[2]).cp,
            vs.cellAt(2, hcols[0]).cp,
            vs.cellAt(2, hcols[1]).cp,
            vs.cellAt(2, hcols[2]).cp,
            vs.cellAt(6, hcols[0]).cp,
            vs.cellAt(6, hcols[1]).cp,
            vs.cellAt(6, hcols[2]).cp,
        },
        .padding = .{
            vs.cellAt(3, hcols[0] + 1).cp,
            vs.cellAt(3, hcols[0] + 2).cp,
            vs.cellAt(3, hcols[1] - 1).cp,
            vs.cellAt(3, hcols[1] + 1).cp,
            vs.cellAt(3, hcols[1] + 2).cp,
            vs.cellAt(3, hcols[2] - 1).cp,
        },
    };
    try oh.snap(@src(),
        \\modes.tui.test.TableSnap
        \\  .counts: [5]usize
        \\    [0]: usize = 3
        \\    [1]: usize = 3
        \\    [2]: usize = 3
        \\    [3]: usize = 3
        \\    [4]: usize = 3
        \\  .top: [3]usize
        \\    [0]: usize = 1
        \\    [1]: usize = 15
        \\    [2]: usize = 23
        \\  .hdr: [3]usize
        \\    [0]: usize = 1
        \\    [1]: usize = 15
        \\    [2]: usize = 23
        \\  .row1: [3]usize
        \\    [0]: usize = 1
        \\    [1]: usize = 15
        \\    [2]: usize = 23
        \\  .row2: [3]usize
        \\    [0]: usize = 1
        \\    [1]: usize = 15
        \\    [2]: usize = 23
        \\  .bot: [3]usize
        \\    [0]: usize = 1
        \\    [1]: usize = 15
        \\    [2]: usize = 23
        \\  .corners: [9]u21
        \\    [0]: u21 = '┌'
        \\    [1]: u21 = '┬'
        \\    [2]: u21 = '┐'
        \\    [3]: u21 = '├'
        \\    [4]: u21 = '┼'
        \\    [5]: u21 = '┤'
        \\    [6]: u21 = '└'
        \\    [7]: u21 = '┴'
        \\    [8]: u21 = '┘'
        \\  .padding: [6]u21
        \\    [0]: u21 = ' '
        \\    [1]: u21 = 'a'
        \\    [2]: u21 = ' '
        \\    [3]: u21 = ' '
        \\    [4]: u21 = '1'
        \\    [5]: u21 = ' '
    ).expectEqual(snap);
}

test "golden snapshot deterministic frame text" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();
    try ui.onProvider(.{ .text = "hello world" });
    try ui.onProvider(.{ .stop = .{ .reason = .done } });

    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    const r0_full = try vs.rowText(std.testing.allocator, 0);
    defer std.testing.allocator.free(r0_full);
    const r1_full = try vs.rowText(std.testing.allocator, 1);
    defer std.testing.allocator.free(r1_full);
    const r8_full = try vs.rowText(std.testing.allocator, 8);
    defer std.testing.allocator.free(r8_full);
    const r9_full = try vs.rowText(std.testing.allocator, 9);
    defer std.testing.allocator.free(r9_full);

    const norm = struct {
        fn run(text: []const u8, out: []u8) []const u8 {
            var w: usize = 0;
            var in_space = false;
            var i: usize = 0;
            while (i < text.len) : (i += 1) {
                // Skip ANSI escape sequences: ESC [ ... final_byte
                if (text[i] == 0x1b and i + 1 < text.len and text[i + 1] == '[') {
                    i += 2;
                    while (i < text.len and text[i] >= 0x20 and text[i] <= 0x3f) : (i += 1) {}
                    // i now points to final byte or end; loop increment will skip it
                    continue;
                }
                const ch = text[i];
                if (ch == ' ') {
                    if (in_space) continue;
                    in_space = true;
                } else {
                    in_space = false;
                }
                if (w < out.len) {
                    out[w] = ch;
                    w += 1;
                }
            }
            return std.mem.trim(u8, out[0..w], " ");
        }
    };
    var n0: [64]u8 = undefined;
    var n1: [64]u8 = undefined;
    var n8: [64]u8 = undefined;
    var n9: [64]u8 = undefined;
    const snap = FrameSnap{
        .row0 = norm.run(r0_full, n0[0..]),
        .row1 = norm.run(r1_full, n1[0..]),
        .row8 = norm.run(r8_full, n8[0..]),
        .row9 = norm.run(r9_full, n9[0..]),
    };
    try oh.snap(@src(),
        \\modes.tui.test.FrameSnap
        \\  .row0: []const u8
        \\    "hello world"
        \\  .row1: []const u8
        \\    ""
        \\  .row8: []const u8
        \\    "shift+drag: select"
        \\  .row9: []const u8
        \\    "1 turn m"
    ).expectEqual(snap);
}

test "e2e multiple parallel tool calls" {
    var ui = try Ui.init(std.testing.allocator, 60, 14, "claude", "anthropic");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "Reading files..." });
    try ui.onProvider(.{ .tool_call = .{ .id = "c1", .name = "read", .args = "{}" } });
    try ui.onProvider(.{ .tool_call = .{ .id = "c2", .name = "write", .args = "{}" } });
    try ui.onProvider(.{ .tool_call = .{ .id = "c3", .name = "bash", .args = "{}" } });
    try ui.onProvider(.{ .tool_result = .{ .id = "c1", .output = "ok", .is_err = false } });
    try ui.onProvider(.{ .tool_result = .{ .id = "c2", .output = "ok", .is_err = false } });
    try ui.onProvider(.{ .tool_result = .{ .id = "c3", .output = "fail", .is_err = true } });
    try ui.onProvider(.{ .text = "Done." });

    var vs = try VScreen.init(std.testing.allocator, 60, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=14: tx_h=9 (rows 0..8)
    // Error tool result shows error text with err fg and error bg
    var found_err_result = false;
    var r: usize = 0;
    while (r < 9) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "fail") != null) {
            // Check if this row has error styling
            vs.expectFg(r, 1, .{ .rgb = 0xcc6666 }) catch continue;
            vs.expectBg(r, 0, .{ .rgb = 0x3c2828 }) catch continue;
            found_err_result = true;
            break;
        }
    }
    try std.testing.expect(found_err_result);
}

test "e2e editor border visible" {
    var ui = try Ui.init(std.testing.allocator, 30, 8, "m", "p");
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 30, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=8: tx_h=3, border row 3, editor row 4, border row 5, footer 6-7
    // Border should be ─ (U+2500) in default border_fg (thinking_med / adaptive)
    try vs.expectText(3, 0, "\xe2\x94\x80"); // ─
    try vs.expectFg(3, 0, .{ .rgb = 0x81a2be }); // thinking_med (adaptive default)
    try vs.expectText(5, 0, "\xe2\x94\x80"); // bottom border too
    try vs.expectFg(5, 0, .{ .rgb = 0x81a2be });
}

test "e2e footer visible at bottom" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "gpt-4", "openai");
    defer ui.deinit();

    try ui.onProvider(.{ .usage = .{ .in_tok = 100, .out_tok = 50, .tot_tok = 150 } });

    var vs = try VScreen.init(std.testing.allocator, 40, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=8: footer at rows 6-7. Check footer line 2 has model.
    const row7 = try vs.rowText(std.testing.allocator, 7);
    defer std.testing.allocator.free(row7);
    try std.testing.expect(std.mem.indexOf(u8, row7, "gpt-4") != null);
}

// ── Golden snapshot tests ──
// Full-frame style assertions: verify exact fg, bg, bold at each content position

test "golden: text block has default fg, no bg fill" {
    var ui = try Ui.init(std.testing.allocator, 30, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "hello" });

    var vs = try VScreen.init(std.testing.allocator, 30, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=8: tx_h=3 (rows 0..2). Text at row 0, col 1 (1-col padding).
    try vs.expectText(0, 1, "hello");
    try vs.expectFg(0, 1, .{ .default = {} }); // theme.text = default
    try vs.expectBg(0, 1, .{ .default = {} }); // no bg for text
    try vs.expectBg(0, 0, .{ .default = {} }); // padding col also default
}

test "golden: tool_call has dim fg with pending bg fill" {
    var ui = try Ui.init(std.testing.allocator, 30, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .tool_call = .{ .id = "c1", .name = "read", .args = "{}" } });

    var vs = try VScreen.init(std.testing.allocator, 30, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Find the tool row — now shows "$ read"
    var tool_row: ?usize = null;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "$ read") != null) {
            tool_row = r;
            break;
        }
    }
    try std.testing.expect(tool_row != null);
    const tr = tool_row.?;

    // Content fg = dim
    try vs.expectFg(tr, 1, .{ .rgb = 0x666666 });
    // Pending bg fill across row
    try vs.expectBg(tr, 0, .{ .rgb = 0x282832 });
}

test "golden: tool_result success has readable fg with success bg" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .tool_result = .{ .id = "c1", .output = "ok", .is_err = false } });

    var vs = try VScreen.init(std.testing.allocator, 40, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Tool results use default fg over success background
    var result_row: ?usize = null;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "ok") != null) {
            result_row = r;
            break;
        }
    }
    try std.testing.expect(result_row != null);
    const rr = result_row.?;

    try vs.expectFg(rr, 1, .{ .default = {} }); // tool_output/default
    try vs.expectBg(rr, 1, .{ .rgb = 0x283228 }); // success bg
}

test "golden: error block has err fg, bold, and error bg full row" {
    var ui = try Ui.init(std.testing.allocator, 30, 8, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .err = "fail" });

    var vs = try VScreen.init(std.testing.allocator, 30, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var err_row: ?usize = null;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "[err] fail") != null) {
            err_row = r;
            break;
        }
    }
    try std.testing.expect(err_row != null);
    const er = err_row.?;

    try vs.expectFg(er, 1, .{ .rgb = 0xcc6666 }); // err
    try vs.expectBold(er, 1, true); // bold
    try vs.expectBg(er, 0, .{ .rgb = 0x3c2828 }); // error bg
    try vs.expectBg(er, 29, .{ .rgb = 0x3c2828 }); // last col
}

test "golden: user message has user_msg_bg full row" {
    var ui = try Ui.init(std.testing.allocator, 30, 8, "m", "p");
    defer ui.deinit();

    try ui.tr.userText("my prompt");

    var vs = try VScreen.init(std.testing.allocator, 30, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var user_row: ?usize = null;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "my prompt") != null) {
            user_row = r;
            break;
        }
    }
    try std.testing.expect(user_row != null);
    const ur = user_row.?;

    try vs.expectBg(ur, 0, .{ .rgb = 0x343541 }); // user_msg_bg
    try vs.expectBg(ur, 29, .{ .rgb = 0x343541 }); // last col
}

test "golden: footer fg matches dim color" {
    var ui = try Ui.initFull(std.testing.allocator, 40, 8, "claude", "anthropic", "/tmp", "main", null);
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 40, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Footer at rows 6-7. Line 1 (row 6) has cwd in dim.
    try vs.expectFg(6, 0, .{ .rgb = 0x666666 }); // dim
    // Footer line 2 has right-aligned model; find it
    const row7 = try vs.rowText(std.testing.allocator, 7);
    defer std.testing.allocator.free(row7);
    try std.testing.expect(std.mem.indexOf(u8, row7, "claude") != null);
}

test "golden: wide CJK in editor clips correctly" {
    var ui = try Ui.init(std.testing.allocator, 10, 6, "m", "p");
    defer ui.deinit();

    // Type wide CJK characters
    _ = try ui.ed.apply(.{ .char = 0x4E2D }); // 中 (width 2)
    _ = try ui.ed.apply(.{ .char = 0x6587 }); // 文 (width 2)
    _ = try ui.ed.apply(.{ .char = 'A' });

    var vs = try VScreen.init(std.testing.allocator, 10, 6);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Editor at row 1 (tx_h=1 for h=6, border=0, editor=1, border=2, footer=3-4... no)
    // h=6: reserved=5 → tx_h=1. Border row 1, editor row 2, border row 3, footer 4-5.
    const editor_row = 2;
    const row = try vs.rowText(std.testing.allocator, editor_row);
    defer std.testing.allocator.free(row);
    // Editor has 1-col padding, then "中文A" = 2+2+1 = 5 cols
    try std.testing.expect(std.mem.indexOf(u8, row, "A") != null);
}

// ── T7d: mock-terminal walkthrough coverage ──

test "T7d settings toggle persistence across re-render" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var ui = try Ui.init(std.testing.allocator, 40, 12, "m", "p");
    defer ui.deinit();

    // Build settings overlay with heap-allocated toggles (overlay.deinit frees them)
    const labels = [_][]const u8{ "Show tools", "Show thinking", "Auto-compact" };
    const toggles = try std.testing.allocator.alloc(bool, 3);
    toggles[0] = true;
    toggles[1] = true;
    toggles[2] = false;
    ui.ov = .{
        .items = &labels,
        .title = "Settings",
        .kind = .settings,
        .toggles = toggles,
    };

    var vs = try VScreen.init(std.testing.allocator, 40, 12);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Toggle first item (Show tools: true -> false)
    ui.ov.?.toggle();

    // Re-render after toggle
    try renderToVs(&ui, &vs);

    const Snap = struct {
        show_tools: bool,
        show_thinking: bool,
        auto_compact: bool,
    };
    try oh.snap(@src(),
        \\modes.tui.test.test.T7d settings toggle persistence across re-render.Snap
        \\  .show_tools: bool = false
        \\  .show_thinking: bool = true
        \\  .auto_compact: bool = false
    ).expectEqual(Snap{
        .show_tools = ui.ov.?.getToggle(0).?,
        .show_thinking = ui.ov.?.getToggle(1).?,
        .auto_compact = ui.ov.?.getToggle(2).?,
    });

    // Overlay still visible after re-render
    try std.testing.expect(ui.ov != null);
}

test "T7d compact notice appears in transcript" {
    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();

    try ui.tr.infoText("compacted in=5 out=2");

    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // tx_h=5 (rows 0..4) — look for compacted text
    var found = false;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "compacted in=5 out=2") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "T7d copy output renders nothing-to-copy notice" {
    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();

    // No response text yet — lastResponseText returns null
    try std.testing.expect(ui.lastResponseText() == null);

    // Simulate what runtime does when copy finds nothing
    try ui.tr.infoText("[nothing to copy]");

    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var found = false;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "[nothing to copy]") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "T7d copy finds last response text" {
    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "first response" });
    try ui.onProvider(.{ .tool_call = .{ .id = "c1", .name = "read", .args = "{}" } });
    try ui.onProvider(.{ .tool_result = .{ .id = "c1", .output = "ok", .is_err = false } });
    try ui.onProvider(.{ .text = "second response" });

    // lastResponseText should find the most recent text block
    const last = ui.lastResponseText();
    try std.testing.expect(last != null);
    try std.testing.expect(std.mem.indexOf(u8, last.?, "second response") != null);
}

test "T7d share blocked by policy renders denial notice" {
    var ui = try Ui.init(std.testing.allocator, 50, 10, "m", "p");
    defer ui.deinit();

    // Simulate what runtime emits when policy denies /share
    try ui.tr.infoText("blocked by policy: /share");

    var vs = try VScreen.init(std.testing.allocator, 50, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var found = false;
    var r: usize = 0;
    while (r < 5) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "blocked by policy: /share") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "T7d subagent progress indicator in footer" {
    var ui = try Ui.init(std.testing.allocator, 50, 10, "m", "p");
    defer ui.deinit();

    // Simulate bg task progress
    ui.panels.setBgStatus(2, 1, 1);

    var vs = try VScreen.init(std.testing.allocator, 50, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Footer at rows 8-9 for h=10 — check bg status appears
    var found_bg = false;
    var r: usize = 7;
    while (r < 10) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "bg") != null) {
            found_bg = true;
            break;
        }
    }
    try std.testing.expect(found_bg);
}

// ── UX4: Overlay walkthrough tests ──

test "UX4 model-select overlay open, navigate, select, close" {
    const ov_mod = @import("overlay.zig");
    var ui = try Ui.init(std.testing.allocator, 50, 14, "claude", "anthropic");
    defer ui.deinit();

    // Open model-select overlay
    const models = [_][]const u8{ "claude-opus-4-6", "claude-sonnet-4", "gpt-4o" };
    ui.ov = ov_mod.Overlay.init(&models, 0);

    var vs = try VScreen.init(std.testing.allocator, 50, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Overlay renders — find "Select Model" title
    var found_title = false;
    var r: usize = 0;
    while (r < 14) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "Select Model") != null) {
            found_title = true;
            break;
        }
    }
    try std.testing.expect(found_title);

    // Initial selection is item 0
    try std.testing.expectEqual(@as(usize, 0), ui.ov.?.sel);
    try std.testing.expect(std.mem.eql(u8, ui.ov.?.selected().?, "claude-opus-4-6"));

    // Navigate down twice
    ui.ov.?.down();
    try std.testing.expectEqual(@as(usize, 1), ui.ov.?.sel);
    ui.ov.?.down();
    try std.testing.expectEqual(@as(usize, 2), ui.ov.?.sel);
    try std.testing.expect(std.mem.eql(u8, ui.ov.?.selected().?, "gpt-4o"));

    // Navigate up wraps to last
    ui.ov.?.down(); // wraps to 0
    try std.testing.expectEqual(@as(usize, 0), ui.ov.?.sel);
    ui.ov.?.up(); // wraps to 2
    try std.testing.expectEqual(@as(usize, 2), ui.ov.?.sel);

    // Re-render with new selection — should show > on selected item
    try renderToVs(&ui, &vs);
    var found_sel = false;
    r = 0;
    while (r < 14) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, ">") != null and
            std.mem.indexOf(u8, row, "gpt-4o") != null)
        {
            found_sel = true;
            break;
        }
    }
    try std.testing.expect(found_sel);

    // Close overlay (esc)
    ui.ov.?.deinit(std.testing.allocator);
    ui.ov = null;
    try std.testing.expect(ui.ov == null);

    // Renders cleanly without overlay
    try renderToVs(&ui, &vs);
}

test "UX4 settings overlay open, toggle, close" {
    var ui = try Ui.init(std.testing.allocator, 50, 14, "m", "p");
    defer ui.deinit();

    // Open settings overlay with heap-allocated toggles
    const labels = [_][]const u8{ "Show tools", "Show thinking", "Auto-compact" };
    const toggles = try std.testing.allocator.alloc(bool, 3);
    toggles[0] = true;
    toggles[1] = true;
    toggles[2] = false;
    ui.ov = .{
        .items = &labels,
        .title = "Settings",
        .kind = .settings,
        .toggles = toggles,
    };

    var vs = try VScreen.init(std.testing.allocator, 50, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Settings title visible
    var found_title = false;
    var r: usize = 0;
    while (r < 14) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "Settings") != null) {
            found_title = true;
            break;
        }
    }
    try std.testing.expect(found_title);

    // Toggle "Show tools" off (sel=0)
    try std.testing.expect(ui.ov.?.getToggle(0).? == true);
    ui.ov.?.toggle();
    try std.testing.expect(ui.ov.?.getToggle(0).? == false);

    // Navigate to "Auto-compact" and toggle on
    ui.ov.?.down(); // sel=1
    ui.ov.?.down(); // sel=2
    try std.testing.expectEqual(@as(usize, 2), ui.ov.?.sel);
    try std.testing.expect(ui.ov.?.getToggle(2).? == false);
    ui.ov.?.toggle();
    try std.testing.expect(ui.ov.?.getToggle(2).? == true);

    // Re-render after toggles
    try renderToVs(&ui, &vs);

    // Close overlay (esc) — overlay cleaned up by deinit
    ui.ov.?.deinit(std.testing.allocator);
    ui.ov = null;
    try std.testing.expect(ui.ov == null);

    // Renders cleanly
    try renderToVs(&ui, &vs);
}

// ── UX5: Settings persistence walkthrough tests ──

test "UX5 show_tools toggle hides tool output in subsequent renders" {
    var ui = try Ui.init(std.testing.allocator, 50, 12, "m", "p");
    defer ui.deinit();

    // Add text + tool + text
    try ui.onProvider(.{ .text = "before tools" });
    try ui.onProvider(.{ .tool_call = .{ .id = "c1", .name = "read", .args = "{}" } });
    try ui.onProvider(.{ .tool_result = .{ .id = "c1", .output = "file content", .is_err = false } });
    try ui.onProvider(.{ .text = "after tools" });

    var vs = try VScreen.init(std.testing.allocator, 50, 12);
    defer vs.deinit();

    // Default: tools visible
    try renderToVs(&ui, &vs);
    var found_tool = false;
    var r: usize = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "$ read") != null) {
            found_tool = true;
            break;
        }
    }
    try std.testing.expect(found_tool);

    // Toggle show_tools off (simulating settings overlay toggle)
    ui.tr.show_tools = false;

    // Re-render — tool blocks hidden
    try renderToVs(&ui, &vs);
    var still_has_tool = false;
    r = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "$ read") != null) {
            still_has_tool = true;
            break;
        }
    }
    try std.testing.expect(!still_has_tool);

    // Text blocks still visible
    var found_before = false;
    var found_after = false;
    r = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "before tools") != null) found_before = true;
        if (std.mem.indexOf(u8, row, "after tools") != null) found_after = true;
    }
    try std.testing.expect(found_before);
    try std.testing.expect(found_after);
}

test "UX5 show_thinking toggle hides thinking in subsequent renders" {
    var ui = try Ui.init(std.testing.allocator, 50, 12, "m", "p");
    defer ui.deinit();

    try ui.onProvider(.{ .text = "question" });
    try ui.onProvider(.{ .thinking = "deep analysis" });
    try ui.onProvider(.{ .text = "answer" });

    var vs = try VScreen.init(std.testing.allocator, 50, 12);
    defer vs.deinit();

    // Default: thinking visible
    try renderToVs(&ui, &vs);
    var found_think = false;
    var r: usize = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "deep analysis") != null) {
            found_think = true;
            break;
        }
    }
    try std.testing.expect(found_think);

    // Toggle thinking off
    ui.tr.show_thinking = false;

    // Re-render — thinking hidden
    try renderToVs(&ui, &vs);
    var still_has_think = false;
    r = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "deep analysis") != null) {
            still_has_think = true;
            break;
        }
    }
    try std.testing.expect(!still_has_think);

    // Text blocks remain
    var found_q = false;
    var found_a = false;
    r = 0;
    while (r < 7) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "question") != null) found_q = true;
        if (std.mem.indexOf(u8, row, "answer") != null) found_a = true;
    }
    try std.testing.expect(found_q);
    try std.testing.expect(found_a);
}

test "UX5 settings toggles persist across multiple render cycles" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var ui = try Ui.init(std.testing.allocator, 50, 14, "m", "p");
    defer ui.deinit();

    // Add mixed content
    try ui.onProvider(.{ .text = "intro" });
    try ui.onProvider(.{ .thinking = "reasoning" });
    try ui.onProvider(.{ .tool_call = .{ .id = "t1", .name = "bash", .args = "{}" } });
    try ui.onProvider(.{ .tool_result = .{ .id = "t1", .output = "done", .is_err = false } });
    try ui.onProvider(.{ .text = "conclusion" });

    var vs = try VScreen.init(std.testing.allocator, 50, 14);
    defer vs.deinit();

    // Disable both tools and thinking
    ui.tr.show_tools = false;
    ui.tr.show_thinking = false;

    // Render 3 times — settings must persist
    try renderToVs(&ui, &vs);
    try renderToVs(&ui, &vs);
    try renderToVs(&ui, &vs);

    // Verify settings unchanged after multiple renders
    const Snap = struct { tools: bool, thinking: bool };
    try oh.snap(@src(),
        \\modes.tui.test.test.UX5 settings toggles persist across multiple render cycles.Snap
        \\  .tools: bool = false
        \\  .thinking: bool = false
    ).expectEqual(Snap{
        .tools = ui.tr.show_tools,
        .thinking = ui.tr.show_thinking,
    });

    // Only text blocks visible: intro, conclusion
    var found_tool = false;
    var found_think = false;
    var found_intro = false;
    var found_concl = false;
    var r: usize = 0;
    while (r < 9) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "<command>") != null) found_tool = true;
        if (std.mem.indexOf(u8, row, "reasoning") != null) found_think = true;
        if (std.mem.indexOf(u8, row, "intro") != null) found_intro = true;
        if (std.mem.indexOf(u8, row, "conclusion") != null) found_concl = true;
    }
    try std.testing.expect(!found_tool);
    try std.testing.expect(!found_think);
    try std.testing.expect(found_intro);
    try std.testing.expect(found_concl);

    // Re-enable and verify they appear again
    ui.tr.show_tools = true;
    ui.tr.show_thinking = true;
    try renderToVs(&ui, &vs);

    var tool_back = false;
    var think_back = false;
    r = 0;
    while (r < 9) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "<command>") != null) tool_back = true;
        if (std.mem.indexOf(u8, row, "reasoning") != null) think_back = true;
    }
    try std.testing.expect(tool_back);
    try std.testing.expect(think_back);
}

// ── UX1: Startup walkthrough ──

test "UX1 startup frame has shift+drag hint in footer" {
    var ui = try Ui.initFull(std.testing.allocator, 60, 10, "gpt-4o", "openai", "/tmp/proj", "main", null);
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 60, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Footer line 1 (row 8 for h=10): shift+drag hint right-aligned
    var found_hint = false;
    var r: usize = 7;
    while (r < 10) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "shift+drag: select") != null) {
            found_hint = true;
            break;
        }
    }
    try std.testing.expect(found_hint);
}

test "UX1 startup frame has model in footer" {
    var ui = try Ui.initFull(std.testing.allocator, 60, 10, "claude-sonnet", "anthropic", "/tmp", "", null);
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 60, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Footer line 2 (last row) has model name
    const last = try vs.rowText(std.testing.allocator, 9);
    defer std.testing.allocator.free(last);
    try std.testing.expect(std.mem.indexOf(u8, last, "claude-sonnet") != null);
}

test "UX1 startup frame has cwd and branch in footer" {
    var ui = try Ui.initFull(std.testing.allocator, 60, 10, "m", "p", "~/proj", "main", null);
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 60, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Footer line 1 (row 8): cwd + branch
    const row8 = try vs.rowText(std.testing.allocator, 8);
    defer std.testing.allocator.free(row8);
    try std.testing.expect(std.mem.indexOf(u8, row8, "~/proj") != null);
    try std.testing.expect(std.mem.indexOf(u8, row8, "(main)") != null);
}

test "UX1 startup empty transcript shows border and editor region" {
    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();

    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // h=10: tx_h=5, border row 5, editor row 6, border row 7, footer 8-9
    // Top border should be ─ (U+2500)
    try vs.expectText(5, 0, "\xe2\x94\x80");
    // Bottom border too
    try vs.expectText(7, 0, "\xe2\x94\x80");
    // Transcript area should be blank (no content yet)
    const row0 = try vs.rowText(std.testing.allocator, 0);
    defer std.testing.allocator.free(row0);
    try std.testing.expectEqual(@as(usize, 0), row0.len);
}

// ── UX2: Input/editing walkthrough ──

test "UX2 type text, undo, redo via harness" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    // Type "hello"
    for ("hello") |ch| {
        _ = try ui.onKey(.{ .char = ch });
    }
    try std.testing.expectEqualStrings("hello", ui.editorText());

    // Undo (ctrl-z) — reverts entire insert group
    _ = try ui.onKey(.{ .ctrl_z = {} });
    try std.testing.expectEqualStrings("", ui.editorText());

    // Redo (ctrl-shift-z) — restores
    _ = try ui.onKey(.{ .ctrl_shift_z = {} });
    try std.testing.expectEqualStrings("hello", ui.editorText());
}

test "UX2 ctrl-u clears editor line" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    for ("some text") |ch| {
        _ = try ui.onKey(.{ .char = ch });
    }
    try std.testing.expectEqualStrings("some text", ui.editorText());

    // ctrl-u kills entire line
    _ = try ui.onKey(.{ .ctrl_u = {} });
    try std.testing.expectEqualStrings("", ui.editorText());
}

test "UX2 multiline editor via ctrl-j inserts newlines" {
    var ui = try Ui.init(std.testing.allocator, 40, 10, "m", "p");
    defer ui.deinit();

    for ("line1") |ch| _ = try ui.onKey(.{ .char = ch });
    _ = try ui.onKey(.{ .ctrl_j = {} }); // newline
    for ("line2") |ch| _ = try ui.onKey(.{ .char = ch });

    try std.testing.expectEqualStrings("line1\nline2", ui.editorText());

    // Render and verify editor shows content
    var vs = try VScreen.init(std.testing.allocator, 40, 10);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Editor rows should contain both lines
    var found_l1 = false;
    var found_l2 = false;
    var r: usize = 0;
    while (r < 10) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "line1") != null) found_l1 = true;
        if (std.mem.indexOf(u8, row, "line2") != null) found_l2 = true;
    }
    try std.testing.expect(found_l1);
    try std.testing.expect(found_l2);
}

test "UX2 model cycle returns cycle_model action" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    // ctrl-p cycles model
    const act = try ui.onKey(.{ .ctrl_p = {} });
    try std.testing.expectEqual(harness.editor.Action.cycle_model, act);
}

test "UX2 editor submit clears and adds to transcript" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    for ("hello world") |ch| _ = try ui.onKey(.{ .char = ch });
    const act = try ui.onKey(.{ .enter = {} });
    try std.testing.expectEqual(harness.editor.Action.submit, act);
    try std.testing.expectEqualStrings("", ui.editorText());

    // Transcript should contain the user message
    var vs = try VScreen.init(std.testing.allocator, 40, 8);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var found = false;
    var r: usize = 0;
    while (r < 3) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "hello world") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "UX2 undo after backspace restores character" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    for ("ab") |ch| _ = try ui.onKey(.{ .char = ch });
    _ = try ui.onKey(.{ .backspace = {} }); // delete 'b'
    try std.testing.expectEqualStrings("a", ui.editorText());

    _ = try ui.onKey(.{ .ctrl_z = {} }); // undo backspace
    try std.testing.expectEqualStrings("ab", ui.editorText());
}

// ── UX1 gap: version banner, context/skills indicators, provider, clean exit ──

test "UX1 version banner text in transcript" {
    var ui = try Ui.init(std.testing.allocator, 60, 14, "m", "p");
    defer ui.deinit();

    // Simulate what showStartup does: push version line
    const ver_line = " pz v" ++ @import("../../app/cli.zig").version;
    try ui.tr.infoText(ver_line);

    var vs = try VScreen.init(std.testing.allocator, 60, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var found = false;
    var r: usize = 0;
    while (r < 9) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "pz v") != null) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "UX1 context and skills indicators in transcript" {
    var ui = try Ui.init(std.testing.allocator, 60, 14, "m", "p");
    defer ui.deinit();

    // Simulate showStartup context/skills sections
    try ui.tr.infoText("[Context]");
    try ui.tr.infoText("  ~/proj/CLAUDE.md");
    try ui.tr.infoText("[Skills]");
    try ui.tr.infoText("  release [project]");

    var vs = try VScreen.init(std.testing.allocator, 60, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    var found_ctx = false;
    var found_skills = false;
    var r: usize = 0;
    while (r < 9) : (r += 1) {
        const row = try vs.rowText(std.testing.allocator, r);
        defer std.testing.allocator.free(row);
        if (std.mem.indexOf(u8, row, "[Context]") != null) found_ctx = true;
        if (std.mem.indexOf(u8, row, "[Skills]") != null) found_skills = true;
    }
    try std.testing.expect(found_ctx);
    try std.testing.expect(found_skills);
}

test "UX1 provider accessible via panels" {
    var ui = try Ui.initFull(std.testing.allocator, 60, 10, "claude", "anthropic", "/tmp", "", null);
    defer ui.deinit();

    try std.testing.expectEqualStrings("anthropic", ui.panels.providerName());

    try ui.setProvider("openai");
    try std.testing.expectEqualStrings("openai", ui.panels.providerName());
}

test "UX1 clean exit via ctrl-c on empty" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    // ctrl-c on empty editor returns cancel (quit)
    const act = try ui.onKey(.{ .ctrl_c = {} });
    try std.testing.expectEqual(harness.editor.Action.cancel, act);
}

test "UX1 clean exit via ctrl-d on empty" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    const act = try ui.onKey(.{ .ctrl_d = {} });
    try std.testing.expectEqual(harness.editor.Action.cancel, act);
}

// ── UX2 gap: history navigation, cancel key ──

test "UX2 up arrow recalls previous input via harness" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    // Type and submit "hello"
    for ("hello") |ch| _ = try ui.onKey(.{ .char = ch });
    _ = try ui.onKey(.{ .enter = {} });

    // Up arrow should recall "hello"
    _ = try ui.onKey(.{ .up = {} });
    try std.testing.expectEqualStrings("hello", ui.editorText());

    // Down arrow returns to empty
    _ = try ui.onKey(.{ .down = {} });
    try std.testing.expectEqualStrings("", ui.editorText());
}

test "UX2 ctrl-c clears text then cancels via harness" {
    var ui = try Ui.init(std.testing.allocator, 40, 8, "m", "p");
    defer ui.deinit();

    // Type text
    for ("draft") |ch| _ = try ui.onKey(.{ .char = ch });

    // ctrl-c with text clears (interrupt)
    const act1 = try ui.onKey(.{ .ctrl_c = {} });
    try std.testing.expectEqual(harness.editor.Action.interrupt, act1);
    try std.testing.expectEqualStrings("", ui.editorText());

    // ctrl-c on empty → cancel
    const act2 = try ui.onKey(.{ .ctrl_c = {} });
    try std.testing.expectEqual(harness.editor.Action.cancel, act2);
}

// ── UX4 gap: resume overlay, close overlay with ctrl-c ──

test "UX4 resume overlay opens and closes" {
    const ov_mod = @import("overlay.zig");
    var ui = try Ui.init(std.testing.allocator, 50, 14, "m", "p");
    defer ui.deinit();

    // Open session overlay (simulating /resume with no arg)
    const sids = try std.testing.allocator.alloc([]u8, 2);
    sids[0] = try std.testing.allocator.dupe(u8, "100");
    sids[1] = try std.testing.allocator.dupe(u8, "200");
    ui.ov = ov_mod.Overlay.initDyn(sids, "Resume Session", .session);

    try std.testing.expect(ui.ov != null);
    try std.testing.expectEqualStrings("Resume Session", ui.ov.?.title);
    try std.testing.expectEqual(ov_mod.Kind.session, ui.ov.?.kind);

    // Render with overlay — no crash
    var vs = try VScreen.init(std.testing.allocator, 50, 14);
    defer vs.deinit();
    try renderToVs(&ui, &vs);

    // Close overlay
    ui.ov.?.deinit(std.testing.allocator);
    ui.ov = null;
    try std.testing.expect(ui.ov == null);

    // Renders cleanly after close
    try renderToVs(&ui, &vs);
}

test "UX4 overlay close with ctrl-c simulated" {
    const ov_mod = @import("overlay.zig");
    var ui = try Ui.init(std.testing.allocator, 50, 14, "m", "p");
    defer ui.deinit();

    // Open model overlay
    const models = [_][]const u8{ "a", "b" };
    ui.ov = ov_mod.Overlay.init(&models, 0);
    try std.testing.expect(ui.ov != null);

    // Simulate ctrl-c close: runtime checks if overlay is open,
    // closes it instead of forwarding to editor. Test the close path.
    if (ui.ov) |*ov| {
        ov.deinit(std.testing.allocator);
        ui.ov = null;
    }
    try std.testing.expect(ui.ov == null);

    // Editor still functional after overlay close
    _ = try ui.onKey(.{ .char = 'x' });
    try std.testing.expectEqualStrings("x", ui.editorText());
}
