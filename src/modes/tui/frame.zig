//! Terminal frame buffer: styled cell grid with cursor tracking.
const std = @import("std");
const wcwidth = @import("wcwidth.zig").wcwidth;

pub const Color = union(enum) {
    default: void,
    idx: u8,
    rgb: u24,

    pub fn eql(a: Color, b: Color) bool {
        const ta = std.meta.activeTag(a);
        const tb = std.meta.activeTag(b);
        if (ta != tb) return false;
        return switch (a) {
            .default => true,
            .idx => |v| v == b.idx,
            .rgb => |v| v == b.rgb,
        };
    }

    pub fn isDefault(c: Color) bool {
        return c == .default;
    }
};

pub const Style = struct {
    fg: Color = .{ .default = {} },
    bg: Color = .{ .default = {} },
    bold: bool = false,
    dim: bool = false,
    italic: bool = false,
    underline: bool = false,
    inverse: bool = false,

    pub fn eql(a: Style, b: Style) bool {
        return Color.eql(a.fg, b.fg) and
            Color.eql(a.bg, b.bg) and
            a.bold == b.bold and
            a.dim == b.dim and
            a.italic == b.italic and
            a.underline == b.underline and
            a.inverse == b.inverse;
    }

    pub fn isDefault(self: Style) bool {
        return eql(self, .{});
    }
};

pub const Rect = struct {
    x: usize,
    y: usize,
    w: usize,
    h: usize,

    pub fn endX(self: Rect, frm: *const Frame) Frame.PosError!usize {
        const x_end = std.math.add(usize, self.x, self.w) catch return error.OutOfBounds;
        if (x_end > frm.w) return error.OutOfBounds;
        return x_end;
    }

    pub fn endY(self: Rect, frm: *const Frame) Frame.PosError!usize {
        const y_end = std.math.add(usize, self.y, self.h) catch return error.OutOfBounds;
        if (y_end > frm.h) return error.OutOfBounds;
        return y_end;
    }

    pub fn clear(self: Rect, frm: *Frame) Frame.PosError!void {
        var y: usize = 0;
        while (y < self.h) : (y += 1) {
            var x: usize = 0;
            while (x < self.w) : (x += 1) {
                try frm.set(self.x + x, self.y + y, ' ', .{});
            }
        }
    }
};

pub const Cell = struct {
    cp: u21 = ' ',
    style: Style = .{},

    pub fn eql(a: Cell, b: Cell) bool {
        return a.cp == b.cp and Style.eql(a.style, b.style);
    }
};

pub const Frame = struct {
    w: usize,
    h: usize,
    cells: []Cell,

    pub const InitError = std.mem.Allocator.Error || error{InvalidSize};
    pub const PosError = error{OutOfBounds};
    pub const WriteError = PosError || error{InvalidUtf8};
    pub const CopyError = error{SizeMismatch};

    pub fn init(alloc: std.mem.Allocator, w: usize, h: usize) InitError!Frame {
        if (w == 0 or h == 0) return error.InvalidSize;
        const ct = std.math.mul(usize, w, h) catch return error.InvalidSize;

        const cells = try alloc.alloc(Cell, ct);
        @memset(cells, .{});

        return .{
            .w = w,
            .h = h,
            .cells = cells,
        };
    }

    pub fn deinit(self: *Frame, alloc: std.mem.Allocator) void {
        alloc.free(self.cells);
        self.* = undefined;
    }

    pub fn clear(self: *Frame) void {
        @memset(self.cells, .{});
    }

    pub fn idx(self: *const Frame, x: usize, y: usize) PosError!usize {
        if (x >= self.w or y >= self.h) return error.OutOfBounds;
        return y * self.w + x;
    }

    pub fn cell(self: *const Frame, x: usize, y: usize) PosError!Cell {
        return self.cells[try self.idx(x, y)];
    }

    pub fn setCell(self: *Frame, x: usize, y: usize, c: Cell) PosError!void {
        self.cells[try self.idx(x, y)] = c;
    }

    pub fn set(self: *Frame, x: usize, y: usize, cp: u21, style: Style) PosError!void {
        return self.setCell(x, y, .{
            .cp = cp,
            .style = style,
        });
    }

    /// Sentinel codepoint for the trailing cell of a wide character.
    pub const wide_pad: u21 = 0;

    pub fn write(self: *Frame, x: usize, y: usize, text: []const u8, style: Style) WriteError!usize {
        if (x >= self.w or y >= self.h) return error.OutOfBounds;

        var col = x;
        var ct: usize = 0;
        var it = (try std.unicode.Utf8View.init(text)).iterator();
        while (col < self.w) {
            const cp = it.nextCodepoint() orelse break;
            // Skip control chars (ESC, etc) to prevent terminal escape leaking
            if (cp < 0x20 and cp != '\t') continue;
            if (cp == 0x7f) continue;
            // Render tab as space
            const rcp: u21 = if (cp == '\t') ' ' else cp;
            const w: usize = if (cp == '\t') 1 else wcwidth(cp);
            if (w == 0) continue;
            if (col + w > self.w) break; // no room for wide char
            self.cells[y * self.w + col] = .{ .cp = rcp, .style = style };
            if (w == 2) {
                self.cells[y * self.w + col + 1] = .{ .cp = wide_pad, .style = style };
            }
            col += w;
            ct += 1;
        }

        return col - x;
    }

    pub fn copyFrom(self: *Frame, other: *const Frame) CopyError!void {
        if (self.w != other.w or self.h != other.h) return error.SizeMismatch;
        std.mem.copyForwards(Cell, self.cells, other.cells);
    }

    pub fn eql(self: *const Frame, other: *const Frame) bool {
        if (self.w != other.w or self.h != other.h) return false;
        for (self.cells, other.cells) |a, b| {
            if (!Cell.eql(a, b)) return false;
        }
        return true;
    }
};

// -- Shared UTF-8 / display-width utilities --

pub fn ensureUtf8(text: []const u8) error{InvalidUtf8}!void {
    _ = std.unicode.Utf8View.init(text) catch return error.InvalidUtf8;
}

pub fn clipCols(text: []const u8, cols: usize) error{InvalidUtf8}![]const u8 {
    if (cols == 0 or text.len == 0) return text[0..0];

    var i: usize = 0;
    var used: usize = 0;
    while (i < text.len) {
        const n = std.unicode.utf8ByteSequenceLength(text[i]) catch return error.InvalidUtf8;
        if (i + n > text.len) return error.InvalidUtf8;
        const cp = std.unicode.utf8Decode(text[i .. i + n]) catch return error.InvalidUtf8;
        const w = wcwidth(cp);
        if (used + w > cols) break;
        i += n;
        used += w;
    }
    return text[0..i];
}

test "frame write clips utf8 input at row width" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var f = try Frame.init(std.testing.allocator, 4, 2);
    defer f.deinit(std.testing.allocator);

    const st = Style{
        .fg = .{ .idx = 2 },
        .underline = true,
    };

    const text = "A\xCE\xB2ZQ";
    const wrote = try f.write(1, 0, text, st);
    try std.testing.expectEqual(@as(usize, 3), wrote);

    const c1 = try f.cell(1, 0);
    const c2 = try f.cell(2, 0);
    const c3 = try f.cell(3, 0);
    try std.testing.expect(Style.eql(st, c1.style));
    try std.testing.expect(Style.eql(st, c2.style));
    try std.testing.expect(Style.eql(st, c3.style));
    const Snap = struct {
        wrote: usize,
        c1: u21,
        c2: u21,
        c3: u21,
    };
    try oh.snap(@src(),
        \\modes.tui.frame.test.frame write clips utf8 input at row width.Snap
        \\  .wrote: usize = 3
        \\  .c1: u21 = 'A'
        \\  .c2: u21 = 'β'
        \\  .c3: u21 = 'Z'
    ).expectEqual(Snap{
        .wrote = wrote,
        .c1 = c1.cp,
        .c2 = c2.cp,
        .c3 = c3.cp,
    });
}

test "frame write validates bounds and utf8" {
    var f = try Frame.init(std.testing.allocator, 2, 1);
    defer f.deinit(std.testing.allocator);

    try std.testing.expectError(error.OutOfBounds, f.write(2, 0, "x", .{}));

    const bad = [_]u8{0xff};
    try std.testing.expectError(error.InvalidUtf8, f.write(0, 0, bad[0..], .{}));
}

test "frame copy requires matching size" {
    var a = try Frame.init(std.testing.allocator, 3, 1);
    defer a.deinit(std.testing.allocator);

    var b = try Frame.init(std.testing.allocator, 3, 1);
    defer b.deinit(std.testing.allocator);

    var c = try Frame.init(std.testing.allocator, 2, 1);
    defer c.deinit(std.testing.allocator);

    _ = try a.write(0, 0, "abc", .{});
    try b.copyFrom(&a);
    try std.testing.expect(b.eql(&a));

    try std.testing.expectError(error.SizeMismatch, c.copyFrom(&a));
}

test "frame write wide CJK characters" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    // 6-col frame: write "A中B" → A(1) + 中(2) + B(1) = 4 cols used
    var f = try Frame.init(std.testing.allocator, 6, 1);
    defer f.deinit(std.testing.allocator);

    const wrote = try f.write(0, 0, "A中B", .{});
    const Snap = struct {
        wrote: usize,
        c0: u21,
        c1: u21,
        c2: u21,
        c3: u21,
    };
    try oh.snap(@src(),
        \\modes.tui.frame.test.frame write wide CJK characters.Snap
        \\  .wrote: usize = 4
        \\  .c0: u21 = 'A'
        \\  .c1: u21 = '中'
        \\  .c2: u21 = '\u{00}'
        \\  .c3: u21 = 'B'
    ).expectEqual(Snap{
        .wrote = wrote,
        .c0 = (try f.cell(0, 0)).cp,
        .c1 = (try f.cell(1, 0)).cp,
        .c2 = (try f.cell(2, 0)).cp,
        .c3 = (try f.cell(3, 0)).cp,
    });
}

test "frame write wide char clipped at boundary" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    // 3-col frame: write "A中" → A fills col 0, 中 needs cols 1-2 → fits
    var f = try Frame.init(std.testing.allocator, 3, 1);
    defer f.deinit(std.testing.allocator);

    const wrote = try f.write(0, 0, "A中X", .{});
    const Snap = struct {
        wrote: usize,
        c0: u21,
        c1: u21,
        c2: u21,
    };
    try oh.snap(@src(),
        \\modes.tui.frame.test.frame write wide char clipped at boundary.Snap
        \\  .wrote: usize = 3
        \\  .c0: u21 = 'A'
        \\  .c1: u21 = '中'
        \\  .c2: u21 = '\u{00}'
    ).expectEqual(Snap{
        .wrote = wrote,
        .c0 = (try f.cell(0, 0)).cp,
        .c1 = (try f.cell(1, 0)).cp,
        .c2 = (try f.cell(2, 0)).cp,
    });
}

test "frame write wide char dropped when only 1 col left" {
    // 2-col frame starting at col 1: only 1 col left, wide char won't fit
    var f = try Frame.init(std.testing.allocator, 2, 1);
    defer f.deinit(std.testing.allocator);

    const wrote = try f.write(1, 0, "中", .{});
    try std.testing.expectEqual(@as(usize, 0), wrote);
}
