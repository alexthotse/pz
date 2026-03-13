const std = @import("std");

pub const Csi = struct {
    prefix: ?u8 = null,
    final: u8,
    params: []u16,
};

pub const Op = union(enum) {
    text: []u8,
    csi: Csi,
    osc: []u8,
    esc: []u8,

    fn deinit(self: *Op, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .text => |buf| alloc.free(buf),
            .csi => |csi| alloc.free(csi.params),
            .osc => |buf| alloc.free(buf),
            .esc => |buf| alloc.free(buf),
        }
        self.* = undefined;
    }
};

pub fn freeOps(alloc: std.mem.Allocator, ops: []Op) void {
    for (ops) |*op| op.deinit(alloc);
    alloc.free(ops);
}

pub fn parseAlloc(alloc: std.mem.Allocator, data: []const u8) ![]Op {
    var ops = std.ArrayList(Op).empty;
    errdefer {
        for (ops.items) |*op| op.deinit(alloc);
        ops.deinit(alloc);
    }

    var i: usize = 0;
    var text_start: usize = 0;
    while (i < data.len) {
        if (data[i] != 0x1b) {
            i += 1;
            continue;
        }

        if (i > text_start) {
            try ops.append(alloc, .{ .text = try alloc.dupe(u8, data[text_start..i]) });
        }

        if (i + 1 >= data.len) {
            try ops.append(alloc, .{ .esc = try alloc.dupe(u8, data[i .. i + 1]) });
            i += 1;
            text_start = i;
            continue;
        }

        switch (data[i + 1]) {
            '[' => {
                const parsed = try parseCsi(alloc, data, i);
                try ops.append(alloc, .{ .csi = parsed.op });
                i = parsed.next;
            },
            ']' => {
                const parsed = try parseOsc(alloc, data, i);
                try ops.append(alloc, .{ .osc = parsed.payload });
                i = parsed.next;
            },
            else => {
                try ops.append(alloc, .{ .esc = try alloc.dupe(u8, data[i .. i + 2]) });
                i += 2;
            },
        }
        text_start = i;
    }

    if (text_start < data.len) {
        try ops.append(alloc, .{ .text = try alloc.dupe(u8, data[text_start..]) });
    }

    return try ops.toOwnedSlice(alloc);
}

const CsiParse = struct {
    op: Csi,
    next: usize,
};

fn parseCsi(alloc: std.mem.Allocator, data: []const u8, start: usize) !CsiParse {
    var i = start + 2;
    var prefix: ?u8 = null;
    if (i < data.len and (data[i] == '?' or data[i] == '>' or data[i] == '=')) {
        prefix = data[i];
        i += 1;
    }

    var params = std.ArrayList(u16).empty;
    errdefer params.deinit(alloc);
    try params.append(alloc, 0);

    while (i < data.len) : (i += 1) {
        const ch = data[i];
        if (ch >= '0' and ch <= '9') {
            params.items[params.items.len - 1] *|= 10;
            params.items[params.items.len - 1] +|= ch - '0';
            continue;
        }
        if (ch == ';') {
            try params.append(alloc, 0);
            continue;
        }
        if (ch >= 0x40 and ch <= 0x7e) {
            return .{
                .op = .{
                    .prefix = prefix,
                    .final = ch,
                    .params = try params.toOwnedSlice(alloc),
                },
                .next = i + 1,
            };
        }
    }

    return .{
        .op = .{
            .prefix = prefix,
            .final = 0,
            .params = try params.toOwnedSlice(alloc),
        },
        .next = data.len,
    };
}

const OscParse = struct {
    payload: []u8,
    next: usize,
};

fn parseOsc(alloc: std.mem.Allocator, data: []const u8, start: usize) !OscParse {
    var i = start + 2;
    while (i < data.len) : (i += 1) {
        if (data[i] == 0x07) {
            return .{
                .payload = try alloc.dupe(u8, data[start + 2 .. i]),
                .next = i + 1,
            };
        }
        if (data[i] == 0x1b and i + 1 < data.len and data[i + 1] == '\\') {
            return .{
                .payload = try alloc.dupe(u8, data[start + 2 .. i]),
                .next = i + 2,
            };
        }
    }
    return .{
        .payload = try alloc.dupe(u8, data[start + 2 .. data.len]),
        .next = data.len,
    };
}

pub const SummaryOpts = struct {
    include_text: bool = true,
};

pub fn summaryAlloc(alloc: std.mem.Allocator, ops: []const Op, opts: SummaryOpts) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);

    for (ops) |op| {
        switch (op) {
            .text => |text| {
                if (!opts.include_text) continue;
                try out.writer(alloc).print("text {d}\n", .{text.len});
            },
            .csi => |csi| {
                try out.appendSlice(alloc, "csi ");
                if (csi.prefix) |p| try out.append(alloc, p);
                try out.append(alloc, csi.final);
                try out.appendSlice(alloc, " ");
                for (csi.params, 0..) |param, idx| {
                    if (idx > 0) try out.append(alloc, ',');
                    try out.writer(alloc).print("{d}", .{param});
                }
                try out.append(alloc, '\n');
            },
            .osc => |payload| {
                const head = std.mem.indexOfScalar(u8, payload, ';') orelse payload.len;
                try out.appendSlice(alloc, "osc ");
                try out.appendSlice(alloc, payload[0..head]);
                try out.append(alloc, '\n');
            },
            .esc => |raw| {
                try out.writer(alloc).print("esc {d}\n", .{raw.len});
            },
        }
    }

    return try out.toOwnedSlice(alloc);
}

test "ansi ast snapshots CSI and OSC structure" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const sample =
        "\x1b[?1049h" ++
        "\x1b[?25l" ++
        "\x1b]0;title\x07" ++
        "\x1b[0m" ++
        "\x1b[2J" ++
        "\x1b[H" ++
        "hello";

    const ops = try parseAlloc(std.testing.allocator, sample);
    defer freeOps(std.testing.allocator, ops);

    const summary = try summaryAlloc(std.testing.allocator, ops, .{ .include_text = false });
    defer std.testing.allocator.free(summary);

    try oh.snap(@src(),
        \\[]u8
        \\  "csi ?h 1049
        \\csi ?l 25
        \\osc 0
        \\csi m 0
        \\csi J 2
        \\csi H 0
        \\"
    ).expectEqual(summary);
}
