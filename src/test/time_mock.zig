//! Test mock: fixed-time clock.
const std = @import("std");
const loop = @import("../core/loop.zig");

pub const FixedMs = struct {
    time_src: loop.TimeSrc = .{ .vt = &loop.TimeSrc.Bind(@This(), nowMs).vt },
    now_ms: i64,

    pub fn nowMs(self: *@This()) i64 {
        return self.now_ms;
    }
};

pub const SeqMs = struct {
    time_src: loop.TimeSrc = .{ .vt = &loop.TimeSrc.Bind(@This(), nowMs).vt },
    vals: []const i64,
    idx: usize = 0,

    pub fn nowMs(self: *@This()) i64 {
        const i = if (self.idx < self.vals.len) self.idx else self.vals.len - 1;
        const now = self.vals[i];
        if (self.idx < self.vals.len) self.idx += 1;
        return now;
    }
};

test "fixed clock stays constant" {
    var clk = FixedMs{ .now_ms = 1234 };
    try std.testing.expectEqual(@as(i64, 1234), clk.nowMs());
    try std.testing.expectEqual(@as(i64, 1234), clk.nowMs());
}

test "sequence clock clamps at last value" {
    var clk = SeqMs{ .vals = &.{ 10, 20, 30 } };
    try std.testing.expectEqual(@as(i64, 10), clk.nowMs());
    try std.testing.expectEqual(@as(i64, 20), clk.nowMs());
    try std.testing.expectEqual(@as(i64, 30), clk.nowMs());
    try std.testing.expectEqual(@as(i64, 30), clk.nowMs());
}
