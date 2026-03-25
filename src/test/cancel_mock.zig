//! Test mock: atomic cancellation flag.
const std = @import("std");
const loop = @import("../core/loop.zig");

pub const Flag = struct {
    cancel_src: loop.CancelSrc = .{ .vt = &loop.CancelSrc.Bind(@This(), isCanceled).vt },
    canceled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn clear(self: *Flag) void {
        self.canceled.store(false, .release);
    }

    pub fn request(self: *Flag) void {
        self.canceled.store(true, .release);
    }

    pub fn isCanceled(self: *Flag) bool {
        return self.canceled.load(.acquire);
    }
};

pub const DelayTrip = struct {
    flag: *Flag,
    delay_ms: u64,

    pub fn run(self: *DelayTrip) void {
        std.Thread.sleep(self.delay_ms * std.time.ns_per_ms);
        self.flag.request();
    }
};

test "delay trip flips cancel flag after sleep" {
    var flag = Flag{};
    var trip = DelayTrip{
        .flag = &flag,
        .delay_ms = 1,
    };
    const thr = try std.Thread.spawn(.{}, DelayTrip.run, .{&trip});
    thr.join();
    try std.testing.expect(flag.isCanceled());
}
