const std = @import("std");

pub const TokenTracker = struct {
    limit: usize,
    used: usize,

    pub fn init(limit: usize) TokenTracker {
        return .{ .limit = limit, .used = 0 };
    }

    pub fn consume(self: *TokenTracker, amount: usize) void {
        self.used +|= amount;
    }

    pub fn remaining(self: *const TokenTracker) usize {
        if (self.used >= self.limit) return 0;
        return self.limit - self.used;
    }

    pub fn isWarning(self: *const TokenTracker) bool {
        return self.used >= (self.limit * 75) / 100;
    }

    pub fn isExhausted(self: *const TokenTracker) bool {
        return self.used >= self.limit;
    }
};

test "token budget tracking" {
    var tracker = TokenTracker.init(1000);
    
    try std.testing.expectEqual(tracker.remaining(), 1000);
    tracker.consume(250);
    try std.testing.expectEqual(tracker.remaining(), 750);
    try std.testing.expect(!tracker.isWarning());
    tracker.consume(500); // total 750
    try std.testing.expectEqual(tracker.remaining(), 250);
    try std.testing.expect(tracker.isWarning());
    tracker.consume(250); // total 1000
    try std.testing.expectEqual(tracker.remaining(), 0);
    try std.testing.expect(tracker.isExhausted());
}
