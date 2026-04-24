const std = @import("std");

/// idle sum REPL
pub const AwaySummary = struct {
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !AwaySummary {
        return AwaySummary{
            .allocator = allocator,
            .enabled = false,
        };
    }

    pub fn deinit(self: *AwaySummary) void {
        _ = self;
    }

    pub fn enable(self: *AwaySummary) void {
        self.enabled = true;
    }

    pub fn process(self: *AwaySummary) !void {
        if (!self.enabled) return;
        // Core logic for AWAY_SUMMARY
    }
};

test "AWAY_SUMMARY lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try AwaySummary.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}
