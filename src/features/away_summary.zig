const std = @import("std");

/// idle sum REPL
pub const AwaySummary = struct {
    allocator: std.mem.Allocator,
    enabled: bool,
    idle_ms: u64,
    last_active_ms: i64,

    pub fn init(allocator: std.mem.Allocator) !AwaySummary {
        return AwaySummary{
            .allocator = allocator,
            .enabled = false,
            .idle_ms = 0,
            .last_active_ms = std.time.milliTimestamp(),
        };
    }

    pub fn deinit(self: *AwaySummary) void {
        _ = self;
    }

    pub fn enable(self: *AwaySummary) void {
        self.enabled = true;
    }

    pub fn recordActivity(self: *AwaySummary) void {
        self.last_active_ms = std.time.milliTimestamp();
    }

    pub fn process(self: *AwaySummary) !void {
        if (!self.enabled) return;
        
        const now = std.time.milliTimestamp();
        const diff = now - self.last_active_ms;
        if (diff > 0) {
            self.idle_ms += @intCast(diff);
        }
        self.last_active_ms = now;
    }

    pub fn getSummary(self: *AwaySummary) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "Idle for {d}ms", .{self.idle_ms});
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
    
    std.time.sleep(10 * std.time.ns_per_ms);
    try feature.process();
    
    const summary = try feature.getSummary();
    try std.testing.expect(summary.len > 0);
}
