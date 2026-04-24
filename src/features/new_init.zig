const std = @import("std");

/// `/init` path
pub const NewInit = struct {
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !NewInit {
        return NewInit{
            .allocator = allocator,
            .enabled = false,
        };
    }

    pub fn deinit(self: *NewInit) void {
        _ = self;
    }

    pub fn enable(self: *NewInit) void {
        self.enabled = true;
    }

    pub fn process(self: *NewInit) !void {
        if (!self.enabled) return;
        // Core logic for NEW_INIT
    }
};

test "NEW_INIT lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try NewInit.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}
