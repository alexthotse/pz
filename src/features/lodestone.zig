const std = @import("std");

/// deep-link protocol reg
pub const Lodestone = struct {
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !Lodestone {
        return Lodestone{
            .allocator = allocator,
            .enabled = false,
        };
    }

    pub fn deinit(self: *Lodestone) void {
        _ = self;
    }

    pub fn enable(self: *Lodestone) void {
        self.enabled = true;
    }

    pub fn process(self: *Lodestone) !void {
        if (!self.enabled) return;
        // Core logic for LODESTONE
    }
};

test "LODESTONE lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try Lodestone.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}
