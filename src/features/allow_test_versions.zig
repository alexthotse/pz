const std = @import("std");

/// test versions native install
pub const AllowTestVersions = struct {
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !AllowTestVersions {
        return AllowTestVersions{
            .allocator = allocator,
            .enabled = false,
        };
    }

    pub fn deinit(self: *AllowTestVersions) void {
        _ = self;
    }

    pub fn enable(self: *AllowTestVersions) void {
        self.enabled = true;
    }

    pub fn process(self: *AllowTestVersions) !void {
        if (!self.enabled) return;
        // Core logic for ALLOW_TEST_VERSIONS
    }
};

test "ALLOW_TEST_VERSIONS lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try AllowTestVersions.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}
