const std = @import("std");

/// native macOS clipboard fast path
pub const NativeClipboardImage = struct {
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !NativeClipboardImage {
        return NativeClipboardImage{
            .allocator = allocator,
            .enabled = false,
        };
    }

    pub fn deinit(self: *NativeClipboardImage) void {
        _ = self;
    }

    pub fn enable(self: *NativeClipboardImage) void {
        self.enabled = true;
    }

    pub fn process(self: *NativeClipboardImage) !void {
        if (!self.enabled) return;
        // Core logic for NATIVE_CLIPBOARD_IMAGE
    }
};

test "NATIVE_CLIPBOARD_IMAGE lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try NativeClipboardImage.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}
