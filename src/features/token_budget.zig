const std = @import("std");

/// budget track, triggers, UI
pub const TokenBudget = struct {
    allocator: std.mem.Allocator,
    enabled: bool,
    max_tokens: u64,
    used_tokens: u64,
    warning_threshold: u64,

    pub fn init(allocator: std.mem.Allocator, max_tokens: u64) !TokenBudget {
        return TokenBudget{
            .allocator = allocator,
            .enabled = false,
            .max_tokens = max_tokens,
            .used_tokens = 0,
            .warning_threshold = (max_tokens * 80) / 100, // 80% warning
        };
    }

    pub fn deinit(self: *TokenBudget) void {
        _ = self;
    }

    pub fn enable(self: *TokenBudget) void {
        self.enabled = true;
    }

    pub fn addUsage(self: *TokenBudget, tokens: u64) void {
        if (!self.enabled) return;
        self.used_tokens += tokens;
    }

    pub fn isExceeded(self: *const TokenBudget) bool {
        return self.used_tokens >= self.max_tokens;
    }

    pub fn needsWarning(self: *const TokenBudget) bool {
        return self.used_tokens >= self.warning_threshold and !self.isExceeded();
    }

    pub fn getRemaining(self: *const TokenBudget) u64 {
        if (self.used_tokens >= self.max_tokens) return 0;
        return self.max_tokens - self.used_tokens;
    }

    pub fn process(self: *TokenBudget) !void {
        if (!self.enabled) return;
        
        if (self.isExceeded()) {
            std.debug.print("TOKEN BUDGET EXCEEDED!\n", .{});
        } else if (self.needsWarning()) {
            std.debug.print("TOKEN BUDGET WARNING: {d} remaining\n", .{self.getRemaining()});
        }
    }
};

test "TOKEN_BUDGET lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try TokenBudget.init(arena.allocator(), 1000);
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    
    feature.addUsage(500);
    try std.testing.expect(!feature.needsWarning());
    try std.testing.expect(!feature.isExceeded());
    
    feature.addUsage(350);
    try std.testing.expect(feature.needsWarning());
    try std.testing.expect(!feature.isExceeded());
    
    feature.addUsage(200);
    try std.testing.expect(!feature.needsWarning());
    try std.testing.expect(feature.isExceeded());
    
    try feature.process();
}
