const std = @import("std");

/// interactive prompt hist
pub const HistoryPicker = struct {
    allocator: std.mem.Allocator,
    enabled: bool,
    history: std.ArrayList([]const u8),
    max_history: usize,

    pub fn init(allocator: std.mem.Allocator, max_history: usize) !HistoryPicker {
        return HistoryPicker{
            .allocator = allocator,
            .enabled = false,
            .history = .empty,
            .max_history = max_history,
        };
    }

    pub fn deinit(self: *HistoryPicker) void {
        for (self.history.items) |item| {
            self.allocator.free(item);
        }
        self.history.deinit(self.allocator);
    }

    pub fn enable(self: *HistoryPicker) void {
        self.enabled = true;
    }

    pub fn addPrompt(self: *HistoryPicker, prompt: []const u8) !void {
        if (!self.enabled) return;
        
        // Don't add empty prompts
        if (prompt.len == 0) return;
        
        // Don't add if it's the same as the last prompt
        if (self.history.items.len > 0 and std.mem.eql(u8, self.history.getLast(), prompt)) {
            return;
        }

        const prompt_copy = try self.allocator.dupe(u8, prompt);
        try self.history.append(self.allocator, prompt_copy);

        // Truncate if we exceed max_history
        if (self.history.items.len > self.max_history) {
            const oldest = self.history.orderedRemove(0);
            self.allocator.free(oldest);
        }
    }

    pub fn getHistory(self: *const HistoryPicker) [][]const u8 {
        return self.history.items;
    }

    pub fn process(self: *HistoryPicker) !void {
        if (!self.enabled) return;
        // Core logic for interactive prompt hist (UI implementation would go here)
    }
};

test "HISTORY_PICKER lifecycle" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try HistoryPicker.init(arena.allocator(), 3);
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    
    try feature.addPrompt("test 1");
    try feature.addPrompt("test 2");
    try feature.addPrompt("test 2"); // Duplicate ignored
    try feature.addPrompt("test 3");
    try feature.addPrompt("test 4"); // Triggers eviction of "test 1"
    
    const hist = feature.getHistory();
    try std.testing.expectEqual(@as(usize, 3), hist.len);
    try std.testing.expectEqualStrings("test 2", hist[0]);
    try std.testing.expectEqualStrings("test 3", hist[1]);
    try std.testing.expectEqualStrings("test 4", hist[2]);
    
    try feature.process();
}
