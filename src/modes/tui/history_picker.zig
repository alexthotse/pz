const std = @import("std");

pub const HistoryPicker = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]const u8),
    selected_idx: usize,

    pub fn init(allocator: std.mem.Allocator) !HistoryPicker {
        return HistoryPicker{
            .allocator = allocator,
            .items = .empty,
            .selected_idx = 0,
        };
    }

    pub fn deinit(self: *HistoryPicker) void {
        for (self.items.items) |item| {
            self.allocator.free(item);
        }
        self.items.deinit(self.allocator);
    }

    pub fn addHistory(self: *HistoryPicker, item: []const u8) !void {
        const copy = try self.allocator.dupe(u8, item);
        try self.items.append(self.allocator, copy);
    }

    pub fn moveSelection(self: *HistoryPicker, delta: isize) void {
        if (self.items.items.len == 0) return;
        const new_idx = @as(isize, @intCast(self.selected_idx)) + delta;
        if (new_idx >= 0 and new_idx < self.items.items.len) {
            self.selected_idx = @as(usize, @intCast(new_idx));
        }
    }

    pub fn getSelected(self: *HistoryPicker) ?[]const u8 {
        if (self.selected_idx < self.items.items.len) {
            return self.items.items[self.selected_idx];
        }
        return null;
    }
};

test "history picker selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    
    var picker = try HistoryPicker.init(arena.allocator());
    defer picker.deinit();
    
    try picker.addHistory("first command");
    try picker.addHistory("second command");
    
    picker.moveSelection(1);
    try std.testing.expectEqualStrings("second command", picker.getSelected().?);
}
