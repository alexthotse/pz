const std = @import("std");
const history_picker = @import("../modes/tui/history_picker.zig");

test "history picker selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    
    var picker = try history_picker.HistoryPicker.init(arena.allocator());
    defer picker.deinit();
    
    try picker.addHistory("first command");
    try picker.addHistory("second command");
    
    picker.moveSelection(1);
    try std.testing.expectEqualStrings("second command", picker.getSelected().?);
}
