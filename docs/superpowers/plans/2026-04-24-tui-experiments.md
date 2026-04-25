# Interaction and UI Experiments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement TUI experimental features (History Picker, Quick Search, Message Actions, Token Budget) from free-code into pz.

**Architecture:** Extend `src/modes/tui/` with new overlays and panels. History Picker and Quick Search will use the existing fuzzy-filtered dropdown component (similar to autocomplete). Token Budget will add a new status bar element and budget tracking logic in `src/core/session/`. Message Actions will add a context menu overlay for rendered messages.

**Tech Stack:** Zig 0.15+, existing TUI framework in `pz`.

---

### Task 1: History Picker Overlay

**Files:**
- Create: `src/modes/tui/history_picker.zig`
- Modify: `src/modes/tui/input.zig` (to trigger history picker)
- Test: `src/test/tui_history_picker.zig`

- [ ] **Step 1: Write the failing test**

```zig
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `zig test src/test/tui_history_picker.zig`
Expected: FAIL with "file not found"

- [ ] **Step 3: Write minimal implementation**

```zig
const std = @import("std");

pub const HistoryPicker = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]const u8),
    selected_idx: usize,

    pub fn init(allocator: std.mem.Allocator) !HistoryPicker {
        return HistoryPicker{
            .allocator = allocator,
            .items = std.ArrayList([]const u8).init(allocator),
            .selected_idx = 0,
        };
    }

    pub fn deinit(self: *HistoryPicker) void {
        for (self.items.items) |item| {
            self.allocator.free(item);
        }
        self.items.deinit();
    }

    pub fn addHistory(self: *HistoryPicker, item: []const u8) !void {
        const copy = try self.allocator.dupe(u8, item);
        try self.items.append(copy);
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `zig test src/test/tui_history_picker.zig`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/modes/tui/history_picker.zig src/test/tui_history_picker.zig
git commit -m "feat(tui): add history picker data structure"
```

### Task 2: Token Budget Tracker

**Files:**
- Create: `src/core/session/budget.zig`
- Modify: `src/core/session.zig`
- Test: `src/test/core_budget.zig`

- [ ] **Step 1: Write the failing test**

```zig
const std = @import("std");
const budget = @import("../core/session/budget.zig");

test "token budget tracking" {
    var tracker = budget.TokenTracker.init(1000);
    
    try std.testing.expectEqual(tracker.remaining(), 1000);
    tracker.consume(250);
    try std.testing.expectEqual(tracker.remaining(), 750);
    try std.testing.expect(tracker.isWarning());
    tracker.consume(800);
    try std.testing.expectEqual(tracker.remaining(), 0);
    try std.testing.expect(tracker.isExhausted());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `zig test src/test/core_budget.zig`
Expected: FAIL with "file not found"

- [ ] **Step 3: Write minimal implementation**

```zig
pub const TokenTracker = struct {
    limit: usize,
    used: usize,

    pub fn init(limit: usize) TokenTracker {
        return .{ .limit = limit, .used = 0 };
    }

    pub fn consume(self: *TokenTracker, amount: usize) void {
        self.used +|= amount;
    }

    pub fn remaining(self: const TokenTracker) usize {
        if (self.used >= self.limit) return 0;
        return self.limit - self.used;
    }

    pub fn isWarning(self: const TokenTracker) bool {
        return self.used >= (self.limit * 75) / 100;
    }

    pub fn isExhausted(self: const TokenTracker) bool {
        return self.used >= self.limit;
    }
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `zig test src/test/core_budget.zig`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/session/budget.zig src/test/core_budget.zig
git commit -m "feat(core): add token budget tracking"
```

