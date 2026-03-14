//! Generic fixed-capacity LRU cache (ring buffer, linear scan).
const std = @import("std");

/// Fixed-capacity LRU cache using a ring buffer with linear scan.
/// No dynamic allocation after init. Suitable for cap <= 1024.
pub fn Lru(comptime K: type, comptime cap: usize) type {
    if (cap == 0) @compileError("capacity must be > 0");

    return struct {
        const Self = @This();

        buf: [cap]K = undefined,
        /// Age order: ages[i] holds the insertion/promotion timestamp for buf[i].
        ages: [cap]u64 = undefined,
        len: usize = 0,
        tick: u64 = 0,

        pub fn contains(self: *Self, key: K) bool {
            for (0..self.len) |i| {
                if (self.buf[i] == key) {
                    self.tick += 1;
                    self.ages[i] = self.tick;
                    return true;
                }
            }
            return false;
        }

        pub fn add(self: *Self, key: K) void {
            // Promote if already present.
            for (0..self.len) |i| {
                if (self.buf[i] == key) {
                    self.tick += 1;
                    self.ages[i] = self.tick;
                    return;
                }
            }

            self.tick += 1;

            if (self.len < cap) {
                // Space available — append.
                self.buf[self.len] = key;
                self.ages[self.len] = self.tick;
                self.len += 1;
                return;
            }

            // Full — evict the oldest (lowest age).
            var oldest: usize = 0;
            for (1..self.len) |i| {
                if (self.ages[i] < self.ages[oldest]) {
                    oldest = i;
                }
            }
            self.buf[oldest] = key;
            self.ages[oldest] = self.tick;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "empty cache contains nothing" {
    var c: Lru(u64, 4) = .{};
    try testing.expect(!c.contains(0));
    try testing.expect(!c.contains(42));
    try testing.expectEqual(@as(usize, 0), c.count());
}

test "add and contains" {
    var c: Lru(u64, 4) = .{};
    c.add(10);
    c.add(20);
    c.add(30);
    try testing.expect(c.contains(10));
    try testing.expect(c.contains(20));
    try testing.expect(c.contains(30));
    try testing.expect(!c.contains(99));
    try testing.expectEqual(@as(usize, 3), c.count());
}

test "fill exactly to capacity" {
    var c: Lru(u64, 4) = .{};
    c.add(1);
    c.add(2);
    c.add(3);
    c.add(4);
    try testing.expectEqual(@as(usize, 4), c.count());
    try testing.expect(c.contains(1));
    try testing.expect(c.contains(2));
    try testing.expect(c.contains(3));
    try testing.expect(c.contains(4));
}

test "overflow evicts oldest" {
    var c: Lru(u64, 4) = .{};
    c.add(1);
    c.add(2);
    c.add(3);
    c.add(4);
    // 1 is oldest — should be evicted.
    c.add(5);
    try testing.expectEqual(@as(usize, 4), c.count());
    try testing.expect(!c.contains(1));
    try testing.expect(c.contains(2));
    try testing.expect(c.contains(3));
    try testing.expect(c.contains(4));
    try testing.expect(c.contains(5));
}

test "re-add promotes and prevents eviction" {
    var c: Lru(u64, 4) = .{};
    c.add(1);
    c.add(2);
    c.add(3);
    c.add(4);
    // Promote 1 — now 2 is oldest.
    c.add(1);
    try testing.expectEqual(@as(usize, 4), c.count());
    c.add(5);
    // 2 should be evicted, not 1.
    try testing.expect(c.contains(1));
    try testing.expect(!c.contains(2));
    try testing.expect(c.contains(3));
    try testing.expect(c.contains(4));
    try testing.expect(c.contains(5));
}

test "contains promotes" {
    var c: Lru(u64, 4) = .{};
    c.add(1);
    c.add(2);
    c.add(3);
    c.add(4);
    // Touch 1 via contains — promotes it.
    try testing.expect(c.contains(1));
    c.add(5);
    // 2 is now oldest and should be evicted.
    try testing.expect(c.contains(1));
    try testing.expect(!c.contains(2));
    try testing.expect(c.contains(5));
}

test "duplicate add keeps count stable" {
    var c: Lru(u64, 4) = .{};
    c.add(1);
    c.add(1);
    c.add(1);
    try testing.expectEqual(@as(usize, 1), c.count());
}

test "eviction chain" {
    var c: Lru(u64, 2) = .{};
    c.add(1);
    c.add(2);
    c.add(3); // evicts 1
    try testing.expect(!c.contains(1));
    c.add(4); // evicts 2
    try testing.expect(!c.contains(2));
    try testing.expect(c.contains(3));
    try testing.expect(c.contains(4));
}

// ---------------------------------------------------------------------------
// ohsnap snapshot tests
// ---------------------------------------------------------------------------

const OhSnap = @import("ohsnap");

const LruSnap = struct {
    present: [8]bool = .{false} ** 8,
    count: usize,
};

fn snapState(lru: anytype, keys: []const u64) LruSnap {
    var s: LruSnap = .{ .count = lru.count() };
    for (keys, 0..) |k, i| {
        // Use a mutable copy to call contains (which promotes).
        // We only want a peek, so we check buf directly.
        for (0..lru.len) |j| {
            if (lru.buf[j] == k) {
                s.present[i] = true;
                break;
            }
        }
    }
    return s;
}

test "snapshot: complex add/promote/evict sequence" {
    const oh = OhSnap{};
    var c: Lru(u64, 4) = .{};
    c.add(10);
    c.add(20);
    c.add(30);
    c.add(40);
    // Promote 10 (now 20 is oldest)
    c.add(10);
    // Add 50 — evicts 20 (oldest)
    c.add(50);

    const keys = [_]u64{ 10, 20, 30, 40, 50 };
    const snap = snapState(&c, &keys);

    try oh.snap(@src(),
        \\core.lru.LruSnap
        \\  .present: [8]bool
        \\    [0]: bool = true
        \\    [1]: bool = false
        \\    [2]: bool = true
        \\    [3]: bool = true
        \\    [4]: bool = true
        \\    [5]: bool = false
        \\    [6]: bool = false
        \\    [7]: bool = false
        \\  .count: usize = 4
    ).expectEqual(snap);
}

test "snapshot: eviction order with promotions" {
    const oh = OhSnap{};
    var c: Lru(u64, 3) = .{};
    // Fill: 1, 2, 3
    c.add(1);
    c.add(2);
    c.add(3);
    // Promote 1
    c.add(1);
    // Add 4 — evicts 2 (oldest)
    c.add(4);
    // Add 5 — evicts 3 (oldest)
    c.add(5);
    // Add 6 — evicts 1 (oldest)
    c.add(6);

    const keys = [_]u64{ 1, 2, 3, 4, 5, 6 };
    const snap = snapState(&c, &keys);

    try oh.snap(@src(),
        \\core.lru.LruSnap
        \\  .present: [8]bool
        \\    [0]: bool = false
        \\    [1]: bool = false
        \\    [2]: bool = false
        \\    [3]: bool = true
        \\    [4]: bool = true
        \\    [5]: bool = true
        \\    [6]: bool = false
        \\    [7]: bool = false
        \\  .count: usize = 3
    ).expectEqual(snap);
}

// ---------------------------------------------------------------------------
// zcheck property tests
// ---------------------------------------------------------------------------

test "property: count never exceeds capacity" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u8, b: u8, c: u8, d: u8, e: u8 }) bool {
            var c: Lru(u8, 3) = .{};
            const vals = [_]u8{ args.a, args.b, args.c, args.d, args.e };
            for (vals) |v| {
                c.add(v);
                if (c.count() > 3) return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: just-added item is always found" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u8, b: u8, c: u8, k: u8 }) bool {
            var c: Lru(u8, 4) = .{};
            c.add(args.a);
            c.add(args.b);
            c.add(args.c);
            c.add(args.k);
            return c.contains(args.k);
        }
    }.prop, .{ .iterations = 500 });
}

test "property: add is idempotent for count" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u8, b: u8, k: u8 }) bool {
            var c: Lru(u8, 4) = .{};
            c.add(args.a);
            c.add(args.b);
            c.add(args.k);
            const before = c.count();
            // Add k again — already present, count must not change
            c.add(args.k);
            return c.count() == before;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: item survives if fewer than cap distinct keys added after" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { k: u8, a: u8, b: u8 }) bool {
            // cap=4, add k, then add at most 2 distinct others => k survives
            var c: Lru(u8, 4) = .{};
            c.add(args.k);
            // Add 2 keys that differ from k
            const x = if (args.a == args.k) args.a +% 1 else args.a;
            const y = if (args.b == args.k) args.b +% 1 else args.b;
            c.add(x);
            c.add(y);
            return c.contains(args.k);
        }
    }.prop, .{ .iterations = 500 });
}

test "property: cap-1 items survive one add" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { seed: u16 }) bool {
            const cap = 4;
            var c: Lru(u16, cap) = .{};
            // Fill with cap distinct items (use seed to vary)
            var items: [cap]u16 = undefined;
            for (0..cap) |i| {
                items[i] = args.seed +% @as(u16, @intCast(i));
                c.add(items[i]);
            }
            // Add one new distinct item
            const new_key = args.seed +% cap;
            c.add(new_key);
            // Exactly cap-1 of the original items must survive
            var survivors: usize = 0;
            for (0..cap) |i| {
                // Peek without promoting
                for (0..c.len) |j| {
                    if (c.buf[j] == items[i]) {
                        survivors += 1;
                        break;
                    }
                }
            }
            return survivors == cap - 1;
        }
    }.prop, .{ .iterations = 500 });
}
