const std = @import("std");

pub const Lossy = struct {
    text: []const u8,
    owned: ?[]u8 = null,

    pub fn init(alloc: std.mem.Allocator, raw: []const u8) !Lossy {
        if (std.unicode.Utf8View.init(raw)) |_| {
            return .{ .text = raw };
        } else |_| {}

        const owned = try sanitizeLossyAlloc(alloc, raw);
        return .{
            .text = owned,
            .owned = owned,
        };
    }

    pub fn deinit(self: Lossy, alloc: std.mem.Allocator) void {
        if (self.owned) |owned| alloc.free(owned);
    }
};

pub fn sanitizeMaybeAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    if (std.unicode.Utf8View.init(raw)) |_| {
        return raw;
    } else |_| {}
    return sanitizeLossyAlloc(alloc, raw);
}

pub fn sanitizeLossyAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (std.unicode.Utf8View.init(raw)) |_| {
        return alloc.dupe(u8, raw);
    } else |_| {}

    var out = try alloc.alloc(u8, raw.len);
    var i: usize = 0;
    var o: usize = 0;
    while (i < raw.len) {
        const n = std.unicode.utf8ByteSequenceLength(raw[i]) catch {
            out[o] = '?';
            o += 1;
            i += 1;
            continue;
        };
        if (i + n > raw.len) {
            out[o] = '?';
            o += 1;
            i += 1;
            continue;
        }
        _ = std.unicode.utf8Decode(raw[i .. i + n]) catch {
            out[o] = '?';
            o += 1;
            i += 1;
            continue;
        };
        @memcpy(out[o .. o + n], raw[i .. i + n]);
        o += n;
        i += n;
    }
    return out[0..o];
}

test "sanitizeMaybeAlloc preserves valid utf8" {
    const in = "ok ✓";
    const out = try sanitizeMaybeAlloc(std.testing.allocator, in);
    try std.testing.expectEqualStrings(in, out);
    try std.testing.expectEqual(@intFromPtr(in.ptr), @intFromPtr(out.ptr));
}

test "sanitizeLossyAlloc replaces invalid utf8 bytes" {
    const bad = [_]u8{ 'o', 0xff, 'k', 0xc3 };
    const out = try sanitizeLossyAlloc(std.testing.allocator, bad[0..]);
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("o?k?", out);
}
