//! URL query-string encoding/decoding helpers.
const std = @import("std");

/// Decode a percent-encoded query value. '+' is decoded as space.
pub fn decodeQueryValue(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == '+') {
            try out.append(alloc, ' ');
            continue;
        }
        if (c != '%') {
            try out.append(alloc, c);
            continue;
        }
        if (i + 2 >= raw.len) return error.InvalidPercentEncoding;
        const hi = fromHex(raw[i + 1]) orelse return error.InvalidPercentEncoding;
        const lo = fromHex(raw[i + 2]) orelse return error.InvalidPercentEncoding;
        try out.append(alloc, (hi << 4) | lo);
        i += 2;
    }
    return out.toOwnedSlice(alloc);
}

/// Decode a single hex character to its numeric value.
pub fn fromHex(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Percent-encode a string for use in a URL query or form body.
/// When `form` is true, spaces are encoded as '+' (application/x-www-form-urlencoded);
/// otherwise spaces are encoded as '%20' (RFC 3986 query component).
pub fn encodeComponentAlloc(alloc: std.mem.Allocator, raw: []const u8, form: bool) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (raw) |c| {
        const unreserved =
            (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved) {
            try out.append(alloc, c);
            continue;
        }
        if (form and c == ' ') {
            try out.append(alloc, '+');
            continue;
        }
        try out.append(alloc, '%');
        try out.append(alloc, hexUpper((c >> 4) & 0x0f));
        try out.append(alloc, hexUpper(c & 0x0f));
    }
    return out.toOwnedSlice(alloc);
}

fn hexUpper(v: u8) u8 {
    return if (v < 10) ('0' + v) else ('A' + (v - 10));
}

test "decodeQueryValue decodes percent and plus" {
    const alloc = std.testing.allocator;
    const got = try decodeQueryValue(alloc, "hello+world%21%2F");
    defer alloc.free(got);
    try std.testing.expectEqualStrings("hello world!/", got);
}

test "decodeQueryValue rejects truncated percent" {
    try std.testing.expectError(error.InvalidPercentEncoding, decodeQueryValue(std.testing.allocator, "a%2"));
}

test "encodeComponentAlloc query mode" {
    const alloc = std.testing.allocator;
    const got = try encodeComponentAlloc(alloc, "a b/c", false);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("a%20b%2Fc", got);
}

test "encodeComponentAlloc form mode" {
    const alloc = std.testing.allocator;
    const got = try encodeComponentAlloc(alloc, "a b/c", true);
    defer alloc.free(got);
    try std.testing.expectEqualStrings("a+b%2Fc", got);
}
