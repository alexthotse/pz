const std = @import("std");
const testing = std.testing;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const ver_current: u16 = 1;
pub const mac_len: usize = HmacSha256.mac_length;

pub const Tag = [mac_len]u8;

pub const Key = struct {
    id: u32,
    bytes: Tag,
};

pub const State = struct {
    lines: u64 = 0,
    last_mac: ?Tag = null,
    last_key_id: ?u32 = null,
};

pub const FailKind = enum {
    malformed,
    unknown_key,
    bad_prev,
    bad_mac,
};

pub const Fail = struct {
    line: u64,
    kind: FailKind,
    state: State,
};

pub const Verify = union(enum) {
    ok: State,
    fail: Fail,
};

const Line = struct {
    v: u16,
    kid: u32,
    prev: ?[]const u8 = null,
    mac: []const u8,
    body: []const u8,
};

pub fn sealAlloc(alloc: std.mem.Allocator, key: Key, prev: ?Tag, body: []const u8) ![]u8 {
    const mac = try calcMac(alloc, key, prev, body);
    var prev_hex_buf: [mac_len * 2]u8 = undefined;
    var mac_hex_buf: [mac_len * 2]u8 = undefined;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    const w = out.writer(alloc);

    try w.writeAll("{\"v\":1,\"kid\":");
    try w.print("{d}", .{key.id});
    try w.writeAll(",\"prev\":");
    if (prev) |tag| {
        try writeJsonStr(w, hexEncode(&prev_hex_buf, &tag));
    } else {
        try w.writeAll("null");
    }
    try w.writeAll(",\"mac\":");
    try writeJsonStr(w, hexEncode(&mac_hex_buf, &mac));
    try w.writeAll(",\"body\":");
    try writeJsonStr(w, body);
    try w.writeByte('}');

    return try out.toOwnedSlice(alloc);
}

pub fn verifyLogAlloc(alloc: std.mem.Allocator, raw: []const u8, keys: []const Key) !Verify {
    var st: State = .{};
    if (raw.len == 0) return .{ .ok = st };

    var it = std.mem.splitScalar(u8, raw, '\n');
    var line_no: u64 = 0;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        line_no += 1;

        const doc = std.json.parseFromSlice(Line, alloc, line, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = false,
        }) catch {
            return .{ .fail = .{ .line = line_no, .kind = .malformed, .state = st } };
        };
        defer doc.deinit();

        if (doc.value.v != ver_current) {
            return .{ .fail = .{ .line = line_no, .kind = .malformed, .state = st } };
        }

        const key = findKey(keys, doc.value.kid) orelse {
            return .{ .fail = .{ .line = line_no, .kind = .unknown_key, .state = st } };
        };

        const prev = if (doc.value.prev) |hex| parseTagHex(hex) catch {
            return .{ .fail = .{ .line = line_no, .kind = .malformed, .state = st } };
        } else null;

        if (!sameTag(st.last_mac, prev)) {
            return .{ .fail = .{ .line = line_no, .kind = .bad_prev, .state = st } };
        }

        const mac = parseTagHex(doc.value.mac) catch {
            return .{ .fail = .{ .line = line_no, .kind = .malformed, .state = st } };
        };
        const want = try calcMac(alloc, key, prev, doc.value.body);
        if (!std.mem.eql(u8, &mac, &want)) {
            return .{ .fail = .{ .line = line_no, .kind = .bad_mac, .state = st } };
        }

        st.lines = line_no;
        st.last_mac = mac;
        st.last_key_id = key.id;
    }

    if (raw[raw.len - 1] != '\n') {
        return .{ .fail = .{ .line = st.lines + 1, .kind = .malformed, .state = st } };
    }

    return .{ .ok = st };
}

fn calcMac(alloc: std.mem.Allocator, key: Key, prev: ?Tag, body: []const u8) !Tag {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(alloc);
    const w = buf.writer(alloc);

    try w.print("{d}\n", .{key.id});
    if (prev) |tag| {
        var prev_hex_buf: [mac_len * 2]u8 = undefined;
        try w.writeAll(hexEncode(&prev_hex_buf, &tag));
    } else {
        try w.writeByte('-');
    }
    try w.writeByte('\n');
    try w.writeAll(body);

    var out: Tag = undefined;
    HmacSha256.create(out[0..], buf.items, &key.bytes);
    return out;
}

fn findKey(keys: []const Key, id: u32) ?Key {
    for (keys) |key| {
        if (key.id == id) return key;
    }
    return null;
}

fn sameTag(a: ?Tag, b: ?Tag) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, &a.?, &b.?);
}

fn parseTagHex(hex: []const u8) !Tag {
    if (hex.len != mac_len * 2) return error.BadHexLen;
    var out: Tag = undefined;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = try parseHexByte(hex[i * 2], hex[i * 2 + 1]);
    }
    return out;
}

fn parseHexByte(hi: u8, lo: u8) !u8 {
    return (try parseNibble(hi) << 4) | try parseNibble(lo);
}

fn parseNibble(ch: u8) !u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => error.BadHex,
    };
}

fn hexEncode(buf: *[mac_len * 2]u8, bytes: *const Tag) []const u8 {
    const alpha = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        buf[i * 2] = alpha[b >> 4];
        buf[i * 2 + 1] = alpha[b & 0x0f];
    }
    return buf[0..];
}

fn writeJsonStr(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

fn lineJoinAlloc(alloc: std.mem.Allocator, lines: []const []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    for (lines) |line| {
        try out.appendSlice(alloc, line);
        try out.append(alloc, '\n');
    }
    return try out.toOwnedSlice(alloc);
}

fn tagHexAlloc(alloc: std.mem.Allocator, tag: ?Tag) !?[]u8 {
    if (tag == null) return null;
    const out = try alloc.alloc(u8, mac_len * 2);
    var buf: [mac_len * 2]u8 = undefined;
    @memcpy(out, hexEncode(&buf, &tag.?));
    return out;
}

test "snapshot: verify survives rotation and tracks last tag" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const k1 = Key{ .id = 1, .bytes = [_]u8{0x11} ** mac_len };
    const k2 = Key{ .id = 2, .bytes = [_]u8{0x22} ** mac_len };

    const l1 = try sealAlloc(testing.allocator, k1, null, "{\"seq\":1}");
    defer testing.allocator.free(l1);
    const raw1 = try lineJoinAlloc(testing.allocator, &.{l1});
    defer testing.allocator.free(raw1);
    const r1 = (try verifyLogAlloc(testing.allocator, raw1, &.{k1})).ok;

    const l2 = try sealAlloc(testing.allocator, k1, r1.last_mac, "{\"seq\":2}");
    defer testing.allocator.free(l2);
    const raw2 = try lineJoinAlloc(testing.allocator, &.{ l1, l2 });
    defer testing.allocator.free(raw2);
    const r2 = (try verifyLogAlloc(testing.allocator, raw2, &.{k1})).ok;

    const l3 = try sealAlloc(testing.allocator, k2, r2.last_mac, "{\"seq\":3}");
    defer testing.allocator.free(l3);

    const raw = try lineJoinAlloc(testing.allocator, &.{ l1, l2, l3 });
    defer testing.allocator.free(raw);
    const got = try verifyLogAlloc(testing.allocator, raw, &.{ k1, k2 });
    const last_hex = (try tagHexAlloc(testing.allocator, got.ok.last_mac)).?;
    defer testing.allocator.free(last_hex);
    const got_snap = try std.fmt.allocPrint(testing.allocator, "lines={d} last={s} kid={?}", .{
        got.ok.lines,
        last_hex,
        got.ok.last_key_id,
    });
    defer testing.allocator.free(got_snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "lines=3 last=6d8ca9c0723a0ec202b418a6545609784b659d3f7873166babf0ed89187e80a8 kid=2"
    ).expectEqual(got_snap);
}

test "snapshot: verify stops at first tampered line" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const key = Key{ .id = 7, .bytes = [_]u8{0x33} ** mac_len };
    const l1 = try sealAlloc(testing.allocator, key, null, "{\"seq\":1}");
    defer testing.allocator.free(l1);
    const raw1 = try lineJoinAlloc(testing.allocator, &.{l1});
    defer testing.allocator.free(raw1);
    const r1 = (try verifyLogAlloc(testing.allocator, raw1, &.{key})).ok;

    const l2 = try sealAlloc(testing.allocator, key, r1.last_mac, "{\"seq\":2}");
    defer testing.allocator.free(l2);
    const tampered = try testing.allocator.dupe(u8, l2);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 3] = '9';

    const raw = try lineJoinAlloc(testing.allocator, &.{ l1, tampered });
    defer testing.allocator.free(raw);
    const got = try verifyLogAlloc(testing.allocator, raw, &.{key});
    const last_hex = (try tagHexAlloc(testing.allocator, got.fail.state.last_mac)).?;
    defer testing.allocator.free(last_hex);
    const got_snap = try std.fmt.allocPrint(testing.allocator, "line={d} kind={s} lines={d} last={s} kid={?}", .{
        got.fail.line,
        @tagName(got.fail.kind),
        got.fail.state.lines,
        last_hex,
        got.fail.state.last_key_id,
    });
    defer testing.allocator.free(got_snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "line=2 kind=bad_mac lines=1 last=7efa0b75a5f823970f888c0f3dcf225f3a05c97670a99a97df13dcfa307c1f28 kid=7"
    ).expectEqual(got_snap);
}

test "crash recovery resumes from last good tag" {
    const key = Key{ .id = 1, .bytes = [_]u8{0x44} ** mac_len };

    const l1 = try sealAlloc(testing.allocator, key, null, "{\"seq\":1}");
    defer testing.allocator.free(l1);
    const raw1 = try lineJoinAlloc(testing.allocator, &.{l1});
    defer testing.allocator.free(raw1);
    const r1 = (try verifyLogAlloc(testing.allocator, raw1, &.{key})).ok;

    const l2 = try sealAlloc(testing.allocator, key, r1.last_mac, "{\"seq\":2}");
    defer testing.allocator.free(l2);

    const broken = try std.fmt.allocPrint(testing.allocator, "{s}\n{s}", .{ l1, l2 });
    defer testing.allocator.free(broken);
    const got = try verifyLogAlloc(testing.allocator, broken, &.{key});
    try testing.expect(got == .fail);
    try testing.expectEqual(@as(u64, 2), got.fail.state.lines);

    const l3 = try sealAlloc(testing.allocator, key, got.fail.state.last_mac, "{\"seq\":3}");
    defer testing.allocator.free(l3);
    const fixed = try lineJoinAlloc(testing.allocator, &.{ l1, l2, l3 });
    defer testing.allocator.free(fixed);
    const ok = try verifyLogAlloc(testing.allocator, fixed, &.{key});
    try testing.expect(ok == .ok);
    try testing.expectEqual(@as(u64, 3), ok.ok.lines);
}
