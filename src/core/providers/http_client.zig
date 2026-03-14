//! Shared HTTP client: auth, retry, SSE streaming, utilities.
//!
//! Providers implement a comptime interface and get connection management,
//! retry with backoff, OAuth refresh, SSE line reading, and error handling
//! for free. Only provider-specific header/body/parsing logic lives outside.
const std = @import("std");
const providers = @import("api.zig");
const auth_mod = @import("auth.zig");
const audit = @import("../audit.zig");
const utf8 = @import("../utf8.zig");

const max_retries = 3;
const base_delay_ms: u64 = 2000;
const max_delay_ms: u64 = 60000;

// ── Utility functions ──────────────────────────────────────────────────

pub fn objGet(map: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .object => |obj| obj,
        else => null,
    };
}

pub fn strGet(map: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

pub fn jsonU64(val: ?std.json.Value) u64 {
    const v = val orelse return 0;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else 0,
        .float => |f| if (f >= 0) @intFromFloat(f) else 0,
        else => 0,
    };
}

pub fn sanitizeUtf8(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    return utf8.sanitizeMaybeAlloc(alloc, raw);
}

pub fn writeJsonLossy(alloc: std.mem.Allocator, js: *std.json.Stringify, raw: []const u8) !void {
    try js.write(try utf8.sanitizeMaybeAlloc(alloc, raw));
}

// ── Auth management ────────────────────────────────────────────────────

/// Refresh OAuth token for a provider. Tries refresh endpoint first, then
/// falls back to reloading from disk (another process may have refreshed).
pub fn refreshAuth(
    alloc: std.mem.Allocator,
    auth: *auth_mod.Result,
    tag: auth_mod.Provider,
    ca_file: ?[]const u8,
    ar: std.mem.Allocator,
) !void {
    const old = auth.auth.oauth;

    if (auth_mod.refreshOAuthForProviderWithHooks(ar, tag, old, .{ .ca_file = ca_file })) |new_oauth| {
        const auth_ar = auth.arena.allocator();
        const new_access = try auth_ar.dupe(u8, new_oauth.access);
        const new_refresh = try auth_ar.dupe(u8, new_oauth.refresh);
        ar.free(new_oauth.access);
        ar.free(new_oauth.refresh);
        auth.auth = .{ .oauth = .{
            .access = new_access,
            .refresh = new_refresh,
            .expires = new_oauth.expires,
        } };
        return;
    } else |_| {}

    // Refresh failed — reload from disk (another instance may have refreshed)
    var reloaded = auth_mod.loadForProvider(alloc, tag) catch return error.RefreshFailed;
    switch (reloaded.auth) {
        .oauth => |oauth| {
            const now = std.time.milliTimestamp();
            if (now < oauth.expires) {
                auth.deinit();
                auth.* = reloaded;
                return;
            }
        },
        else => {},
    }
    reloaded.deinit();
    return error.RefreshFailed;
}

/// Proactive pre-request refresh: if token looks expired, try refreshing.
/// Failure is non-fatal — the 401 retry handler will surface real errors.
pub fn tryProactiveRefresh(
    alloc: std.mem.Allocator,
    auth: *auth_mod.Result,
    tag: auth_mod.Provider,
    ca_file: ?[]const u8,
    ar: std.mem.Allocator,
) void {
    if (auth.auth != .oauth) return;
    const now = std.time.milliTimestamp();
    if (now < auth.auth.oauth.expires) return;
    refreshAuth(alloc, auth, tag, ca_file, ar) catch {};
}

// ── Retry loop ─────────────────────────────────────────────────────────

/// Real sleeper: delegates to std.Thread.sleep.
pub const RealSleeper = struct {
    pub fn sleep(_: *RealSleeper, ms: u64) void {
        std.Thread.sleep(ms * std.time.ns_per_ms);
    }
};

/// Execute the retry loop: connect, send, receive head, handle 401/429/5xx.
///
/// On 401 with OAuth, refreshes the token and calls `rebuildHdrs` to get
/// new provider-specific headers before retrying.
pub fn retryLoop(
    stream: anytype,
    http: *std.http.Client,
    uri: std.Uri,
    body: []const u8,
    hdrs: *std.ArrayListUnmanaged(std.http.Header),
    auth: *auth_mod.Result,
    alloc: std.mem.Allocator,
    tag: auth_mod.Provider,
    ca_file: ?[]const u8,
    ar: std.mem.Allocator,
    sleeper: anytype,
    rebuildHdrs: *const fn (*auth_mod.Result, std.mem.Allocator) anyerror!std.ArrayListUnmanaged(std.http.Header),
) !void {
    var attempt: u32 = 0;
    var did_refresh = false;
    while (true) : (attempt += 1) {
        stream.req = try http.request(.POST, uri, .{
            .extra_headers = hdrs.items,
            .keep_alive = false,
        });

        stream.req.transfer_encoding = .{ .content_length = body.len };
        var bw = try stream.req.sendBodyUnflushed(&stream.send_buf);
        try bw.writer.writeAll(body);
        try bw.end();
        try stream.req.connection.?.flush();

        stream.response = try stream.req.receiveHead(&stream.redir_buf);
        const status_int: u16 = @intFromEnum(stream.response.head.status);

        // On 401 with OAuth, try refreshing token once
        if (status_int == 401 and auth.auth == .oauth and !did_refresh) {
            did_refresh = true;
            const refreshed = if (refreshAuth(alloc, auth, tag, ca_file, ar)) true else |_| false;
            if (refreshed) {
                drainResponse(stream, ar);
                stream.req.deinit();
                hdrs.* = try rebuildHdrs(auth, ar);
                continue;
            }
        }

        const retryable = status_int == 429 or (status_int >= 500 and status_int < 600);
        if (!retryable or attempt >= max_retries) break;

        drainResponse(stream, ar);
        stream.req.deinit();

        // Backoff: min(base * 2^attempt, max)
        const delay: u64 = @min(max_delay_ms, base_delay_ms * (@as(u64, 1) << @intCast(attempt)));
        sleeper.sleep(delay);
    }
}

pub fn drainResponse(stream: anytype, ar: std.mem.Allocator) void {
    const rdr = stream.response.reader(&stream.transfer_buf);
    _ = rdr.allocRemaining(ar, .limited(16384)) catch {};
}

// ── Error body handling ────────────────────────────────────────────────

/// Read and format error body from non-200 response. Provider-specific
/// `extractMsg` extracts a human-readable message from the raw body;
/// pass `null` to use the full body.
pub fn formatErrBody(
    stream: anytype,
    ar: std.mem.Allocator,
    extractMsg: ?*const fn ([]const u8) ?[]const u8,
) !void {
    stream.err_mode = true;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const rdr = stream.response.readerDecompressing(
        &stream.transfer_buf,
        &decomp,
        &decomp_buf,
    );
    const err_body = rdr.allocRemaining(ar, .limited(16384)) catch
        try ar.dupe(u8, "unknown error");
    const status_int: u16 = @intFromEnum(stream.response.head.status);
    const safe_body = sanitizeUtf8(ar, err_body) catch "unknown error";
    const msg = if (extractMsg) |f| (f(safe_body) orelse safe_body) else safe_body;
    const redacted = audit.redactTextAlloc(ar, msg, .@"pub") catch "unknown error";
    stream.err_text = try std.fmt.allocPrint(ar, "{d} {s}", .{ status_int, redacted });
}

// ── SSE next() implementation ──────────────────────────────────────────

/// Shared `next()` implementation for SSE streams. Handles pending events,
/// error mode, arena reset, and SSE line reading. Delegates actual data
/// parsing to the provider-specific `parseSseData` method.
///
/// Ownership contract: event data (text, thinking, tool_call slices) points
/// into the stream's arena. The arena resets on each `next()` call, so callers
/// MUST consume or dupe event data before calling `next()` again.
pub fn sseNext(self: anytype) anyerror!?providers.Event {
    if (self.pending) |ev| {
        self.pending = null;
        return ev;
    }

    if (self.done) return null;

    if (self.err_mode) {
        self.err_mode = false;
        self.done = true;
        self.pending = .{ .stop = .{ .reason = .err } };
        return .{ .err = self.err_text orelse "unknown error" };
    }

    // Reset per-frame arena: previous event strings already consumed by caller.
    _ = self.arena.reset(.retain_capacity);

    while (true) {
        const rdr = self.body_rdr orelse {
            self.done = true;
            return null;
        };
        const line = rdr.takeDelimiter('\n') catch |err| switch (err) {
            error.ReadFailed => {
                self.done = true;
                return null;
            },
            error.StreamTooLong => continue,
        };

        const raw_line = line orelse {
            self.done = true;
            return null;
        };

        const raw = std.mem.trimRight(u8, raw_line, "\r");

        // Extract SSE data payload, handling both "data: " and "data:" prefixes
        const data = if (std.mem.startsWith(u8, raw, "data: "))
            raw["data: ".len..]
        else if (std.mem.startsWith(u8, raw, "data:"))
            std.mem.trimLeft(u8, raw["data:".len..], " ")
        else
            continue;

        if (std.mem.eql(u8, data, "[DONE]")) continue;

        const ar = self.arena.allocator();
        const data_copy = try ar.dupe(u8, data);

        const ev = self.parseSseData(data_copy) catch continue;
        if (ev) |e| return e;
    }
}

// ── Test helpers ───────────────────────────────────────────────────────

pub fn randSafeToken(rnd: std.Random, buf: []u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-";
    const n = rnd.intRangeAtMost(usize, 1, buf.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const idx = rnd.intRangeLessThan(usize, 0, alphabet.len);
        buf[i] = alphabet[idx];
    }
    return buf[0..n];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "objGet returns object or null" {
    const ar = testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, ar, "{\"a\":{\"b\":1},\"c\":\"str\"}", .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expect(objGet(root, "a") != null);
    try testing.expect(objGet(root, "c") == null);
    try testing.expect(objGet(root, "missing") == null);
}

test "strGet returns string or null" {
    const ar = testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, ar, "{\"s\":\"val\",\"n\":42}", .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try testing.expectEqualStrings("val", strGet(root, "s").?);
    try testing.expect(strGet(root, "n") == null);
    try testing.expect(strGet(root, "nope") == null);
}

test "jsonU64 handles all value types" {
    try testing.expectEqual(@as(u64, 42), jsonU64(.{ .integer = 42 }));
    try testing.expectEqual(@as(u64, 0), jsonU64(.{ .integer = -5 }));
    try testing.expectEqual(@as(u64, 3), jsonU64(.{ .float = 3.7 }));
    try testing.expectEqual(@as(u64, 0), jsonU64(.{ .float = -1.0 }));
    try testing.expectEqual(@as(u64, 0), jsonU64(.{ .bool = true }));
    try testing.expectEqual(@as(u64, 0), jsonU64(null));
}

test "sanitizeUtf8 replaces invalid bytes" {
    const result = try sanitizeUtf8(testing.allocator, "ab\xfe\xffcd");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("ab??cd", result);
}

test "sanitizeUtf8 passes through valid" {
    const result = try sanitizeUtf8(testing.allocator, "hello");
    try testing.expectEqualStrings("hello", result);
}
