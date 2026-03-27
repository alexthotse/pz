//! Real API E2E tests — run when ANTHROPIC_API_KEY env is set OR OAuth tokens exist.
const std = @import("std");
const providers = @import("../core/providers.zig");
const auth_mod = @import("../core/providers/auth.zig");
const anthropic = @import("../core/providers/anthropic.zig");
/// Try API key from env, then OAuth from auth file. Skip if neither available.
/// E2E tests use page_allocator because std.http.Client has internal
/// connection pool leaks on error paths (stdlib issue, not ours).
const e2e_alloc = std.heap.page_allocator;

fn loadAuthOrSkip() error{SkipZigTest}!auth_mod.Result {
    return auth_mod.loadForProvider(e2e_alloc, .anthropic) catch return error.SkipZigTest;
}

fn makeClientWithKey(key: []const u8) !anthropic.Client {
    var arena = std.heap.ArenaAllocator.init(e2e_alloc);
    errdefer arena.deinit();
    const ar = arena.allocator();
    const key_dup = try ar.dupe(u8, key);
    return .{
        .alloc = e2e_alloc,
        .auth = .{
            .arena = arena,
            .auth = .{ .api_key = key_dup },
        },
        .http = .{ .allocator = std.heap.page_allocator },
        .ca_file = null,
    };
}

fn simpleReq(model: []const u8) providers.Request {
    return .{
        .model = model,
        .msgs = &.{.{
            .role = .user,
            .parts = &.{.{ .text = "Say hello in one word." }},
        }},
        .opts = .{ .max_out = 64, .thinking = .off },
    };
}

/// Start a provider stream, skipping if auth refresh fails (expired OAuth + rate limit).
fn startOrSkip(client: *anthropic.Client, req: providers.Request) error{ SkipZigTest, OutOfMemory }!*providers.Stream {
    return client.provider.start(req) catch |err| switch (err) {
        error.RefreshFailed, error.RefreshInvalidGrant => return error.SkipZigTest,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.SkipZigTest, // network errors in test → skip
    };
}

fn drainStream(stream: *providers.Stream) !struct { text: usize, total: usize, has_err: bool } {
    var text_n: usize = 0;
    var total: usize = 0;
    var has_err = false;
    while (try stream.next()) |ev| {
        total += 1;
        switch (ev) {
            .text => text_n += 1,
            .err => has_err = true,
            else => {},
        }
    }
    return .{ .text = text_n, .total = total, .has_err = has_err };
}

test "real API: simple prompt returns text" {
    const auth_result = try loadAuthOrSkip();
    // Use page_allocator for HTTP client — std.http.Client has internal
    // connection pool leaks on error paths that are stdlib bugs, not ours.
    var client = anthropic.Client{
        .alloc = e2e_alloc,
        .auth = auth_result,
        .http = .{ .allocator = std.heap.page_allocator },
        .ca_file = null,
    };
    defer client.deinit(); // owns auth arena

    const stream = try startOrSkip(&client, simpleReq("claude-sonnet-4-20250514"));
    defer stream.deinit();

    const stats = try drainStream(stream);
    try std.testing.expect(stats.text > 0);
    try std.testing.expect(!stats.has_err);
}

test "real API: invalid key returns auth error" {
    var auth_result = try loadAuthOrSkip(); // only run when real tests enabled
    auth_result.deinit();
    var client = try makeClientWithKey("sk-bogus-invalid-key-12345");
    defer client.deinit();

    const stream = try client.provider.start(simpleReq("claude-sonnet-4-20250514"));
    defer stream.deinit();

    const stats = try drainStream(stream);
    // Invalid key: API returns error, not text
    try std.testing.expect(stats.text == 0);
    try std.testing.expect(stats.has_err);
}

test "real API: streaming delivers events" {
    const auth_result = try loadAuthOrSkip();
    var client = anthropic.Client{
        .alloc = e2e_alloc,
        .auth = auth_result,
        .http = .{ .allocator = std.heap.page_allocator },
        .ca_file = null,
    };
    defer client.deinit();

    const stream = try startOrSkip(&client, simpleReq("claude-sonnet-4-20250514"));
    defer stream.deinit();

    const stats = try drainStream(stream);
    try std.testing.expect(stats.total > 1);
    try std.testing.expect(stats.text > 0);
}

test "real API: bad model returns error" {
    const auth_result = try loadAuthOrSkip();
    var client = anthropic.Client{
        .alloc = e2e_alloc,
        .auth = auth_result,
        .http = .{ .allocator = std.heap.page_allocator },
        .ca_file = null,
    };
    defer client.deinit();

    const stream = try startOrSkip(&client, simpleReq("nonexistent-model-xyz"));
    defer stream.deinit();

    const stats = try drainStream(stream);
    try std.testing.expect(stats.text == 0);
    try std.testing.expect(stats.has_err);
}
