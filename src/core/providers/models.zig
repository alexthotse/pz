//! Centralized model metadata registry.
//! Single source of truth for context windows, pricing, and capabilities.
const std = @import("std");

pub const Provider = enum { anthropic, openai };

pub const ModelInfo = struct {
    name: []const u8,
    provider: Provider,
    ctx_win: u32, // context window in tokens
    in_cost: u64, // micents per million input tokens
    out_cost: u64, // micents per million output tokens
    cache_read: u64, // micents per million cache-read tokens
    cache_write: u64, // micents per million cache-write tokens
    thinking: bool, // supports extended thinking
};

/// Known model table. Ordered for readability, not lookup.
const registry = [_]ModelInfo{
    // ── Anthropic ────────────────────────────────────────────────
    .{ .name = "claude-opus-4", .provider = .anthropic, .ctx_win = 200_000, .in_cost = 1500, .out_cost = 7500, .cache_read = 150, .cache_write = 1875, .thinking = true },
    .{ .name = "claude-sonnet-4", .provider = .anthropic, .ctx_win = 200_000, .in_cost = 300, .out_cost = 1500, .cache_read = 30, .cache_write = 375, .thinking = true },
    .{ .name = "claude-haiku-3", .provider = .anthropic, .ctx_win = 200_000, .in_cost = 80, .out_cost = 400, .cache_read = 8, .cache_write = 100, .thinking = false },
    .{ .name = "claude-3-5-sonnet", .provider = .anthropic, .ctx_win = 200_000, .in_cost = 300, .out_cost = 1500, .cache_read = 30, .cache_write = 375, .thinking = false },
    .{ .name = "claude-3-5-haiku", .provider = .anthropic, .ctx_win = 200_000, .in_cost = 80, .out_cost = 400, .cache_read = 8, .cache_write = 100, .thinking = false },
    // ── OpenAI ───────────────────────────────────────────────────
    .{ .name = "gpt-4o", .provider = .openai, .ctx_win = 128_000, .in_cost = 250, .out_cost = 1000, .cache_read = 125, .cache_write = 0, .thinking = false },
    .{ .name = "gpt-4o-mini", .provider = .openai, .ctx_win = 128_000, .in_cost = 15, .out_cost = 60, .cache_read = 7, .cache_write = 0, .thinking = false },
    .{ .name = "gpt-4-turbo", .provider = .openai, .ctx_win = 128_000, .in_cost = 1000, .out_cost = 3000, .cache_read = 0, .cache_write = 0, .thinking = false },
    .{ .name = "o1", .provider = .openai, .ctx_win = 200_000, .in_cost = 1500, .out_cost = 6000, .cache_read = 750, .cache_write = 0, .thinking = true },
    .{ .name = "o1-mini", .provider = .openai, .ctx_win = 128_000, .in_cost = 300, .out_cost = 1200, .cache_read = 150, .cache_write = 0, .thinking = true },
    .{ .name = "o1-pro", .provider = .openai, .ctx_win = 200_000, .in_cost = 15000, .out_cost = 60000, .cache_read = 0, .cache_write = 0, .thinking = true },
    .{ .name = "o3", .provider = .openai, .ctx_win = 200_000, .in_cost = 1000, .out_cost = 4000, .cache_read = 500, .cache_write = 0, .thinking = true },
    .{ .name = "o3-mini", .provider = .openai, .ctx_win = 200_000, .in_cost = 110, .out_cost = 440, .cache_read = 55, .cache_write = 0, .thinking = true },
    .{ .name = "o4-mini", .provider = .openai, .ctx_win = 200_000, .in_cost = 110, .out_cost = 440, .cache_read = 55, .cache_write = 0, .thinking = true },
};

/// Find model by name: exact prefix match against registry entries.
/// Handles versioned names like "claude-opus-4-20250514" matching "claude-opus-4".
pub fn findModel(name: []const u8) ?ModelInfo {
    // Longest prefix wins — iterate all, keep best.
    var best: ?ModelInfo = null;
    var best_len: usize = 0;
    for (&registry) |*m| {
        if (name.len >= m.name.len and
            std.mem.eql(u8, name[0..m.name.len], m.name) and
            m.name.len > best_len)
        {
            best = m.*;
            best_len = m.name.len;
        }
    }
    if (best != null) return best;
    // Fallback: substring match (e.g. model contains "opus").
    for (&registry) |*m| {
        if (std.mem.indexOf(u8, name, m.name) != null) return m.*;
    }
    return null;
}

pub fn contextWindow(name: []const u8) ?u32 {
    return if (findModel(name)) |m| m.ctx_win else null;
}

pub fn supportsThinking(name: []const u8) bool {
    return if (findModel(name)) |m| m.thinking else false;
}

pub const CostRates = struct { in: u64, out: u64, cr: u64, cw: u64 };

pub fn costRates(name: []const u8) ?CostRates {
    const m = findModel(name) orelse return null;
    return .{ .in = m.in_cost, .out = m.out_cost, .cr = m.cache_read, .cw = m.cache_write };
}

// ── Tests ────────────────────────────────────────────────────────

const testing = std.testing;

test "findModel exact prefix" {
    const m = findModel("claude-opus-4-20250514").?;
    try testing.expectEqualStrings("claude-opus-4", m.name);
    try testing.expect(m.thinking);
    try testing.expectEqual(@as(u32, 200_000), m.ctx_win);
}

test "findModel versioned sonnet" {
    const m = findModel("claude-sonnet-4-20250514").?;
    try testing.expectEqualStrings("claude-sonnet-4", m.name);
    try testing.expect(m.thinking);
}

test "findModel old sonnet no thinking" {
    const m = findModel("claude-3-5-sonnet-20241022").?;
    try testing.expectEqualStrings("claude-3-5-sonnet", m.name);
    try testing.expect(!m.thinking);
}

test "findModel haiku no thinking" {
    const m = findModel("claude-haiku-3-20240307").?;
    try testing.expect(!m.thinking);
}

test "findModel openai" {
    const m = findModel("gpt-4o-mini").?;
    try testing.expectEqual(Provider.openai, m.provider);
    try testing.expectEqual(@as(u64, 15), m.in_cost);
}

test "findModel unknown returns null" {
    try testing.expect(findModel("unknown-model-xyz") == null);
}

test "contextWindow" {
    try testing.expectEqual(@as(u32, 200_000), contextWindow("claude-opus-4-6").?);
    try testing.expect(contextWindow("nonexistent") == null);
}

test "supportsThinking matches anthropic" {
    try testing.expect(supportsThinking("claude-opus-4-20250514"));
    try testing.expect(supportsThinking("claude-sonnet-4-20250514"));
    try testing.expect(!supportsThinking("claude-haiku-3-20240307"));
    try testing.expect(!supportsThinking("claude-3-5-sonnet-20241022"));
}

test "supportsThinking matches openai" {
    try testing.expect(supportsThinking("o1"));
    try testing.expect(supportsThinking("o3-mini"));
    try testing.expect(!supportsThinking("gpt-4o"));
}

test "costRates opus" {
    const r = costRates("claude-opus-4-6").?;
    try testing.expectEqual(@as(u64, 1500), r.in);
    try testing.expectEqual(@as(u64, 7500), r.out);
    try testing.expectEqual(@as(u64, 150), r.cr);
    try testing.expectEqual(@as(u64, 1875), r.cw);
}

test "costRates sonnet" {
    const r = costRates("claude-sonnet-4-6").?;
    try testing.expectEqual(@as(u64, 300), r.in);
    try testing.expectEqual(@as(u64, 1500), r.out);
}

test "costRates openai" {
    const r = costRates("gpt-4o").?;
    try testing.expectEqual(@as(u64, 250), r.in);
    try testing.expectEqual(@as(u64, 1000), r.out);
}

test "costRates unknown returns null" {
    try testing.expect(costRates("nonexistent") == null);
}

test "longest prefix wins gpt-4o vs gpt-4o-mini" {
    // "gpt-4o-mini" should match the mini entry, not "gpt-4o"
    const m = findModel("gpt-4o-mini").?;
    try testing.expectEqualStrings("gpt-4o-mini", m.name);
    try testing.expectEqual(@as(u64, 15), m.in_cost);
}
