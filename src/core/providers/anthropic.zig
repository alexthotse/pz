//! Anthropic Messages API client.
const std = @import("std");
const providers = @import("api.zig");
const auth_mod = @import("auth.zig");
const hc = @import("http_client.zig");
const models = @import("models.zig");

const api_version = "2023-06-01";
const default_max_tokens: u32 = 16384;

pub const Cfg = struct {
    pub const provider_tag = auth_mod.Provider.anthropic;
    pub const api_host = "api.anthropic.com";
    pub const api_path = "/v1/messages";

    pub const ExtFields = struct {
        cache_write: u64,
        tool_id: std.ArrayListUnmanaged(u8),
    };

    pub fn ext_init() ExtFields {
        return .{ .cache_write = 0, .tool_id = .{} };
    }

    pub fn ext_deinit(self: *Stream, alloc: std.mem.Allocator) void {
        self.ext.tool_id.deinit(alloc);
    }

    pub fn ext_reset(self: *Stream) void {
        self.ext.cache_write = 0;
        self.ext.tool_id.clearRetainingCapacity();
    }

    pub fn buildAuthHeaders(auth: *auth_mod.Result, ar: std.mem.Allocator) anyerror!std.ArrayListUnmanaged(std.http.Header) {
        var hdrs = std.ArrayListUnmanaged(std.http.Header){};
        try hdrs.append(ar, .{ .name = "content-type", .value = "application/json" });
        try hdrs.append(ar, .{ .name = "anthropic-version", .value = api_version });

        switch (auth.auth) {
            .oauth => |oauth| {
                const bearer = try std.fmt.allocPrint(ar, "Bearer {s}", .{oauth.access});
                try hdrs.append(ar, .{ .name = "anthropic-beta", .value = "claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14,interleaved-thinking-2025-05-14" });
                try hdrs.append(ar, .{ .name = "anthropic-dangerous-direct-browser-access", .value = "true" });
                try hdrs.append(ar, .{ .name = "authorization", .value = bearer });
                try hdrs.append(ar, .{ .name = "user-agent", .value = "claude-cli/2.1.79 (external, cli)" });
                try hdrs.append(ar, .{ .name = "x-app", .value = "cli" });
            },
            .api_key => |key| {
                try hdrs.append(ar, .{ .name = "x-api-key", .value = key });
            },
        }
        return hdrs;
    }

    pub fn buildBody(alloc: std.mem.Allocator, req: providers.Request, is_oauth: bool) anyerror![]u8 {
        return buildBodyImpl(alloc, req, is_oauth);
    }

    pub fn parseSseData(self: *Stream, data: []const u8) anyerror!?providers.Event {
        return parseSseDataImpl(self, data);
    }
};

pub const Client = hc.SseClient(Cfg);
const Stream = hc.SseStream(Cfg);

const objGet = hc.objGet;
const strGet = hc.strGet;
const jsonU64 = hc.jsonU64;
const sanitizeUtf8 = hc.sanitizeUtf8;
const writeJsonLossy = hc.writeJsonLossy;

// ── SSE parsing ────────────────────────────────────────────────────────

fn parseSseDataImpl(self: *Stream, data: []const u8) !?providers.Event {
    const ar = self.arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, ar, data, .{
        .allocate = .alloc_always,
    }) catch return null;

    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };

    const ev_type = switch (root.get("type") orelse return null) {
        .string => |s| s,
        else => return null,
    };

    const SseEvType = enum { message_start, content_block_start, content_block_delta, content_block_stop, message_delta };
    const ev_map = std.StaticStringMap(SseEvType).initComptime(.{
        .{ "message_start", .message_start },
        .{ "content_block_start", .content_block_start },
        .{ "content_block_delta", .content_block_delta },
        .{ "content_block_stop", .content_block_stop },
        .{ "message_delta", .message_delta },
    });

    const resolved = ev_map.get(ev_type) orelse return null;
    return switch (resolved) {
        .message_start => onMessageStart(self, root),
        .content_block_start => onBlockStart(self, root),
        .content_block_delta => onBlockDelta(self, root),
        .content_block_stop => onBlockStop(self),
        .message_delta => onMessageDelta(self, root),
    };
}

fn onMessageStart(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const msg = objGet(root, "message") orelse return null;
    const usage = objGet(msg, "usage") orelse return null;
    self.in_tok = jsonU64(usage.get("input_tokens"));
    self.cache_read = jsonU64(usage.get("cache_read_input_tokens"));
    self.ext.cache_write = jsonU64(usage.get("cache_creation_input_tokens"));
    return null;
}

fn onBlockStart(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const cb = objGet(root, "content_block") orelse return null;
    const cb_type = strGet(cb, "type") orelse return null;

    if (!std.mem.eql(u8, cb_type, "tool_use")) return null;

    self.ext.tool_id.clearRetainingCapacity();
    self.tool_name.clearRetainingCapacity();
    self.tool_args.clearRetainingCapacity();

    if (strGet(cb, "id")) |id| try self.ext.tool_id.appendSlice(self.alloc, id);
    if (strGet(cb, "name")) |name| try self.tool_name.appendSlice(self.alloc, name);
    self.in_tool = true;
    return null;
}

fn onBlockDelta(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const delta = objGet(root, "delta") orelse return null;
    const delta_type = strGet(delta, "type") orelse return null;

    const DeltaType = enum { text_delta, thinking_delta, input_json_delta };
    const delta_map = std.StaticStringMap(DeltaType).initComptime(.{
        .{ "text_delta", .text_delta },
        .{ "thinking_delta", .thinking_delta },
        .{ "input_json_delta", .input_json_delta },
    });

    const dt = delta_map.get(delta_type) orelse return null;
    switch (dt) {
        .text_delta => if (strGet(delta, "text")) |text| return .{ .text = text },
        .thinking_delta => if (strGet(delta, "thinking")) |text| return .{ .thinking = text },
        .input_json_delta => if (self.in_tool) {
            if (strGet(delta, "partial_json")) |pj|
                try self.tool_args.appendSlice(self.alloc, pj);
        },
    }
    return null;
}

fn onBlockStop(self: *Stream) !?providers.Event {
    if (!self.in_tool) return null;
    self.in_tool = false;
    const ar = self.arena.allocator();
    return .{ .tool_call = .{
        .id = try ar.dupe(u8, self.ext.tool_id.items),
        .name = try ar.dupe(u8, self.tool_name.items),
        .args = try ar.dupe(u8, self.tool_args.items),
    } };
}

fn onMessageDelta(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    if (objGet(root, "usage")) |usage| {
        self.out_tok = jsonU64(usage.get("output_tokens"));
    }
    const delta = objGet(root, "delta") orelse return null;
    const reason_str = strGet(delta, "stop_reason") orelse return null;

    const usage_ev: providers.Event = .{ .usage = .{
        .in_tok = self.in_tok,
        .out_tok = self.out_tok,
        .tot_tok = self.in_tok + self.out_tok,
        .cache_read = self.cache_read,
        .cache_write = self.ext.cache_write,
    } };
    self.pending = .{ .stop = .{ .reason = mapStopReason(reason_str) } };
    self.done = true;
    return usage_ev;
}

fn mapStopReason(reason: []const u8) providers.StopReason {
    const map = std.StaticStringMap(providers.StopReason).initComptime(.{
        .{ "end_turn", .done },
        .{ "max_tokens", .max_out },
        .{ "tool_use", .tool },
        .{ "canceled", .canceled },
        .{ "err", .err },
    });
    return map.get(reason) orelse .done;
}

// ── Body building ──────────────────────────────────────────────────────

fn supportsThinking(model: []const u8) bool {
    return models.supportsThinking(model);
}

fn testBuildBody(alloc: std.mem.Allocator, req: providers.Request) ![]u8 {
    return buildBodyImpl(alloc, req, false);
}

fn buildBodyImpl(alloc: std.mem.Allocator, req: providers.Request, is_oauth: bool) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    var out: std.io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    var js: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };

    try js.beginObject();

    try js.objectField("model");
    try js.write(req.model);

    try js.objectField("max_tokens");
    const base_max = req.opts.max_out orelse default_max_tokens;
    // max_tokens must exceed thinking budget
    const think_bud: u32 = if (req.opts.thinking == .budget and req.opts.thinking_budget > 0)
        req.opts.thinking_budget
    else
        0;
    try js.write(if (think_bud >= base_max) think_bud + default_max_tokens else base_max);

    try js.objectField("stream");
    try js.write(true);

    if (req.opts.temp) |temp| {
        try js.objectField("temperature");
        try js.write(temp);
    }

    if (req.opts.top_p) |top_p| {
        try js.objectField("top_p");
        try js.write(top_p);
    }

    if (req.opts.stop.len > 0) {
        try js.objectField("stop_sequences");
        try js.beginArray();
        for (req.opts.stop) |seq| try js.write(seq);
        try js.endArray();
    }

    // Thinking configuration
    switch (req.opts.thinking) {
        .off => {},
        .adaptive => if (supportsThinking(req.model)) {
            try js.objectField("thinking");
            try js.beginObject();
            try js.objectField("type");
            try js.write("adaptive");
            try js.endObject();
        },
        .budget => if (supportsThinking(req.model)) {
            const budget = if (req.opts.thinking_budget > 0) req.opts.thinking_budget else 4096;
            try js.objectField("thinking");
            try js.beginObject();
            try js.objectField("type");
            try js.write("enabled");
            try js.objectField("budget_tokens");
            try js.write(budget);
            try js.endObject();
        },
    }

    // Extract system messages as top-level "system" field.
    // OAuth tokens MUST include Claude Code identity system prompt.
    try writeSystem(ar, &js, req.msgs, is_oauth);

    try js.objectField("messages");
    try writeMessages(ar, &js, req.msgs);

    if (req.tools.len > 0) {
        try js.objectField("tools");
        try js.beginArray();
        for (req.tools) |tool| {
            try js.beginObject();
            try js.objectField("name");
            try writeJsonLossy(ar, &js, tool.name);
            try js.objectField("description");
            try writeJsonLossy(ar, &js, tool.desc);
            try js.objectField("input_schema");
            if (tool.schema.len > 0) {
                try js.beginWriteRaw();
                try js.writer.writeAll(tool.schema);
                js.endWriteRaw();
            } else {
                try js.beginObject();
                try js.objectField("type");
                try js.write("object");
                try js.endObject();
            }
            try js.endObject();
        }
        try js.endArray();
    }

    try js.endObject();

    return out.toOwnedSlice() catch return error.OutOfMemory;
}

const claude_code_identity = "You are Claude Code, Anthropic's official CLI for Claude.";

fn writeSystem(alloc: std.mem.Allocator, js: *std.json.Stringify, msgs: []const providers.Msg, is_oauth: bool) !void {
    // Count total system text parts for cache_control on last one
    var total: usize = 0;
    for (msgs) |msg| {
        if (msg.role != .system) continue;
        for (msg.parts) |part| {
            if (part == .text) total += 1;
        }
    }
    // OAuth tokens require Claude Code identity system prompt
    if (is_oauth) total += 1;
    if (total == 0) return;

    try js.objectField("system");
    try js.beginArray();
    var idx: usize = 0;

    // OAuth: prepend Claude Code identity (required by API)
    if (is_oauth) {
        try js.beginObject();
        try js.objectField("type");
        try js.write("text");
        try js.objectField("text");
        try js.write(claude_code_identity);
        idx += 1;
        if (idx == total) {
            try js.objectField("cache_control");
            try js.beginObject();
            try js.objectField("type");
            try js.write("ephemeral");
            try js.endObject();
        }
        try js.endObject();
    }
    for (msgs) |msg| {
        if (msg.role != .system) continue;
        for (msg.parts) |part| {
            switch (part) {
                .text => |text| {
                    try js.beginObject();
                    try js.objectField("type");
                    try js.write("text");
                    try js.objectField("text");
                    try writeJsonLossy(alloc, js, text);
                    // Mark last system block for prompt caching
                    idx += 1;
                    if (idx == total) {
                        try js.objectField("cache_control");
                        try js.beginObject();
                        try js.objectField("type");
                        try js.write("ephemeral");
                        try js.endObject();
                    }
                    try js.endObject();
                },
                else => return error.UnsupportedPartType,
            }
        }
    }
    try js.endArray();
}

fn writeMessages(alloc: std.mem.Allocator, js: *std.json.Stringify, msgs: []const providers.Msg) !void {
    try js.beginArray();

    var prev_role: ?[]const u8 = null;
    var content_open = false;

    for (msgs) |msg| {
        if (msg.role == .system) continue; // handled by writeSystem

        const role: []const u8 = switch (msg.role) {
            .system => return error.UnsupportedRole,
            .user => "user",
            .assistant => "assistant",
            .tool => "user",
        };

        const same = prev_role != null and std.mem.eql(u8, prev_role.?, role);
        if (!same) {
            if (content_open) {
                try js.endArray();
                try js.endObject();
            }
            try js.beginObject();
            try js.objectField("role");
            try js.write(role);
            try js.objectField("content");
            try js.beginArray();
            content_open = true;
        }

        for (msg.parts) |part| {
            try js.beginObject();
            switch (part) {
                .text => |text| {
                    try js.objectField("type");
                    try js.write("text");
                    try js.objectField("text");
                    try writeJsonLossy(alloc, js, text);
                },
                .tool_call => |tc| {
                    try js.objectField("type");
                    try js.write("tool_use");
                    try js.objectField("id");
                    try js.write(tc.id);
                    try js.objectField("name");
                    try writeJsonLossy(alloc, js, tc.name);
                    try js.objectField("input");
                    if (tc.args.len > 0) {
                        try js.beginWriteRaw();
                        try js.writer.writeAll(tc.args);
                        js.endWriteRaw();
                    } else {
                        try js.beginObject();
                        try js.endObject();
                    }
                },
                .tool_result => |tr| {
                    try js.objectField("type");
                    try js.write("tool_result");
                    try js.objectField("tool_use_id");
                    try js.write(tr.id);
                    try js.objectField("content");
                    try writeJsonLossy(alloc, js, tr.output);
                    if (tr.is_err) {
                        try js.objectField("is_error");
                        try js.write(true);
                    }
                },
            }
            try js.endObject();
        }

        prev_role = role;
    }

    if (content_open) {
        try js.endArray();
        try js.endObject();
    }

    try js.endArray();
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const utf8_case = @import("../../test/utf8_case.zig");

fn testStream() Stream {
    return hc.testStream(Cfg);
}

fn testParse(stream: *Stream, data: []const u8) !?providers.Event {
    return hc.testParse(Cfg, stream, data);
}

fn resetParserState(stream: *Stream) void {
    hc.resetParserState(Cfg, stream);
}

fn expectSnap(comptime src: std.builtin.SourceLocation, got: []u8, comptime want: []const u8) !void {
    try hc.expectSnap(src, got, want);
}

const randSafeToken = hc.randSafeToken;

test "mapStopReason known values" {
    try testing.expectEqual(providers.StopReason.done, mapStopReason("end_turn"));
    try testing.expectEqual(providers.StopReason.max_out, mapStopReason("max_tokens"));
    try testing.expectEqual(providers.StopReason.tool, mapStopReason("tool_use"));
    try testing.expectEqual(providers.StopReason.canceled, mapStopReason("canceled"));
    try testing.expectEqual(providers.StopReason.err, mapStopReason("err"));
}

test "mapStopReason unknown falls back to done" {
    try testing.expectEqual(providers.StopReason.done, mapStopReason("unknown_xyz"));
}

test "sanitizeUtf8 property: output is valid utf8" {
    const pbt = @import("../prop_test.zig");
    try pbt.expectSanValid(sanitizeUtf8, 64, .{ .iterations = 200 });
}

test "sanitizeUtf8 property: valid utf8 is preserved" {
    const pbt = @import("../prop_test.zig");
    try pbt.expectSanPreserves(sanitizeUtf8, 24, .{ .iterations = 200 });
}

test "provider api message redacts secret-bearing body" {
    const audit = @import("../audit.zig");
    const safe = try sanitizeUtf8(testing.allocator,
        \\{"error":{"message":"authorization: bearer sk-live"}}
    );
    const msg = hc.extractJsonErrMsg(safe) orelse return error.TestUnexpectedResult;
    const redacted = try audit.redactTextAlloc(testing.allocator, msg, .@"pub");
    defer testing.allocator.free(redacted);
    const err = try std.fmt.allocPrint(testing.allocator, "401 {s}", .{redacted});
    defer testing.allocator.free(err);

    try testing.expect(std.mem.indexOf(u8, err, "sk-live") == null);
    try testing.expect(std.mem.indexOf(u8, err, "[secret:") != null);
}

test "parseSseData text delta" {
    var stream = testStream();
    defer stream.arena.deinit();

    const ev = try testParse(&stream,
        \\{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("hello", ev.?.text);
}

test "parseSseData thinking delta" {
    var stream = testStream();
    defer stream.arena.deinit();

    const ev = try testParse(&stream,
        \\{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"hmm"}}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("hmm", ev.?.thinking);
}

test "parseSseData message_start extracts usage" {
    var stream = testStream();
    defer stream.arena.deinit();

    const ev = try testParse(&stream,
        \\{"type":"message_start","message":{"usage":{"input_tokens":100,"cache_read_input_tokens":50,"cache_creation_input_tokens":25}}}
    );
    try testing.expect(ev == null);
    try testing.expectEqual(@as(u64, 100), stream.in_tok);
    try testing.expectEqual(@as(u64, 50), stream.cache_read);
    try testing.expectEqual(@as(u64, 25), stream.ext.cache_write);
}

test "parseSseData tool_use block accumulates" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    // Start tool block
    _ = try testParse(&stream,
        \\{"type":"content_block_start","content_block":{"type":"tool_use","id":"t1","name":"bash"}}
    );

    // Accumulate args
    _ = try testParse(&stream,
        \\{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"{\"cmd\":"}}
    );
    _ = try testParse(&stream,
        \\{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":"\"ls\"}"}}
    );
    const state_snap = try std.fmt.allocPrint(testing.allocator, "in_tool={any}\nid={s}\nname={s}\nargs={s}\n", .{
        stream.in_tool,
        stream.ext.tool_id.items,
        stream.tool_name.items,
        stream.tool_args.items,
    });
    defer testing.allocator.free(state_snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "in_tool=true
        \\id=t1
        \\name=bash
        \\args={"cmd":"ls"}
        \\"
    ).expectEqual(state_snap);

    // Stop — should emit tool_call event
    const ev = try testParse(&stream,
        \\{"type":"content_block_stop"}
    );
    const tc = switch (ev orelse return error.TestUnexpectedResult) {
        .tool_call => |tool_call| tool_call,
        else => return error.TestUnexpectedResult,
    };
    const ev_snap = try std.fmt.allocPrint(testing.allocator, "id={s}\nname={s}\nargs={s}\nin_tool={any}\n", .{
        tc.id,
        tc.name,
        tc.args,
        stream.in_tool,
    });
    defer testing.allocator.free(ev_snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "id=t1
        \\name=bash
        \\args={"cmd":"ls"}
        \\in_tool=false
        \\"
    ).expectEqual(ev_snap);
}

test "parseSseData message_delta stop reason and usage" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();

    stream.in_tok = 100;

    const ev = try testParse(&stream,
        \\{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}
    );
    const usage = switch (ev orelse return error.TestUnexpectedResult) {
        .usage => |got| got,
        else => return error.TestUnexpectedResult,
    };
    const pending = switch (stream.pending orelse return error.TestUnexpectedResult) {
        .stop => |stop| stop,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(testing.allocator, "usage={d}|{d}|{d}\npending={s}\ndone={any}\n", .{
        usage.in_tok,
        usage.out_tok,
        usage.tot_tok,
        @tagName(pending.reason),
        stream.done,
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "usage=100|42|142
        \\pending=done
        \\done=true
        \\"
    ).expectEqual(snap);
}

test "parseSseData property randomized tool_use lifecycle preserves args and tool stop" {
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0xa17a_c0de);
    const rnd = prng.random();

    var iter: usize = 0;
    while (iter < 128) : (iter += 1) {
        resetParserState(&stream);

        var id_buf: [24]u8 = undefined;
        const call_id = try std.fmt.bufPrint(&id_buf, "tool-{d}", .{iter});

        var head_buf: [16]u8 = undefined;
        const args_head = randSafeToken(rnd, &head_buf);
        var tail_buf: [16]u8 = undefined;
        const args_tail = randSafeToken(rnd, &tail_buf);

        var full_buf: [64]u8 = undefined;
        const args_full = try std.fmt.bufPrint(&full_buf, "{s}{s}", .{ args_head, args_tail });

        var ev_start_buf: [256]u8 = undefined;
        const ev_start = try std.fmt.bufPrint(
            &ev_start_buf,
            "{{\"type\":\"content_block_start\",\"content_block\":{{\"type\":\"tool_use\",\"id\":\"{s}\",\"name\":\"bash\"}}}}",
            .{call_id},
        );
        try testing.expect((try testParse(&stream, ev_start)) == null);

        var ev_head_buf: [256]u8 = undefined;
        const ev_head = try std.fmt.bufPrint(
            &ev_head_buf,
            "{{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{s}\"}}}}",
            .{args_head},
        );
        try testing.expect((try testParse(&stream, ev_head)) == null);

        var ev_tail_buf: [256]u8 = undefined;
        const ev_tail = try std.fmt.bufPrint(
            &ev_tail_buf,
            "{{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{s}\"}}}}",
            .{args_tail},
        );
        try testing.expect((try testParse(&stream, ev_tail)) == null);

        const tool_ev = (try testParse(&stream, "{\"type\":\"content_block_stop\"}")) orelse return error.TestUnexpectedResult;
        switch (tool_ev) {
            .tool_call => |tc| {
                try testing.expectEqualStrings(call_id, tc.id);
                try testing.expectEqualStrings("bash", tc.name);
                try testing.expectEqualStrings(args_full, tc.args);
            },
            else => return error.TestUnexpectedResult,
        }

        const usage_ev = (try testParse(
            &stream,
            "{\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}",
        )) orelse return error.TestUnexpectedResult;
        switch (usage_ev) {
            .usage => |usage| {
                try testing.expectEqual(@as(u64, 0), usage.in_tok);
                try testing.expectEqual(@as(u64, 7), usage.out_tok);
                try testing.expectEqual(@as(u64, 7), usage.tot_tok);
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expect(stream.pending != null);
        try testing.expectEqual(providers.StopReason.tool, stream.pending.?.stop.reason);
    }
}

test "parseSseData unknown type returns null" {
    var stream = testStream();
    defer stream.arena.deinit();

    const ev = try testParse(&stream,
        \\{"type":"ping"}
    );
    try testing.expect(ev == null);
}

test "parseSseData invalid json returns null" {
    var stream = testStream();
    defer stream.arena.deinit();

    const ev = try testParse(&stream, "not json at all");
    try testing.expect(ev == null);
}

test "parseSseData fuzz random payloads do not crash parser state" {
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0xa17a_f022);
    const rnd = prng.random();

    var seed: usize = 0;
    while (seed < 4096) : (seed += 1) {
        resetParserState(&stream);

        const len = rnd.intRangeAtMost(usize, 0, 192);
        var buf: [192]u8 = undefined;
        rnd.bytes(buf[0..len]);

        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(testing.allocator);
        try out.appendSlice(testing.allocator, "{\"type\":\"");
        try out.appendSlice(testing.allocator, buf[0..@min(len, 24)]);
        try out.appendSlice(testing.allocator, "\",\"delta\":{\"type\":\"");
        if (len > 24) try out.appendSlice(testing.allocator, buf[24..@min(len, 48)]);
        try out.appendSlice(testing.allocator, "\",\"partial_json\":\"");
        if (len > 48) try out.appendSlice(testing.allocator, buf[48..len]);
        try out.appendSlice(testing.allocator, "\"}}");

        const ar = stream.arena.allocator();
        const copy = try ar.dupe(u8, out.items);
        _ = stream.parseSseData(copy) catch |err| {
            if (err == error.OutOfMemory) return err;
            return error.TestUnexpectedResult;
        };
    }
}

test "buildBody minimal request" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"
    );
}

test "buildBody includes temp top_p and stop sequences" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const stops = [_][]const u8{ "END", "STOP" };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{
            .thinking = .off,
            .temp = 0.25,
            .top_p = 0.9,
            .stop = stops[0..],
        },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"temperature":0.25,"top_p":0.8999999761581421,"stop_sequences":["END","STOP"],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"
    );
}

test "buildBody with system message and cache_control" {
    const msgs = [_]providers.Msg{
        .{ .role = .system, .parts = &.{.{ .text = "You are helpful." }} },
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"system":[{"type":"text","text":"You are helpful.","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"
    );
}

test "buildBody with tools" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "run ls" }} },
    };
    const tools = [_]providers.Tool{
        .{ .name = "bash", .desc = "Run commands", .schema = "{\"type\":\"object\",\"properties\":{\"cmd\":{\"type\":\"string\"}}}" },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .tools = &tools,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"run ls"}]}],"tools":[{"name":"bash","description":"Run commands","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}}]}"
    );
}

test "buildBody thinking adaptive" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "think" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-opus-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .adaptive },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-opus-4-20250514","max_tokens":16384,"stream":true,"thinking":{"type":"adaptive"},"messages":[{"role":"user","content":[{"type":"text","text":"think"}]}]}"
    );
}

test "buildBody thinking budget" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "think" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .budget, .thinking_budget = 8192 },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"thinking":{"type":"enabled","budget_tokens":8192},"messages":[{"role":"user","content":[{"type":"text","text":"think"}]}]}"
    );
}

test "buildBody thinking budget exceeds max_tokens" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "think" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-opus-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .budget, .thinking_budget = 32768 },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-opus-4-20250514","max_tokens":49152,"stream":true,"thinking":{"type":"enabled","budget_tokens":32768},"messages":[{"role":"user","content":[{"type":"text","text":"think"}]}]}"
    );
}

test "buildBody message merging same roles" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "one" }} },
        .{ .role = .user, .parts = &.{.{ .text = "two" }} },
        .{ .role = .assistant, .parts = &.{.{ .text = "reply" }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"one"},{"type":"text","text":"two"}]},{"role":"assistant","content":[{"type":"text","text":"reply"}]}]}"
    );
}

test "buildBody tool_call and tool_result" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "run ls" }} },
        .{ .role = .assistant, .parts = &.{.{ .tool_call = .{
            .id = "tc1",
            .name = "bash",
            .args = "{\"cmd\":\"ls\"}",
        } }} },
        .{ .role = .tool, .parts = &.{.{ .tool_result = .{
            .id = "tc1",
            .output = "file.txt",
        } }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"run ls"}]},{"role":"assistant","content":[{"type":"tool_use","id":"tc1","name":"bash","input":{"cmd":"ls"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tc1","content":"file.txt"}]}]}"
    );
}

test "buildBody tool_result error flag" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "run bad" }} },
        .{ .role = .assistant, .parts = &.{.{ .tool_call = .{
            .id = "tc2",
            .name = "bash",
            .args = "{}",
        } }} },
        .{ .role = .tool, .parts = &.{.{ .tool_result = .{
            .id = "tc2",
            .output = "command failed",
            .is_err = true,
        } }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"run bad"}]},{"role":"assistant","content":[{"type":"tool_use","id":"tc2","name":"bash","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tc2","content":"command failed","is_error":true}]}]}"
    );
}

test "buildBody replaces invalid utf8 tool output lossy" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "run" }} },
        .{ .role = .assistant, .parts = &.{.{ .tool_call = .{
            .id = "tc2",
            .name = "bash",
            .args = "{}",
        } }} },
        .{ .role = .tool, .parts = &.{.{ .tool_result = .{
            .id = "tc2",
            .output = utf8_case.bad_tool_out[0..],
        } }} },
    };
    const body = try testBuildBody(testing.allocator, .{
        .model = "claude-sonnet-4-20250514",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"claude-sonnet-4-20250514","max_tokens":16384,"stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"run"}]},{"role":"assistant","content":[{"type":"tool_use","id":"tc2","name":"bash","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"tc2","content":"o?k?"}]}]}"
    );
}

test "supportsThinking" {
    try testing.expect(supportsThinking("claude-opus-4-20250514"));
    try testing.expect(supportsThinking("claude-sonnet-4-20250514"));
    try testing.expect(!supportsThinking("claude-haiku-3-20240307"));
    try testing.expect(!supportsThinking("claude-3-5-sonnet-20241022"));
}

test "SseStream error mode emits err then stop" {
    var stream = testStream();
    defer stream.arena.deinit();

    stream.err_mode = true;
    stream.err_text = "401 unauthorized";

    const ev1 = try stream.next();
    try testing.expect(ev1 != null);
    try testing.expectEqualStrings("401 unauthorized", ev1.?.err);

    const ev2 = try stream.next();
    try testing.expect(ev2 != null);
    try testing.expectEqual(providers.StopReason.err, ev2.?.stop.reason);

    const ev3 = try stream.next();
    try testing.expect(ev3 == null);
}

test "SseStream pending delivery via next" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();

    // Simulate message_delta setting pending stop
    stream.done = true;
    stream.pending = .{ .stop = .{ .reason = .tool } };

    const ev = try stream.next();
    const snap = try std.fmt.allocPrint(testing.allocator, "reason={s}\n", .{
        @tagName(ev.?.stop.reason),
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "reason=tool
        \\"
    ).expectEqual(snap);

    // After pending consumed, done=true returns null
    try testing.expect((try stream.next()) == null);
}

test "SseStream done returns null" {
    var stream = testStream();
    defer stream.arena.deinit();
    stream.done = true;
    try testing.expect((try stream.next()) == null);
}
