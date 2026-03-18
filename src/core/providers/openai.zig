//! OpenAI Responses API client.
const std = @import("std");
const providers = @import("api.zig");
const auth_mod = @import("auth.zig");
const hc = @import("http_client.zig");

const default_max_output_tokens: u32 = 16384;

pub const Cfg = struct {
    pub const provider_tag = auth_mod.Provider.openai;
    pub const api_host = "api.openai.com";
    pub const api_path = "/v1/responses";

    pub const ExtFields = struct {
        saw_tool_call: bool,
        tool_call_id: std.ArrayListUnmanaged(u8),
    };

    pub fn ext_init() ExtFields {
        return .{ .saw_tool_call = false, .tool_call_id = .{} };
    }

    pub fn ext_deinit(self: *Stream, alloc: std.mem.Allocator) void {
        self.ext.tool_call_id.deinit(alloc);
    }

    pub fn ext_reset(self: *Stream) void {
        self.ext.saw_tool_call = false;
        self.ext.tool_call_id.clearRetainingCapacity();
    }

    pub fn buildAuthHeaders(auth: *auth_mod.Result, ar: std.mem.Allocator) anyerror!std.ArrayListUnmanaged(std.http.Header) {
        var hdrs = std.ArrayListUnmanaged(std.http.Header){};
        try hdrs.append(ar, .{ .name = "content-type", .value = "application/json" });
        switch (auth.auth) {
            .oauth => |oauth| {
                const bearer = try std.fmt.allocPrint(ar, "Bearer {s}", .{oauth.access});
                try hdrs.append(ar, .{ .name = "authorization", .value = bearer });
            },
            .api_key => |key| {
                const bearer = try std.fmt.allocPrint(ar, "Bearer {s}", .{key});
                try hdrs.append(ar, .{ .name = "authorization", .value = bearer });
            },
        }
        return hdrs;
    }

    pub fn buildBody(alloc: std.mem.Allocator, req: providers.Request) anyerror![]u8 {
        return buildBodyImpl(alloc, req);
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

    const ev_type = strGet(root, "type") orelse return null;
    const EventType = enum {
        output_item_added,
        output_item_done,
        tool_args_delta,
        tool_args_done,
        output_text_delta,
        refusal_delta,
        reasoning_delta,
        completed,
        failed,
        error_ev,
    };
    const event_map = std.StaticStringMap(EventType).initComptime(.{
        .{ "response.output_item.added", .output_item_added },
        .{ "response.output_item.done", .output_item_done },
        .{ "response.function_call_arguments.delta", .tool_args_delta },
        .{ "response.function_call_arguments.done", .tool_args_done },
        .{ "response.output_text.delta", .output_text_delta },
        .{ "response.refusal.delta", .refusal_delta },
        .{ "response.reasoning_summary_text.delta", .reasoning_delta },
        .{ "response.completed", .completed },
        .{ "response.failed", .failed },
        .{ "error", .error_ev },
    });

    const resolved = event_map.get(ev_type) orelse return null;
    return switch (resolved) {
        .output_item_added => onOutputItemAdded(self, root),
        .output_item_done => onOutputItemDone(self, root),
        .tool_args_delta => onToolArgsDelta(self, root),
        .tool_args_done => onToolArgsDone(self, root),
        .output_text_delta => onTextDelta(root),
        .refusal_delta => onTextDelta(root),
        .reasoning_delta => onReasoningDelta(root),
        .completed => onCompleted(self, root),
        .failed => onFailed(self),
        .error_ev => onError(self, root),
    };
}

fn onOutputItemAdded(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const item = objGet(root, "item") orelse return null;
    const item_type = strGet(item, "type") orelse return null;
    if (!std.mem.eql(u8, item_type, "function_call")) return null;

    self.ext.tool_call_id.clearRetainingCapacity();
    self.tool_name.clearRetainingCapacity();
    self.tool_args.clearRetainingCapacity();

    if (strGet(item, "call_id")) |call_id| try self.ext.tool_call_id.appendSlice(self.alloc, call_id);
    if (strGet(item, "name")) |name| try self.tool_name.appendSlice(self.alloc, name);
    if (strGet(item, "arguments")) |args| try self.tool_args.appendSlice(self.alloc, args);
    self.in_tool = true;
    return null;
}

fn onToolArgsDelta(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    if (!self.in_tool) return null;
    const delta = strGet(root, "delta") orelse return null;
    try self.tool_args.appendSlice(self.alloc, delta);
    return null;
}

fn onToolArgsDone(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    if (!self.in_tool) return null;
    const args = strGet(root, "arguments") orelse return null;
    self.tool_args.clearRetainingCapacity();
    try self.tool_args.appendSlice(self.alloc, args);
    return null;
}

fn onOutputItemDone(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const item = objGet(root, "item") orelse return null;
    const item_type = strGet(item, "type") orelse return null;
    if (!std.mem.eql(u8, item_type, "function_call")) return null;

    if (strGet(item, "call_id")) |call_id| {
        self.ext.tool_call_id.clearRetainingCapacity();
        try self.ext.tool_call_id.appendSlice(self.alloc, call_id);
    }
    if (strGet(item, "name")) |name| {
        self.tool_name.clearRetainingCapacity();
        try self.tool_name.appendSlice(self.alloc, name);
    }
    if (strGet(item, "arguments")) |args| {
        self.tool_args.clearRetainingCapacity();
        try self.tool_args.appendSlice(self.alloc, args);
    }

    const id = self.ext.tool_call_id.items;
    if (id.len == 0) return null;

    const name = self.tool_name.items;
    const args = if (self.tool_args.items.len > 0) self.tool_args.items else "{}";

    self.in_tool = false;
    self.ext.saw_tool_call = true;

    const ar = self.arena.allocator();
    return .{ .tool_call = .{
        .id = try ar.dupe(u8, id),
        .name = try ar.dupe(u8, name),
        .args = try ar.dupe(u8, args),
    } };
}

fn onTextDelta(root: std.json.ObjectMap) !?providers.Event {
    const delta = strGet(root, "delta") orelse return null;
    return .{ .text = delta };
}

fn onReasoningDelta(root: std.json.ObjectMap) !?providers.Event {
    const delta = strGet(root, "delta") orelse return null;
    return .{ .thinking = delta };
}

fn onCompleted(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const response = objGet(root, "response") orelse return null;
    const usage = objGet(response, "usage");

    const in_tok = if (usage) |u| jsonU64(u.get("input_tokens")) else 0;
    const out_tok = if (usage) |u| jsonU64(u.get("output_tokens")) else 0;
    const total_tok = if (usage) |u| jsonU64(u.get("total_tokens")) else 0;
    const cache_read = if (usage) |u| blk: {
        const details = objGet(u, "input_tokens_details") orelse break :blk 0;
        break :blk jsonU64(details.get("cached_tokens"));
    } else 0;

    self.in_tok = in_tok;
    self.out_tok = out_tok;
    self.cache_read = cache_read;

    var stop_reason = mapStopStatus(strGet(response, "status"));
    if (self.ext.saw_tool_call and stop_reason == .done) stop_reason = .tool;

    self.pending = .{ .stop = .{ .reason = stop_reason } };
    self.done = true;

    const usage_ev: providers.Event = .{ .usage = .{
        .in_tok = in_tok,
        .out_tok = out_tok,
        .tot_tok = if (total_tok > 0) total_tok else in_tok + out_tok + cache_read,
        .cache_read = cache_read,
        .cache_write = 0,
    } };
    return usage_ev;
}

fn onFailed(self: *Stream) !?providers.Event {
    self.done = true;
    self.pending = .{ .stop = .{ .reason = .err } };
    return .{ .err = "response failed" };
}

fn onError(self: *Stream, root: std.json.ObjectMap) !?providers.Event {
    const err_obj = objGet(root, "error");
    const msg = if (strGet(root, "message")) |m|
        m
    else if (err_obj) |eo|
        strGet(eo, "message") orelse "unknown error"
    else
        "unknown error";
    self.done = true;
    self.pending = .{ .stop = .{ .reason = .err } };
    return .{ .err = msg };
}

fn mapStopStatus(status: ?[]const u8) providers.StopReason {
    const st = status orelse return .done;
    const map = std.StaticStringMap(providers.StopReason).initComptime(.{
        .{ "completed", .done },
        .{ "incomplete", .max_out },
        .{ "cancelled", .canceled },
        .{ "failed", .err },
        .{ "in_progress", .done },
        .{ "queued", .done },
    });
    return map.get(st) orelse .done;
}

// ── Body building ──────────────────────────────────────────────────────

fn callIdFromToolId(id: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, id, '|')) |idx| return id[0..idx];
    return id;
}

fn reasoningEffort(opts: providers.Opts) ?[]const u8 {
    return switch (opts.thinking) {
        .off => null,
        .adaptive => "medium",
        .budget => blk: {
            const b = opts.thinking_budget;
            if (b <= 1024) break :blk "minimal";
            if (b <= 4096) break :blk "low";
            if (b <= 16384) break :blk "medium";
            break :blk "high";
        },
    };
}

fn buildBodyImpl(alloc: std.mem.Allocator, req: providers.Request) ![]u8 {
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

    try js.objectField("stream");
    try js.write(true);

    try js.objectField("store");
    try js.write(false);

    try js.objectField("max_output_tokens");
    try js.write(req.opts.max_out orelse default_max_output_tokens);

    if (req.opts.temp) |temp| {
        try js.objectField("temperature");
        try js.write(temp);
    }
    if (req.opts.top_p) |top_p| {
        try js.objectField("top_p");
        try js.write(top_p);
    }

    if (reasoningEffort(req.opts)) |effort| {
        try js.objectField("reasoning");
        try js.beginObject();
        try js.objectField("effort");
        try js.write(effort);
        try js.objectField("summary");
        try js.write("auto");
        try js.endObject();
    }

    try js.objectField("input");
    try writeInput(ar, &js, req.msgs);

    if (req.tools.len > 0) {
        try js.objectField("tools");
        try writeTools(ar, &js, req.tools);
    }

    try js.endObject();

    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn writeInput(alloc: std.mem.Allocator, js: *std.json.Stringify, msgs: []const providers.Msg) !void {
    try js.beginArray();
    for (msgs) |msg| {
        switch (msg.role) {
            .system => try writeTextInput(alloc, js, "developer", msg.parts),
            .user => try writeTextInput(alloc, js, "user", msg.parts),
            .assistant => try writeAssistantInput(alloc, js, msg.parts),
            .tool => try writeToolInput(alloc, js, msg.parts),
        }
    }
    try js.endArray();
}

fn writeTextInput(alloc: std.mem.Allocator, js: *std.json.Stringify, role: []const u8, parts: []const providers.Part) !void {
    var text_count: usize = 0;
    for (parts) |part| {
        if (part == .text) text_count += 1;
    }
    if (text_count == 0) return;

    try js.beginObject();
    try js.objectField("role");
    try js.write(role);
    try js.objectField("content");
    try js.beginArray();
    for (parts) |part| switch (part) {
        .text => |text| {
            try js.beginObject();
            try js.objectField("type");
            try js.write("input_text");
            try js.objectField("text");
            try writeJsonLossy(alloc, js, text);
            try js.endObject();
        },
        else => return error.UnsupportedPartType,
    };
    try js.endArray();
    try js.endObject();
}

fn writeAssistantInput(alloc: std.mem.Allocator, js: *std.json.Stringify, parts: []const providers.Part) !void {
    for (parts) |part| switch (part) {
        .text => |text| {
            try js.beginObject();
            try js.objectField("type");
            try js.write("message");
            try js.objectField("role");
            try js.write("assistant");
            try js.objectField("status");
            try js.write("completed");
            try js.objectField("content");
            try js.beginArray();
            try js.beginObject();
            try js.objectField("type");
            try js.write("output_text");
            try js.objectField("text");
            try writeJsonLossy(alloc, js, text);
            try js.objectField("annotations");
            try js.beginArray();
            try js.endArray();
            try js.endObject();
            try js.endArray();
            try js.endObject();
        },
        .tool_call => |tc| {
            try js.beginObject();
            try js.objectField("type");
            try js.write("function_call");
            try js.objectField("call_id");
            try js.write(callIdFromToolId(tc.id));
            try js.objectField("name");
            try writeJsonLossy(alloc, js, tc.name);
            try js.objectField("arguments");
            try writeJsonLossy(alloc, js, tc.args);
            try js.endObject();
        },
        else => return error.UnsupportedPartType,
    };
}

fn writeToolInput(alloc: std.mem.Allocator, js: *std.json.Stringify, parts: []const providers.Part) !void {
    for (parts) |part| switch (part) {
        .tool_result => |tr| {
            try js.beginObject();
            try js.objectField("type");
            try js.write("function_call_output");
            try js.objectField("call_id");
            try js.write(callIdFromToolId(tr.id));
            try js.objectField("output");
            try writeJsonLossy(alloc, js, tr.output);
            try js.endObject();
        },
        else => return error.UnsupportedPartType,
    };
}

fn writeTools(alloc: std.mem.Allocator, js: *std.json.Stringify, tools: []const providers.Tool) !void {
    try js.beginArray();
    for (tools) |tool| {
        try js.beginObject();
        try js.objectField("type");
        try js.write("function");
        try js.objectField("name");
        try writeJsonLossy(alloc, js, tool.name);
        try js.objectField("description");
        try writeJsonLossy(alloc, js, tool.desc);
        try js.objectField("parameters");
        if (tool.schema.len > 0) {
            try js.beginWriteRaw();
            try js.writer.writeAll(tool.schema);
            js.endWriteRaw();
        } else {
            try js.beginObject();
            try js.objectField("type");
            try js.write("object");
            try js.objectField("properties");
            try js.beginObject();
            try js.endObject();
            try js.endObject();
        }
        try js.objectField("strict");
        try js.write(false);
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

test "mapStopStatus maps known statuses" {
    try testing.expectEqual(providers.StopReason.done, mapStopStatus("completed"));
    try testing.expectEqual(providers.StopReason.max_out, mapStopStatus("incomplete"));
    try testing.expectEqual(providers.StopReason.canceled, mapStopStatus("cancelled"));
    try testing.expectEqual(providers.StopReason.err, mapStopStatus("failed"));
}

test "mapStopStatus unknown defaults to done" {
    try testing.expectEqual(providers.StopReason.done, mapStopStatus("mystery"));
    try testing.expectEqual(providers.StopReason.done, mapStopStatus(null));
}

test "sanitizeUtf8 property: output is valid utf8" {
    const pbt = @import("../prop_test.zig");
    try pbt.expectSanValid(sanitizeUtf8, 64, .{ .iterations = 200 });
}

test "sanitizeUtf8 property: valid utf8 is preserved" {
    const pbt = @import("../prop_test.zig");
    try pbt.expectSanPreserves(sanitizeUtf8, 24, .{ .iterations = 200 });
}

test "provider error text redacts secret-bearing body" {
    const audit = @import("../audit.zig");
    const safe = try sanitizeUtf8(testing.allocator, "authorization: bearer sk-live");
    const redacted = try audit.redactTextAlloc(testing.allocator, safe, .@"pub");
    defer testing.allocator.free(redacted);
    const err = try std.fmt.allocPrint(testing.allocator, "401 {s}", .{redacted});
    defer testing.allocator.free(err);

    try testing.expect(std.mem.indexOf(u8, err, "sk-live") == null);
    try testing.expect(std.mem.indexOf(u8, err, "[secret:") != null);
}

test "parseSseData output_text.delta emits text event" {
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"response.output_text.delta","delta":"hello"}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("hello", ev.?.text);
}

test "parseSseData refusal delta emits text event" {
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"response.refusal.delta","delta":"nope"}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("nope", ev.?.text);
}

test "parseSseData reasoning delta emits thinking event" {
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"response.reasoning_summary_text.delta","delta":"hmm"}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("hmm", ev.?.thinking);
}

test "parseSseData function call lifecycle emits tool_call" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_call_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    _ = try testParse(&stream,
        \\{"type":"response.output_item.added","item":{"type":"function_call","call_id":"c1","name":"bash","arguments":"{\"cmd\":\"ls"}}
    );
    _ = try testParse(&stream,
        \\{"type":"response.function_call_arguments.delta","delta":"\" -la\""}}
    );
    _ = try testParse(&stream,
        \\{"type":"response.function_call_arguments.done","arguments":"{\"cmd\":\"ls -la\"}"}
    );
    const ev = try testParse(&stream,
        \\{"type":"response.output_item.done","item":{"type":"function_call","call_id":"c1","name":"bash","arguments":"{\"cmd\":\"ls -la\"}"}}
    );
    const tc = switch (ev orelse return error.TestUnexpectedResult) {
        .tool_call => |tool_call| tool_call,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(testing.allocator, "id={s}\nname={s}\nargs={s}\n", .{
        tc.id,
        tc.name,
        tc.args,
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "id=c1
        \\name=bash
        \\args={"cmd":"ls -la"}
        \\"
    ).expectEqual(snap);
}

test "parseSseData completed emits usage and pending stop done" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":4,"total_tokens":14,"input_tokens_details":{"cached_tokens":3}}}}
    );
    const usage = switch (ev orelse return error.TestUnexpectedResult) {
        .usage => |got| got,
        else => return error.TestUnexpectedResult,
    };
    const pending = switch (stream.pending orelse return error.TestUnexpectedResult) {
        .stop => |stop| stop,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(testing.allocator, "usage={d}|{d}|{d}|{d}\npending={s}\ndone={any}\n", .{
        usage.in_tok,
        usage.out_tok,
        usage.tot_tok,
        usage.cache_read,
        @tagName(pending.reason),
        stream.done,
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "usage=10|4|14|3
        \\pending=done
        \\done=true
        \\"
    ).expectEqual(snap);
}

test "parseSseData completed maps tool stop when tool call seen" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    stream.ext.saw_tool_call = true;
    const ev = try testParse(&stream,
        \\{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":1}}}
    );
    const usage = switch (ev orelse return error.TestUnexpectedResult) {
        .usage => |got| got,
        else => return error.TestUnexpectedResult,
    };
    const pending = switch (stream.pending orelse return error.TestUnexpectedResult) {
        .stop => |stop| stop,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(testing.allocator, "usage={d}|{d}|{d}|{d}\npending={s}\ndone={any}\n", .{
        usage.in_tok,
        usage.out_tok,
        usage.tot_tok,
        usage.cache_read,
        @tagName(pending.reason),
        stream.done,
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "usage=1|1|2|0
        \\pending=tool
        \\done=true
        \\"
    ).expectEqual(snap);
}

test "parseSseData error emits err and stop" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"error","message":"boom"}
    );
    const err_txt = switch (ev orelse return error.TestUnexpectedResult) {
        .err => |txt| txt,
        else => return error.TestUnexpectedResult,
    };
    const pending = switch (stream.pending orelse return error.TestUnexpectedResult) {
        .stop => |stop| stop,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(testing.allocator, "err={s}\npending={s}\ndone={any}\n", .{
        err_txt,
        @tagName(pending.reason),
        stream.done,
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "err=boom
        \\pending=err
        \\done=true
        \\"
    ).expectEqual(snap);
}

test "parseSseData unknown and invalid return null" {
    var stream = testStream();
    defer stream.arena.deinit();
    try testing.expect((try testParse(&stream, "{\"type\":\"noop\"}")) == null);
    try testing.expect((try testParse(&stream, "not json")) == null);
}

test "callIdFromToolId strips item suffix" {
    try testing.expectEqualStrings("call-1", callIdFromToolId("call-1|fc_123"));
    try testing.expectEqualStrings("call-2", callIdFromToolId("call-2"));
}

test "buildBody minimal request has model stream and input" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const body = try buildBodyImpl(testing.allocator, .{
        .model = "gpt-5",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"gpt-5","stream":true,"store":false,"max_output_tokens":16384,"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}"
    );
}

test "buildBody includes reasoning for adaptive and budget" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const adaptive = try buildBodyImpl(testing.allocator, .{
        .model = "gpt-5",
        .msgs = &msgs,
        .opts = .{ .thinking = .adaptive },
    });
    defer testing.allocator.free(adaptive);
    try expectSnap(@src(), adaptive,
        \\[]u8
        \\  "{"model":"gpt-5","stream":true,"store":false,"max_output_tokens":16384,"reasoning":{"effort":"medium","summary":"auto"},"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}"
    );

    const budget = try buildBodyImpl(testing.allocator, .{
        .model = "gpt-5",
        .msgs = &msgs,
        .opts = .{ .thinking = .budget, .thinking_budget = 500 },
    });
    defer testing.allocator.free(budget);
    try expectSnap(@src(), budget,
        \\[]u8
        \\  "{"model":"gpt-5","stream":true,"store":false,"max_output_tokens":16384,"reasoning":{"effort":"minimal","summary":"auto"},"input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}"
    );
}

test "buildBody includes system assistant tool history and tool definitions" {
    const msgs = [_]providers.Msg{
        .{ .role = .system, .parts = &.{.{ .text = "sys" }} },
        .{ .role = .user, .parts = &.{.{ .text = "run" }} },
        .{ .role = .assistant, .parts = &.{.{ .tool_call = .{
            .id = "call-1|fc_1",
            .name = "bash",
            .args = "{\"cmd\":\"ls\"}",
        } }} },
        .{ .role = .tool, .parts = &.{.{ .tool_result = .{
            .id = "call-1|fc_1",
            .output = "ok",
        } }} },
    };
    const tools = [_]providers.Tool{
        .{ .name = "bash", .desc = "Run shell", .schema = "{\"type\":\"object\"}" },
    };
    const body = try buildBodyImpl(testing.allocator, .{
        .model = "gpt-5",
        .msgs = &msgs,
        .tools = &tools,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"gpt-5","stream":true,"store":false,"max_output_tokens":16384,"input":[{"role":"developer","content":[{"type":"input_text","text":"sys"}]},{"role":"user","content":[{"type":"input_text","text":"run"}]},{"type":"function_call","call_id":"call-1","name":"bash","arguments":"{\"cmd\":\"ls\"}"},{"type":"function_call_output","call_id":"call-1","output":"ok"}],"tools":[{"type":"function","name":"bash","description":"Run shell","parameters":{"type":"object"},"strict":false}]}"
    );
}

test "buildBody replaces invalid utf8 tool output lossy" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "run" }} },
        .{ .role = .assistant, .parts = &.{.{ .tool_call = .{
            .id = "call-1|fc_1",
            .name = "bash",
            .args = "{\"cmd\":\"ls\"}",
        } }} },
        .{ .role = .tool, .parts = &.{.{ .tool_result = .{
            .id = "call-1|fc_1",
            .output = utf8_case.bad_tool_out[0..],
        } }} },
    };
    const body = try buildBodyImpl(testing.allocator, .{
        .model = "gpt-5",
        .msgs = &msgs,
        .opts = .{ .thinking = .off },
    });
    defer testing.allocator.free(body);
    try expectSnap(@src(), body,
        \\[]u8
        \\  "{"model":"gpt-5","stream":true,"store":false,"max_output_tokens":16384,"input":[{"role":"user","content":[{"type":"input_text","text":"run"}]},{"type":"function_call","call_id":"call-1","name":"bash","arguments":"{\"cmd\":\"ls\"}"},{"type":"function_call_output","call_id":"call-1","output":"o?k?"}]}"
    );
}

test "parseSseData property randomized tool lifecycle preserves args and tool stop" {
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_call_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0x0A11_C0DE);
    const rnd = prng.random();

    var iter: usize = 0;
    while (iter < 128) : (iter += 1) {
        resetParserState(&stream);

        var id_buf: [24]u8 = undefined;
        const call_id = try std.fmt.bufPrint(&id_buf, "call-{d}", .{iter});

        var head_buf: [16]u8 = undefined;
        const args_head = randSafeToken(rnd, &head_buf);
        var tail_buf: [16]u8 = undefined;
        const args_tail = randSafeToken(rnd, &tail_buf);

        var full_buf: [64]u8 = undefined;
        const args_full = try std.fmt.bufPrint(&full_buf, "{s}{s}", .{ args_head, args_tail });

        var ev_added_buf: [256]u8 = undefined;
        const ev_added = try std.fmt.bufPrint(
            &ev_added_buf,
            "{{\"type\":\"response.output_item.added\",\"item\":{{\"type\":\"function_call\",\"call_id\":\"{s}\",\"name\":\"bash\",\"arguments\":\"{s}\"}}}}",
            .{ call_id, args_head },
        );
        try testing.expect((try testParse(&stream, ev_added)) == null);

        var ev_delta_buf: [192]u8 = undefined;
        const ev_delta = try std.fmt.bufPrint(
            &ev_delta_buf,
            "{{\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{s}\"}}",
            .{args_tail},
        );
        try testing.expect((try testParse(&stream, ev_delta)) == null);

        var ev_done_args_buf: [256]u8 = undefined;
        const ev_done_args = try std.fmt.bufPrint(
            &ev_done_args_buf,
            "{{\"type\":\"response.function_call_arguments.done\",\"arguments\":\"{s}\"}}",
            .{args_full},
        );
        try testing.expect((try testParse(&stream, ev_done_args)) == null);

        var ev_item_done_buf: [256]u8 = undefined;
        const ev_item_done = try std.fmt.bufPrint(
            &ev_item_done_buf,
            "{{\"type\":\"response.output_item.done\",\"item\":{{\"type\":\"function_call\",\"call_id\":\"{s}\",\"name\":\"bash\"}}}}",
            .{call_id},
        );
        const tool_ev = (try testParse(&stream, ev_item_done)) orelse return error.TestUnexpectedResult;
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
            "{\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":2,\"output_tokens\":3,\"total_tokens\":5}}}",
        )) orelse return error.TestUnexpectedResult;
        switch (usage_ev) {
            .usage => |usage| {
                try testing.expectEqual(@as(u64, 2), usage.in_tok);
                try testing.expectEqual(@as(u64, 3), usage.out_tok);
                try testing.expectEqual(@as(u64, 5), usage.tot_tok);
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expect(stream.pending != null);
        try testing.expectEqual(providers.StopReason.tool, stream.pending.?.stop.reason);
    }
}

test "SseStream error mode emits err then stop" {
    var stream = testStream();
    defer stream.arena.deinit();

    stream.err_mode = true;
    stream.err_text = "429 rate limited";

    const ev1 = try stream.next();
    try testing.expect(ev1 != null);
    try testing.expectEqualStrings("429 rate limited", ev1.?.err);

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

    // Simulate completed event setting pending stop
    stream.done = true;
    stream.pending = .{ .stop = .{ .reason = .done } };

    const ev = try stream.next();
    const snap = try std.fmt.allocPrint(testing.allocator, "reason={s}\n", .{
        @tagName(ev.?.stop.reason),
    });
    defer testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "reason=done
        \\"
    ).expectEqual(snap);

    // After pending consumed, done=true returns null
    try testing.expect((try stream.next()) == null);
}

test "parseSseData failed emits err and stop" {
    var stream = testStream();
    defer stream.arena.deinit();
    const ev = try testParse(&stream,
        \\{"type":"response.failed"}
    );
    try testing.expect(ev != null);
    try testing.expectEqualStrings("response failed", ev.?.err);
    try testing.expect(stream.pending != null);
    try testing.expectEqual(providers.StopReason.err, stream.pending.?.stop.reason);
}

test "parseSseData fuzz random payloads do not crash parser state" {
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.ext.tool_call_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0x5eed_0a11);
    const rnd = prng.random();

    var seed: usize = 0;
    while (seed < 4096) : (seed += 1) {
        const len = rnd.intRangeAtMost(usize, 0, 192);
        var buf: [192]u8 = undefined;
        rnd.bytes(buf[0..len]);

        // Best effort random JSON-ish envelope to exercise fast/slow parser paths.
        var out: std.ArrayListUnmanaged(u8) = .empty;
        defer out.deinit(testing.allocator);
        try out.appendSlice(testing.allocator, "{\"type\":\"");
        try out.appendSlice(testing.allocator, buf[0..@min(len, 24)]);
        try out.appendSlice(testing.allocator, "\",\"delta\":\"");
        if (len > 24) try out.appendSlice(testing.allocator, buf[24..len]);
        try out.appendSlice(testing.allocator, "\"}");

        const ar = stream.arena.allocator();
        const copy = try ar.dupe(u8, out.items);
        _ = stream.parseSseData(copy) catch |err| {
            if (err == error.OutOfMemory) return err;
            return error.TestUnexpectedResult;
        };
    }
}
