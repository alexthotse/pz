const std = @import("std");
const providers = @import("contract.zig");
const auth_mod = @import("auth.zig");
const audit = @import("../audit.zig");
const utf8 = @import("../utf8.zig");

const api_version = "2023-06-01";
const api_host = "api.anthropic.com";
const api_path = "/v1/messages";
const default_max_tokens: u32 = 16384;

pub const Client = struct {
    alloc: std.mem.Allocator,
    auth: auth_mod.Result,
    http: std.http.Client,
    ca_file: ?[]u8,

    pub fn init(alloc: std.mem.Allocator, hooks: auth_mod.Hooks) !Client {
        var auth_res = try auth_mod.loadForProviderWithHooks(alloc, .anthropic, hooks);
        errdefer auth_res.deinit();
        const ca_dup = if (hooks.ca_file) |path| try alloc.dupe(u8, path) else null;
        errdefer if (ca_dup) |path| alloc.free(path);
        return .{
            .alloc = alloc,
            .auth = auth_res,
            .http = .{ .allocator = alloc },
            .ca_file = ca_dup,
        };
    }

    pub fn deinit(self: *Client) void {
        self.http.deinit();
        self.auth.deinit();
        if (self.ca_file) |path| self.alloc.free(path);
    }

    pub fn isSub(self: *const Client) bool {
        return self.auth.auth == .oauth;
    }

    pub fn asProvider(self: *Client) providers.Provider {
        return providers.Provider.from(Client, self, Client.start);
    }

    const max_retries = 3;
    const base_delay_ms = 2000;
    const max_delay_ms = 60000;

    /// Proactive pre-request refresh: if token looks expired, try refreshing.
    /// Failure is non-fatal — the 401 retry handler will surface real errors.
    fn tryProactiveRefresh(self: *Client, ar: std.mem.Allocator) void {
        if (self.auth.auth != .oauth) return;
        const now = std.time.milliTimestamp();
        if (now < self.auth.auth.oauth.expires) return;
        if (self.refreshAuth(ar)) |_| {} else |err| {
            std.debug.print("warning: proactive token refresh failed: {s}\n", .{@errorName(err)});
        }
    }

    /// Refresh OAuth token. Tries refresh endpoint first, then reloads from
    /// disk (another process may have refreshed).
    fn refreshAuth(self: *Client, ar: std.mem.Allocator) !void {
        const old = self.auth.auth.oauth;

        // Try refresh endpoint
        if (auth_mod.refreshOAuthForProviderWithHooks(ar, .anthropic, old, .{ .ca_file = self.ca_file })) |new_oauth| {
            const auth_ar = self.auth.arena.allocator();
            const new_access = try auth_ar.dupe(u8, new_oauth.access);
            const new_refresh = try auth_ar.dupe(u8, new_oauth.refresh);
            ar.free(new_oauth.access);
            ar.free(new_oauth.refresh);
            self.auth.auth = .{ .oauth = .{
                .access = new_access,
                .refresh = new_refresh,
                .expires = new_oauth.expires,
            } };
            return;
        } else |_| {}

        // Refresh failed — reload from disk (another instance may have refreshed)
        var reloaded = auth_mod.loadForProvider(self.alloc, .anthropic) catch return error.RefreshFailed;
        switch (reloaded.auth) {
            .oauth => |oauth| {
                const now = std.time.milliTimestamp();
                if (now < oauth.expires) {
                    // Disk has a valid token — swap
                    self.auth.deinit();
                    self.auth = reloaded;
                    return;
                }
            },
            else => {},
        }
        reloaded.deinit();
        return error.RefreshFailed;
    }

    fn buildAuthHeaders(self: *Client, ar: std.mem.Allocator) !std.ArrayListUnmanaged(std.http.Header) {
        var hdrs = std.ArrayListUnmanaged(std.http.Header){};
        try hdrs.append(ar, .{ .name = "content-type", .value = "application/json" });
        try hdrs.append(ar, .{ .name = "anthropic-version", .value = api_version });

        switch (self.auth.auth) {
            .oauth => |oauth| {
                const bearer = try std.fmt.allocPrint(ar, "Bearer {s}", .{oauth.access});
                try hdrs.append(ar, .{ .name = "anthropic-beta", .value = "oauth-2025-04-20" });
                try hdrs.append(ar, .{ .name = "anthropic-dangerous-direct-browser-access", .value = "true" });
                try hdrs.append(ar, .{ .name = "authorization", .value = bearer });
            },
            .api_key => |key| {
                try hdrs.append(ar, .{ .name = "x-api-key", .value = key });
            },
        }
        return hdrs;
    }

    fn start(self: *Client, req: providers.Req) anyerror!providers.Stream {
        const stream = try self.alloc.create(SseStream);
        stream.* = SseStream.initFields(self.alloc);
        errdefer {
            stream.arena.deinit();
            self.alloc.destroy(stream);
        }

        const ar = stream.arena.allocator();

        // Proactively refresh expired OAuth tokens (best-effort: 401 handler retries)
        self.tryProactiveRefresh(ar);

        // Build request body
        const body = try buildBody(ar, req);

        // Auth headers
        var hdrs = try self.buildAuthHeaders(ar);

        const uri = std.Uri{
            .scheme = "https",
            .host = .{ .raw = api_host },
            .path = .{ .raw = api_path },
        };

        var attempt: u32 = 0;
        var did_refresh = false;
        while (true) : (attempt += 1) {
            stream.req = try self.http.request(.POST, uri, .{
                .extra_headers = hdrs.items,
                .keep_alive = false,
            });

            // Send body
            stream.req.transfer_encoding = .{ .content_length = body.len };
            var bw = try stream.req.sendBodyUnflushed(&stream.send_buf);
            try bw.writer.writeAll(body);
            try bw.end();
            try stream.req.connection.?.flush();

            // Receive response head
            stream.response = try stream.req.receiveHead(&stream.redir_buf);

            const status_int: u16 = @intFromEnum(stream.response.head.status);

            // On 401 with OAuth, try refreshing token once
            if (status_int == 401 and self.auth.auth == .oauth and !did_refresh) {
                did_refresh = true;
                const refreshed = if (self.refreshAuth(ar)) true else |_| false;
                if (refreshed) {
                    // Drain old response before retry (read failure is non-fatal: deinit closes connection)
                    const rdr = stream.response.reader(&stream.transfer_buf);
                    _ = rdr.allocRemaining(ar, .limited(16384)) catch |err| {
                        std.debug.print("warning: drain failed: {s}\n", .{@errorName(err)});
                    };
                    stream.req.deinit();
                    hdrs = try self.buildAuthHeaders(ar);
                    continue;
                }
                // Refresh failed — fall through to show the 401 error
            }

            const retryable = status_int == 429 or (status_int >= 500 and status_int < 600);

            if (!retryable or attempt >= max_retries) break;

            // Drain response body before retry (read failure is non-fatal: deinit closes connection)
            const rdr = stream.response.reader(&stream.transfer_buf);
            _ = rdr.allocRemaining(ar, .limited(16384)) catch |err| {
                std.debug.print("warning: drain failed: {s}\n", .{@errorName(err)});
            };
            stream.req.deinit();

            // Backoff: min(base * 2^attempt, max)
            const delay: u64 = @min(max_delay_ms, base_delay_ms * (@as(u64, 1) << @intCast(attempt)));
            std.Thread.sleep(delay * std.time.ns_per_ms);
        }

        if (stream.response.head.status != .ok) {
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
            // Sanitize: response body may not be valid UTF-8
            const safe_body = sanitizeUtf8(ar, err_body) catch "unknown error";
            // Extract human-readable message from API JSON error body
            const msg = extractApiErrMsg(safe_body) orelse safe_body;
            const redacted = audit.redactTextAlloc(ar, msg, .@"pub") catch "unknown error";
            stream.err_text = try std.fmt.allocPrint(ar, "{d} {s}", .{ status_int, redacted });
        } else {
            stream.body_rdr = stream.response.reader(&stream.transfer_buf);
        }

        return providers.Stream.fromAbortable(SseStream, stream, SseStream.next, SseStream.deinit, SseStream.abort);
    }
};

const SseStream = struct {
    alloc: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    req: std.http.Client.Request,
    response: std.http.Client.Response,
    send_buf: [1024]u8,
    transfer_buf: [16384]u8,
    redir_buf: [0]u8,
    body_rdr: ?*std.Io.Reader,

    // SSE state
    in_tok: u64,
    out_tok: u64,
    cache_read: u64,
    cache_write: u64,
    tool_id: std.ArrayListUnmanaged(u8),
    tool_name: std.ArrayListUnmanaged(u8),
    tool_args: std.ArrayListUnmanaged(u8),
    in_tool: bool,
    done: bool,
    err_mode: bool,
    err_text: ?[]const u8,
    pending: ?providers.Ev,

    fn initFields(alloc: std.mem.Allocator) SseStream {
        return .{
            .alloc = alloc,
            .arena = std.heap.ArenaAllocator.init(alloc),
            .req = undefined,
            .response = undefined,
            .send_buf = undefined,
            .transfer_buf = undefined,
            .redir_buf = .{},
            .body_rdr = null,
            .in_tok = 0,
            .out_tok = 0,
            .cache_read = 0,
            .cache_write = 0,
            .tool_id = .{},
            .tool_name = .{},
            .tool_args = .{},
            .in_tool = false,
            .done = false,
            .err_mode = false,
            .err_text = null,
            .pending = null,
        };
    }

    fn next(self: *SseStream) anyerror!?providers.Ev {
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
            if (!std.mem.startsWith(u8, raw, "data: ")) continue;
            const data = raw["data: ".len..];
            if (std.mem.eql(u8, data, "[DONE]")) continue;

            // Copy data before parsing (takeDelimiter buffer is reused)
            const ar = self.arena.allocator();
            const data_copy = try ar.dupe(u8, data);

            const ev = self.parseSseData(data_copy) catch continue;
            if (ev) |e| return e;
        }
    }

    fn parseSseData(self: *SseStream, data: []const u8) !?providers.Ev {
        const ar = self.arena.allocator();

        var parsed = std.json.parseFromSlice(std.json.Value, ar, data, .{
            .allocate = .alloc_always,
        }) catch return null;
        _ = &parsed;

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
            .message_start => self.onMessageStart(root),
            .content_block_start => self.onBlockStart(root),
            .content_block_delta => self.onBlockDelta(root),
            .content_block_stop => self.onBlockStop(),
            .message_delta => self.onMessageDelta(root),
        };
    }

    fn onMessageStart(self: *SseStream, root: std.json.ObjectMap) !?providers.Ev {
        const msg = objGet(root, "message") orelse return null;
        const usage = objGet(msg, "usage") orelse return null;
        self.in_tok = jsonU64(usage.get("input_tokens"));
        self.cache_read = jsonU64(usage.get("cache_read_input_tokens"));
        self.cache_write = jsonU64(usage.get("cache_creation_input_tokens"));
        return null;
    }

    fn onBlockStart(self: *SseStream, root: std.json.ObjectMap) !?providers.Ev {
        const cb = objGet(root, "content_block") orelse return null;
        const cb_type = strGet(cb, "type") orelse return null;

        if (!std.mem.eql(u8, cb_type, "tool_use")) return null;

        self.tool_id.clearRetainingCapacity();
        self.tool_name.clearRetainingCapacity();
        self.tool_args.clearRetainingCapacity();

        if (strGet(cb, "id")) |id| try self.tool_id.appendSlice(self.alloc, id);
        if (strGet(cb, "name")) |name| try self.tool_name.appendSlice(self.alloc, name);
        self.in_tool = true;
        return null;
    }

    fn onBlockDelta(self: *SseStream, root: std.json.ObjectMap) !?providers.Ev {
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

    fn onBlockStop(self: *SseStream) !?providers.Ev {
        if (!self.in_tool) return null;
        self.in_tool = false;
        const ar = self.arena.allocator();
        return .{ .tool_call = .{
            .id = try ar.dupe(u8, self.tool_id.items),
            .name = try ar.dupe(u8, self.tool_name.items),
            .args = try ar.dupe(u8, self.tool_args.items),
        } };
    }

    fn onMessageDelta(self: *SseStream, root: std.json.ObjectMap) !?providers.Ev {
        if (objGet(root, "usage")) |usage| {
            self.out_tok = jsonU64(usage.get("output_tokens"));
        }
        const delta = objGet(root, "delta") orelse return null;
        const reason_str = strGet(delta, "stop_reason") orelse return null;

        const usage_ev: providers.Ev = .{ .usage = .{
            .in_tok = self.in_tok,
            .out_tok = self.out_tok,
            .tot_tok = self.in_tok + self.out_tok,
            .cache_read = self.cache_read,
            .cache_write = self.cache_write,
        } };
        self.pending = .{ .stop = .{ .reason = mapStopReason(reason_str) } };
        self.done = true;
        return usage_ev;
    }

    fn deinit(self: *SseStream) void {
        const alloc = self.alloc;
        self.tool_id.deinit(alloc);
        self.tool_name.deinit(alloc);
        self.tool_args.deinit(alloc);
        self.req.deinit();
        self.arena.deinit();
        alloc.destroy(self);
    }

    fn abort(self: *SseStream) void {
        if (self.req.connection) |conn| {
            std.posix.shutdown(conn.stream_reader.getStream().handle, .recv) catch {};
        }
    }
};

fn objGet(map: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .object => |obj| obj,
        else => null,
    };
}

fn strGet(map: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn supportsThinking(model: []const u8) bool {
    // Models that support extended thinking
    return std.mem.indexOf(u8, model, "opus") != null or
        std.mem.indexOf(u8, model, "sonnet-4") != null;
}

fn sanitizeUtf8(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    return utf8.sanitizeMaybeAlloc(alloc, raw);
}

/// Extract "message" from Anthropic JSON error: {"type":"error","error":{"message":"..."}}
/// Returns a slice into the input body (the JSON string value is unescaped in-place by the parser,
/// but we just scan for the key and extract the raw value to avoid lifetime issues).
fn extractApiErrMsg(body: []const u8) ?[]const u8 {
    // Find "message":" and extract until closing quote (handles the common case without allocation)
    const needle = "\"message\":\"";
    const start = (std.mem.indexOf(u8, body, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfScalarPos(u8, body, start, '"') orelse return null;
    const msg = body[start..end];
    return if (msg.len > 0) msg else null;
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

fn jsonU64(val: ?std.json.Value) u64 {
    const v = val orelse return 0;
    return switch (v) {
        .integer => |i| if (i >= 0) @intCast(i) else 0,
        .float => |f| if (f >= 0) @intFromFloat(f) else 0,
        else => 0,
    };
}

fn buildBody(alloc: std.mem.Allocator, req: providers.Req) ![]u8 {
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

    // Extract system messages as top-level "system" field
    try writeSystem(ar, &js, req.msgs);

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

fn writeJsonLossy(alloc: std.mem.Allocator, js: *std.json.Stringify, raw: []const u8) !void {
    try js.write(try utf8.sanitizeMaybeAlloc(alloc, raw));
}

fn writeSystem(alloc: std.mem.Allocator, js: *std.json.Stringify, msgs: []const providers.Msg) !void {
    // Count total system text parts for cache_control on last one
    var total: usize = 0;
    for (msgs) |msg| {
        if (msg.role != .system) continue;
        for (msg.parts) |part| {
            if (part == .text) total += 1;
        }
    }
    if (total == 0) return;

    try js.objectField("system");
    try js.beginArray();
    var idx: usize = 0;
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
                else => {},
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
            .system => unreachable,
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
                    try writeJsonLossy(alloc, js, tr.out);
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

fn testStream() SseStream {
    return SseStream.initFields(testing.allocator);
}

fn testParse(stream: *SseStream, data: []const u8) !?providers.Ev {
    const ar = stream.arena.allocator();
    const copy = try ar.dupe(u8, data);
    return stream.parseSseData(copy);
}

fn randSafeToken(rnd: std.Random, buf: []u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-";
    const n = rnd.intRangeAtMost(usize, 1, buf.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const idx = rnd.intRangeLessThan(usize, 0, alphabet.len);
        buf[i] = alphabet[idx];
    }
    return buf[0..n];
}

fn resetParserState(stream: *SseStream) void {
    _ = stream.arena.reset(.retain_capacity);
    stream.in_tok = 0;
    stream.out_tok = 0;
    stream.cache_read = 0;
    stream.cache_write = 0;
    stream.in_tool = false;
    stream.done = false;
    stream.err_mode = false;
    stream.err_text = null;
    stream.pending = null;
    stream.tool_id.clearRetainingCapacity();
    stream.tool_name.clearRetainingCapacity();
    stream.tool_args.clearRetainingCapacity();
}

fn expectSnap(comptime src: std.builtin.SourceLocation, got: []u8, comptime want: []const u8) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    try oh.snap(src, want).expectEqual(got);
}

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

test "jsonU64 integer" {
    try testing.expectEqual(@as(u64, 42), jsonU64(.{ .integer = 42 }));
}

test "jsonU64 negative clamps to zero" {
    try testing.expectEqual(@as(u64, 0), jsonU64(.{ .integer = -5 }));
}

test "jsonU64 float" {
    try testing.expectEqual(@as(u64, 3), jsonU64(.{ .float = 3.7 }));
}

test "jsonU64 null" {
    try testing.expectEqual(@as(u64, 0), jsonU64(null));
}

test "jsonU64 non-numeric" {
    try testing.expectEqual(@as(u64, 0), jsonU64(.{ .bool = true }));
}

test "sanitizeUtf8 valid passes through" {
    const input = "hello world";
    const result = try sanitizeUtf8(testing.allocator, input);
    try testing.expectEqualStrings("hello world", result);
}

test "sanitizeUtf8 invalid bytes replaced" {
    const input = "ab\xfe\xffcd";
    const result = try sanitizeUtf8(testing.allocator, input);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("ab??cd", result);
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
    const safe = try sanitizeUtf8(testing.allocator,
        \\{"error":{"message":"authorization: bearer sk-live"}}
    );
    const msg = extractApiErrMsg(safe) orelse return error.TestUnexpectedResult;
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
    try testing.expectEqual(@as(u64, 25), stream.cache_write);
}

test "parseSseData tool_use block accumulates" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var stream = testStream();
    defer stream.arena.deinit();
    defer stream.tool_id.deinit(testing.allocator);
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
        stream.tool_id.items,
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
    defer stream.tool_id.deinit(testing.allocator);
    defer stream.tool_name.deinit(testing.allocator);
    defer stream.tool_args.deinit(testing.allocator);

    var prng = std.Random.DefaultPrng.init(0xa17a_c0de);
    const rnd = prng.random();

    var iter: usize = 0;
    while (iter < 128) : (iter += 1) {
        resetParserState(&stream);

        var id_buf: [24]u8 = undefined;
        const call_id = std.fmt.bufPrint(&id_buf, "tool-{d}", .{iter}) catch unreachable;

        var head_buf: [16]u8 = undefined;
        const args_head = randSafeToken(rnd, &head_buf);
        var tail_buf: [16]u8 = undefined;
        const args_tail = randSafeToken(rnd, &tail_buf);

        var full_buf: [64]u8 = undefined;
        const args_full = std.fmt.bufPrint(&full_buf, "{s}{s}", .{ args_head, args_tail }) catch unreachable;

        var ev_start_buf: [256]u8 = undefined;
        const ev_start = std.fmt.bufPrint(
            &ev_start_buf,
            "{{\"type\":\"content_block_start\",\"content_block\":{{\"type\":\"tool_use\",\"id\":\"{s}\",\"name\":\"bash\"}}}}",
            .{call_id},
        ) catch unreachable;
        try testing.expect((try testParse(&stream, ev_start)) == null);

        var ev_head_buf: [256]u8 = undefined;
        const ev_head = std.fmt.bufPrint(
            &ev_head_buf,
            "{{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{s}\"}}}}",
            .{args_head},
        ) catch unreachable;
        try testing.expect((try testParse(&stream, ev_head)) == null);

        var ev_tail_buf: [256]u8 = undefined;
        const ev_tail = std.fmt.bufPrint(
            &ev_tail_buf,
            "{{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"input_json_delta\",\"partial_json\":\"{s}\"}}}}",
            .{args_tail},
        ) catch unreachable;
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
    defer stream.tool_id.deinit(testing.allocator);
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
    const body = try buildBody(testing.allocator, .{
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
            .out = "file.txt",
        } }} },
    };
    const body = try buildBody(testing.allocator, .{
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
            .out = "command failed",
            .is_err = true,
        } }} },
    };
    const body = try buildBody(testing.allocator, .{
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
            .out = utf8_case.bad_tool_out[0..],
        } }} },
    };
    const body = try buildBody(testing.allocator, .{
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
