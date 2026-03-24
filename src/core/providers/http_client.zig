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
const el_mod = @import("../event_loop.zig");
pub const EventLoop = el_mod.EventLoop;
const ElEvent = el_mod.Event;

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
/// When refresh fails AND the token is expired, propagates the error
/// (sending an expired token is pointless). When the token might still
/// be valid, logs and continues.
pub fn tryProactiveRefresh(
    alloc: std.mem.Allocator,
    auth: *auth_mod.Result,
    tag: auth_mod.Provider,
    ca_file: ?[]const u8,
    ar: std.mem.Allocator,
) !void {
    if (auth.auth != .oauth) return;
    const now = std.time.milliTimestamp();
    if (now < auth.auth.oauth.expires) return;
    refreshAuth(alloc, auth, tag, ca_file, ar) catch |err| {
        // Token is expired and refresh failed — no point sending it
        if (now >= auth.auth.oauth.expires) return err;
        std.log.warn("proactive oauth refresh failed: {}", .{err});
    };
}

// ── Retry loop ─────────────────────────────────────────────────────────

/// Interruptible sleeper backed by EventLoop.
/// Registers a cancel pipe fd and uses EventLoop.wait with timeout
/// for both backoff delays and cancel responsiveness.
pub const RealSleeper = struct {
    cancel_fd: std.posix.fd_t = -1,
    el: ?*EventLoop = null,

    /// Wait using EventLoop with timeout. The cancel fd (if set) is
    /// already registered with the event loop, so a cancel signal
    /// will interrupt the wait immediately.
    /// Falls back to poll on cancel_fd when no event loop is available.
    pub fn sleep(self: *RealSleeper, ms: u64) void {
        const timeout: i32 = if (ms > std.math.maxInt(i32))
            std.math.maxInt(i32)
        else
            @intCast(ms);

        if (self.el) |el| {
            var buf: [el_mod.max_events]ElEvent = undefined;
            _ = el.wait(timeout, &buf) catch return;
            return;
        }

        // Always poll on cancel_fd — never use Thread.sleep.
        // If cancel_fd is not set, use a self-pipe to get a
        // pollable fd that simply times out.
        var fds = [1]std.posix.pollfd{.{
            .fd = if (self.cancel_fd >= 0) self.cancel_fd else selfPipeFd(),
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        _ = std.posix.poll(&fds, timeout) catch return;
    }

    /// Return the read end of a process-wide self-pipe used as a
    /// pollable fd when no cancel_fd or event loop is available.
    /// The write end is never written to, so poll simply times out.
    fn selfPipeFd() std.posix.fd_t {
        const S = struct {
            var fd: std.posix.fd_t = -1;
            var mu: std.Thread.Mutex = .{};
        };
        // Fast path: already initialized.
        if (@atomicLoad(std.posix.fd_t, &S.fd, .acquire) >= 0) return S.fd;
        S.mu.lock();
        defer S.mu.unlock();
        // Double-check after acquiring lock.
        if (S.fd >= 0) return S.fd;
        const fds = std.posix.pipe2(.{ .CLOEXEC = true }) catch return -1;
        @atomicStore(std.posix.fd_t, &S.fd, fds[0], .release);
        // Write end intentionally leaked — never written.
        return fds[0];
    }
};

/// Execute the retry loop: connect, send, receive head, handle 401/429/5xx.
///
/// On 401 with OAuth, refreshes the token and calls `rebuildHdrs` to get
/// new provider-specific headers before retrying. On 401 without OAuth,
/// propagates immediately (no retry).
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
    cancel: ?providers.CancelPoll,
) !void {
    // Proactive refresh: check token expiry before first attempt
    try tryProactiveRefresh(alloc, auth, tag, ca_file, ar);

    var attempt: u32 = 0;
    var did_refresh = false;
    while (true) : (attempt += 1) {
        if (cancel) |c| if (c.isCanceled()) return error.Canceled;

        stream.req = try http.request(.POST, uri, .{
            .extra_headers = hdrs.items,
            .keep_alive = false,
            // SSE streams must not be compressed: we read lines incrementally
            // and gzip content-encoding destroys the SSE framing.
            .headers = .{ .accept_encoding = .omit },
        });

        stream.req.transfer_encoding = .{ .content_length = body.len };
        var bw = try stream.req.sendBodyUnflushed(&stream.send_buf);
        try bw.writer.writeAll(body);
        try bw.end();
        try stream.req.connection.?.flush();

        stream.response = try stream.req.receiveHead(&stream.redir_buf);
        const status_int: u16 = @intFromEnum(stream.response.head.status);

        // On 401 without OAuth: no refresh possible, propagate immediately
        if (status_int == 401 and auth.auth != .oauth) break;

        // On 401 with OAuth, try refreshing token once
        if (status_int == 401 and auth.auth == .oauth and !did_refresh) {
            did_refresh = true;
            if (refreshAuth(alloc, auth, tag, ca_file, ar)) {
                drainResponse(stream, ar);
                stream.req.deinit();
                hdrs.* = try rebuildHdrs(auth, ar);
                continue;
            } else |_| {
                return error.RefreshFailed;
            }
        }

        const retryable = status_int == 429 or (status_int >= 500 and status_int < 600);
        if (!retryable or attempt >= max_retries) break;

        drainResponse(stream, ar);
        stream.req.deinit();

        // Backoff: min(base * 2^attempt, max)
        const delay: u64 = @min(max_delay_ms, base_delay_ms * (@as(u64, 1) << @intCast(attempt)));
        if (cancel) |c| if (c.isCanceled()) return error.Canceled;
        sleeper.sleep(delay);
        if (cancel) |c| if (c.isCanceled()) return error.Canceled;
    }
}

pub fn drainResponse(stream: anytype, ar: std.mem.Allocator) void {
    const rdr = stream.response.reader(&stream.transfer_buf);
    _ = rdr.allocRemaining(ar, .limited(16384)) catch |err| switch (err) {
        error.OutOfMemory => std.log.warn("drain response OOM", .{}),
        else => {},
    };
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
        // Try to extract a complete line from the nonblocking buffer first.
        if (extractNbLine(self)) |raw| {
            if (try processSseLine(self, raw)) |ev| return ev;
            continue;
        }

        // If event loop is active, use nonblocking fd reads into nb_buf.
        if (self.el) |el| {
            if (self.conn_fd) |fd| {
                var wait_buf: [el_mod.max_events]ElEvent = undefined;
                const evs = el.wait(-1, &wait_buf) catch {
                    self.done = true;
                    return null;
                };
                var fd_ready = false;
                for (evs) |ev| {
                    if (ev.fd == fd and ev.readable) fd_ready = true;
                }
                if (!fd_ready) {
                    self.done = true;
                    return null;
                }
                // Nonblocking read into nb_buf
                var read_buf: [8192]u8 = undefined;
                const n = std.posix.read(fd, &read_buf) catch |err| switch (err) {
                    error.WouldBlock => continue,
                    else => {
                        self.done = true;
                        return null;
                    },
                };
                if (n == 0) {
                    self.done = true;
                    return null;
                }
                self.nb_buf.appendSlice(self.alloc, read_buf[0..n]) catch return error.OutOfMemory;
                // Extract and process lines from the buffer
                while (extractNbLine(self)) |raw| {
                    if (try processSseLine(self, raw)) |ev| return ev;
                }
                continue;
            }
        }

        // Fallback: blocking read via body_rdr (no event loop)
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
        if (try processSseLine(self, raw)) |ev| return ev;
    }
}

/// Extract one complete line from the nonblocking buffer.
/// Returns the line (without trailing \n/\r\n) or null if no complete line.
fn extractNbLine(self: anytype) ?[]const u8 {
    const buf = self.nb_buf.items;
    const nl = std.mem.indexOfScalar(u8, buf, '\n') orelse return null;
    const line = std.mem.trimRight(u8, buf[0..nl], "\r");
    // Shift remaining bytes to front
    const rest = buf[nl + 1 ..];
    std.mem.copyForwards(u8, self.nb_buf.items[0..rest.len], rest);
    self.nb_buf.items.len = rest.len;
    return line;
}

/// Process a single SSE line. Returns an event if one was parsed, null to continue.
fn processSseLine(self: anytype, raw: []const u8) anyerror!?providers.Event {
    const data = if (std.mem.startsWith(u8, raw, "data: "))
        raw["data: ".len..]
    else if (std.mem.startsWith(u8, raw, "data:"))
        std.mem.trimLeft(u8, raw["data:".len..], " ")
    else
        return null;

    if (std.mem.eql(u8, data, "[DONE]")) return null;

    const ar = self.arena.allocator();
    const data_copy = try ar.dupe(u8, data);

    const ev = self.parseSseData(data_copy) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    return ev;
}

/// Extract the connection fd from an SseStream's HTTP request.
/// Returns null if no connection is available.
pub fn connFd(stream: anytype) ?std.posix.fd_t {
    const conn = stream.req.connection orelse return null;
    return conn.stream_reader.getStream().handle;
}

// ── Shared JSON error extraction ───────────────────────────────────────

/// Extract "message" from JSON error bodies. Works for both Anthropic
/// `{"type":"error","error":{"message":"..."}}` and OpenAI
/// `{"error":{"message":"..."}}` formats.
///
/// Handles escaped quotes in the message value by scanning for the
/// closing unescaped `"`.
pub fn extractJsonErrMsg(body: []const u8) ?[]const u8 {
    const needle = "\"message\":\"";
    const start = (std.mem.indexOf(u8, body, needle) orelse return null) + needle.len;
    // Scan for unescaped closing quote
    var i: usize = start;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\') {
            i += 1; // skip escaped char
            continue;
        }
        if (body[i] == '"') {
            const msg = body[start..i];
            return if (msg.len > 0) msg else null;
        }
    }
    return null;
}

// ── SseClient generic ─────────────────────────────────────────────────

/// Comptime generic that provides a shared Client + SseStream for any
/// provider. Config must supply:
///   - `provider_tag: auth_mod.Provider` — .anthropic or .openai
///   - `api_host: []const u8`, `api_path: []const u8`
///   - `ExtFields: type` — provider-specific SseStream fields
///   - `ext_init: fn() ExtFields` — initializer for ext fields
///   - `ext_deinit: fn(*Self, std.mem.Allocator) void` — cleanup
///   - `ext_reset: fn(*Self) void` — reset for test reuse
///   - `buildAuthHeaders: fn(*auth_mod.Result, std.mem.Allocator) anyerror!HdrList`
///   - `buildBody: fn(std.mem.Allocator, providers.Request) anyerror![]u8`
///   - `parseSseData: fn(*Self, []const u8) anyerror!?providers.Event`
pub fn SseClient(comptime Cfg: type) type {
    return struct {
        const Self = @This();

        pub const Stream = SseStream(Cfg);

        alloc: std.mem.Allocator,
        auth: auth_mod.Result,
        http: std.http.Client,
        ca_file: ?[]u8,
        el: ?*EventLoop = null,
        cancel: ?providers.CancelPoll = null,

        pub fn init(alloc: std.mem.Allocator, hooks: auth_mod.Hooks) !Self {
            var auth_res = try auth_mod.loadForProviderWithHooks(alloc, Cfg.provider_tag, hooks);
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

        pub fn deinit(self: *Self) void {
            self.http.deinit();
            self.auth.deinit();
            if (self.ca_file) |path| self.alloc.free(path);
        }

        pub fn isSub(self: *const Self) bool {
            return self.auth.auth == .oauth;
        }

        pub fn asProvider(self: *Self) providers.Provider {
            return providers.Provider.from(Self, self, Self.start);
        }

        fn start(self: *Self, req: providers.Request) anyerror!providers.Stream {
            const stream = try self.alloc.create(Stream);
            stream.* = Stream.initFields(self.alloc);
            stream.el = self.el;
            errdefer {
                stream.arena.deinit();
                self.alloc.destroy(stream);
            }

            const ar = stream.arena.allocator();

            const body = try Cfg.buildBody(ar, req, self.auth.auth == .oauth);
            var hdrs = try Cfg.buildAuthHeaders(&self.auth, ar);

            const uri = std.Uri{
                .scheme = "https",
                .host = .{ .raw = Cfg.api_host },
                .path = .{ .raw = Cfg.api_path },
            };

            var slp = RealSleeper{ .el = self.el };
            try retryLoop(stream, &self.http, uri, body, &hdrs, &self.auth, self.alloc, Cfg.provider_tag, self.ca_file, ar, &slp, Cfg.buildAuthHeaders, self.cancel);

            if (stream.response.head.status != .ok) {
                try formatErrBody(stream, ar, extractJsonErrMsg);
            } else {
                stream.body_rdr = stream.response.reader(&stream.transfer_buf);
                stream.conn_fd = connFd(stream);
                if (stream.el) |el| {
                    if (stream.conn_fd) |fd| try el.register(fd, .read);
                }
            }

            return providers.Stream.fromAbortable(Stream, stream, Stream.next, Stream.deinit, Stream.abort);
        }
    };
}

/// Comptime generic SseStream with shared fields + provider-specific ext.
pub fn SseStream(comptime Cfg: type) type {
    return struct {
        const Self = @This();

        // Shared fields
        alloc: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        req: std.http.Client.Request,
        response: std.http.Client.Response,
        send_buf: [1024]u8,
        transfer_buf: [16384]u8,
        redir_buf: [0]u8,
        body_rdr: ?*std.Io.Reader,

        // Event loop integration
        el: ?*EventLoop,
        conn_fd: ?std.posix.fd_t,

        // Nonblocking SSE line buffer — accumulates partial reads between
        // event-loop-driven readable events. Used only when el != null.
        nb_buf: std.ArrayListUnmanaged(u8) = .{},

        // Common SSE state
        in_tok: u64,
        out_tok: u64,
        cache_read: u64,
        tool_name: std.ArrayListUnmanaged(u8),
        tool_args: std.ArrayListUnmanaged(u8),
        in_tool: bool,
        done: bool,
        err_mode: bool,
        err_text: ?[]const u8,
        pending: ?providers.Event,

        // Provider-specific fields
        ext: Cfg.ExtFields,

        pub fn initFields(alloc: std.mem.Allocator) Self {
            return .{
                .alloc = alloc,
                .arena = std.heap.ArenaAllocator.init(alloc),
                .req = undefined,
                .response = undefined,
                .send_buf = undefined,
                .transfer_buf = undefined,
                .redir_buf = .{},
                .body_rdr = null,
                .el = null,
                .conn_fd = null,
                .in_tok = 0,
                .out_tok = 0,
                .cache_read = 0,
                .tool_name = .{},
                .tool_args = .{},
                .in_tool = false,
                .done = false,
                .err_mode = false,
                .err_text = null,
                .pending = null,
                .ext = Cfg.ext_init(),
            };
        }

        pub fn next(self: *Self) anyerror!?providers.Event {
            return sseNext(self);
        }

        pub fn parseSseData(self: *Self, data: []const u8) anyerror!?providers.Event {
            return Cfg.parseSseData(self, data);
        }

        pub fn deinit(self: *Self) void {
            if (self.el) |el| {
                if (self.conn_fd) |fd| el.unregister(fd) catch {}; // cleanup: propagation impossible
            }
            const alloc = self.alloc;
            self.nb_buf.deinit(alloc);
            Cfg.ext_deinit(self, alloc);
            self.tool_name.deinit(alloc);
            self.tool_args.deinit(alloc);
            self.req.deinit();
            self.arena.deinit();
            alloc.destroy(self);
        }

        pub fn abort(self: *Self) void {
            if (self.req.connection) |conn| {
                std.posix.shutdown(conn.stream_reader.getStream().handle, .recv) catch {}; // cleanup: propagation impossible
            }
        }
    };
}

// ── Test helpers ───────────────────────────────────────────────────────

pub fn testStream(comptime Cfg: type) SseStream(Cfg) {
    return SseStream(Cfg).initFields(testing.allocator);
}

pub fn testParse(comptime Cfg: type, stream: *SseStream(Cfg), data: []const u8) !?providers.Event {
    const ar = stream.arena.allocator();
    const copy = try ar.dupe(u8, data);
    return stream.parseSseData(copy);
}

pub fn resetParserState(comptime Cfg: type, stream: *SseStream(Cfg)) void {
    _ = stream.arena.reset(.retain_capacity);
    stream.in_tok = 0;
    stream.out_tok = 0;
    stream.cache_read = 0;
    stream.in_tool = false;
    stream.done = false;
    stream.err_mode = false;
    stream.err_text = null;
    stream.pending = null;
    stream.tool_name.clearRetainingCapacity();
    stream.tool_args.clearRetainingCapacity();
    Cfg.ext_reset(stream);
}

pub fn expectSnap(comptime src: std.builtin.SourceLocation, got: []u8, comptime want: []const u8) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    try oh.snap(src, want).expectEqual(got);
}

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

test "extractJsonErrMsg extracts message from error JSON" {
    const msg = extractJsonErrMsg(
        \\{"type":"error","error":{"type":"invalid_request","message":"bad input"}}
    );
    try testing.expect(msg != null);
    try testing.expectEqualStrings("bad input", msg.?);
}

test "extractJsonErrMsg handles escaped quotes" {
    const msg = extractJsonErrMsg(
        \\{"error":{"message":"got a \"quoted\" thing"}}
    );
    try testing.expect(msg != null);
    try testing.expectEqualStrings("got a \\\"quoted\\\" thing", msg.?);
}

test "extractJsonErrMsg returns null on non-error JSON" {
    try testing.expect(extractJsonErrMsg("{}") == null);
    try testing.expect(extractJsonErrMsg("plain text") == null);
}

test "extractJsonErrMsg openai format" {
    const msg = extractJsonErrMsg(
        \\{"error":{"message":"rate limit exceeded","type":"rate_limit_error"}}
    );
    try testing.expect(msg != null);
    try testing.expectEqualStrings("rate limit exceeded", msg.?);
}
