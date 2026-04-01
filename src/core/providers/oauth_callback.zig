//! Local HTTP server for OAuth redirect callback.
const std = @import("std");

pub const Opts = struct {
    bind_ip: []const u8 = "127.0.0.1",
    redirect_host: []const u8 = "127.0.0.1",
    path: []const u8 = "/callback",
    success_redirect_url: ?[]const u8 = null,
    /// Per-connection read deadline in milliseconds.
    read_deadline_ms: u32 = 5_000,
};

pub const CodeState = struct {
    code: []u8,
    state: []u8,

    pub fn deinit(self: *CodeState, alloc: std.mem.Allocator) void {
        alloc.free(self.code);
        alloc.free(self.state);
        self.* = undefined;
    }
};

pub const Listener = struct {
    alloc: std.mem.Allocator,
    server: std.net.Server,
    redirect_uri: []u8,
    path: []u8,
    success_redirect_url: ?[]u8,
    read_deadline_ms: u32,

    pub fn init(alloc: std.mem.Allocator, opts: Opts) !Listener {
        const addr = try std.net.Address.parseIp(opts.bind_ip, 0);
        var server = try addr.listen(.{ .reuse_address = true });
        errdefer server.deinit();

        const listen_port = server.listen_address.getPort();
        const redirect_uri = try std.fmt.allocPrint(alloc, "http://{s}:{d}{s}", .{
            opts.redirect_host,
            listen_port,
            opts.path,
        });
        errdefer alloc.free(redirect_uri);

        const path = try alloc.dupe(u8, opts.path);
        errdefer alloc.free(path);
        const success_redirect_url = if (opts.success_redirect_url) |url|
            try alloc.dupe(u8, url)
        else
            null;
        errdefer if (success_redirect_url) |url| alloc.free(url);

        return .{
            .alloc = alloc,
            .server = server,
            .redirect_uri = redirect_uri,
            .path = path,
            .success_redirect_url = success_redirect_url,
            .read_deadline_ms = opts.read_deadline_ms,
        };
    }

    pub fn deinit(self: *Listener) void {
        self.server.deinit();
        self.alloc.free(self.redirect_uri);
        self.alloc.free(self.path);
        if (self.success_redirect_url) |url| self.alloc.free(url);
        self.* = undefined;
    }

    pub fn port(self: *const Listener) u16 {
        return self.server.listen_address.getPort();
    }

    pub fn waitForCodeState(
        self: *Listener,
        alloc: std.mem.Allocator,
        timeout_ms: i32,
    ) !CodeState {
        var timer = std.time.Timer.start() catch return error.OAuthCallbackTimeout;
        const deadline_ns: u64 = if (timeout_ms > 0)
            @as(u64, @intCast(timeout_ms)) * std.time.ns_per_ms
        else
            0;

        while (true) {
            // Compute remaining poll timeout from overall deadline.
            const remaining_ms: i32 = if (timeout_ms <= 0)
                timeout_ms // 0 = immediate, negative = infinite
            else blk: {
                const elapsed_ns = timer.read();
                if (elapsed_ns >= deadline_ns) return error.OAuthCallbackTimeout;
                const left_ns = deadline_ns - elapsed_ns;
                const left_ms = left_ns / std.time.ns_per_ms;
                break :blk if (left_ms > std.math.maxInt(i32))
                    std.math.maxInt(i32)
                else
                    @intCast(left_ms);
            };

            var fds = [_]std.posix.pollfd{.{
                .fd = self.server.stream.handle,
                .events = std.posix.POLL.IN,
                .revents = 0,
            }};
            const ready = try std.posix.poll(&fds, remaining_ms);
            if (ready == 0) return error.OAuthCallbackTimeout;

            if (self.tryAcceptOne(alloc)) |out| {
                return out;
            } else |err| switch (err) {
                // Retryable: bad request, wrong path, missing params, non-loopback,
                // stalled client. Loop back and wait for next connection.
                error.InvalidOAuthCallbackRequest,
                error.NonLoopbackPeer,
                error.OAuthReadTimeout,
                => continue,
                else => return err,
            }
        }
    }

    /// Accept a single connection and try to extract code+state from it.
    fn tryAcceptOne(self: *Listener, alloc: std.mem.Allocator) !CodeState {
        var conn = try self.server.accept();
        defer conn.stream.close();

        // Reject non-loopback peers.
        if (!isLoopback(conn.address)) return error.NonLoopbackPeer;

        // Set per-connection read deadline to abort trickle/stalled clients.
        try setRecvTimeout(conn.stream.handle, self.read_deadline_ms);

        var req_buf: [8192]u8 = undefined;
        var req_len: usize = 0;
        while (req_len < req_buf.len) {
            const n = std.posix.read(conn.stream.handle, req_buf[req_len..]) catch |err| switch (err) {
                error.WouldBlock => return error.OAuthReadTimeout,
                else => return err,
            };
            if (n == 0) break;
            req_len += n;
            if (std.mem.indexOf(u8, req_buf[0..req_len], "\r\n\r\n") != null) break;
        }
        if (req_len == 0) {
            try writeHtml(conn.stream.handle, "400 Bad Request", callback_error_body);
            return error.InvalidOAuthCallbackRequest;
        }

        const query = parseQueryFromHttpRequest(req_buf[0..req_len], self.path) catch {
            try writeHtml(conn.stream.handle, "400 Bad Request", callback_error_body);
            return error.InvalidOAuthCallbackRequest;
        };
        var out = parseCodeStateQuery(alloc, query) catch {
            try writeHtml(conn.stream.handle, "400 Bad Request", callback_error_body);
            return error.InvalidOAuthCallbackRequest;
        };
        errdefer out.deinit(alloc);

        if (out.code.len == 0 or out.state.len == 0) {
            try writeHtml(conn.stream.handle, "400 Bad Request", callback_error_body);
            return error.InvalidOAuthCallbackRequest;
        }

        if (self.success_redirect_url) |url| {
            try writeRedirect(conn.stream.handle, url);
        } else {
            try writeHtml(conn.stream.handle, "200 OK", callback_ok_body);
        }
        return out;
    }
};

pub fn parseCodeStateQuery(alloc: std.mem.Allocator, query: []const u8) !CodeState {
    var code: ?[]u8 = null;
    errdefer if (code) |v| alloc.free(v);
    var state: ?[]u8 = null;
    errdefer if (state) |v| alloc.free(v);

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const name = pair[0..eq];
        const value = pair[eq + 1 ..];

        if (std.mem.eql(u8, name, "code") and code == null) {
            code = try decodeQueryValue(alloc, value);
            continue;
        }
        if (std.mem.eql(u8, name, "state") and state == null) {
            state = try decodeQueryValue(alloc, value);
            continue;
        }
    }

    return .{
        .code = code orelse return error.InvalidOAuthInput,
        .state = state orelse return error.InvalidOAuthInput,
    };
}

fn parseQueryFromHttpRequest(request: []const u8, expected_path: []const u8) ![]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return error.InvalidOAuthCallbackRequest;
    const line = request[0..line_end];
    if (!std.mem.startsWith(u8, line, "GET ")) return error.InvalidOAuthCallbackRequest;

    const rest = line["GET ".len..];
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.InvalidOAuthCallbackRequest;
    const target = rest[0..sp];

    const q = std.mem.indexOfScalar(u8, target, '?') orelse return error.InvalidOAuthCallbackRequest;
    if (q != expected_path.len) return error.InvalidOAuthCallbackRequest;
    if (!std.mem.eql(u8, target[0..q], expected_path)) return error.InvalidOAuthCallbackRequest;
    return target[q + 1 ..];
}

const decodeQueryValue = @import("../url.zig").decodeQueryValue;

/// True if the peer address is IPv4 127.0.0.0/8 or IPv6 ::1.
fn isLoopback(addr: std.net.Address) bool {
    return switch (addr.any.family) {
        std.posix.AF.INET => std.mem.asBytes(&addr.in.sa.addr)[0] == 127,
        std.posix.AF.INET6 => std.mem.eql(u8, &addr.in6.sa.addr, &[_]u8{0} ** 15 ++ [_]u8{1}),
        else => false,
    };
}

/// Set SO_RCVTIMEO on fd. Best-effort; failure is non-fatal since poll
/// already bounds the overall wait.
fn setRecvTimeout(fd: std.posix.fd_t, ms: u32) !void {
    const tv = std.posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast(@as(u32, ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

fn writeHtml(fd: std.posix.fd_t, status: []const u8, body: []const u8) !void {
    var header: [256]u8 = undefined;
    const hdr = try std.fmt.bufPrint(
        &header,
        "HTTP/1.1 {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ status, body.len },
    );
    _ = std.posix.write(fd, hdr) catch {}; // cleanup: propagation impossible
    _ = std.posix.write(fd, body) catch {}; // cleanup: propagation impossible
}

fn writeRedirect(fd: std.posix.fd_t, location: []const u8) !void {
    const body = "<!doctype html><html><body><h1>Redirecting…</h1></body></html>";
    var header: [512]u8 = undefined;
    const hdr = try std.fmt.bufPrint(
        &header,
        "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ location, body.len },
    );
    _ = std.posix.write(fd, hdr) catch {}; // cleanup: propagation impossible
    _ = std.posix.write(fd, body) catch {}; // cleanup: propagation impossible
}

const callback_ok_body =
    "<!doctype html><html><body><h1>Login complete</h1><p>You can return to pz.</p></body></html>";
const callback_error_body =
    "<!doctype html><html><body><h1>Login failed</h1><p>Missing or invalid OAuth callback parameters.</p></body></html>";

fn sendTestCallback(port: u16, req: []const u8) void {
    std.Thread.sleep(20 * std.time.ns_per_ms);
    const addr = std.net.Address.parseIp("127.0.0.1", port) catch return;
    var stream = std.net.tcpConnectToAddress(addr) catch return;
    defer stream.close();
    _ = std.posix.write(stream.handle, req) catch return;
    var sink: [256]u8 = undefined;
    _ = std.posix.read(stream.handle, &sink) catch {}; // cleanup: propagation impossible
}

fn sendTestCallbackReadAlloc(alloc: std.mem.Allocator, port: u16, req: []const u8) ![]u8 {
    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var stream = try std.net.tcpConnectToAddress(addr);
    defer stream.close();
    _ = try std.posix.write(stream.handle, req);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var buf: [1024]u8 = undefined;
    while (true) {
        const n = try std.posix.read(stream.handle, &buf);
        if (n == 0) break;
        try out.appendSlice(alloc, buf[0..n]);
    }
    return try out.toOwnedSlice(alloc);
}

test "parseCodeStateQuery decodes URL-encoded params" {
    var got = try parseCodeStateQuery(std.testing.allocator, "code=abc123&state=state%20456");
    defer got.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc123", got.code);
    try std.testing.expectEqualStrings("state 456", got.state);
}

test "parseCodeStateQuery rejects missing state" {
    try std.testing.expectError(error.InvalidOAuthInput, parseCodeStateQuery(std.testing.allocator, "code=abc123"));
}

test "listener captures callback code and state" {
    var listener = try Listener.init(std.testing.allocator, .{});
    defer listener.deinit();

    const req = "GET /callback?code=abc&state=def HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    const t = try std.Thread.spawn(.{}, sendTestCallback, .{ listener.port(), req });
    defer t.join();

    var got = try listener.waitForCodeState(std.testing.allocator, 3000);
    defer got.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc", got.code);
    try std.testing.expectEqualStrings("def", got.state);
}

test "listener redirects browser to success url after valid callback" {
    var listener = try Listener.init(std.testing.allocator, .{
        .success_redirect_url = "https://console.anthropic.com/oauth/code/success?app=claude-code",
    });
    defer listener.deinit();

    const req = "GET /callback?code=abc&state=def HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    const t = try std.Thread.spawn(.{}, struct {
        fn run(p: u16) void {
            std.Thread.sleep(20 * std.time.ns_per_ms);
            const resp = sendTestCallbackReadAlloc(std.testing.allocator, p, req) catch return;
            defer std.testing.allocator.free(resp);
            std.testing.expect(std.mem.indexOf(u8, resp, "HTTP/1.1 302 Found") != null) catch return;
            std.testing.expect(std.mem.indexOf(u8, resp, "Location: https://console.anthropic.com/oauth/code/success?app=claude-code") != null) catch return;
        }
    }.run, .{listener.port()});
    defer t.join();

    var got = try listener.waitForCodeState(std.testing.allocator, 3000);
    defer got.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("abc", got.code);
    try std.testing.expectEqualStrings("def", got.state);
}

test "listener times out when callback is not received" {
    var listener = try Listener.init(std.testing.allocator, .{});
    defer listener.deinit();

    try std.testing.expectError(error.OAuthCallbackTimeout, listener.waitForCodeState(std.testing.allocator, 25));
}

test "listener retries on wrong path then times out" {
    var listener = try Listener.init(std.testing.allocator, .{});
    defer listener.deinit();

    const req = "GET /callbackx?code=abc&state=def HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    const t = try std.Thread.spawn(.{}, sendTestCallback, .{ listener.port(), req });
    defer t.join();

    // Invalid path is retried; with no valid follow-up, overall timeout fires.
    try std.testing.expectError(error.OAuthCallbackTimeout, listener.waitForCodeState(std.testing.allocator, 200));
}

test "listener retries on missing state then times out" {
    var listener = try Listener.init(std.testing.allocator, .{});
    defer listener.deinit();

    const req = "GET /callback?code=abc HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    const t = try std.Thread.spawn(.{}, sendTestCallback, .{ listener.port(), req });
    defer t.join();

    // Missing state is retried; with no valid follow-up, overall timeout fires.
    try std.testing.expectError(error.OAuthCallbackTimeout, listener.waitForCodeState(std.testing.allocator, 200));
}

test "listener retries invalid then accepts valid callback" {
    var listener = try Listener.init(std.testing.allocator, .{});
    defer listener.deinit();

    const bad_req = "GET /wrong?code=abc&state=def HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    const good_req = "GET /callback?code=real&state=csrf HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";

    // Send bad then good with a small delay between.
    const t = try std.Thread.spawn(.{}, struct {
        fn run(p: u16) void {
            // First: invalid path
            sendTestCallback(p, bad_req);
            // Second: valid callback
            sendTestCallback(p, good_req);
        }
    }.run, .{listener.port()});
    defer t.join();

    var got = try listener.waitForCodeState(std.testing.allocator, 5000);
    defer got.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("real", got.code);
    try std.testing.expectEqualStrings("csrf", got.state);
}

test "isLoopback accepts 127.x.x.x" {
    const lo = try std.net.Address.parseIp("127.0.0.1", 0);
    try std.testing.expect(isLoopback(lo));
    const lo2 = try std.net.Address.parseIp("127.255.0.1", 0);
    try std.testing.expect(isLoopback(lo2));
}

test "isLoopback rejects non-loopback IPv4" {
    const ext = try std.net.Address.parseIp("192.168.1.1", 0);
    try std.testing.expect(!isLoopback(ext));
}

test "isLoopback accepts ::1" {
    const lo6 = try std.net.Address.parseIp("::1", 0);
    try std.testing.expect(isLoopback(lo6));
}

test "isLoopback rejects non-loopback IPv6" {
    const ext6 = try std.net.Address.parseIp("::2", 0);
    try std.testing.expect(!isLoopback(ext6));
}

test "listener stalled client retried then times out" {
    var listener = try Listener.init(std.testing.allocator, .{ .read_deadline_ms = 50 });
    defer listener.deinit();

    // Connect but send nothing; read deadline fires, retry loop exhausts overall timeout.
    const t = try std.Thread.spawn(.{}, struct {
        fn run(p: u16) void {
            std.Thread.sleep(20 * std.time.ns_per_ms);
            const addr = std.net.Address.parseIp("127.0.0.1", p) catch return;
            var stream = std.net.tcpConnectToAddress(addr) catch return;
            // Hold connection open without sending.
            std.Thread.sleep(1 * std.time.ns_per_s);
            stream.close();
        }
    }.run, .{listener.port()});
    defer t.join();

    const err = listener.waitForCodeState(std.testing.allocator, 300);
    try std.testing.expectError(error.OAuthCallbackTimeout, err);
}
