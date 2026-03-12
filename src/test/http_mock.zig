const std = @import("std");

pub const Response = struct {
    status: []const u8 = "200 OK",
    headers: []const []const u8 = &.{},
    body: []const u8 = "",
};

pub const Expect = struct {
    method: []const u8 = "GET",
    target: []const u8 = "/",
    host: ?[]const u8 = null,
};

pub const Step = struct {
    expect: Expect = .{},
    resp: Response,
};

pub const Server = struct {
    const max_reqs = 16;

    server: std.net.Server,
    steps: []const Step = &.{},
    resps: []const Response = &.{},
    req_bufs: [max_reqs][8192]u8 = undefined,
    req_lens: [max_reqs]usize = [_]usize{0} ** max_reqs,
    req_count: usize = 0,
    failure: ?anyerror = null,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(_: std.mem.Allocator, steps: []const Step) !Server {
        if (steps.len == 0 or steps.len > max_reqs) return error.InvalidResponseCount;
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const server = try addr.listen(.{ .reuse_address = true });
        return .{
            .server = server,
            .steps = steps,
        };
    }

    pub fn initSeq(resps: []const Response) !Server {
        if (resps.len == 0 or resps.len > max_reqs) return error.InvalidResponseCount;
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const server = try addr.listen(.{ .reuse_address = true });
        return .{
            .server = server,
            .resps = resps,
        };
    }

    pub fn deinit(self: *Server) void {
        self.server.deinit();
        self.* = undefined;
    }

    pub fn port(self: *const Server) u16 {
        return self.server.listen_address.getPort();
    }

    pub fn spawn(self: *Server) !std.Thread {
        return std.Thread.spawn(.{}, run, .{self});
    }

    pub fn join(self: *Server, thr: std.Thread) !void {
        self.stop.store(true, .release);
        thr.join();
        if (self.failure) |err| return err;
    }

    pub fn request(self: *const Server, idx: usize) []const u8 {
        std.debug.assert(idx < self.req_count);
        return self.req_bufs[idx][0..self.req_lens[idx]];
    }

    pub fn requestAt(self: *const Server, idx: usize) []const u8 {
        return self.request(idx);
    }

    pub fn requestCount(self: *const Server) usize {
        return self.req_count;
    }

    pub fn urlAlloc(self: *const Server, alloc: std.mem.Allocator, path: []const u8) ![]u8 {
        return std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}{s}", .{ self.port(), path });
    }
};

fn run(self: *Server) void {
    if (self.steps.len != 0) {
        var i: usize = 0;
        while (i < self.steps.len) : (i += 1) {
            var conn = acceptReady(self) catch |err| {
                self.failure = err;
                return;
            } orelse return;
            defer conn.stream.close();

            self.req_lens[i] = readRequest(conn.stream.handle, self.req_bufs[i][0..]) catch |err| {
                self.failure = err;
                return;
            };
            self.req_count = i + 1;

            if (!matchesExpect(self.req_bufs[i][0..self.req_lens[i]], self.steps[i].expect)) {
                self.failure = error.UnexpectedRequest;
                return;
            }
            writeResponse(conn.stream.handle, self.steps[i].resp) catch |err| {
                self.failure = err;
                return;
            };
        }
        return;
    }

    for (self.resps, 0..) |resp, i| {
        var conn = acceptReady(self) catch |err| {
            self.failure = err;
            return;
        } orelse return;
        defer conn.stream.close();

        self.req_lens[i] = readRequest(conn.stream.handle, self.req_bufs[i][0..]) catch |err| {
            self.failure = err;
            return;
        };
        self.req_count = i + 1;
        writeResponse(conn.stream.handle, resp) catch |err| {
            self.failure = err;
            return;
        };
    }
}

fn acceptReady(self: *Server) !?std.net.Server.Connection {
    var fds = [_]std.posix.pollfd{.{
        .fd = self.server.stream.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    while (true) {
        if (self.stop.load(.acquire)) return null;
        const ready = try std.posix.poll(fds[0..], 20);
        if (ready == 0) continue;
        return try self.server.accept();
    }
}

fn readRequest(fd: std.posix.socket_t, buf: []u8) !usize {
    var off: usize = 0;
    while (off < buf.len) {
        const got = try std.posix.read(fd, buf[off..]);
        if (got == 0) break;
        off += got;
        if (std.mem.indexOf(u8, buf[0..off], "\r\n\r\n") != null) break;
    }
    return off;
}

fn readResponse(fd: std.posix.socket_t, buf: []u8) !usize {
    var off: usize = 0;
    while (off < buf.len) {
        const got = try std.posix.read(fd, buf[off..]);
        if (got == 0) break;
        off += got;
        if (std.mem.indexOf(u8, buf[0..off], "\r\n\r\n")) |hdr_end| {
            const body_off = hdr_end + 4;
            if (header(buf[0..off], "content-length")) |raw_len| {
                const body_len = std.fmt.parseInt(usize, raw_len, 10) catch return error.InvalidContentLength;
                if (off >= body_off + body_len) break;
            }
        }
    }
    return off;
}

pub fn requestLine(raw: []const u8) ?[]const u8 {
    const end = std.mem.indexOf(u8, raw, "\r\n") orelse return null;
    return raw[0..end];
}

pub fn header(raw: []const u8, name: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, raw, "\r\n") orelse return null;
    var pos = line_end + 2;
    while (pos <= raw.len) {
        const end = std.mem.indexOfPos(u8, raw, pos, "\r\n") orelse return null;
        if (end == pos) return null;
        const line = raw[pos..end];
        if (std.mem.indexOfScalar(u8, line, ':')) |sep| {
            const got_name = std.mem.trim(u8, line[0..sep], " \t");
            const got_val = std.mem.trim(u8, line[sep + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(got_name, name)) return got_val;
        }
        pos = end + 2;
    }
    return null;
}

fn matchesExpect(raw: []const u8, exp: Expect) bool {
    const line = requestLine(raw) orelse return false;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const method = it.next() orelse return false;
    const target = it.next() orelse return false;
    const ver = it.next() orelse return false;
    if (it.next() != null) return false;
    if (!std.mem.eql(u8, exp.method, "*") and !std.mem.eql(u8, method, exp.method)) return false;
    if (!std.mem.eql(u8, exp.target, "*") and !std.mem.eql(u8, target, exp.target)) return false;
    if (!std.mem.eql(u8, ver, "HTTP/1.1")) return false;
    if (exp.host) |host| {
        const got_host = header(raw, "host") orelse return false;
        if (!std.mem.eql(u8, got_host, host)) return false;
    }
    return true;
}

fn writeResponse(fd: std.posix.socket_t, resp: Response) !void {
    const prefix = try std.fmt.allocPrint(std.heap.page_allocator, "HTTP/1.1 {s}\r\n", .{resp.status});
    defer std.heap.page_allocator.free(prefix);
    _ = try std.posix.write(fd, prefix);
    var saw_len = false;
    for (resp.headers) |hdr| {
        if (std.ascii.startsWithIgnoreCase(hdr, "content-length:")) saw_len = true;
        _ = try std.posix.write(fd, hdr);
        _ = try std.posix.write(fd, "\r\n");
    }
    if (!saw_len) {
        const len = try std.fmt.allocPrint(std.heap.page_allocator, "Content-Length: {d}\r\n", .{resp.body.len});
        defer std.heap.page_allocator.free(len);
        _ = try std.posix.write(fd, len);
    }
    _ = try std.posix.write(fd, "\r\n");
    _ = try std.posix.write(fd, resp.body);
}

test "http mock captures ordered requests and returns scripted responses" {
    var server = try Server.init(std.testing.allocator, &.{
        .{
            .expect = .{
                .method = "GET",
                .target = "/health",
                .host = "127.0.0.1",
            },
            .resp = .{
                .status = "302 Found",
                .headers = &.{"Location: /ready"},
            },
        },
        .{
            .expect = .{
                .method = "GET",
                .target = "/ready",
                .host = "127.0.0.1",
            },
            .resp = .{
                .status = "201 Created",
                .headers = &.{"Content-Type: text/plain"},
                .body = "ok",
            },
        },
    });
    defer server.deinit();

    const thr = try server.spawn();

    var addr = try std.net.Address.parseIp("127.0.0.1", server.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd }).close();
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(
        fd,
        "GET /health HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    var buf: [128]u8 = undefined;
    const got = try readResponse(fd, buf[0..]);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..got], "HTTP/1.1 302 Found") != null);

    const fd2 = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd2 }).close();
    try std.posix.connect(fd2, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(
        fd2,
        "GET /ready HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );

    const got2 = try readResponse(fd2, buf[0..]);
    try server.join(thr);

    try std.testing.expectEqual(@as(usize, 2), server.requestCount());
    try std.testing.expectEqualStrings("GET /health HTTP/1.1", requestLine(server.request(0)).?);
    try std.testing.expectEqualStrings("127.0.0.1", header(server.request(0), "host").?);
    try std.testing.expectEqualStrings("GET /ready HTTP/1.1", requestLine(server.request(1)).?);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..got2], "HTTP/1.1 201 Created") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..got2], "ok") != null);
}

test "http mock serves sequential responses and captures each request" {
    const resps = [_]Response{
        .{
            .status = "302 Found",
            .headers = &.{"Location: /next"},
        },
        .{
            .status = "200 OK",
            .headers = &.{"Content-Type: text/plain"},
            .body = "done",
        },
    };
    var server = try Server.initSeq(&resps);
    defer server.deinit();

    const thr = try server.spawn();

    var addr = try std.net.Address.parseIp("127.0.0.1", server.port());

    const fd0 = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd0 }).close();
    try std.posix.connect(fd0, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(
        fd0,
        "GET /start HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "\r\n",
    );
    var buf0: [256]u8 = undefined;
    const got0 = try readResponse(fd0, buf0[0..]);

    const fd1 = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd1 }).close();
    try std.posix.connect(fd1, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(
        fd1,
        "GET /next HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "\r\n",
    );
    var buf1: [256]u8 = undefined;
    const got1 = try readResponse(fd1, buf1[0..]);

    try server.join(thr);

    try std.testing.expectEqual(@as(usize, 2), server.requestCount());
    try std.testing.expect(std.mem.indexOf(u8, server.requestAt(0), "GET /start HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, server.requestAt(1), "GET /next HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf0[0..got0], "HTTP/1.1 302 Found") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf1[0..got1], "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf1[0..got1], "done") != null);
}
