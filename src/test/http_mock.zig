const std = @import("std");

pub const Response = struct {
    status: []const u8 = "200 OK",
    headers: []const []const u8 = &.{},
    body: []const u8 = "",
};

pub const Server = struct {
    server: std.net.Server,
    resp: Response,
    req_buf: [8192]u8 = undefined,
    req_len: usize = 0,

    pub fn init(resp: Response) !Server {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const server = try addr.listen(.{ .reuse_address = true });
        return .{
            .server = server,
            .resp = resp,
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

    pub fn request(self: *const Server) []const u8 {
        return self.req_buf[0..self.req_len];
    }
};

fn run(self: *Server) void {
    var conn = self.server.accept() catch return;
    defer conn.stream.close();

    self.req_len = readRequest(conn.stream.handle, self.req_buf[0..]) catch 0;
    writeResponse(conn.stream.handle, self.resp) catch {};
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

fn writeResponse(fd: std.posix.socket_t, resp: Response) !void {
    const prefix = try std.fmt.allocPrint(std.heap.page_allocator, "HTTP/1.1 {s}\r\n", .{resp.status});
    defer std.heap.page_allocator.free(prefix);
    _ = try std.posix.write(fd, prefix);
    var saw_len = false;
    for (resp.headers) |header| {
        if (std.ascii.startsWithIgnoreCase(header, "content-length:")) saw_len = true;
        _ = try std.posix.write(fd, header);
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

test "http mock captures request and returns canned response" {
    var server = try Server.init(.{
        .status = "201 Created",
        .headers = &.{"Content-Type: text/plain"},
        .body = "ok",
    });
    defer server.deinit();

    const thr = try server.spawn();

    var addr = try std.net.Address.parseIp("127.0.0.1", server.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd }).close();
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(fd,
        "GET /health HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "\r\n",
    );

    var buf: [128]u8 = undefined;
    const got = try std.posix.read(fd, buf[0..]);
    thr.join();

    try std.testing.expect(std.mem.indexOf(u8, server.request(), "GET /health HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..got], "HTTP/1.1 201 Created") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..got], "ok") != null);
}
