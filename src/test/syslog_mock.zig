const std = @import("std");

pub const UdpCollector = struct {
    fd: std.posix.socket_t,
    addr: std.net.Address,
    buf: [4096]u8 = undefined,
    len: usize = 0,

    pub fn init() !UdpCollector {
        var addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
        errdefer (std.net.Stream{ .handle = fd }).close();

        var socklen = addr.getOsSockLen();
        try std.posix.bind(fd, &addr.any, socklen);
        try std.posix.getsockname(fd, &addr.any, &socklen);

        return .{
            .fd = fd,
            .addr = addr,
        };
    }

    pub fn deinit(self: *UdpCollector) void {
        (std.net.Stream{ .handle = self.fd }).close();
        self.* = undefined;
    }

    pub fn port(self: *const UdpCollector) u16 {
        return self.addr.getPort();
    }

    pub fn spawn(self: *UdpCollector) !std.Thread {
        return std.Thread.spawn(.{}, runUdp, .{self});
    }

    pub fn message(self: *const UdpCollector) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const TcpCollector = struct {
    server: std.net.Server,
    buf: [4096]u8 = undefined,
    len: usize = 0,

    pub fn init() !TcpCollector {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const server = try addr.listen(.{ .reuse_address = true });
        return .{ .server = server };
    }

    pub fn deinit(self: *TcpCollector) void {
        self.server.deinit();
        self.* = undefined;
    }

    pub fn port(self: *const TcpCollector) u16 {
        return self.server.listen_address.getPort();
    }

    pub fn spawn(self: *TcpCollector) !std.Thread {
        return std.Thread.spawn(.{}, runTcp, .{self});
    }

    pub fn message(self: *const TcpCollector) []const u8 {
        return self.buf[0..self.len];
    }
};

fn runUdp(self: *UdpCollector) void {
    self.len = std.posix.recvfrom(self.fd, self.buf[0..], 0, null, null) catch 0;
}

fn runTcp(self: *TcpCollector) void {
    var conn = self.server.accept() catch return;
    defer conn.stream.close();
    self.len = readOctetFrame(conn.stream.handle, self.buf[0..]) catch 0;
}

fn readOctetFrame(fd: std.posix.socket_t, buf: []u8) !usize {
    var len_buf: [32]u8 = undefined;
    var len_used: usize = 0;

    while (true) {
        var byte: [1]u8 = undefined;
        const got = try std.posix.read(fd, byte[0..]);
        if (got == 0) return error.EndOfStream;
        if (byte[0] == ' ') break;
        if (byte[0] < '0' or byte[0] > '9') return error.InvalidFrame;
        if (len_used >= len_buf.len) return error.FrameTooLarge;
        len_buf[len_used] = byte[0];
        len_used += 1;
    }
    if (len_used == 0) return error.InvalidFrame;

    const frame_len = try std.fmt.parseInt(usize, len_buf[0..len_used], 10);
    if (frame_len > buf.len) return error.FrameTooLarge;

    var off: usize = 0;
    while (off < frame_len) {
        const got = try std.posix.read(fd, buf[off..frame_len]);
        if (got == 0) return error.EndOfStream;
        off += got;
    }
    return frame_len;
}

test "udp collector captures datagram" {
    var collector = try UdpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var addr = try std.net.Address.parseIp("127.0.0.1", collector.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
    defer (std.net.Stream{ .handle = fd }).close();
    _ = try std.posix.sendto(fd, "udp-mock", 0, &addr.any, addr.getOsSockLen());

    t.join();
    try std.testing.expectEqualStrings("udp-mock", collector.message());
}

test "tcp collector captures octet-counted frame" {
    var collector = try TcpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var addr = try std.net.Address.parseIp("127.0.0.1", collector.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd }).close();
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(fd, "8 tcp-mock");

    t.join();
    try std.testing.expectEqualStrings("tcp-mock", collector.message());
}
