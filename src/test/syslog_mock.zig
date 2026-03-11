const std = @import("std");
const max_msgs: usize = 16;
const max_msg_len: usize = 4096;

pub const UdpCollector = struct {
    fd: std.posix.socket_t,
    addr: std.net.Address,
    goal: usize = 1,
    count: usize = 0,
    bufs: [max_msgs][max_msg_len]u8 = undefined,
    lens: [max_msgs]usize = [_]usize{0} ** max_msgs,

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
        return self.spawnCount(1);
    }

    pub fn spawnCount(self: *UdpCollector, n: usize) !std.Thread {
        if (n == 0 or n > max_msgs) return error.InvalidCount;
        self.goal = n;
        self.count = 0;
        self.lens = [_]usize{0} ** max_msgs;
        return std.Thread.spawn(.{}, runUdp, .{self});
    }

    pub fn message(self: *const UdpCollector) []const u8 {
        return self.messageAt(0);
    }

    pub fn messageAt(self: *const UdpCollector, idx: usize) []const u8 {
        return self.bufs[idx][0..self.lens[idx]];
    }

    pub fn msgCount(self: *const UdpCollector) usize {
        return self.count;
    }
};

pub const TcpCollector = struct {
    server: std.net.Server,
    goal: usize = 1,
    count: usize = 0,
    bufs: [max_msgs][max_msg_len]u8 = undefined,
    lens: [max_msgs]usize = [_]usize{0} ** max_msgs,

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
        return self.spawnCount(1);
    }

    pub fn spawnCount(self: *TcpCollector, n: usize) !std.Thread {
        if (n == 0 or n > max_msgs) return error.InvalidCount;
        self.goal = n;
        self.count = 0;
        self.lens = [_]usize{0} ** max_msgs;
        return std.Thread.spawn(.{}, runTcp, .{self});
    }

    pub fn message(self: *const TcpCollector) []const u8 {
        return self.messageAt(0);
    }

    pub fn messageAt(self: *const TcpCollector, idx: usize) []const u8 {
        return self.bufs[idx][0..self.lens[idx]];
    }

    pub fn msgCount(self: *const TcpCollector) usize {
        return self.count;
    }
};

fn runUdp(self: *UdpCollector) void {
    while (self.count < self.goal) : (self.count += 1) {
        self.lens[self.count] = recvUdp(self.fd, self.bufs[self.count][0..]) catch return;
    }
}

fn runTcp(self: *TcpCollector) void {
    while (self.count < self.goal) {
        var conn = self.server.accept() catch return;
        while (self.count < self.goal) {
            self.lens[self.count] = readOctetFrame(conn.stream.handle, self.bufs[self.count][0..]) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return,
            };
            self.count += 1;
        }
        conn.stream.close();
    }
}

fn recvUdp(fd: std.posix.socket_t, buf: []u8) !usize {
    while (true) {
        const rc = std.posix.system.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .BADF => return error.FileDescriptorClosed,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn readOctetFrame(fd: std.posix.socket_t, buf: []u8) !usize {
    var len_buf: [32]u8 = undefined;
    var len_used: usize = 0;

    while (true) {
        var byte: [1]u8 = undefined;
        const got = try readFd(fd, byte[0..]);
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
        const got = try readFd(fd, buf[off..frame_len]);
        if (got == 0) return error.EndOfStream;
        off += got;
    }
    return frame_len;
}

fn readFd(fd: std.posix.fd_t, buf: []u8) !usize {
    while (true) {
        const rc = std.posix.system.read(fd, buf.ptr, buf.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .BADF => return error.FileDescriptorClosed,
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
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

test "udp collector captures multiple datagrams" {
    var collector = try UdpCollector.init();
    defer collector.deinit();

    const t = try collector.spawnCount(2);

    var addr = try std.net.Address.parseIp("127.0.0.1", collector.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
    defer (std.net.Stream{ .handle = fd }).close();
    _ = try std.posix.sendto(fd, "udp-1", 0, &addr.any, addr.getOsSockLen());
    _ = try std.posix.sendto(fd, "udp-2", 0, &addr.any, addr.getOsSockLen());

    t.join();
    try std.testing.expectEqual(@as(usize, 2), collector.msgCount());
    try std.testing.expectEqualStrings("udp-1", collector.messageAt(0));
    try std.testing.expectEqualStrings("udp-2", collector.messageAt(1));
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

test "tcp collector captures multiple octet-counted frames" {
    var collector = try TcpCollector.init();
    defer collector.deinit();

    const t = try collector.spawnCount(2);

    var addr = try std.net.Address.parseIp("127.0.0.1", collector.port());
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd }).close();
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
    _ = try std.posix.write(fd, "5 tcp-1");
    _ = try std.posix.write(fd, "5 tcp-2");

    t.join();
    try std.testing.expectEqual(@as(usize, 2), collector.msgCount());
    try std.testing.expectEqualStrings("tcp-1", collector.messageAt(0));
    try std.testing.expectEqualStrings("tcp-2", collector.messageAt(1));
}
