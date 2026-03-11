const std = @import("std");

pub const version: u8 = 1;
pub const nil = "-";

pub const Transport = enum {
    udp,
    tcp,
};

pub const Facility = enum(u5) {
    kern = 0,
    user = 1,
    mail = 2,
    daemon = 3,
    auth = 4,
    syslog = 5,
    lpr = 6,
    news = 7,
    uucp = 8,
    cron = 9,
    authpriv = 10,
    ftp = 11,
    ntp = 12,
    audit = 13,
    alert = 14,
    clock = 15,
    local0 = 16,
    local1 = 17,
    local2 = 18,
    local3 = 19,
    local4 = 20,
    local5 = 21,
    local6 = 22,
    local7 = 23,
};

pub const Severity = enum(u3) {
    emergency = 0,
    alert = 1,
    critical = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,
};

pub const Priority = struct {
    facility: Facility = .user,
    severity: Severity = .info,

    pub fn value(self: Priority) u8 {
        return @as(u8, @intFromEnum(self.facility)) * 8 + @as(u8, @intFromEnum(self.severity));
    }
};

pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

pub const Element = struct {
    id: []const u8,
    params: []const Param = &.{},
};

pub const Message = struct {
    pri: Priority = .{},
    timestamp_ms: ?i64 = null,
    hostname: []const u8 = nil,
    app_name: []const u8 = nil,
    procid: []const u8 = nil,
    msgid: []const u8 = nil,
    structured_data: []const Element = &.{},
    msg: ?[]const u8 = null,

    pub fn validate(self: Message) !void {
        try validateHeaderField(self.hostname, 255);
        try validateHeaderField(self.app_name, 48);
        try validateHeaderField(self.procid, 128);
        try validateHeaderField(self.msgid, 32);

        if (self.timestamp_ms) |ts| {
            if (ts < 0) return error.InvalidTimestamp;
        }

        for (self.structured_data) |elem| {
            try validateSdName(elem.id);
            for (elem.params) |param| {
                try validateSdName(param.name);
            }
        }
    }
};

pub const SenderOpts = struct {
    transport: Transport = .udp,
    host: []const u8,
    port: u16 = 514,
};

pub const Sender = struct {
    alloc: std.mem.Allocator,
    transport: Transport,
    fd: std.posix.socket_t,
    addr: std.net.Address,

    pub fn init(alloc: std.mem.Allocator, opts: SenderOpts) !Sender {
        if (opts.host.len == 0) return error.InvalidHost;

        const addr = try resolve(alloc, opts.host, opts.port);
        const fd = try openSocket(addr, opts.transport);
        errdefer {
            (std.net.Stream{ .handle = fd }).close();
        }

        if (opts.transport == .tcp) {
            try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
        }

        return .{
            .alloc = alloc,
            .transport = opts.transport,
            .fd = fd,
            .addr = addr,
        };
    }

    pub fn deinit(self: *Sender) void {
        (std.net.Stream{ .handle = self.fd }).close();
        self.* = undefined;
    }

    pub fn send(self: *Sender, msg: Message) !void {
        const raw = try encodeAlloc(self.alloc, msg);
        defer self.alloc.free(raw);
        try self.sendRaw(raw);
    }

    pub fn sendRaw(self: *Sender, raw: []const u8) !void {
        switch (self.transport) {
            .udp => {
                const sent = try std.posix.sendto(self.fd, raw, 0, &self.addr.any, self.addr.getOsSockLen());
                if (sent != raw.len) return error.ShortWrite;
            },
            .tcp => {
                var prefix_buf: [32]u8 = undefined;
                const prefix = try std.fmt.bufPrint(&prefix_buf, "{d} ", .{raw.len});
                try sendAll(self.fd, prefix);
                try sendAll(self.fd, raw);
            },
        }
    }
};

pub fn encodeAlloc(alloc: std.mem.Allocator, msg: Message) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    try write(out.writer(alloc), msg);
    return try out.toOwnedSlice(alloc);
}

pub fn write(writer: anytype, msg: Message) !void {
    try msg.validate();

    try writer.print("<{d}>{d} ", .{ msg.pri.value(), version });
    if (msg.timestamp_ms) |ts| {
        try writeTimestamp(writer, ts);
    } else {
        try writer.writeAll(nil);
    }

    try writer.writeByte(' ');
    try writer.writeAll(msg.hostname);
    try writer.writeByte(' ');
    try writer.writeAll(msg.app_name);
    try writer.writeByte(' ');
    try writer.writeAll(msg.procid);
    try writer.writeByte(' ');
    try writer.writeAll(msg.msgid);
    try writer.writeByte(' ');
    try writeStructuredData(writer, msg.structured_data);

    if (msg.msg) |body| {
        try writer.writeByte(' ');
        try writer.writeAll(body);
    }
}

fn resolve(alloc: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    const addrs = try std.net.getAddressList(alloc, host, port);
    defer addrs.deinit();

    if (addrs.addrs.len == 0) return error.UnknownHostName;
    return addrs.addrs[0];
}

fn openSocket(addr: std.net.Address, transport: Transport) !std.posix.socket_t {
    const kind: u32 = switch (transport) {
        .udp => std.posix.SOCK.DGRAM,
        .tcp => std.posix.SOCK.STREAM,
    };
    const proto: u32 = switch (transport) {
        .udp => std.posix.IPPROTO.UDP,
        .tcp => std.posix.IPPROTO.TCP,
    };
    return try std.posix.socket(addr.any.family, kind | std.posix.SOCK.CLOEXEC, proto);
}

fn sendAll(fd: std.posix.socket_t, raw: []const u8) !void {
    var off: usize = 0;
    while (off < raw.len) {
        const sent = try std.posix.send(fd, raw[off..], 0);
        if (sent == 0) return error.ShortWrite;
        off += sent;
    }
}

fn writeTimestamp(writer: anytype, timestamp_ms: i64) !void {
    if (timestamp_ms < 0) return error.InvalidTimestamp;

    const secs: u64 = @intCast(@divTrunc(timestamp_ms, std.time.ms_per_s));
    const millis: u16 = @intCast(@mod(timestamp_ms, std.time.ms_per_s));

    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();

    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        millis,
    });
}

fn writeStructuredData(writer: anytype, elems: []const Element) !void {
    if (elems.len == 0) {
        try writer.writeAll(nil);
        return;
    }

    for (elems) |elem| {
        try writer.writeByte('[');
        try writer.writeAll(elem.id);
        for (elem.params) |param| {
            try writer.writeByte(' ');
            try writer.writeAll(param.name);
            try writer.writeAll("=\"");
            try writeParamValue(writer, param.value);
            try writer.writeByte('"');
        }
        try writer.writeByte(']');
    }
}

fn writeParamValue(writer: anytype, raw: []const u8) !void {
    for (raw) |c| {
        switch (c) {
            '"', '\\', ']' => {
                try writer.writeByte('\\');
                try writer.writeByte(c);
            },
            else => try writer.writeByte(c),
        }
    }
}

fn validateHeaderField(raw: []const u8, max_len: usize) !void {
    if (std.mem.eql(u8, raw, nil)) return;
    if (raw.len == 0 or raw.len > max_len) return error.InvalidHeaderField;

    for (raw) |c| {
        if (c < 33 or c > 126) return error.InvalidHeaderField;
    }
}

fn validateSdName(raw: []const u8) !void {
    if (raw.len == 0 or raw.len > 32) return error.InvalidStructuredData;

    for (raw) |c| {
        if (c < 33 or c > 126) return error.InvalidStructuredData;
        switch (c) {
            '=', ']', '"' => return error.InvalidStructuredData,
            else => {},
        }
    }
}

const UdpCollector = struct {
    fd: std.posix.socket_t,
    addr: std.net.Address,
    buf: [2048]u8 = undefined,
    len: usize = 0,

    fn init() !UdpCollector {
        var addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.UDP);
        errdefer {
            (std.net.Stream{ .handle = fd }).close();
        }

        var socklen = addr.getOsSockLen();
        try std.posix.bind(fd, &addr.any, socklen);
        try std.posix.getsockname(fd, &addr.any, &socklen);

        return .{
            .fd = fd,
            .addr = addr,
        };
    }

    fn deinit(self: *UdpCollector) void {
        (std.net.Stream{ .handle = self.fd }).close();
        self.* = undefined;
    }

    fn port(self: *const UdpCollector) u16 {
        return self.addr.getPort();
    }

    fn run(self: *UdpCollector) void {
        self.len = std.posix.recvfrom(self.fd, self.buf[0..], 0, null, null) catch 0;
    }

    fn message(self: *const UdpCollector) []const u8 {
        return self.buf[0..self.len];
    }
};

const TcpCollector = struct {
    server: std.net.Server,
    buf: [2048]u8 = undefined,
    len: usize = 0,

    fn init() !TcpCollector {
        const addr = try std.net.Address.parseIp("127.0.0.1", 0);
        const server = try addr.listen(.{ .reuse_address = true });
        return .{ .server = server };
    }

    fn deinit(self: *TcpCollector) void {
        self.server.deinit();
        self.* = undefined;
    }

    fn port(self: *const TcpCollector) u16 {
        return self.server.listen_address.getPort();
    }

    fn run(self: *TcpCollector) void {
        var conn = self.server.accept() catch return;
        defer conn.stream.close();

        self.len = readOctetFrame(conn.stream.handle, self.buf[0..]) catch 0;
    }

    fn message(self: *const TcpCollector) []const u8 {
        return self.buf[0..self.len];
    }
};

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

test "encodeAlloc formats RFC 5424 with escaped structured data" {
    const raw = try encodeAlloc(std.testing.allocator, .{
        .pri = .{ .facility = .local0, .severity = .notice },
        .timestamp_ms = 123,
        .hostname = "host1",
        .app_name = "pz",
        .procid = "42",
        .msgid = "AUDIT",
        .structured_data = &.{
            .{
                .id = "audit@32473",
                .params = &.{
                    .{ .name = "actor", .value = "alice\"root" },
                    .{ .name = "path", .value = "C:\\tmp]" },
                },
            },
        },
        .msg = "login ok",
    });
    defer std.testing.allocator.free(raw);

    try std.testing.expectEqualStrings(
        "<133>1 1970-01-01T00:00:00.123Z host1 pz 42 AUDIT [audit@32473 actor=\"alice\\\"root\" path=\"C:\\\\tmp\\]\"] login ok",
        raw,
    );
}

test "encodeAlloc rejects invalid header field bytes" {
    try std.testing.expectError(error.InvalidHeaderField, encodeAlloc(std.testing.allocator, .{
        .hostname = "bad host",
    }));
}

test "udp sender emits datagram to local collector" {
    var collector = try UdpCollector.init();
    defer collector.deinit();

    const t = try std.Thread.spawn(.{}, UdpCollector.run, .{&collector});

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try sender.send(.{
        .pri = .{ .facility = .local4, .severity = .warning },
        .timestamp_ms = 0,
        .hostname = "node1",
        .app_name = "pz",
        .procid = "777",
        .msgid = "AUDIT",
        .structured_data = &.{
            .{
                .id = "meta",
                .params = &.{
                    .{ .name = "seq", .value = "1" },
                },
            },
        },
        .msg = "udp path",
    });

    t.join();

    try std.testing.expectEqualStrings(
        "<164>1 1970-01-01T00:00:00.000Z node1 pz 777 AUDIT [meta seq=\"1\"] udp path",
        collector.message(),
    );
}

test "tcp sender emits octet-counted frame to local collector" {
    var collector = try TcpCollector.init();
    defer collector.deinit();

    const t = try std.Thread.spawn(.{}, TcpCollector.run, .{&collector});

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .tcp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try sender.send(.{
        .pri = .{ .facility = .local6, .severity = .err },
        .timestamp_ms = 0,
        .hostname = "node2",
        .app_name = "pz",
        .procid = "999",
        .msgid = "FAIL",
        .msg = "tcp path",
    });

    t.join();

    try std.testing.expectEqualStrings(
        "<179>1 1970-01-01T00:00:00.000Z node2 pz 999 FAIL - tcp path",
        collector.message(),
    );
}
