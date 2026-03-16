//! RFC 5424 syslog client: UDP/TCP/TLS transport, structured data.
const std = @import("std");
const policy = @import("policy.zig");
const syslog_mock = @import("../test/syslog_mock.zig");

pub const version: u8 = 1;
pub const nil = "-";

pub const Transport = enum {
    udp,
    tcp,
    tls,
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

pub const TlsOpts = struct {
    ca_file: ?[]const u8 = null,
    client_cert: ?[]const u8 = null,
    client_key: ?[]const u8 = null,
};

pub const SenderOpts = struct {
    transport: Transport = .udp,
    host: []const u8,
    port: u16 = 514,
    deadline_s: i64 = 10,
    egress: ?policy.Policy = null,
    tool: ?[]const u8 = "syslog",
    allow_private: bool = false,
    tls: TlsOpts = .{},
    hooks: Hooks = .{},
};

pub const Sender = struct {
    alloc: std.mem.Allocator,
    transport: Transport,
    host: []u8,
    port: u16,
    deadline_s: i64,
    allow_private: bool,
    tls_opts: TlsOpts,
    hooks: Hooks,
    fd: std.posix.socket_t,
    addr: std.net.Address,
    tls_state: ?*anyopaque = null,

    pub fn init(alloc: std.mem.Allocator, opts: SenderOpts) !Sender {
        if (opts.host.len == 0) return error.InvalidHost;
        if (opts.egress) |egress| try checkHostAllowed(opts.host, egress, opts.tool);

        const host = try alloc.dupe(u8, opts.host);
        errdefer alloc.free(host);

        const addr = try opts.hooks.resolve(alloc, opts.host, opts.port);

        if (!opts.allow_private and policy.isBlockedNetAddr(addr))
            return error.PrivateAddr;

        const sock_transport: Transport = if (opts.transport == .tls) .tcp else opts.transport;
        const fd = try opts.hooks.open_socket(addr, sock_transport);
        errdefer opts.hooks.close_socket(fd);

        if (opts.transport == .tcp or opts.transport == .tls) {
            try opts.hooks.connect(fd, addr);
            opts.hooks.set_deadlines(fd, opts.deadline_s);
        }

        var tls_state: ?*anyopaque = null;
        if (opts.transport == .tls) {
            tls_state = try opts.hooks.tls_handshake(fd, host, opts.tls);
        }

        return .{
            .alloc = alloc,
            .transport = opts.transport,
            .host = host,
            .port = opts.port,
            .deadline_s = opts.deadline_s,
            .allow_private = opts.allow_private,
            .tls_opts = opts.tls,
            .hooks = opts.hooks,
            .fd = fd,
            .addr = addr,
            .tls_state = tls_state,
        };
    }

    pub fn deinit(self: *Sender) void {
        if (self.tls_state) |st| self.hooks.tls_close(st);
        self.hooks.close_socket(self.fd);
        self.alloc.free(self.host);
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
                self.sendUdp(raw) catch {
                    try self.refresh();
                    try self.sendUdp(raw);
                };
            },
            .tcp => {
                self.sendTcp(raw) catch {
                    try self.refresh();
                    try self.sendTcp(raw);
                };
            },
            .tls => {
                self.sendTls(raw) catch {
                    try self.refresh();
                    try self.sendTls(raw);
                };
            },
        }
    }

    fn refresh(self: *Sender) !void {
        const addr = try self.hooks.resolve(self.alloc, self.host, self.port);

        if (!self.allow_private and policy.isBlockedNetAddr(addr))
            return error.PrivateAddr;

        const sock_transport: Transport = if (self.transport == .tls) .tcp else self.transport;
        const fd = try self.hooks.open_socket(addr, sock_transport);
        errdefer self.hooks.close_socket(fd);
        if (self.transport == .tcp or self.transport == .tls) {
            try self.hooks.connect(fd, addr);
            self.hooks.set_deadlines(fd, self.deadline_s);
        }

        var tls_state: ?*anyopaque = null;
        if (self.transport == .tls) {
            tls_state = try self.hooks.tls_handshake(fd, self.host, self.tls_opts);
        }

        if (self.tls_state) |st| self.hooks.tls_close(st);
        self.hooks.close_socket(self.fd);
        self.fd = fd;
        self.addr = addr;
        self.tls_state = tls_state;
    }

    fn sendUdp(self: *Sender, raw: []const u8) !void {
        const fit = try fitUdpAlloc(self.alloc, raw);
        defer fit.deinit(self.alloc);
        try self.hooks.send_udp(self.fd, fit.raw, self.addr);
    }

    fn sendTcp(self: *Sender, raw: []const u8) !void {
        var prefix_buf: [32]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "{d} ", .{raw.len});
        try self.hooks.send_tcp(self.fd, prefix);
        try self.hooks.send_tcp(self.fd, raw);
    }

    fn sendTls(self: *Sender, raw: []const u8) !void {
        const st = self.tls_state orelse return error.TlsNotEstablished;
        var prefix_buf: [32]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&prefix_buf, "{d} ", .{raw.len});
        try self.hooks.tls_send(st, prefix);
        try self.hooks.tls_send(st, raw);
    }
};

fn checkHostAllowed(host: []const u8, egress: policy.Policy, tool: ?[]const u8) error{HostDenied}!void {
    const prefix = "runtime/syslog/";
    var path_buf: [320]u8 = undefined;
    if (prefix.len + host.len > path_buf.len) return error.HostDenied;
    @memcpy(path_buf[0..prefix.len], prefix);
    for (host, 0..) |c, i| path_buf[prefix.len + i] = std.ascii.toLower(c);
    if (egress.eval(path_buf[0 .. prefix.len + host.len], tool) != .allow) return error.HostDenied;
}

const Hooks = struct {
    resolve: *const fn (alloc: std.mem.Allocator, host: []const u8, port: u16) anyerror!std.net.Address = resolve,
    open_socket: *const fn (addr: std.net.Address, transport: Transport) anyerror!std.posix.socket_t = openSocket,
    connect: *const fn (fd: std.posix.socket_t, addr: std.net.Address) anyerror!void = connectSocket,
    set_deadlines: *const fn (fd: std.posix.socket_t, secs: i64) void = setDeadlines,
    send_udp: *const fn (fd: std.posix.socket_t, raw: []const u8, addr: std.net.Address) anyerror!void = sendUdpRaw,
    send_tcp: *const fn (fd: std.posix.socket_t, raw: []const u8) anyerror!void = sendAll,
    close_socket: *const fn (fd: std.posix.socket_t) void = closeSocket,
    tls_handshake: *const fn (fd: std.posix.socket_t, host: []const u8, opts: TlsOpts) anyerror!*anyopaque = tlsHandshakeStub,
    tls_send: *const fn (state: *anyopaque, data: []const u8) anyerror!void = tlsSendStub,
    tls_close: *const fn (state: *anyopaque) void = tlsCloseStub,
};

const udp_max_len: usize = 1024;
const trunc_sd_id = "trunc@32473";

const UdpFit = struct {
    raw: []const u8,
    own: ?[]u8 = null,

    fn deinit(self: UdpFit, alloc: std.mem.Allocator) void {
        if (self.own) |buf| alloc.free(buf);
    }
};

const FrameView = struct {
    pre_sd: []const u8,
    sd: []const u8,
    msg: ?[]const u8,
};

fn fitUdpAlloc(alloc: std.mem.Allocator, raw: []const u8) !UdpFit {
    if (raw.len <= udp_max_len) return .{ .raw = raw };

    const view = try splitFrame(raw);

    var orig_buf: [32]u8 = undefined;
    const orig_len = try std.fmt.bufPrint(&orig_buf, "{d}", .{raw.len});

    var marker_buf: [96]u8 = undefined;
    const marker = try std.fmt.bufPrint(&marker_buf, "[{s} transport=\"udp\" orig_len=\"{s}\"]", .{
        trunc_sd_id,
        orig_len,
    });

    const keep_sd = !std.mem.eql(u8, view.sd, nil);
    const has_msg = view.msg != null;
    const fixed_len = view.pre_sd.len +
        (if (keep_sd) view.sd.len else @as(usize, 0)) +
        marker.len +
        @as(usize, @intFromBool(has_msg));
    if (fixed_len > udp_max_len) return error.UdpFrameTooLarge;

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(alloc);

    try out.ensureTotalCapacityPrecise(alloc, udp_max_len);
    try out.appendSlice(alloc, view.pre_sd);
    if (keep_sd) try out.appendSlice(alloc, view.sd);
    try out.appendSlice(alloc, marker);

    if (view.msg) |msg| {
        const budget = udp_max_len - fixed_len;
        try out.append(alloc, ' ');
        try out.appendSlice(alloc, msg[0..budget]);
    }

    const own = try out.toOwnedSlice(alloc);
    return .{
        .raw = own,
        .own = own,
    };
}

fn splitFrame(raw: []const u8) !FrameView {
    var off: usize = 0;
    var spaces: usize = 0;
    while (spaces < 6) : (off += 1) {
        if (off >= raw.len) return error.InvalidFrame;
        if (raw[off] == ' ') spaces += 1;
    }

    const sd_start = off;
    if (sd_start >= raw.len) return error.InvalidFrame;

    if (raw[sd_start] == '-') {
        const sd_end = sd_start + 1;
        if (sd_end > raw.len) return error.InvalidFrame;
        if (sd_end == raw.len) {
            return .{
                .pre_sd = raw[0..sd_start],
                .sd = raw[sd_start..sd_end],
                .msg = null,
            };
        }
        if (raw[sd_end] != ' ') return error.InvalidFrame;
        return .{
            .pre_sd = raw[0..sd_start],
            .sd = raw[sd_start..sd_end],
            .msg = raw[sd_end + 1 ..],
        };
    }

    if (raw[sd_start] != '[') return error.InvalidFrame;

    var depth: usize = 0;
    var in_quote = false;
    var i = sd_start;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (in_quote) {
            if (c == '\\') {
                i += 1;
                if (i >= raw.len) return error.InvalidFrame;
                continue;
            }
            if (c == '"') in_quote = false;
            continue;
        }

        switch (c) {
            '[' => depth += 1,
            ']' => {
                if (depth == 0) return error.InvalidFrame;
                depth -= 1;
                if (depth != 0) continue;

                const sd_end = i + 1;
                if (sd_end == raw.len) {
                    return .{
                        .pre_sd = raw[0..sd_start],
                        .sd = raw[sd_start..sd_end],
                        .msg = null,
                    };
                }

                if (raw[sd_end] == '[') continue;
                if (raw[sd_end] != ' ') return error.InvalidFrame;

                return .{
                    .pre_sd = raw[0..sd_start],
                    .sd = raw[sd_start..sd_end],
                    .msg = raw[sd_end + 1 ..],
                };
            },
            '"' => in_quote = true,
            else => {},
        }
    }

    return error.InvalidFrame;
}

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
        .tcp, .tls => std.posix.SOCK.STREAM,
    };
    const proto: u32 = switch (transport) {
        .udp => std.posix.IPPROTO.UDP,
        .tcp, .tls => std.posix.IPPROTO.TCP,
    };
    return try std.posix.socket(addr.any.family, kind | std.posix.SOCK.CLOEXEC, proto);
}

fn connectSocket(fd: std.posix.socket_t, addr: std.net.Address) !void {
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());
}

fn closeSocket(fd: std.posix.socket_t) void {
    (std.net.Stream{ .handle = fd }).close();
}

/// Apply SO_SNDTIMEO and SO_RCVTIMEO so TCP/TLS syslog connections
/// cannot hang indefinitely. Best-effort: failure is non-fatal.
fn setDeadlines(fd: std.posix.socket_t, secs: i64) void {
    const tv = std.posix.timeval{ .sec = secs, .usec = 0 };
    const tv_bytes: []const u8 = std.mem.asBytes(&tv);
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, tv_bytes) catch {}; // cleanup: propagation impossible
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv_bytes) catch {}; // cleanup: propagation impossible
}

fn sendUdpRaw(fd: std.posix.socket_t, raw: []const u8, addr: std.net.Address) !void {
    const sent = try std.posix.sendto(fd, raw, 0, &addr.any, addr.getOsSockLen());
    if (sent != raw.len) return error.ShortWrite;
}

fn sendAll(fd: std.posix.socket_t, raw: []const u8) !void {
    var off: usize = 0;
    while (off < raw.len) {
        const sent = try std.posix.send(fd, raw[off..], 0);
        if (sent == 0) return error.ShortWrite;
        off += sent;
    }
}

fn tlsHandshakeStub(_: std.posix.socket_t, _: []const u8, _: TlsOpts) !*anyopaque {
    return error.TlsNotConfigured;
}

fn tlsSendStub(_: *anyopaque, _: []const u8) !void {
    return error.TlsNotConfigured;
}

fn tlsCloseStub(_: *anyopaque) void {}

fn noopDeadlines(_: std.posix.socket_t, _: i64) void {}

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
    var collector = try syslog_mock.UdpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "127.0.0.1",
        .port = collector.port(),
        .allow_private = true,
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
    var collector = try syslog_mock.TcpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .tcp,
        .host = "127.0.0.1",
        .port = collector.port(),
        .allow_private = true,
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

test "udp sender truncates only the payload and annotates metadata" {
    var collector = try syslog_mock.UdpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "127.0.0.1",
        .port = collector.port(),
        .allow_private = true,
    });
    defer sender.deinit();

    const msg = try std.testing.allocator.alloc(u8, udp_max_len * 2);
    defer std.testing.allocator.free(msg);
    @memset(msg, 'x');

    const raw = try encodeAlloc(std.testing.allocator, .{
        .pri = .{ .facility = .local5, .severity = .notice },
        .timestamp_ms = 0,
        .hostname = "node3",
        .app_name = "pz",
        .procid = "1001",
        .msgid = "AUDIT",
        .structured_data = &.{
            .{
                .id = "meta",
                .params = &.{
                    .{ .name = "seq", .value = "9" },
                },
            },
        },
        .msg = msg,
    });
    defer std.testing.allocator.free(raw);

    try sender.sendRaw(raw);
    t.join();

    try std.testing.expectEqual(udp_max_len, collector.message().len);
    try std.testing.expect(std.mem.indexOf(u8, collector.message(), "[trunc@32473 transport=\"udp\" orig_len=\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, collector.message(), msg[0..64]) != null);
}

test "tcp sender preserves the full payload for large messages" {
    var collector = try syslog_mock.TcpCollector.init();
    defer collector.deinit();

    const t = try collector.spawn();

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .tcp,
        .host = "127.0.0.1",
        .port = collector.port(),
        .allow_private = true,
    });
    defer sender.deinit();

    const msg = try std.testing.allocator.alloc(u8, udp_max_len * 2);
    defer std.testing.allocator.free(msg);
    @memset(msg, 'y');

    const raw = try encodeAlloc(std.testing.allocator, .{
        .pri = .{ .facility = .local6, .severity = .warning },
        .timestamp_ms = 0,
        .hostname = "node4",
        .app_name = "pz",
        .procid = "1002",
        .msgid = "AUDIT",
        .structured_data = &.{
            .{
                .id = "meta",
                .params = &.{
                    .{ .name = "seq", .value = "10" },
                },
            },
        },
        .msg = msg,
    });
    defer std.testing.allocator.free(raw);

    try sender.sendRaw(raw);
    t.join();

    try std.testing.expectEqualStrings(raw, collector.message());
    try std.testing.expect(std.mem.indexOf(u8, collector.message(), trunc_sd_id) == null);
}

test "udp sender re-resolves hostname after send failure" {
    const Wrap = struct {
        var h = struct {
            resolve_ct: usize = 0,
            sent_port: u16 = 0,
        }{};

        fn resolve(raw_alloc: std.mem.Allocator, _: []const u8, _: u16) !std.net.Address {
            _ = raw_alloc;
            const self = &h;
            self.resolve_ct += 1;
            return std.net.Address.parseIp("127.0.0.1", if (self.resolve_ct == 1) 4011 else 4012);
        }

        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t {
            return 0;
        }

        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}

        fn sendUdp(_: std.posix.socket_t, raw: []const u8, addr: std.net.Address) !void {
            _ = raw;
            if (addr.getPort() == 4011) return error.NetworkUnreachable;
            h.sent_port = addr.getPort();
        }

        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}

        fn closeSocket(_: std.posix.socket_t) void {}
    };

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "localhost",
        .port = 514,
        .allow_private = true,
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
        },
    });
    defer sender.deinit();

    try sender.send(.{
        .hostname = "host",
        .app_name = "pz",
        .procid = "1",
        .msgid = "AUDIT",
        .msg = "retry",
    });

    try std.testing.expectEqual(@as(usize, 2), Wrap.h.resolve_ct);
    try std.testing.expectEqual(@as(u16, 4012), Wrap.h.sent_port);
}

test "sender init rejects host absent from policy" {
    const rules = [_]policy.Rule{
        .{ .pattern = "runtime/syslog/audit.example.com", .effect = .allow, .tool = "syslog" },
    };

    try std.testing.expectError(error.HostDenied, Sender.init(std.testing.allocator, .{
        .host = "blocked.example.com",
        .egress = .{ .rules = &rules },
        .hooks = .{
            .resolve = struct {
                fn f(_: std.mem.Allocator, _: []const u8, _: u16) !std.net.Address {
                    return error.TestUnexpectedResult;
                }
            }.f,
        },
    }));
}

test "sender init accepts host allowed by policy" {
    const Wrap = struct {
        var resolved = false;

        fn resolve(_: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
            resolved = true;
            try std.testing.expectEqualStrings("Audit.EXAMPLE.com", host);
            return std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
        }

        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t {
            return 0;
        }

        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}
        fn sendUdp(_: std.posix.socket_t, _: []const u8, _: std.net.Address) !void {}
        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}
        fn closeSocket(_: std.posix.socket_t) void {}
    };
    const rules = [_]policy.Rule{
        .{ .pattern = "runtime/syslog/audit.example.com", .effect = .allow, .tool = "syslog" },
    };

    var sender = try Sender.init(std.testing.allocator, .{
        .host = "Audit.EXAMPLE.com",
        .egress = .{ .rules = &rules },
        .allow_private = true,
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
        },
    });
    defer sender.deinit();

    try std.testing.expect(Wrap.resolved);
}

test "sender rejects private address after resolution" {
    try std.testing.expectError(error.PrivateAddr, Sender.init(std.testing.allocator, .{
        .host = "private.example.com",
        .hooks = .{
            .resolve = struct {
                fn f(_: std.mem.Allocator, _: []const u8, port: u16) !std.net.Address {
                    return std.net.Address.initIp4(.{ 10, 0, 0, 1 }, port);
                }
            }.f,
        },
    }));
}

test "sender allows private address when allow_private set" {
    const Wrap = struct {
        fn resolve(_: std.mem.Allocator, _: []const u8, port: u16) !std.net.Address {
            return std.net.Address.initIp4(.{ 192, 168, 1, 1 }, port);
        }
        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t { return 0; }
        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}
        fn sendUdp(_: std.posix.socket_t, _: []const u8, _: std.net.Address) !void {}
        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}
        fn closeSocket(_: std.posix.socket_t) void {}
    };

    var sender = try Sender.init(std.testing.allocator, .{
        .host = "internal.example.com",
        .allow_private = true,
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
        },
    });
    defer sender.deinit();
}

test "tls sender invokes handshake and send hooks" {
    const Wrap = struct {
        var state = TlsMockState{};

        const TlsMockState = struct {
            handshake_ct: usize = 0,
            closed: bool = false,
        };

        fn resolve(_: std.mem.Allocator, _: []const u8, port: u16) !std.net.Address {
            return std.net.Address.initIp4(.{ 34, 117, 59, 81 }, port);
        }
        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t { return 0; }
        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}
        fn sendUdp(_: std.posix.socket_t, _: []const u8, _: std.net.Address) !void {}
        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}
        fn closeSocket(_: std.posix.socket_t) void {}

        fn handshake(_: std.posix.socket_t, _: []const u8, _: TlsOpts) !*anyopaque {
            state.handshake_ct += 1;
            return @ptrCast(&state);
        }

        fn tlsClose(ptr: *anyopaque) void {
            _ = ptr;
            state.closed = true;
        }
    };

    Wrap.state = .{};

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .tls,
        .host = "syslog.example.com",
        .port = 6514,
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .set_deadlines = noopDeadlines,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
            .tls_handshake = Wrap.handshake,
            .tls_close = Wrap.tlsClose,
        },
    });
    defer sender.deinit();

    try std.testing.expectEqual(@as(usize, 1), Wrap.state.handshake_ct);
    try std.testing.expect(sender.tls_state != null);
}

test "tls sender re-handshakes on refresh" {
    const Wrap = struct {
        var state = State{};

        const State = struct {
            handshake_ct: usize = 0,
            send_fail: bool = true,
            closed_ct: usize = 0,
        };

        fn resolve(_: std.mem.Allocator, _: []const u8, port: u16) !std.net.Address {
            return std.net.Address.initIp4(.{ 34, 117, 59, 81 }, port);
        }
        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t { return 0; }
        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}
        fn sendUdp(_: std.posix.socket_t, _: []const u8, _: std.net.Address) !void {}
        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}
        fn closeSocket(_: std.posix.socket_t) void {}

        fn handshake(_: std.posix.socket_t, _: []const u8, _: TlsOpts) !*anyopaque {
            state.handshake_ct += 1;
            return @ptrCast(&state);
        }

        fn tlsSend(_: *anyopaque, _: []const u8) !void {
            if (state.send_fail) {
                state.send_fail = false;
                return error.ConnectionReset;
            }
        }

        fn tlsClose(_: *anyopaque) void {
            state.closed_ct += 1;
        }
    };

    Wrap.state = .{};

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .tls,
        .host = "syslog.example.com",
        .port = 6514,
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .set_deadlines = noopDeadlines,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
            .tls_handshake = Wrap.handshake,
            .tls_send = Wrap.tlsSend,
            .tls_close = Wrap.tlsClose,
        },
    });
    defer sender.deinit();

    try sender.send(.{
        .hostname = "host",
        .app_name = "pz",
        .procid = "1",
        .msgid = "AUDIT",
        .msg = "tls-retry",
    });

    try std.testing.expectEqual(@as(usize, 2), Wrap.state.handshake_ct);
    try std.testing.expectEqual(@as(usize, 1), Wrap.state.closed_ct);
}

test "private address check on refresh after re-resolution" {
    const Wrap = struct {
        var h = struct {
            resolve_ct: usize = 0,
        }{};

        fn resolve(_: std.mem.Allocator, _: []const u8, port: u16) !std.net.Address {
            h.resolve_ct += 1;
            if (h.resolve_ct == 1) return std.net.Address.initIp4(.{ 34, 117, 59, 81 }, port);
            return std.net.Address.initIp4(.{ 10, 0, 0, 1 }, port);
        }
        fn openSocket(_: std.net.Address, _: Transport) !std.posix.socket_t { return 0; }
        fn connect(_: std.posix.socket_t, _: std.net.Address) !void {}
        fn sendUdp(_: std.posix.socket_t, _: []const u8, _: std.net.Address) !void {
            return error.NetworkUnreachable;
        }
        fn sendTcp(_: std.posix.socket_t, _: []const u8) !void {}
        fn closeSocket(_: std.posix.socket_t) void {}
    };

    Wrap.h = .{};

    var sender = try Sender.init(std.testing.allocator, .{
        .transport = .udp,
        .host = "syslog.example.com",
        .hooks = .{
            .resolve = Wrap.resolve,
            .open_socket = Wrap.openSocket,
            .connect = Wrap.connect,
            .send_udp = Wrap.sendUdp,
            .send_tcp = Wrap.sendTcp,
            .close_socket = Wrap.closeSocket,
        },
    });
    defer sender.deinit();

    try std.testing.expectError(error.PrivateAddr, sender.send(.{
        .hostname = "host",
        .app_name = "pz",
        .procid = "1",
        .msgid = "AUDIT",
        .msg = "dns-rebind",
    }));
}
