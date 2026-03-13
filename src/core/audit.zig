const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const integrity = @import("audit_integrity.zig");
const syslog = @import("syslog.zig");

pub const ver_current: u16 = 1;

pub const Vis = enum {
    @"pub",
    mask,
    hash,
    secret,
};

pub const Sev = enum {
    debug,
    info,
    notice,
    warn,
    err,
    crit,
};

pub const Out = enum {
    ok,
    deny,
    fail,
};

pub const Kind = enum {
    sess,
    turn,
    tool,
    policy,
    auth,
    ship,
};

pub const Str = struct {
    text: []const u8,
    vis: Vis = .@"pub",
};

pub const Site = struct {
    host: ?[]const u8 = null,
    app: ?[]const u8 = null,
    pid: ?u32 = null,
};

pub const ActorKind = enum {
    user,
    agent,
    tool,
    sys,
};

pub const Actor = struct {
    kind: ActorKind,
    id: ?Str = null,
    role: ?[]const u8 = null,
};

pub const ResKind = enum {
    sess,
    turn,
    file,
    cmd,
    net,
    auth,
    cfg,
    ship,
};

pub const Res = struct {
    kind: ResKind,
    name: Str,
    op: ?[]const u8 = null,
};

pub const Val = union(enum) {
    str: []const u8,
    int: i64,
    uint: u64,
    bool: bool,
};

pub const Attr = struct {
    key: []const u8,
    vis: Vis = .@"pub",
    val: Val,
};

pub const SessOp = enum {
    start,
    @"resume",
    stop,
    compact,
};

pub const SessData = struct {
    op: SessOp,
    tty: bool = false,
    wd: ?Str = null,
};

pub const TurnPhase = enum {
    prompt,
    dispatch,
    stream,
    done,
};

pub const TurnData = struct {
    idx: u32,
    phase: TurnPhase,
    model: ?[]const u8 = null,
};

pub const ToolData = struct {
    name: Str,
    call_id: ?[]const u8 = null,
    argv: ?Str = null,
    code: ?i32 = null,
    ms: ?u32 = null,
};

pub const PolicyEff = enum {
    allow,
    deny,
};

pub const PolicyData = struct {
    eff: PolicyEff,
    rule: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

pub const AuthData = struct {
    mech: []const u8,
    sub: ?Str = null,
};

pub const ShipData = struct {
    proto: []const u8,
    batch: u32,
    dst: Str,
    len: u32,
};

pub const Data = union(Kind) {
    sess: SessData,
    turn: TurnData,
    tool: ToolData,
    policy: PolicyData,
    auth: AuthData,
    ship: ShipData,
};

pub const Entry = struct {
    version: u16 = ver_current,
    ts_ms: i64,
    sid: []const u8,
    seq: u64,
    sev: Sev = .info,
    out: Out = .ok,
    site: Site = .{},
    actor: Actor = .{ .kind = .sys },
    res: ?Res = null,
    msg: ?Str = null,
    data: Data,
    attrs: []const Attr = &.{},
};

pub fn kindOf(ent: Entry) Kind {
    return std.meta.activeTag(ent.data);
}

pub fn needsRedact(ent: Entry) bool {
    if (ent.actor.id) |id| {
        if (id.vis != .@"pub") return true;
    }
    if (ent.res) |res| {
        if (res.name.vis != .@"pub") return true;
    }
    if (ent.msg) |msg| {
        if (msg.vis != .@"pub") return true;
    }
    if (dataNeedsRedact(ent.data)) return true;
    for (ent.attrs) |attr| {
        if (attr.vis != .@"pub") return true;
    }
    return false;
}

pub const FrameOpts = struct {
    facility: syslog.Facility = .audit,
    hostname: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    procid: ?[]const u8 = null,
    msgid: []const u8 = "audit",
    sd_id: []const u8 = "pz@32473",
};

pub const FrameHdr = struct {
    ts_ms: i64,
    sid: []const u8,
    seq: u64,
    sev: Sev = .info,
    site: Site = .{},
};

pub const ConnVTable = struct {
    sendRaw: *const fn (ctx: *anyopaque, raw: []const u8) anyerror!void,
    deinit: *const fn (ctx: *anyopaque) void,
};

pub const Conn = struct {
    ctx: *anyopaque,
    vtable: *const ConnVTable,

    pub fn sendRaw(self: Conn, raw: []const u8) !void {
        try self.vtable.sendRaw(self.ctx, raw);
    }

    pub fn deinit(self: Conn) void {
        self.vtable.deinit(self.ctx);
    }
};

pub const Connector = struct {
    ctx: *anyopaque,
    connect: *const fn (ctx: *anyopaque) anyerror!Conn,
};

pub const ShipOpts = struct {
    connector: Connector,
    buf_cap: usize = 64,
    backoff_min_ms: u32 = 100,
    backoff_max_ms: u32 = 5_000,
};

pub const SendState = enum {
    sent,
    buffered,
};

pub const SendRes = struct {
    state: SendState,
    flushed: usize = 0,
    queued: usize = 0,
    dropped: usize = 0,
    err: ?anyerror = null,
    connected: bool = false,
    next_retry_ms: ?i64 = null,
};

pub const FlushRes = struct {
    sent: usize = 0,
    queued: usize = 0,
    err: ?anyerror = null,
    connected: bool = false,
    next_retry_ms: ?i64 = null,
};

pub const Stats = struct {
    connected: bool,
    queued: usize,
    dropped: u64,
    backoff_ms: u32,
    next_retry_ms: ?i64,
};

const BufPush = struct {
    dropped: usize = 0,
};

const ConnTry = struct {
    ok: bool = false,
    err: ?anyerror = null,
};

const Ring = struct {
    alloc: Allocator,
    slots: []?[]u8,
    head: usize = 0,
    len: usize = 0,
    dropped: u64 = 0,

    fn init(alloc: Allocator, cap: usize) !Ring {
        if (cap == 0) {
            return .{
                .alloc = alloc,
                .slots = &[_]?[]u8{},
            };
        }

        const slots = try alloc.alloc(?[]u8, cap);
        @memset(slots, null);
        return .{
            .alloc = alloc,
            .slots = slots,
        };
    }

    fn deinit(self: *Ring) void {
        while (self.len > 0) self.pop();
        if (self.slots.len > 0) self.alloc.free(self.slots);
        self.* = undefined;
    }

    fn push(self: *Ring, raw: []const u8) !BufPush {
        if (self.slots.len == 0) {
            self.dropped += 1;
            return .{ .dropped = 1 };
        }

        const dup = try self.alloc.dupe(u8, raw);
        if (self.len == self.slots.len) {
            const idx = self.head;
            self.alloc.free(self.slots[idx].?);
            self.slots[idx] = dup;
            self.head = nextIdx(self.slots.len, idx);
            self.dropped += 1;
            return .{ .dropped = 1 };
        }

        const idx = (self.head + self.len) % self.slots.len;
        self.slots[idx] = dup;
        self.len += 1;
        return .{};
    }

    fn peek(self: *const Ring) ?[]const u8 {
        if (self.len == 0) return null;
        return self.slots[self.head].?;
    }

    fn pop(self: *Ring) void {
        const idx = self.head;
        self.alloc.free(self.slots[idx].?);
        self.slots[idx] = null;
        self.head = nextIdx(self.slots.len, idx);
        self.len -= 1;
    }
};

pub const ReconnSender = struct {
    alloc: Allocator,
    connr: Connector,
    conn: ?Conn = null,
    ring: Ring,
    backoff_min_ms: u32,
    backoff_max_ms: u32,
    backoff_ms: u32,
    next_retry_ms: ?i64 = null,

    pub fn init(alloc: Allocator, opts: ShipOpts) !ReconnSender {
        if (opts.backoff_min_ms == 0 or opts.backoff_max_ms < opts.backoff_min_ms) {
            return error.InvalidBackoff;
        }

        return .{
            .alloc = alloc,
            .connr = opts.connector,
            .ring = try Ring.init(alloc, opts.buf_cap),
            .backoff_min_ms = opts.backoff_min_ms,
            .backoff_max_ms = opts.backoff_max_ms,
            .backoff_ms = opts.backoff_min_ms,
        };
    }

    pub fn deinit(self: *ReconnSender) void {
        self.dropConn();
        self.ring.deinit();
        self.* = undefined;
    }

    pub fn stats(self: *const ReconnSender) Stats {
        return .{
            .connected = self.conn != null,
            .queued = self.ring.len,
            .dropped = self.ring.dropped,
            .backoff_ms = self.backoff_ms,
            .next_retry_ms = self.next_retry_ms,
        };
    }

    pub fn sendRaw(self: *ReconnSender, raw: []const u8, now_ms: i64) !SendRes {
        if (self.conn == null or self.ring.len > 0) {
            const conn = try self.tryConn(now_ms);
            if (!conn.ok) {
                const push = try self.ring.push(raw);
                return .{
                    .state = .buffered,
                    .queued = self.ring.len,
                    .dropped = push.dropped,
                    .err = conn.err,
                    .connected = false,
                    .next_retry_ms = self.next_retry_ms,
                };
            }

            if (self.ring.len > 0) {
                const push = try self.ring.push(raw);
                const fl = try self.flushLive(now_ms);
                return .{
                    .state = if (self.ring.len == 0) .sent else .buffered,
                    .flushed = fl.sent,
                    .queued = fl.queued,
                    .dropped = push.dropped,
                    .err = fl.err,
                    .connected = fl.connected,
                    .next_retry_ms = fl.next_retry_ms,
                };
            }
        }

        self.conn.?.sendRaw(raw) catch |err| {
            self.dropConn();
            self.noteFail(now_ms);
            const push = try self.ring.push(raw);
            return .{
                .state = .buffered,
                .queued = self.ring.len,
                .dropped = push.dropped,
                .err = err,
                .connected = false,
                .next_retry_ms = self.next_retry_ms,
            };
        };

        return .{
            .state = .sent,
            .queued = self.ring.len,
            .connected = true,
        };
    }

    pub fn flush(self: *ReconnSender, now_ms: i64) !FlushRes {
        const conn = try self.tryConn(now_ms);
        if (!conn.ok) {
            return .{
                .queued = self.ring.len,
                .err = conn.err,
                .connected = false,
                .next_retry_ms = self.next_retry_ms,
            };
        }
        return try self.flushLive(now_ms);
    }

    fn tryConn(self: *ReconnSender, now_ms: i64) !ConnTry {
        if (self.conn != null) return .{ .ok = true };
        if (self.next_retry_ms) |retry_ms| {
            if (now_ms < retry_ms) return .{};
        }

        self.conn = self.connr.connect(self.connr.ctx) catch |err| {
            self.noteFail(now_ms);
            return .{ .err = err };
        };
        self.next_retry_ms = null;
        self.backoff_ms = self.backoff_min_ms;
        return .{ .ok = true };
    }

    fn flushLive(self: *ReconnSender, now_ms: i64) !FlushRes {
        var sent: usize = 0;
        while (self.ring.peek()) |raw| {
            self.conn.?.sendRaw(raw) catch |err| {
                self.dropConn();
                self.noteFail(now_ms);
                return .{
                    .sent = sent,
                    .queued = self.ring.len,
                    .err = err,
                    .connected = false,
                    .next_retry_ms = self.next_retry_ms,
                };
            };
            self.ring.pop();
            sent += 1;
        }

        return .{
            .sent = sent,
            .queued = self.ring.len,
            .connected = true,
        };
    }

    fn noteFail(self: *ReconnSender, now_ms: i64) void {
        const retry_ms: i64 = self.backoff_ms;
        self.next_retry_ms = std.math.add(i64, now_ms, retry_ms) catch std.math.maxInt(i64);

        if (self.backoff_ms < self.backoff_max_ms) {
            const next = @as(u64, self.backoff_ms) * 2;
            self.backoff_ms = if (next >= self.backoff_max_ms) self.backoff_max_ms else @intCast(next);
        }
    }

    fn dropConn(self: *ReconnSender) void {
        if (self.conn) |conn| conn.deinit();
        self.conn = null;
    }
};

pub const SyslogShipper = struct {
    alloc: Allocator,
    frame: FrameOpts,
    reconn: ReconnSender,

    pub fn init(alloc: Allocator, frame: FrameOpts, opts: ShipOpts) !SyslogShipper {
        return .{
            .alloc = alloc,
            .frame = frame,
            .reconn = try ReconnSender.init(alloc, opts),
        };
    }

    pub fn deinit(self: *SyslogShipper) void {
        self.reconn.deinit();
        self.* = undefined;
    }

    pub fn send(self: *SyslogShipper, ent: Entry, now_ms: i64) !SendRes {
        const raw = try encodeFrameAlloc(self.alloc, self.frame, ent);
        defer self.alloc.free(raw);
        return try self.reconn.sendRaw(raw, now_ms);
    }

    pub fn flush(self: *SyslogShipper, now_ms: i64) !FlushRes {
        return try self.reconn.flush(now_ms);
    }

    pub fn stats(self: *const SyslogShipper) Stats {
        return self.reconn.stats();
    }
};

pub const SenderConnector = struct {
    alloc: Allocator,
    opts: syslog.SenderOpts,

    pub fn connector(self: *SenderConnector) Connector {
        return .{
            .ctx = self,
            .connect = &connect,
        };
    }

    const Peer = struct {
        alloc: Allocator,
        sender: syslog.Sender,
    };

    const peer_vt = ConnVTable{
        .sendRaw = peerSendRaw,
        .deinit = peerDeinit,
    };

    fn connect(ctx: *anyopaque) !Conn {
        const self: *SenderConnector = @ptrCast(@alignCast(ctx));
        const peer = try self.alloc.create(Peer);
        errdefer self.alloc.destroy(peer);

        peer.* = .{
            .alloc = self.alloc,
            .sender = try syslog.Sender.init(self.alloc, self.opts),
        };
        return .{
            .ctx = peer,
            .vtable = &peer_vt,
        };
    }

    fn peerSendRaw(ctx: *anyopaque, raw: []const u8) !void {
        const peer: *Peer = @ptrCast(@alignCast(ctx));
        try peer.sender.sendRaw(raw);
    }

    fn peerDeinit(ctx: *anyopaque) void {
        const peer: *Peer = @ptrCast(@alignCast(ctx));
        const alloc = peer.alloc;
        peer.sender.deinit();
        alloc.destroy(peer);
    }
};

pub fn encodeFrameAlloc(alloc: Allocator, opts: FrameOpts, ent: Entry) ![]u8 {
    const body = try encodeAlloc(alloc, ent);
    defer alloc.free(body);

    return try encodeFrameBodyAlloc(alloc, opts, .{
        .ts_ms = ent.ts_ms,
        .sid = ent.sid,
        .seq = ent.seq,
        .sev = ent.sev,
        .site = ent.site,
    }, body);
}

pub fn encodeFrameBodyAlloc(alloc: Allocator, opts: FrameOpts, hdr: FrameHdr, body: []const u8) ![]u8 {
    var pid_buf: [32]u8 = undefined;
    const procid = blk: {
        if (hdr.site.pid) |pid| break :blk try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
        if (opts.procid) |procid| break :blk procid;
        break :blk syslog.nil;
    };

    var seq_buf: [32]u8 = undefined;
    const seq = try std.fmt.bufPrint(&seq_buf, "{d}", .{hdr.seq});

    return try syslog.encodeAlloc(alloc, .{
        .pri = .{
            .facility = opts.facility,
            .severity = sevSyslog(hdr.sev),
        },
        .timestamp_ms = hdr.ts_ms,
        .hostname = hdr.site.host orelse opts.hostname orelse syslog.nil,
        .app_name = hdr.site.app orelse opts.app_name orelse syslog.nil,
        .procid = procid,
        .msgid = opts.msgid,
        .structured_data = &.{
            .{
                .id = opts.sd_id,
                .params = &.{
                    .{ .name = "sid", .value = hdr.sid },
                    .{ .name = "seq", .value = seq },
                },
            },
        },
        .msg = body,
    });
}

pub fn encodeAlloc(alloc: Allocator, ent: Entry) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    try writeEntry(buf.writer(alloc), ent);
    return try buf.toOwnedSlice(alloc);
}

pub fn sealAlloc(
    alloc: Allocator,
    ent: Entry,
    key: integrity.Key,
    prev: ?integrity.Tag,
) ![]u8 {
    const body = try encodeAlloc(alloc, ent);
    defer alloc.free(body);
    return try integrity.sealAlloc(alloc, key, prev, body);
}

pub fn writeEntry(w: anytype, ent: Entry) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "v");
    try w.print("{d}", .{ent.version});

    try writeObjKey(w, &first, "ts_ms");
    try w.print("{d}", .{ent.ts_ms});

    try writeObjKey(w, &first, "sid");
    try writeJsonStr(w, ent.sid);

    try writeObjKey(w, &first, "seq");
    try w.print("{d}", .{ent.seq});

    try writeObjKey(w, &first, "kind");
    try writeJsonStr(w, @tagName(kindOf(ent)));

    try writeObjKey(w, &first, "sev");
    try writeJsonStr(w, @tagName(ent.sev));

    try writeObjKey(w, &first, "out");
    try writeJsonStr(w, @tagName(ent.out));

    if (hasSite(ent.site)) {
        try writeObjKey(w, &first, "site");
        try writeSite(w, ent.site);
    }

    try writeObjKey(w, &first, "actor");
    try writeActor(w, ent.actor);

    if (ent.res) |res| {
        try writeObjKey(w, &first, "res");
        try writeRes(w, res);
    }

    if (ent.msg) |msg| {
        try writeObjKey(w, &first, "msg");
        try writeStr(w, msg);
    }

    try writeObjKey(w, &first, "data");
    try writeData(w, ent.data);

    try writeObjKey(w, &first, "attrs");
    try writeAttrs(w, ent.attrs);

    try w.writeByte('}');
}

fn dataNeedsRedact(data: Data) bool {
    return switch (data) {
        .sess => |v| if (v.wd) |wd| wd.vis != .@"pub" else false,
        .turn => false,
        .tool => |v| blk: {
            if (v.name.vis != .@"pub") break :blk true;
            if (v.argv) |argv| {
                if (argv.vis != .@"pub") break :blk true;
            }
            break :blk false;
        },
        .policy => false,
        .auth => |v| if (v.sub) |sub| sub.vis != .@"pub" else false,
        .ship => |v| v.dst.vis != .@"pub",
    };
}

fn sevSyslog(sev: Sev) syslog.Severity {
    return switch (sev) {
        .debug => .debug,
        .info => .info,
        .notice => .notice,
        .warn => .warning,
        .err => .err,
        .crit => .critical,
    };
}

fn nextIdx(cap: usize, idx: usize) usize {
    if (cap == 0) return 0;
    return (idx + 1) % cap;
}

fn hasSite(site: Site) bool {
    return site.host != null or site.app != null or site.pid != null;
}

fn writeSite(w: anytype, site: Site) !void {
    try w.writeByte('{');
    var first = true;
    if (site.host) |host| {
        try writeObjKey(w, &first, "host");
        try writeJsonStr(w, host);
    }
    if (site.app) |app| {
        try writeObjKey(w, &first, "app");
        try writeJsonStr(w, app);
    }
    if (site.pid) |pid| {
        try writeObjKey(w, &first, "pid");
        try w.print("{d}", .{pid});
    }
    try w.writeByte('}');
}

fn writeActor(w: anytype, actor: Actor) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "kind");
    try writeJsonStr(w, @tagName(actor.kind));

    if (actor.id) |id| {
        try writeObjKey(w, &first, "id");
        try writeStr(w, id);
    }
    if (actor.role) |role| {
        try writeObjKey(w, &first, "role");
        try writeJsonStr(w, role);
    }
    try w.writeByte('}');
}

fn writeRes(w: anytype, res: Res) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "kind");
    try writeJsonStr(w, @tagName(res.kind));

    try writeObjKey(w, &first, "name");
    try writeStr(w, res.name);

    if (res.op) |op| {
        try writeObjKey(w, &first, "op");
        try writeJsonStr(w, op);
    }
    try w.writeByte('}');
}

const path_marks = [_][]const u8{
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".aws/credentials",
    ".kube/config",
    ".npmrc",
    ".netrc",
    ".pypirc",
    ".env",
    ".docker/config.json",
    ".pz/auth.json",
    ".pz/policy.json",
    ".pz/settings.json",
};

const secret_marks = [_][]const u8{
    "authorization:",
    "authorization=",
    "bearer ",
    "cookie:",
    "cookie=",
    "access_token",
    "refresh_token",
    "id_token",
    "oauth_token",
    "session_token",
    "token=",
    "api_key",
    "api-key",
    "apikey",
    "x-api-key",
    "x-auth-token",
    "client_secret",
    "secret_key",
    "private_key",
    "password",
    "passwd",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
};

fn containsNoCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn hasAnyNoCase(hay: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (containsNoCase(hay, needle)) return true;
    }
    return false;
}

fn hasAny(hay: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.mem.indexOf(u8, hay, needle) != null) return true;
    }
    return false;
}

fn detectPubRedact(txt: []const u8) ?[]const u8 {
    if (hasAnyNoCase(txt, &path_marks)) return "path";
    if (hasAnyNoCase(txt, &secret_marks) or
        hasAny(txt, &.{
            "sk-",
            "ghp_",
            "gho_",
            "ghs_",
            "ghu_",
            "github_pat_",
            "xoxb-",
            "xoxp-",
            "AKIA",
            "ASIA",
        })) return "secret";
    return null;
}

fn taggedTextAlloc(alloc: Allocator, tag: []const u8, txt: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "[{s}:{x:0>16}]", .{ tag, std.hash.Wyhash.hash(0, txt) });
}

pub fn redactTextAlloc(alloc: Allocator, txt: []const u8, vis: Vis) ![]u8 {
    return switch (vis) {
        .@"pub" => if (detectPubRedact(txt)) |tag|
            try taggedTextAlloc(alloc, tag, txt)
        else
            try alloc.dupe(u8, txt),
        .mask => try taggedTextAlloc(alloc, "mask", txt),
        .hash => try taggedTextAlloc(alloc, "hash", txt),
        .secret => try taggedTextAlloc(alloc, "secret", txt),
    };
}

fn writeTaggedJsonStr(w: anytype, tag: []const u8, txt: []const u8) !void {
    var hash_buf: [16]u8 = undefined;
    const hash_txt = try std.fmt.bufPrint(&hash_buf, "{x:0>16}", .{std.hash.Wyhash.hash(0, txt)});
    var tag_buf: [32]u8 = undefined;
    const out = try std.fmt.bufPrint(&tag_buf, "[{s}:{s}]", .{ tag, hash_txt });
    try writeJsonStr(w, out);
}

fn writeVisText(w: anytype, txt: []const u8, vis: Vis) !void {
    switch (vis) {
        .@"pub" => {
            if (detectPubRedact(txt)) |tag| {
                try writeTaggedJsonStr(w, tag, txt);
            } else {
                try writeJsonStr(w, txt);
            }
        },
        .mask => try writeTaggedJsonStr(w, "mask", txt),
        .hash => try writeTaggedJsonStr(w, "hash", txt),
        .secret => try writeTaggedJsonStr(w, "secret", txt),
    }
}

fn writeStr(w: anytype, s: Str) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "text");
    try writeVisText(w, s.text, s.vis);

    try writeObjKey(w, &first, "vis");
    try writeJsonStr(w, @tagName(s.vis));

    try w.writeByte('}');
}

fn writeAttrs(w: anytype, attrs: []const Attr) !void {
    try w.writeByte('[');
    for (attrs, 0..) |attr, i| {
        if (i > 0) try w.writeByte(',');
        try writeAttr(w, attr);
    }
    try w.writeByte(']');
}

fn writeAttr(w: anytype, attr: Attr) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "key");
    try writeJsonStr(w, attr.key);

    try writeObjKey(w, &first, "vis");
    try writeJsonStr(w, @tagName(attr.vis));

    switch (attr.val) {
        .str => |v| {
            try writeObjKey(w, &first, "ty");
            try writeJsonStr(w, "str");
            try writeObjKey(w, &first, "val");
            try writeVisText(w, v, attr.vis);
        },
        .int => |v| {
            try writeObjKey(w, &first, "ty");
            try writeJsonStr(w, "int");
            try writeObjKey(w, &first, "val");
            try w.print("{d}", .{v});
        },
        .uint => |v| {
            try writeObjKey(w, &first, "ty");
            try writeJsonStr(w, "uint");
            try writeObjKey(w, &first, "val");
            try w.print("{d}", .{v});
        },
        .bool => |v| {
            try writeObjKey(w, &first, "ty");
            try writeJsonStr(w, "bool");
            try writeObjKey(w, &first, "val");
            try w.writeAll(if (v) "true" else "false");
        },
    }

    try w.writeByte('}');
}

fn writeData(w: anytype, data: Data) !void {
    try w.writeByte('{');
    var first = true;

    switch (data) {
        .sess => |v| {
            try writeObjKey(w, &first, "op");
            try writeJsonStr(w, @tagName(v.op));

            try writeObjKey(w, &first, "tty");
            try w.writeAll(if (v.tty) "true" else "false");

            if (v.wd) |wd| {
                try writeObjKey(w, &first, "wd");
                try writeStr(w, wd);
            }
        },
        .turn => |v| {
            try writeObjKey(w, &first, "idx");
            try w.print("{d}", .{v.idx});

            try writeObjKey(w, &first, "phase");
            try writeJsonStr(w, @tagName(v.phase));

            if (v.model) |model| {
                try writeObjKey(w, &first, "model");
                try writeJsonStr(w, model);
            }
        },
        .tool => |v| {
            try writeObjKey(w, &first, "name");
            try writeStr(w, v.name);

            if (v.call_id) |call_id| {
                try writeObjKey(w, &first, "call_id");
                try writeJsonStr(w, call_id);
            }
            if (v.argv) |argv| {
                try writeObjKey(w, &first, "argv");
                try writeStr(w, argv);
            }
            if (v.code) |code| {
                try writeObjKey(w, &first, "code");
                try w.print("{d}", .{code});
            }
            if (v.ms) |ms| {
                try writeObjKey(w, &first, "ms");
                try w.print("{d}", .{ms});
            }
        },
        .policy => |v| {
            try writeObjKey(w, &first, "eff");
            try writeJsonStr(w, @tagName(v.eff));

            if (v.rule) |rule| {
                try writeObjKey(w, &first, "rule");
                try writeJsonStr(w, rule);
            }
            if (v.scope) |scope| {
                try writeObjKey(w, &first, "scope");
                try writeJsonStr(w, scope);
            }
        },
        .auth => |v| {
            try writeObjKey(w, &first, "mech");
            try writeJsonStr(w, v.mech);

            if (v.sub) |sub| {
                try writeObjKey(w, &first, "sub");
                try writeStr(w, sub);
            }
        },
        .ship => |v| {
            try writeObjKey(w, &first, "proto");
            try writeJsonStr(w, v.proto);

            try writeObjKey(w, &first, "batch");
            try w.print("{d}", .{v.batch});

            try writeObjKey(w, &first, "dst");
            try writeStr(w, v.dst);

            try writeObjKey(w, &first, "len");
            try w.print("{d}", .{v.len});
        },
    }

    try w.writeByte('}');
}

fn writeObjKey(w: anytype, first: *bool, key: []const u8) !void {
    if (!first.*) try w.writeByte(',');
    first.* = false;
    try writeJsonStr(w, key);
    try w.writeByte(':');
}

fn writeJsonStr(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\x08' => try w.writeAll("\\b"),
            '\x0c' => try w.writeAll("\\f"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...0x07, 0x0b, 0x0e...0x1f => {
                const hex = "0123456789abcdef";
                const esc = [6]u8{
                    '\\',
                    'u',
                    '0',
                    '0',
                    hex[c >> 4],
                    hex[c & 0x0f],
                };
                try w.writeAll(&esc);
            },
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

test "snapshot: canonical tool entry encoding" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const attrs = [_]Attr{
        .{ .key = "cache_hit", .val = .{ .bool = false } },
        .{ .key = "bytes", .val = .{ .uint = 512 } },
        .{ .key = "stderr", .vis = .mask, .val = .{ .str = "permission denied" } },
    };

    const ent = Entry{
        .ts_ms = 1_731_000_000_123,
        .sid = "sess-01",
        .seq = 7,
        .sev = .warn,
        .out = .fail,
        .site = .{
            .host = "mbp",
            .app = "pz",
            .pid = 4242,
        },
        .actor = .{
            .kind = .agent,
            .id = .{ .text = "codex", .vis = .@"pub" },
            .role = "runner",
        },
        .res = .{
            .kind = .file,
            .name = .{ .text = "src/core/audit.zig", .vis = .mask },
            .op = "write",
        },
        .msg = .{ .text = "tool failed", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "exec_command", .vis = .@"pub" },
                .call_id = "toolu_01",
                .argv = .{ .text = "cat ~/.ssh/id_rsa", .vis = .secret },
                .code = 1,
                .ms = 29,
            },
        },
        .attrs = &attrs,
    };

    const raw = try encodeAlloc(talloc, ent);
    defer talloc.free(raw);

    const snap = try std.fmt.allocPrint(talloc, "kind={s} | redact={s} | json={s}", .{
        @tagName(kindOf(ent)),
        if (needsRedact(ent)) "true" else "false",
        raw,
    });
    defer talloc.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "kind=tool | redact=true | json={"v":1,"ts_ms":1731000000123,"sid":"sess-01","seq":7,"kind":"tool","sev":"warn","out":"fail","site":{"host":"mbp","app":"pz","pid":4242},"actor":{"kind":"agent","id":{"text":"codex","vis":"pub"},"role":"runner"},"res":{"kind":"file","name":{"text":"[mask:2aa5dc7ee92f3807]","vis":"mask"},"op":"write"},"msg":{"text":"tool failed","vis":"pub"},"data":{"name":{"text":"exec_command","vis":"pub"},"call_id":"toolu_01","argv":{"text":"[secret:8c3b19aca7d7c3f8]","vis":"secret"},"code":1,"ms":29},"attrs":[{"key":"cache_hit","vis":"pub","ty":"bool","val":false},{"key":"bytes","vis":"pub","ty":"uint","val":512},{"key":"stderr","vis":"mask","ty":"str","val":"[mask:bdfd41dd2fcacdeb]"}]}"
    ).expectEqual(snap);
}

test "detectPubRedact flags expanded secret markers" {
    try testing.expectEqualStrings("secret", detectPubRedact("client_secret=s3cr3t").?);
    try testing.expectEqualStrings("secret", detectPubRedact("password=letmein").?);
    try testing.expectEqualStrings("secret", detectPubRedact("GET /cb?token=abc").?);
    try testing.expectEqualStrings("secret", detectPubRedact("github_pat_deadbeef").?);
}

test "detectPubRedact flags expanded path markers" {
    try testing.expectEqualStrings("path", detectPubRedact("cat ~/.kube/config").?);
    try testing.expectEqualStrings("path", detectPubRedact("load .env before start").?);
    try testing.expectEqualStrings("path", detectPubRedact("npm token lives in .npmrc").?);
}

test "property: redactTextAlloc leaves plain ids unchanged" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            const txt = args.s.slice();
            const red = redactTextAlloc(testing.allocator, txt, .@"pub") catch return false;
            defer testing.allocator.free(red);
            return std.mem.eql(u8, txt, red);
        }
    }.prop, .{ .iterations = 1000 });
}

test "property: redactTextAlloc hides secret-bearing text" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            const txt = std.fmt.allocPrint(testing.allocator, "authorization: bearer {s}", .{args.s.slice()}) catch return false;
            defer testing.allocator.free(txt);
            const red = redactTextAlloc(testing.allocator, txt, .@"pub") catch return false;
            defer testing.allocator.free(red);
            return std.mem.indexOf(u8, red, "[secret:") != null and std.mem.indexOf(u8, red, args.s.slice()) == null;
        }
    }.prop, .{ .iterations = 1000 });
}

test "property: redactTextAlloc hides path-bearing text" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            const txt = std.fmt.allocPrint(testing.allocator, "cp /tmp/{s}/.env backup", .{args.s.slice()}) catch return false;
            defer testing.allocator.free(txt);
            const red = redactTextAlloc(testing.allocator, txt, .@"pub") catch return false;
            defer testing.allocator.free(red);
            return std.mem.indexOf(u8, red, "[path:") != null and std.mem.indexOf(u8, red, args.s.slice()) == null;
        }
    }.prop, .{ .iterations = 1000 });
}

test "redactTextAlloc with mask emits tagged surrogate" {
    const red = try redactTextAlloc(testing.allocator, "plain text", .mask);
    defer testing.allocator.free(red);
    try testing.expect(std.mem.indexOf(u8, red, "[mask:") != null);
    try testing.expect(!std.mem.eql(u8, red, "plain text"));
}

test "snapshot: variant encodings stay canonical" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const sess_raw = try encodeAlloc(talloc, .{
        .ts_ms = 10,
        .sid = "sess-a",
        .seq = 1,
        .data = .{
            .sess = .{
                .op = .start,
                .tty = true,
                .wd = .{ .text = "/repo", .vis = .mask },
            },
        },
    });
    defer talloc.free(sess_raw);

    const policy_raw = try encodeAlloc(talloc, .{
        .ts_ms = 11,
        .sid = "sess-a",
        .seq = 2,
        .out = .deny,
        .actor = .{
            .kind = .sys,
        },
        .res = .{
            .kind = .file,
            .name = .{ .text = ".pz/secrets", .vis = .secret },
            .op = "read",
        },
        .data = .{
            .policy = .{
                .eff = .deny,
                .rule = "*.audit.log",
                .scope = "path",
            },
        },
    });
    defer talloc.free(policy_raw);

    const auth_raw = try encodeAlloc(talloc, .{
        .ts_ms = 12,
        .sid = "sess-a",
        .seq = 3,
        .sev = .notice,
        .actor = .{
            .kind = .user,
            .id = .{ .text = "joel", .vis = .@"pub" },
        },
        .data = .{
            .auth = .{
                .mech = "oauth",
                .sub = .{ .text = "user@example.com", .vis = .hash },
            },
        },
    });
    defer talloc.free(auth_raw);

    const ship_raw = try encodeAlloc(talloc, .{
        .ts_ms = 13,
        .sid = "sess-a",
        .seq = 4,
        .sev = .info,
        .data = .{
            .ship = .{
                .proto = "syslog+tls",
                .batch = 8,
                .dst = .{ .text = "siem.internal:6514", .vis = .mask },
                .len = 1420,
            },
        },
        .attrs = &.{
            .{ .key = "retry", .val = .{ .uint = 1 } },
        },
    });
    defer talloc.free(ship_raw);

    const snap = try std.fmt.allocPrint(talloc, "sess={s} | policy={s} | auth={s} | ship={s}", .{
        sess_raw,
        policy_raw,
        auth_raw,
        ship_raw,
    });
    defer talloc.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "sess={"v":1,"ts_ms":10,"sid":"sess-a","seq":1,"kind":"sess","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"op":"start","tty":true,"wd":{"text":"[mask:47a56333843b7ed0]","vis":"mask"}},"attrs":[]} | policy={"v":1,"ts_ms":11,"sid":"sess-a","seq":2,"kind":"policy","sev":"info","out":"deny","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[secret:cb01a7199946da94]","vis":"secret"},"op":"read"},"data":{"eff":"deny","rule":"*.audit.log","scope":"path"},"attrs":[]} | auth={"v":1,"ts_ms":12,"sid":"sess-a","seq":3,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"user","id":{"text":"joel","vis":"pub"}},"data":{"mech":"oauth","sub":{"text":"[hash:ce3e6e686cd0c59f]","vis":"hash"}},"attrs":[]} | ship={"v":1,"ts_ms":13,"sid":"sess-a","seq":4,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":8,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":1420},"attrs":[{"key":"retry","vis":"pub","ty":"uint","val":1}]}"
    ).expectEqual(snap);
}

test "property: public secret markers always redact" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { tail: zc.Id }) bool {
            const alloc = testing.allocator;
            const raw = std.fmt.allocPrint(alloc, "authorization=Bearer sk-{s}", .{args.tail.slice()}) catch return false;
            defer alloc.free(raw);
            const out = redactTextAlloc(alloc, raw, .@"pub") catch return false;
            defer alloc.free(out);
            return std.mem.startsWith(u8, out, "[secret:") and
                std.mem.indexOf(u8, out, "authorization") == null and
                std.mem.indexOf(u8, out, "sk-") == null;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: public protected paths always redact" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { name: zc.Id }) bool {
            const alloc = testing.allocator;
            const raw = std.fmt.allocPrint(alloc, "cp ~/.ssh/{s} ~/.cache/copy", .{args.name.slice()}) catch return false;
            defer alloc.free(raw);
            const out = redactTextAlloc(alloc, raw, .@"pub") catch return false;
            defer alloc.free(out);
            return std.mem.startsWith(u8, out, "[path:") and
                std.mem.indexOf(u8, out, ".ssh/") == null;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: plain public ids stay visible" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { txt: zc.Id }) bool {
            const alloc = testing.allocator;
            const raw = args.txt.slice();
            const out = redactTextAlloc(alloc, raw, .@"pub") catch return false;
            defer alloc.free(out);
            return std.mem.eql(u8, out, raw);
        }
    }.prop, .{ .iterations = 500 });
}

test "encoding escapes control bytes and stays stable" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const ent = Entry{
        .ts_ms = 77,
        .sid = "sess-b",
        .seq = 9,
        .msg = .{ .text = "line\n\x01\t", .vis = .mask },
        .data = .{
            .turn = .{
                .idx = 3,
                .phase = .done,
                .model = "gpt-5",
            },
        },
        .attrs = &.{
            .{ .key = "ctrl", .vis = .mask, .val = .{ .str = "a\n\x02b" } },
            .{ .key = "delta", .val = .{ .int = -4 } },
        },
    };

    const raw_a = try encodeAlloc(talloc, ent);
    defer talloc.free(raw_a);
    const raw_b = try encodeAlloc(talloc, ent);
    defer talloc.free(raw_b);

    try testing.expectEqualStrings(raw_a, raw_b);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":77,"sid":"sess-b","seq":9,"kind":"turn","sev":"info","out":"ok","actor":{"kind":"sys"},"msg":{"text":"[mask:aba5f20f2fb92386]","vis":"mask"},"data":{"idx":3,"phase":"done","model":"gpt-5"},"attrs":[{"key":"ctrl","vis":"mask","ty":"str","val":"[mask:31310066477309fa]"},{"key":"delta","vis":"pub","ty":"int","val":-4}]}"
    ).expectEqual(raw_a);
}

test "snapshot: runtime control entries encode canonically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const cfg_raw = try encodeAlloc(talloc, .{
        .ts_ms = 88,
        .sid = "runtime",
        .seq = 1,
        .sev = .notice,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .cfg,
            .name = .{ .text = "runtime", .vis = .@"pub" },
            .op = "model",
        },
        .msg = .{ .text = "runtime control success", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "runtime", .vis = .@"pub" },
                .call_id = "model",
                .argv = .{ .text = "claude-opus-4-6", .vis = .@"pub" },
            },
        },
        .attrs = &.{
            .{ .key = "provider", .val = .{ .str = "anthropic" } },
        },
    });
    defer talloc.free(cfg_raw);

    const sess_raw = try encodeAlloc(talloc, .{
        .ts_ms = 89,
        .sid = "runtime",
        .seq = 2,
        .sev = .err,
        .out = .fail,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .sess,
            .name = .{ .text = "session", .vis = .@"pub" },
            .op = "resume",
        },
        .msg = .{ .text = "SessionNotFound", .vis = .mask },
        .data = .{
            .tool = .{
                .name = .{ .text = "runtime", .vis = .@"pub" },
                .call_id = "resume",
                .argv = .{ .text = "/tmp/pz/sess/100.jsonl", .vis = .mask },
            },
        },
        .attrs = &.{},
    });
    defer talloc.free(sess_raw);

    const snap = try std.fmt.allocPrint(talloc, "cfg={s} | sess={s}", .{ cfg_raw, sess_raw });
    defer talloc.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "cfg={"v":1,"ts_ms":88,"sid":"runtime","seq":1,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"model"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"model","argv":{"text":"claude-opus-4-6","vis":"pub"}},"attrs":[{"key":"provider","vis":"pub","ty":"str","val":"anthropic"}]} | sess={"v":1,"ts_ms":89,"sid":"runtime","seq":2,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"[mask:bd710b2156a1699e]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:3208ed5235fe5d94]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(snap);
}

test "snapshot: audit payload ships through syslog canonically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const frame = try encodeFrameAlloc(talloc, .{
        .facility = .auth,
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
        .msgid = "audit",
    }, .{
        .ts_ms = 123,
        .sid = "sess-c",
        .seq = 7,
        .sev = .warn,
        .actor = .{
            .kind = .tool,
            .id = .{ .text = "bash", .vis = .@"pub" },
        },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = "rm -rf /tmp/nope", .vis = .mask },
            .op = "exec",
        },
        .data = .{
            .tool = .{
                .name = .{ .text = "bash", .vis = .@"pub" },
                .call_id = "call-7",
                .argv = .{ .text = "rm -rf /tmp/nope", .vis = .mask },
                .code = 143,
                .ms = 19,
            },
        },
        .attrs = &.{
            .{ .key = "cancel", .val = .{ .bool = true } },
        },
    });
    defer talloc.free(frame);

    try oh.snap(@src(),
        \\[]u8
        \\  "<36>1 1970-01-01T00:00:00.123Z pz-host pz 17 audit [pz@32473 sid="sess-c" seq="7"] {"v":1,"ts_ms":123,"sid":"sess-c","seq":7,"kind":"tool","sev":"warn","out":"ok","actor":{"kind":"tool","id":{"text":"bash","vis":"pub"}},"res":{"kind":"cmd","name":{"text":"[mask:a3f737f3e5d8415e]","vis":"mask"},"op":"exec"},"data":{"name":{"text":"bash","vis":"pub"},"call_id":"call-7","argv":{"text":"[mask:a3f737f3e5d8415e]","vis":"mask"},"code":143,"ms":19},"attrs":[{"key":"cancel","vis":"pub","ty":"bool","val":true}]}"
    ).expectEqual(frame);
}

const MockErr = error{
    ConnectFail,
    SendFail,
};

const ConnStep = enum {
    ok,
    fail,
};

const SendStep = enum {
    ok,
    fail,
};

const MockNet = struct {
    alloc: Allocator,
    conn_steps: []const ConnStep,
    send_steps: []const SendStep,
    conn_idx: usize = 0,
    send_idx: usize = 0,
    conn_calls: usize = 0,
    sent: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *MockNet) void {
        for (self.sent.items) |raw| self.alloc.free(raw);
        self.sent.deinit(self.alloc);
        self.* = undefined;
    }

    fn connector(self: *MockNet) Connector {
        return .{
            .ctx = self,
            .connect = &connect,
        };
    }

    const vt = ConnVTable{
        .sendRaw = sendRaw,
        .deinit = deinitConn,
    };

    fn connect(ctx: *anyopaque) !Conn {
        const self: *MockNet = @ptrCast(@alignCast(ctx));
        self.conn_calls += 1;
        const step = if (self.conn_idx < self.conn_steps.len) self.conn_steps[self.conn_idx] else .ok;
        self.conn_idx += 1;
        return switch (step) {
            .ok => .{
                .ctx = self,
                .vtable = &vt,
            },
            .fail => MockErr.ConnectFail,
        };
    }

    fn sendRaw(ctx: *anyopaque, raw: []const u8) !void {
        const self: *MockNet = @ptrCast(@alignCast(ctx));
        const step = if (self.send_idx < self.send_steps.len) self.send_steps[self.send_idx] else .ok;
        self.send_idx += 1;
        switch (step) {
            .ok => try self.sent.append(self.alloc, try self.alloc.dupe(u8, raw)),
            .fail => return MockErr.SendFail,
        }
    }

    fn deinitConn(_: *anyopaque) void {}
};

fn testEntry(seq: u64) Entry {
    return .{
        .ts_ms = @intCast(seq),
        .sid = "sess-r",
        .seq = seq,
        .data = .{
            .ship = .{
                .proto = "syslog+tls",
                .batch = 1,
                .dst = .{ .text = "siem.internal:6514", .vis = .mask },
                .len = 128,
            },
        },
    };
}

fn errName(err: ?anyerror) []const u8 {
    return if (err) |e| @errorName(e) else "null";
}

fn fmtOptI64(buf: []u8, v: ?i64) ![]const u8 {
    return if (v) |n| try std.fmt.bufPrint(buf, "{d}", .{n}) else "null";
}

test "syslog shipper buffers disconnect and flushes in order" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var net = MockNet{
        .alloc = testing.allocator,
        .conn_steps = &.{ .ok, .ok },
        .send_steps = &.{ .ok, .fail, .ok, .ok },
    };
    defer net.deinit();

    var ship = try SyslogShipper.init(testing.allocator, .{
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
    }, .{
        .connector = net.connector(),
        .buf_cap = 4,
        .backoff_min_ms = 10,
        .backoff_max_ms = 40,
    });
    defer ship.deinit();

    const r1 = try ship.send(testEntry(1), 0);
    const r2 = try ship.send(testEntry(2), 0);
    const r3 = try ship.send(testEntry(3), 0);
    const early = try ship.flush(9);
    const late = try ship.flush(10);
    const st = ship.stats();
    var retry_buf: [32]u8 = undefined;

    try testing.expect(r1.state == .sent);
    try testing.expect(r2.state == .buffered);
    try testing.expect(r3.state == .buffered);
    try testing.expectEqualStrings("SendFail", errName(r2.err));
    try testing.expectEqualStrings("null", errName(r3.err));

    const snap = try std.fmt.allocPrint(testing.allocator, "queued={d} | dropped={d} | backoff_ms={d} | next_retry_ms={s} | early_err={s} | early_sent={d} | late_err={s} | late_sent={d} | conn_calls={d} | one={s} | two={s} | three={s}", .{
        st.queued,
        st.dropped,
        st.backoff_ms,
        try fmtOptI64(&retry_buf, st.next_retry_ms),
        errName(early.err),
        early.sent,
        errName(late.err),
        late.sent,
        net.conn_calls,
        net.sent.items[0],
        net.sent.items[1],
        net.sent.items[2],
    });
    defer testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "queued=0 | dropped=0 | backoff_ms=10 | next_retry_ms=null | early_err=null | early_sent=0 | late_err=null | late_sent=2 | conn_calls=2 | one=<110>1 1970-01-01T00:00:00.001Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="1"] {"v":1,"ts_ms":1,"sid":"sess-r","seq":1,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":128},"attrs":[]} | two=<110>1 1970-01-01T00:00:00.002Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="2"] {"v":1,"ts_ms":2,"sid":"sess-r","seq":2,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":128},"attrs":[]} | three=<110>1 1970-01-01T00:00:00.003Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="3"] {"v":1,"ts_ms":3,"sid":"sess-r","seq":3,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":128},"attrs":[]}"
    ).expectEqual(snap);
}

test "syslog shipper drops oldest on ring overflow" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var net = MockNet{
        .alloc = testing.allocator,
        .conn_steps = &.{ .fail, .ok },
        .send_steps = &.{ .ok, .ok },
    };
    defer net.deinit();

    var ship = try SyslogShipper.init(testing.allocator, .{
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
    }, .{
        .connector = net.connector(),
        .buf_cap = 2,
        .backoff_min_ms = 5,
        .backoff_max_ms = 20,
    });
    defer ship.deinit();

    const r1 = try ship.send(testEntry(1), 0);
    const r2 = try ship.send(testEntry(2), 1);
    const r3 = try ship.send(testEntry(3), 2);
    const fl = try ship.flush(5);

    try testing.expect(r1.state == .buffered);
    try testing.expect(r2.state == .buffered);
    try testing.expect(r3.state == .buffered);
    try testing.expectEqualStrings("ConnectFail", errName(r1.err));

    const snap = try std.fmt.allocPrint(testing.allocator, "r3_dropped={d} | queued={d} | dropped={d} | fl_sent={d} | conn_calls={d} | first={s} | second={s}", .{
        r3.dropped,
        ship.stats().queued,
        ship.stats().dropped,
        fl.sent,
        net.conn_calls,
        net.sent.items[0],
        net.sent.items[1],
    });
    defer testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "r3_dropped=1 | queued=0 | dropped=1 | fl_sent=2 | conn_calls=2 | first=<110>1 1970-01-01T00:00:00.002Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="2"] {"v":1,"ts_ms":2,"sid":"sess-r","seq":2,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":128},"attrs":[]} | second=<110>1 1970-01-01T00:00:00.003Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="3"] {"v":1,"ts_ms":3,"sid":"sess-r","seq":3,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:f0239d9bd7eeba5f]","vis":"mask"},"len":128},"attrs":[]}"
    ).expectEqual(snap);
}

test "syslog shipper bounds reconnect backoff and resets after connect" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var net = MockNet{
        .alloc = testing.allocator,
        .conn_steps = &.{ .fail, .fail, .fail, .ok },
        .send_steps = &.{.ok},
    };
    defer net.deinit();

    var ship = try SyslogShipper.init(testing.allocator, .{
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
    }, .{
        .connector = net.connector(),
        .buf_cap = 2,
        .backoff_min_ms = 5,
        .backoff_max_ms = 12,
    });
    defer ship.deinit();

    _ = try ship.send(testEntry(1), 0);
    const s0 = ship.stats();

    _ = try ship.flush(5);
    const s1 = ship.stats();

    _ = try ship.flush(15);
    const s2 = ship.stats();

    const fl = try ship.flush(27);
    const s3 = ship.stats();
    try testing.expectEqual(@as(usize, 1), fl.sent);
    try testing.expectEqual(@as(usize, 1), net.sent.items.len);

    const Snap = struct {
        s0: Stats,
        s1: Stats,
        s2: Stats,
        s3: Stats,
    };
    try oh.snap(@src(),
        \\core.audit.test.syslog shipper bounds reconnect backoff and resets after connect.Snap
        \\  .s0: core.audit.Stats
        \\    .connected: bool = false
        \\    .queued: usize = 1
        \\    .dropped: u64 = 0
        \\    .backoff_ms: u32 = 10
        \\    .next_retry_ms: ?i64
        \\      5
        \\  .s1: core.audit.Stats
        \\    .connected: bool = false
        \\    .queued: usize = 1
        \\    .dropped: u64 = 0
        \\    .backoff_ms: u32 = 12
        \\    .next_retry_ms: ?i64
        \\      15
        \\  .s2: core.audit.Stats
        \\    .connected: bool = false
        \\    .queued: usize = 1
        \\    .dropped: u64 = 0
        \\    .backoff_ms: u32 = 12
        \\    .next_retry_ms: ?i64
        \\      27
        \\  .s3: core.audit.Stats
        \\    .connected: bool = true
        \\    .queued: usize = 0
        \\    .dropped: u64 = 0
        \\    .backoff_ms: u32 = 5
        \\    .next_retry_ms: ?i64
        \\      null
    ).expectEqual(Snap{
        .s0 = s0,
        .s1 = s1,
        .s2 = s2,
        .s3 = s3,
    });
}
