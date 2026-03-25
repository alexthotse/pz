//! Structured audit log: events, severity, HMAC-chained integrity.
const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const integrity = @import("audit_integrity.zig");
const signing = @import("signing.zig");
const syslog = @import("syslog.zig");

pub const RedactKey = signing.RedactKey;

pub const ver_current: u16 = 1;

/// Field visibility level for audit redaction.
pub const Vis = enum {
    @"pub",
    mask,
    hash,
    secret,
};

/// Audit event severity (syslog-aligned).
pub const Severity = enum {
    debug,
    info,
    notice,
    warn,
    err,
    crit,
};

/// Audit event outcome.
pub const Outcome = enum {
    ok,
    deny,
    fail,
};

pub const EventKind = enum {
    sess,
    turn,
    tool,
    policy,
    auth,
    forward,
    ctrl,
};

/// Text with visibility annotation for redaction.
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

pub const ResourceKind = enum {
    sess,
    turn,
    file,
    cmd,
    net,
    auth,
    cfg,
    forward,
};

pub const Resource = struct {
    kind: ResourceKind,
    name: Str,
    op: ?[]const u8 = null,
};

pub const Value = union(enum) {
    str: []const u8,
    int: i64,
    uint: u64,
    bool: bool,
};

pub const Attribute = struct {
    key: []const u8,
    vis: Vis = .@"pub",
    val: Value,
};

pub const SessionOp = enum {
    start,
    @"resume",
    stop,
    compact,
};

pub const SessionData = struct {
    op: SessionOp,
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

pub const PolicyEffect = enum {
    allow,
    deny,
};

pub const PolicyData = struct {
    effect: PolicyEffect,
    rule: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

pub const AuthData = struct {
    mechanism: []const u8,
    subject: ?Str = null,
};

pub const ForwardData = struct {
    proto: []const u8,
    batch: u32,
    dst: Str,
    len: u32,
};

pub const CtrlOp = enum {
    model,
    @"resume",
    @"export",
    compact,
    subagent,
    editor,
    clipboard,
};

pub const CtrlData = struct {
    op: CtrlOp,
    target: ?Str = null,
    detail: ?Str = null,
};

pub const Data = union(EventKind) {
    sess: SessionData,
    turn: TurnData,
    tool: ToolData,
    policy: PolicyData,
    auth: AuthData,
    forward: ForwardData,
    ctrl: CtrlData,
};

pub const Entry = struct {
    version: u16 = ver_current,
    ts_ms: i64,
    sid: []const u8,
    seq: u64,
    severity: Severity = .info,
    outcome: Outcome = .ok,
    site: Site = .{},
    actor: Actor = .{ .kind = .sys },
    res: ?Resource = null,
    msg: ?Str = null,
    data: Data,
    attrs: []const Attribute = &.{},
};

pub fn kindOf(ent: Entry) EventKind {
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
    severity: Severity = .info,
    site: Site = .{},
};

pub const Connection = struct {
    vt: *const Vt,

    pub const Vt = struct {
        send_raw: *const fn (self: *Connection, raw: []const u8) anyerror!void,
        deinit: *const fn (self: *Connection) void,
    };

    pub fn sendRaw(self: *Connection, raw: []const u8) !void {
        return self.vt.send_raw(self, raw);
    }

    pub fn deinit(self: *Connection) void {
        self.vt.deinit(self);
    }

    pub fn Bind(
        comptime T: type,
        comptime send_fn: fn (*T, []const u8) anyerror!void,
        comptime deinit_fn: fn (*T) void,
    ) type {
        return struct {
            pub const vt = Vt{
                .send_raw = sendRawFn,
                .deinit = deinitFn,
            };
            fn sendRawFn(c: *Connection, raw: []const u8) anyerror!void {
                const self: *T = @fieldParentPtr("connection", c);
                return send_fn(self, raw);
            }
            fn deinitFn(c: *Connection) void {
                const self: *T = @fieldParentPtr("connection", c);
                deinit_fn(self);
            }
        };
    }
};

pub const Connector = struct {
    vt: *const Vt,

    pub const Vt = struct {
        connect: *const fn (self: *Connector) anyerror!*Connection,
    };

    pub fn connect(self: *Connector) !*Connection {
        return self.vt.connect(self);
    }

    pub fn Bind(comptime T: type, comptime connect_fn: fn (*T) anyerror!*Connection) type {
        return struct {
            pub const vt = Vt{
                .connect = connectFn,
            };
            fn connectFn(cr: *Connector) anyerror!*Connection {
                const self: *T = @fieldParentPtr("connector", cr);
                return connect_fn(self);
            }
        };
    }
};

pub const OverflowPolicy = enum {
    drop_oldest,
    fail_closed,
};

pub const ForwardOpts = struct {
    connector: *Connector,
    buf_cap: usize = 64,
    backoff_min_ms: u32 = 100,
    backoff_max_ms: u32 = 5_000,
    overflow: OverflowPolicy = .drop_oldest,
    spool_dir: ?std.fs.Dir = null,
};

pub const SendState = enum {
    sent,
    buffered,
};

pub const SendResult = struct {
    state: SendState,
    flushed: usize = 0,
    queued: usize = 0,
    dropped: usize = 0,
    err: ?anyerror = null,
    connected: bool = false,
    next_retry_ms: ?i64 = null,
};

pub const FlushResult = struct {
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
    overflow: OverflowPolicy = .drop_oldest,
    spool_dir: ?std.fs.Dir = null,
    spool_seq: u64 = 0,

    fn init(alloc: Allocator, cap: usize, overflow: OverflowPolicy, spool_dir: ?std.fs.Dir) !Ring {
        if (cap == 0) {
            return .{
                .alloc = alloc,
                .slots = &[_]?[]u8{},
                .overflow = overflow,
                .spool_dir = spool_dir,
            };
        }

        const slots = try alloc.alloc(?[]u8, cap);
        @memset(slots, null);
        var ring = Ring{
            .alloc = alloc,
            .slots = slots,
            .overflow = overflow,
            .spool_dir = spool_dir,
        };

        // Restore from spool if available
        if (spool_dir != null) try ring.restoreSpool();

        return ring;
    }

    fn deinit(self: *Ring) void {
        // Free memory but preserve spool files for durability
        while (self.len > 0) self.drop();
        if (self.slots.len > 0) self.alloc.free(self.slots);
        self.* = undefined;
    }

    /// Free slot memory without removing spool file.
    fn drop(self: *Ring) void {
        const idx = self.head;
        self.alloc.free(self.slots[idx].?);
        self.slots[idx] = null;
        self.head = nextIdx(self.slots.len, idx);
        self.len -= 1;
    }

    fn push(self: *Ring, raw: []const u8) !BufPush {
        if (self.slots.len == 0) {
            self.dropped += 1;
            return .{ .dropped = 1 };
        }

        if (self.len == self.slots.len) {
            switch (self.overflow) {
                .drop_oldest => {
                    const dup = try self.alloc.dupe(u8, raw);
                    const idx = self.head;
                    self.removeSpool(idx);
                    self.alloc.free(self.slots[idx].?);
                    self.slots[idx] = dup;
                    self.head = nextIdx(self.slots.len, idx);
                    self.dropped += 1;
                    try self.writeSpool(raw);
                    return .{ .dropped = 1 };
                },
                .fail_closed => return error.SpoolFull,
            }
        }

        const dup = try self.alloc.dupe(u8, raw);
        const idx = (self.head + self.len) % self.slots.len;
        self.slots[idx] = dup;
        self.len += 1;
        try self.writeSpool(raw);
        return .{};
    }

    fn peek(self: *const Ring) ?[]const u8 {
        if (self.len == 0) return null;
        return self.slots[self.head].?;
    }

    fn pop(self: *Ring) void {
        const idx = self.head;
        self.removeSpool(idx);
        self.alloc.free(self.slots[idx].?);
        self.slots[idx] = null;
        self.head = nextIdx(self.slots.len, idx);
        self.len -= 1;
    }

    fn writeSpool(self: *Ring, raw: []const u8) error{ SpoolCreate, SpoolWrite, SpoolName }!void {
        const dir = self.spool_dir orelse return;
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{d:0>16}.spool", .{self.spool_seq}) catch return error.SpoolName;
        self.spool_seq += 1;
        const f = dir.createFile(name, .{ .truncate = true }) catch return error.SpoolCreate;
        defer f.close();
        f.writeAll(raw) catch return error.SpoolWrite;
    }

    fn removeSpool(self: *Ring, slot_idx: usize) void {
        const dir = self.spool_dir orelse return;
        // Compute spool seq from slot index relative to current state
        // The oldest spool file corresponds to head's sequence
        const age = if (slot_idx >= self.head)
            slot_idx - self.head
        else
            self.slots.len - self.head + slot_idx;
        const base_seq = if (self.spool_seq >= self.len) self.spool_seq - self.len else 0;
        const seq = base_seq + age;
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "{d:0>16}.spool", .{seq}) catch unreachable; // 20 digits + 6 = 26 < 32
        dir.deleteFile(name) catch {}; // cleanup: propagation impossible
    }

    const SpoolEntry = struct { seq: u64, name: [32]u8, len: usize };

    fn restoreSpool(self: *Ring) !void {
        const dir = self.spool_dir orelse return;
        if (self.slots.len == 0) return;

        // Scan all spool files, sort by seq, load oldest up to ring capacity.
        var list: std.ArrayListUnmanaged(SpoolEntry) = .empty;
        defer list.deinit(self.alloc);

        var it = dir.iterate();
        while (try it.next()) |ent| {
            if (!std.mem.endsWith(u8, ent.name, ".spool")) continue;
            const stem = ent.name[0 .. ent.name.len - 6];
            const seq = std.fmt.parseInt(u64, stem, 10) catch continue; // malformed filename, skip
            var entry: SpoolEntry = undefined;
            entry.seq = seq;
            entry.len = ent.name.len;
            @memcpy(entry.name[0..ent.name.len], ent.name);
            try list.append(self.alloc, entry);
        }

        // Sort by seq
        std.mem.sort(SpoolEntry, list.items, {}, struct {
            fn cmp(_: void, a: SpoolEntry, b: SpoolEntry) bool {
                return a.seq < b.seq;
            }
        }.cmp);

        for (list.items) |item| {
            if (self.len >= self.slots.len) break;
            const name = item.name[0..item.len];
            const data = dir.readFileAlloc(self.alloc, name, 64 * 1024) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue, // I/O error on individual spool file, skip
            };
            const idx = (self.head + self.len) % self.slots.len;
            self.slots[idx] = data;
            self.len += 1;
            if (item.seq >= self.spool_seq) self.spool_seq = item.seq + 1;
        }
    }
};

pub const ReconnSender = struct {
    alloc: Allocator,
    connr: *Connector,
    conn: ?*Connection = null,
    ring: Ring,
    backoff_min_ms: u32,
    backoff_max_ms: u32,
    backoff_ms: u32,
    next_retry_ms: ?i64 = null,

    pub fn init(alloc: Allocator, opts: ForwardOpts) !ReconnSender {
        if (opts.backoff_min_ms == 0 or opts.backoff_max_ms < opts.backoff_min_ms) {
            return error.InvalidBackoff;
        }

        return .{
            .alloc = alloc,
            .connr = opts.connector,
            .ring = try Ring.init(alloc, opts.buf_cap, opts.overflow, opts.spool_dir),
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

    pub fn sendRaw(self: *ReconnSender, raw: []const u8, now_ms: i64) !SendResult {
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

    pub fn flush(self: *ReconnSender, now_ms: i64) !FlushResult {
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

        self.conn = self.connr.connect() catch |err| {
            self.noteFail(now_ms);
            return .{ .err = err };
        };
        self.next_retry_ms = null;
        self.backoff_ms = self.backoff_min_ms;
        return .{ .ok = true };
    }

    fn flushLive(self: *ReconnSender, now_ms: i64) !FlushResult {
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

    pub fn init(alloc: Allocator, frame: FrameOpts, opts: ForwardOpts) !SyslogShipper {
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

    pub fn send(self: *SyslogShipper, ent: Entry, now_ms: i64) !SendResult {
        const raw = try encodeFrameAlloc(self.alloc, self.frame, ent);
        defer self.alloc.free(raw);
        return try self.reconn.sendRaw(raw, now_ms);
    }

    pub fn flush(self: *SyslogShipper, now_ms: i64) !FlushResult {
        return try self.reconn.flush(now_ms);
    }

    pub fn stats(self: *const SyslogShipper) Stats {
        return self.reconn.stats();
    }
};

pub const SenderConnector = struct {
    connector: Connector = .{ .vt = &ConnBind.vt },
    alloc: Allocator,
    opts: syslog.SenderOpts,

    const ConnBind = Connector.Bind(SenderConnector, doConnect);

    const Peer = struct {
        connection: Connection = .{ .vt = &PeerBind.vt },
        alloc: Allocator,
        sender: syslog.Sender,
    };

    const PeerBind = Connection.Bind(Peer, peerSendRaw, peerDeinit);

    fn doConnect(self: *SenderConnector) !*Connection {
        const peer = try self.alloc.create(Peer);
        errdefer self.alloc.destroy(peer);

        peer.* = .{
            .alloc = self.alloc,
            .sender = try syslog.Sender.init(self.alloc, self.opts),
        };
        return &peer.connection;
    }

    fn peerSendRaw(peer: *Peer, raw: []const u8) !void {
        try peer.sender.sendRaw(raw);
    }

    fn peerDeinit(peer: *Peer) void {
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
        .severity = ent.severity,
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
            .severity = sevSyslog(hdr.severity),
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
    prev: ?integrity.Mac,
    seq_tracker: ?*integrity.SeqTracker,
) ![]u8 {
    const body = try encodeAlloc(alloc, ent);
    defer alloc.free(body);
    const seq = if (seq_tracker) |st| try st.next() else null;
    return try integrity.sealAllocSeq(alloc, key, prev, body, seq);
}

pub fn writeEntry(w: anytype, ent: Entry) !void {
    const rkey = RedactKey.fromSid(ent.sid);
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
    try writeJsonStr(w, @tagName(ent.severity));

    try writeObjKey(w, &first, "out");
    try writeJsonStr(w, @tagName(ent.outcome));

    if (hasSite(ent.site)) {
        try writeObjKey(w, &first, "site");
        try writeSite(w, ent.site);
    }

    try writeObjKey(w, &first, "actor");
    try writeActor(w, ent.actor, rkey);

    if (ent.res) |res| {
        try writeObjKey(w, &first, "res");
        try writeRes(w, res, rkey);
    }

    if (ent.msg) |msg| {
        try writeObjKey(w, &first, "msg");
        try writeStr(w, msg, rkey);
    }

    try writeObjKey(w, &first, "data");
    try writeData(w, ent.data, rkey);

    try writeObjKey(w, &first, "attrs");
    try writeAttrs(w, ent.attrs, rkey);

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
        .auth => |v| if (v.subject) |sub| sub.vis != .@"pub" else false,
        .forward => |v| v.dst.vis != .@"pub",
        .ctrl => |v| blk: {
            if (v.target) |t| if (t.vis != .@"pub") break :blk true;
            if (v.detail) |d| if (d.vis != .@"pub") break :blk true;
            break :blk false;
        },
    };
}

fn sevSyslog(sev: Severity) syslog.Severity {
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

fn writeActor(w: anytype, actor: Actor, rkey: RedactKey) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "kind");
    try writeJsonStr(w, @tagName(actor.kind));

    if (actor.id) |id| {
        try writeObjKey(w, &first, "id");
        try writeStr(w, id, rkey);
    }
    if (actor.role) |role| {
        try writeObjKey(w, &first, "role");
        try writeJsonStr(w, role);
    }
    try w.writeByte('}');
}

fn writeRes(w: anytype, res: Resource, rkey: RedactKey) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "kind");
    try writeJsonStr(w, @tagName(res.kind));

    try writeObjKey(w, &first, "name");
    try writeStr(w, res.name, rkey);

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

/// Process-level ephemeral redaction key, initialized once.
/// Used by callers of `redactTextAlloc` that lack session context.
var proc_rkey: RedactKey = undefined;
var proc_rkey_init = false;

fn procKey() RedactKey {
    if (!proc_rkey_init) {
        var seed: [signing.rkey_len]u8 = undefined;
        std.crypto.random.bytes(&seed);
        proc_rkey = .{ .bytes = seed };
        proc_rkey_init = true;
    }
    return proc_rkey;
}

fn taggedTextAlloc(alloc: Allocator, tag: []const u8, txt: []const u8, rkey: RedactKey) ![]u8 {
    var hex: [16]u8 = undefined;
    _ = rkey.surrogate(txt, &hex);
    return std.fmt.allocPrint(alloc, "[{s}:{s}]", .{ tag, hex[0..] });
}

/// Redact text using the process-level ephemeral key.
/// For session-scoped redaction, use `redactKeyedAlloc`.
pub fn redactTextAlloc(alloc: Allocator, txt: []const u8, vis: Vis) ![]u8 {
    return redactKeyedAlloc(alloc, txt, vis, procKey());
}

/// Redact text using a caller-supplied key (session-scoped).
pub fn redactKeyedAlloc(alloc: Allocator, txt: []const u8, vis: Vis, rkey: RedactKey) ![]u8 {
    return switch (vis) {
        .@"pub" => if (detectPubRedact(txt)) |tag|
            try taggedTextAlloc(alloc, tag, txt, rkey)
        else
            try alloc.dupe(u8, txt),
        .mask => try taggedTextAlloc(alloc, "mask", txt, rkey),
        .hash => try taggedTextAlloc(alloc, "hash", txt, rkey),
        .secret => try taggedTextAlloc(alloc, "secret", txt, rkey),
    };
}

fn writeTaggedJsonStr(w: anytype, tag: []const u8, txt: []const u8, rkey: RedactKey) !void {
    var hex: [16]u8 = undefined;
    _ = rkey.surrogate(txt, &hex);
    var tag_buf: [32]u8 = undefined;
    const out = try std.fmt.bufPrint(&tag_buf, "[{s}:{s}]", .{ tag, hex[0..] });
    try writeJsonStr(w, out);
}

fn writeVisText(w: anytype, txt: []const u8, vis: Vis, rkey: RedactKey) !void {
    switch (vis) {
        .@"pub" => {
            if (detectPubRedact(txt)) |tag| {
                try writeTaggedJsonStr(w, tag, txt, rkey);
            } else {
                try writeJsonStr(w, txt);
            }
        },
        .mask => try writeTaggedJsonStr(w, "mask", txt, rkey),
        .hash => try writeTaggedJsonStr(w, "hash", txt, rkey),
        .secret => try writeTaggedJsonStr(w, "secret", txt, rkey),
    }
}

fn writeStr(w: anytype, s: Str, rkey: RedactKey) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "text");
    try writeVisText(w, s.text, s.vis, rkey);

    try writeObjKey(w, &first, "vis");
    try writeJsonStr(w, @tagName(s.vis));

    try w.writeByte('}');
}

fn writeAttrs(w: anytype, attrs: []const Attribute, rkey: RedactKey) !void {
    try w.writeByte('[');
    for (attrs, 0..) |attr, i| {
        if (i > 0) try w.writeByte(',');
        try writeAttr(w, attr, rkey);
    }
    try w.writeByte(']');
}

fn writeAttr(w: anytype, attr: Attribute, rkey: RedactKey) !void {
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
            try writeVisText(w, v, attr.vis, rkey);
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

fn writeData(w: anytype, data: Data, rkey: RedactKey) !void {
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
                try writeStr(w, wd, rkey);
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
            try writeStr(w, v.name, rkey);

            if (v.call_id) |call_id| {
                try writeObjKey(w, &first, "call_id");
                try writeJsonStr(w, call_id);
            }
            if (v.argv) |argv| {
                try writeObjKey(w, &first, "argv");
                try writeStr(w, argv, rkey);
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
            try writeJsonStr(w, @tagName(v.effect));

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
            try writeJsonStr(w, v.mechanism);

            if (v.subject) |sub| {
                try writeObjKey(w, &first, "sub");
                try writeStr(w, sub, rkey);
            }
        },
        .forward => |v| {
            try writeObjKey(w, &first, "proto");
            try writeJsonStr(w, v.proto);

            try writeObjKey(w, &first, "batch");
            try w.print("{d}", .{v.batch});

            try writeObjKey(w, &first, "dst");
            try writeStr(w, v.dst, rkey);

            try writeObjKey(w, &first, "len");
            try w.print("{d}", .{v.len});
        },
        .ctrl => |v| {
            try writeObjKey(w, &first, "op");
            try writeJsonStr(w, @tagName(v.op));

            if (v.target) |t| {
                try writeObjKey(w, &first, "target");
                try writeStr(w, t, rkey);
            }
            if (v.detail) |d| {
                try writeObjKey(w, &first, "detail");
                try writeStr(w, d, rkey);
            }
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

const writeJsonStr = @import("json.zig").writeJsonStr;

test "snapshot: canonical tool entry encoding" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const attrs = [_]Attribute{
        .{ .key = "cache_hit", .val = .{ .bool = false } },
        .{ .key = "bytes", .val = .{ .uint = 512 } },
        .{ .key = "stderr", .vis = .mask, .val = .{ .str = "permission denied" } },
    };

    const ent = Entry{
        .ts_ms = 1_731_000_000_123,
        .sid = "sess-01",
        .seq = 7,
        .severity = .warn,
        .outcome = .fail,
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
        \\  "kind=tool | redact=true | json={"v":1,"ts_ms":1731000000123,"sid":"sess-01","seq":7,"kind":"tool","sev":"warn","out":"fail","site":{"host":"mbp","app":"pz","pid":4242},"actor":{"kind":"agent","id":{"text":"codex","vis":"pub"},"role":"runner"},"res":{"kind":"file","name":{"text":"[mask:31b03db53031ba68]","vis":"mask"},"op":"write"},"msg":{"text":"tool failed","vis":"pub"},"data":{"name":{"text":"exec_command","vis":"pub"},"call_id":"toolu_01","argv":{"text":"[secret:261ac4eb2f8dea22]","vis":"secret"},"code":1,"ms":29},"attrs":[{"key":"cache_hit","vis":"pub","ty":"bool","val":false},{"key":"bytes","vis":"pub","ty":"uint","val":512},{"key":"stderr","vis":"mask","ty":"str","val":"[mask:a575177ce0d07786]"}]}"
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
        .outcome = .deny,
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
                .effect = .deny,
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
        .severity = .notice,
        .actor = .{
            .kind = .user,
            .id = .{ .text = "joel", .vis = .@"pub" },
        },
        .data = .{
            .auth = .{
                .mechanism = "oauth",
                .subject = .{ .text = "user@example.com", .vis = .hash },
            },
        },
    });
    defer talloc.free(auth_raw);

    const ship_raw = try encodeAlloc(talloc, .{
        .ts_ms = 13,
        .sid = "sess-a",
        .seq = 4,
        .severity = .info,
        .data = .{
            .forward = .{
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

    const snap = try std.fmt.allocPrint(talloc, "sess={s} | policy={s} | auth={s} | forward={s}", .{
        sess_raw,
        policy_raw,
        auth_raw,
        ship_raw,
    });
    defer talloc.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "sess={"v":1,"ts_ms":10,"sid":"sess-a","seq":1,"kind":"sess","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"op":"start","tty":true,"wd":{"text":"[mask:bfd73010ad3334a7]","vis":"mask"}},"attrs":[]} | policy={"v":1,"ts_ms":11,"sid":"sess-a","seq":2,"kind":"policy","sev":"info","out":"deny","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[secret:0075ed38fd9eb2c4]","vis":"secret"},"op":"read"},"data":{"eff":"deny","rule":"*.audit.log","scope":"path"},"attrs":[]} | auth={"v":1,"ts_ms":12,"sid":"sess-a","seq":3,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"user","id":{"text":"joel","vis":"pub"}},"data":{"mech":"oauth","sub":{"text":"[hash:a5291921179ec2a4]","vis":"hash"}},"attrs":[]} | forward={"v":1,"ts_ms":13,"sid":"sess-a","seq":4,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":8,"dst":{"text":"[mask:51581415926ae87a]","vis":"mask"},"len":1420},"attrs":[{"key":"retry","vis":"pub","ty":"uint","val":1}]}"
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
        \\  "{"v":1,"ts_ms":77,"sid":"sess-b","seq":9,"kind":"turn","sev":"info","out":"ok","actor":{"kind":"sys"},"msg":{"text":"[mask:2dd706d1d652ef70]","vis":"mask"},"data":{"idx":3,"phase":"done","model":"gpt-5"},"attrs":[{"key":"ctrl","vis":"mask","ty":"str","val":"[mask:3a967bb5ff310f5e]"},{"key":"delta","vis":"pub","ty":"int","val":-4}]}"
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
        .severity = .notice,
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
        .severity = .err,
        .outcome = .fail,
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
        \\  "cfg={"v":1,"ts_ms":88,"sid":"runtime","seq":1,"kind":"tool","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"model"},"msg":{"text":"runtime control success","vis":"pub"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"model","argv":{"text":"claude-opus-4-6","vis":"pub"}},"attrs":[{"key":"provider","vis":"pub","ty":"str","val":"anthropic"}]} | sess={"v":1,"ts_ms":89,"sid":"runtime","seq":2,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"sess","name":{"text":"session","vis":"pub"},"op":"resume"},"msg":{"text":"[mask:a3d269af3f28886b]","vis":"mask"},"data":{"name":{"text":"runtime","vis":"pub"},"call_id":"resume","argv":{"text":"[mask:6e5d4487dda40bf0]","vis":"mask"}},"attrs":[]}"
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
        .severity = .warn,
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
        \\  "<36>1 1970-01-01T00:00:00.123Z pz-host pz 17 audit [pz@32473 sid="sess-c" seq="7"] {"v":1,"ts_ms":123,"sid":"sess-c","seq":7,"kind":"tool","sev":"warn","out":"ok","actor":{"kind":"tool","id":{"text":"bash","vis":"pub"}},"res":{"kind":"cmd","name":{"text":"[mask:da6c048c4b4e0f06]","vis":"mask"},"op":"exec"},"data":{"name":{"text":"bash","vis":"pub"},"call_id":"call-7","argv":{"text":"[mask:da6c048c4b4e0f06]","vis":"mask"},"code":143,"ms":19},"attrs":[{"key":"cancel","vis":"pub","ty":"bool","val":true}]}"
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
    connector: Connector = .{ .vt = &ConnBind.vt },
    connection: Connection = .{ .vt = &PeerBind.vt },
    alloc: Allocator,
    conn_steps: []const ConnStep,
    send_steps: []const SendStep,
    conn_idx: usize = 0,
    send_idx: usize = 0,
    conn_calls: usize = 0,
    sent: std.ArrayListUnmanaged([]u8) = .empty,

    const ConnBind = Connector.Bind(MockNet, doConnect);
    const PeerBind = Connection.Bind(MockNet, doSendRaw, doConnDeinit);

    fn deinit(self: *MockNet) void {
        for (self.sent.items) |raw| self.alloc.free(raw);
        self.sent.deinit(self.alloc);
        self.* = undefined;
    }

    fn doConnect(self: *MockNet) !*Connection {
        self.conn_calls += 1;
        const step = if (self.conn_idx < self.conn_steps.len) self.conn_steps[self.conn_idx] else .ok;
        self.conn_idx += 1;
        return switch (step) {
            .ok => &self.connection,
            .fail => MockErr.ConnectFail,
        };
    }

    fn doSendRaw(self: *MockNet, raw: []const u8) !void {
        const step = if (self.send_idx < self.send_steps.len) self.send_steps[self.send_idx] else .ok;
        self.send_idx += 1;
        switch (step) {
            .ok => try self.sent.append(self.alloc, try self.alloc.dupe(u8, raw)),
            .fail => return MockErr.SendFail,
        }
    }

    fn doConnDeinit(_: *MockNet) void {}
};

fn testEntry(seq: u64) Entry {
    return .{
        .ts_ms = @intCast(seq),
        .sid = "sess-r",
        .seq = seq,
        .data = .{
            .forward = .{
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
        .connector = &net.connector,
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
        \\  "queued=0 | dropped=0 | backoff_ms=10 | next_retry_ms=null | early_err=null | early_sent=0 | late_err=null | late_sent=2 | conn_calls=2 | one=<110>1 1970-01-01T00:00:00.001Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="1"] {"v":1,"ts_ms":1,"sid":"sess-r","seq":1,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:9b5a41fcc246a2f3]","vis":"mask"},"len":128},"attrs":[]} | two=<110>1 1970-01-01T00:00:00.002Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="2"] {"v":1,"ts_ms":2,"sid":"sess-r","seq":2,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:9b5a41fcc246a2f3]","vis":"mask"},"len":128},"attrs":[]} | three=<110>1 1970-01-01T00:00:00.003Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="3"] {"v":1,"ts_ms":3,"sid":"sess-r","seq":3,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:9b5a41fcc246a2f3]","vis":"mask"},"len":128},"attrs":[]}"
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
        .connector = &net.connector,
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
        \\  "r3_dropped=1 | queued=0 | dropped=1 | fl_sent=2 | conn_calls=2 | first=<110>1 1970-01-01T00:00:00.002Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="2"] {"v":1,"ts_ms":2,"sid":"sess-r","seq":2,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:9b5a41fcc246a2f3]","vis":"mask"},"len":128},"attrs":[]} | second=<110>1 1970-01-01T00:00:00.003Z pz-host pz 17 audit [pz@32473 sid="sess-r" seq="3"] {"v":1,"ts_ms":3,"sid":"sess-r","seq":3,"kind":"forward","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":1,"dst":{"text":"[mask:9b5a41fcc246a2f3]","vis":"mask"},"len":128},"attrs":[]}"
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
        .connector = &net.connector,
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

test "snapshot: ctrl event encoding for privileged actions" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const model_raw = try encodeAlloc(talloc, .{
        .ts_ms = 100,
        .sid = "sess-ctrl",
        .seq = 1,
        .severity = .notice,
        .actor = .{ .kind = .user, .id = .{ .text = "joel", .vis = .@"pub" } },
        .res = .{
            .kind = .cfg,
            .name = .{ .text = "runtime", .vis = .@"pub" },
            .op = "model",
        },
        .msg = .{ .text = "model switch", .vis = .@"pub" },
        .data = .{
            .ctrl = .{
                .op = .model,
                .target = .{ .text = "claude-opus-4-6", .vis = .@"pub" },
            },
        },
    });
    defer talloc.free(model_raw);

    const export_raw = try encodeAlloc(talloc, .{
        .ts_ms = 101,
        .sid = "sess-ctrl",
        .seq = 2,
        .severity = .info,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .file,
            .name = .{ .text = "/tmp/out.md", .vis = .mask },
            .op = "write",
        },
        .data = .{
            .ctrl = .{
                .op = .clipboard,
                .detail = .{ .text = "/tmp/out.md", .vis = .mask },
            },
        },
    });
    defer talloc.free(export_raw);

    const subagent_raw = try encodeAlloc(talloc, .{
        .ts_ms = 102,
        .sid = "sess-ctrl",
        .seq = 3,
        .severity = .warn,
        .outcome = .deny,
        .actor = .{ .kind = .agent, .id = .{ .text = "sub-1", .vis = .@"pub" } },
        .data = .{
            .ctrl = .{
                .op = .subagent,
                .target = .{ .text = "sub-1", .vis = .@"pub" },
                .detail = .{ .text = "policy denied", .vis = .@"pub" },
            },
        },
    });
    defer talloc.free(subagent_raw);

    const snap = try std.fmt.allocPrint(talloc, "model={s} | export={s} | subagent={s}", .{
        model_raw,
        export_raw,
        subagent_raw,
    });
    defer talloc.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "model={"v":1,"ts_ms":100,"sid":"sess-ctrl","seq":1,"kind":"ctrl","sev":"notice","out":"ok","actor":{"kind":"user","id":{"text":"joel","vis":"pub"}},"res":{"kind":"cfg","name":{"text":"runtime","vis":"pub"},"op":"model"},"msg":{"text":"model switch","vis":"pub"},"data":{"op":"model","target":{"text":"claude-opus-4-6","vis":"pub"}},"attrs":[]} | export={"v":1,"ts_ms":101,"sid":"sess-ctrl","seq":2,"kind":"ctrl","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:e905cd364db2dbf1]","vis":"mask"},"op":"write"},"data":{"op":"clipboard","detail":{"text":"[mask:e905cd364db2dbf1]","vis":"mask"}},"attrs":[]} | subagent={"v":1,"ts_ms":102,"sid":"sess-ctrl","seq":3,"kind":"ctrl","sev":"warn","out":"deny","actor":{"kind":"agent","id":{"text":"sub-1","vis":"pub"}},"data":{"op":"subagent","target":{"text":"sub-1","vis":"pub"},"detail":{"text":"policy denied","vis":"pub"}},"attrs":[]}"
    ).expectEqual(snap);
}

test "ctrl needsRedact detects masked target and detail" {
    try testing.expect(!needsRedact(.{
        .ts_ms = 1,
        .sid = "s",
        .seq = 1,
        .data = .{ .ctrl = .{ .op = .model, .target = .{ .text = "pub", .vis = .@"pub" } } },
    }));
    try testing.expect(needsRedact(.{
        .ts_ms = 1,
        .sid = "s",
        .seq = 1,
        .data = .{ .ctrl = .{ .op = .model, .target = .{ .text = "secret", .vis = .mask } } },
    }));
    try testing.expect(needsRedact(.{
        .ts_ms = 1,
        .sid = "s",
        .seq = 1,
        .data = .{ .ctrl = .{ .op = .@"export", .detail = .{ .text = "/tmp/x", .vis = .secret } } },
    }));
}

test "fail_closed overflow rejects push when ring full" {
    var ring = try Ring.init(testing.allocator, 2, .fail_closed, null);
    defer ring.deinit();

    const r1 = try ring.push("a");
    try testing.expectEqual(@as(usize, 0), r1.dropped);
    const r2 = try ring.push("b");
    try testing.expectEqual(@as(usize, 0), r2.dropped);

    try testing.expectError(error.SpoolFull, ring.push("c"));
    try testing.expectEqual(@as(usize, 2), ring.len);
    try testing.expectEqual(@as(u64, 0), ring.dropped);
}

test "durable spool persists and restores events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write events into a ring with spool
    {
        var ring = try Ring.init(testing.allocator, 4, .drop_oldest, tmp.dir);
        defer ring.deinit();

        _ = try ring.push("event-0");
        _ = try ring.push("event-1");
        _ = try ring.push("event-2");
        try testing.expectEqual(@as(usize, 3), ring.len);
    }

    // Restore into a new ring from same spool dir
    {
        var ring = try Ring.init(testing.allocator, 4, .drop_oldest, tmp.dir);
        defer ring.deinit();

        try testing.expectEqual(@as(usize, 3), ring.len);
        try testing.expectEqualStrings("event-0", ring.peek().?);
        ring.pop();
        try testing.expectEqualStrings("event-1", ring.peek().?);
        ring.pop();
        try testing.expectEqualStrings("event-2", ring.peek().?);
        ring.pop();
        try testing.expectEqual(@as(usize, 0), ring.len);
    }
}

test "durable spool restores only up to ring capacity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write 5 events into a ring with cap 8
    {
        var ring = try Ring.init(testing.allocator, 8, .drop_oldest, tmp.dir);
        defer ring.deinit();
        var i: u8 = 0;
        while (i < 5) : (i += 1) {
            var buf: [16]u8 = undefined;
            const name = std.fmt.bufPrint(&buf, "msg-{d}", .{i}) catch unreachable;
            _ = try ring.push(name);
        }
        try testing.expectEqual(@as(usize, 5), ring.len);
    }

    // Restore into a ring with cap 3 -- should load only 3
    {
        var ring = try Ring.init(testing.allocator, 3, .drop_oldest, tmp.dir);
        defer ring.deinit();
        try testing.expectEqual(@as(usize, 3), ring.len);
        try testing.expectEqualStrings("msg-0", ring.peek().?);
    }
}

test "fail_closed propagates through ReconnSender" {
    var net = MockNet{
        .alloc = testing.allocator,
        .conn_steps = &.{ .fail, .fail, .fail },
        .send_steps = &.{},
    };
    defer net.deinit();

    var rs = try ReconnSender.init(testing.allocator, .{
        .connector = &net.connector,
        .buf_cap = 2,
        .backoff_min_ms = 5,
        .backoff_max_ms = 20,
        .overflow = .fail_closed,
    });
    defer rs.deinit();

    _ = try rs.sendRaw("a", 0);
    _ = try rs.sendRaw("b", 1);
    try testing.expectError(error.SpoolFull, rs.sendRaw("c", 2));
    try testing.expectEqual(@as(usize, 2), rs.ring.len);
}

test "e2e: denied cmd → seal → syslog frame → udp mock → verify HMAC + redaction" {
    const syslog_mock = @import("../test/syslog_mock.zig");
    const talloc = testing.allocator;

    // 1. Build a denied-command audit entry (e.g. "cat .pz/auth.json")
    const denied_cmd = "cat .pz/auth.json";
    const ent = Entry{
        .ts_ms = 1_700_000_000_000,
        .sid = "sess-e2e",
        .seq = 1,
        .severity = .warn,
        .outcome = .deny,
        .site = .{ .host = "e2e-host", .app = "pz", .pid = 9999 },
        .actor = .{ .kind = .tool, .id = .{ .text = "bash", .vis = .@"pub" } },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = denied_cmd, .vis = .secret },
            .op = "exec",
        },
        .msg = .{ .text = "command denied by policy", .vis = .@"pub" },
        .data = .{
            .policy = .{
                .effect = .deny,
                .rule = "self-protect",
                .scope = "bash",
            },
        },
    };

    // 2. Seal with HMAC chain (first entry, no prev)
    const hmac_key = integrity.Key{ .id = 42, .bytes = [_]u8{0xAB} ** integrity.mac_len };
    const sealed = try sealAlloc(talloc, ent, hmac_key, null, null);
    defer talloc.free(sealed);

    // 3. Frame as RFC 5424 syslog
    const body = try encodeAlloc(talloc, ent);
    defer talloc.free(body);
    const frame = try encodeFrameBodyAlloc(talloc, .{
        .facility = .auth,
        .hostname = "e2e-host",
        .app_name = "pz",
        .procid = "9999",
        .msgid = "audit",
    }, .{
        .ts_ms = ent.ts_ms,
        .sid = ent.sid,
        .seq = ent.seq,
        .severity = ent.severity,
        .site = ent.site,
    }, body);
    defer talloc.free(frame);

    // 4. Send to UDP mock collector
    var collector = try syslog_mock.UdpCollector.init();
    defer collector.deinit();
    const recv_thread = try collector.spawn();

    const send_fd = try std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
        std.posix.IPPROTO.UDP,
    );
    defer (std.net.Stream{ .handle = send_fd }).close();
    var dest = try std.net.Address.parseIp("127.0.0.1", collector.port());
    _ = try std.posix.sendto(send_fd, frame, 0, &dest.any, dest.getOsSockLen());

    // 5. Receive from collector
    recv_thread.join();
    const received = collector.message();
    try testing.expectEqualStrings(frame, received);

    // 6. Verify HMAC chain integrity
    const sealed_log = try std.fmt.allocPrint(talloc, "{s}\n", .{sealed});
    defer talloc.free(sealed_log);
    const verify = try integrity.verifyLogAlloc(talloc, sealed_log, &.{hmac_key});
    try testing.expect(verify == .ok);
    try testing.expectEqual(@as(u64, 1), verify.ok.lines);

    // 7. Verify command text is redacted (not present in cleartext in frame or sealed)
    try testing.expect(std.mem.indexOf(u8, frame, denied_cmd) == null);
    try testing.expect(std.mem.indexOf(u8, sealed, denied_cmd) == null);

    // Verify the redaction surrogate IS present (secret: tag)
    try testing.expect(std.mem.indexOf(u8, frame, "[secret:") != null);
    try testing.expect(std.mem.indexOf(u8, body, "[secret:") != null);
}
