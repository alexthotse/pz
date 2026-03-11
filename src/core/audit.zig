const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
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

pub fn encodeAlloc(alloc: Allocator, ent: Entry) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    try writeEntry(buf.writer(alloc), ent);
    return try buf.toOwnedSlice(alloc);
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

fn writeStr(w: anytype, s: Str) !void {
    try w.writeByte('{');
    var first = true;

    try writeObjKey(w, &first, "text");
    try writeJsonStr(w, s.text);

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
            try writeJsonStr(w, v);
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

    const Snap = struct {
        kind: Kind,
        redact: bool,
        json: []const u8,
    };

    const snap = Snap{
        .kind = kindOf(ent),
        .redact = needsRedact(ent),
        .json = raw,
    };

    try oh.snap(@src(),
        \\core.audit.test.snapshot: canonical tool entry encoding.Snap
        \\  .kind: core.audit.Kind
        \\    .tool
        \\  .redact: bool = true
        \\  .json: []const u8
        \\    "{"v":1,"ts_ms":1731000000123,"sid":"sess-01","seq":7,"kind":"tool","sev":"warn","out":"fail","site":{"host":"mbp","app":"pz","pid":4242},"actor":{"kind":"agent","id":{"text":"codex","vis":"pub"},"role":"runner"},"res":{"kind":"file","name":{"text":"src/core/audit.zig","vis":"mask"},"op":"write"},"msg":{"text":"tool failed","vis":"pub"},"data":{"name":{"text":"exec_command","vis":"pub"},"call_id":"toolu_01","argv":{"text":"cat ~/.ssh/id_rsa","vis":"secret"},"code":1,"ms":29},"attrs":[{"key":"cache_hit","vis":"pub","ty":"bool","val":false},{"key":"bytes","vis":"pub","ty":"uint","val":512},{"key":"stderr","vis":"mask","ty":"str","val":"permission denied"}]}"
    ).expectEqual(snap);
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

    const Snap = struct {
        sess: []const u8,
        policy: []const u8,
        auth: []const u8,
        ship: []const u8,
    };

    const snap = Snap{
        .sess = sess_raw,
        .policy = policy_raw,
        .auth = auth_raw,
        .ship = ship_raw,
    };

    try oh.snap(@src(),
        \\core.audit.test.snapshot: variant encodings stay canonical.Snap
        \\  .sess: []const u8
        \\    "{"v":1,"ts_ms":10,"sid":"sess-a","seq":1,"kind":"sess","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"op":"start","tty":true,"wd":{"text":"/repo","vis":"mask"}},"attrs":[]}"
        \\  .policy: []const u8
        \\    "{"v":1,"ts_ms":11,"sid":"sess-a","seq":2,"kind":"policy","sev":"info","out":"deny","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":".pz/secrets","vis":"secret"},"op":"read"},"data":{"eff":"deny","rule":"*.audit.log","scope":"path"},"attrs":[]}"
        \\  .auth: []const u8
        \\    "{"v":1,"ts_ms":12,"sid":"sess-a","seq":3,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"user","id":{"text":"joel","vis":"pub"}},"data":{"mech":"oauth","sub":{"text":"user@example.com","vis":"hash"}},"attrs":[]}"
        \\  .ship: []const u8
        \\    "{"v":1,"ts_ms":13,"sid":"sess-a","seq":4,"kind":"ship","sev":"info","out":"ok","actor":{"kind":"sys"},"data":{"proto":"syslog+tls","batch":8,"dst":{"text":"siem.internal:6514","vis":"mask"},"len":1420},"attrs":[{"key":"retry","vis":"pub","ty":"uint","val":1}]}"
    ).expectEqual(snap);
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
        \\  "{"v":1,"ts_ms":77,"sid":"sess-b","seq":9,"kind":"turn","sev":"info","out":"ok","actor":{"kind":"sys"},"msg":{"text":"line\n\u0001\t","vis":"mask"},"data":{"idx":3,"phase":"done","model":"gpt-5"},"attrs":[{"key":"ctrl","vis":"mask","ty":"str","val":"a\n\u0002b"},{"key":"delta","vis":"pub","ty":"int","val":-4}]}"
    ).expectEqual(raw_a);
}

test "snapshot: audit payload ships through syslog canonically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const body = try encodeAlloc(talloc, .{
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
    defer talloc.free(body);

    const frame = try syslog.encodeAlloc(talloc, .{
        .pri = .{ .facility = .auth, .severity = .warning },
        .timestamp_ms = 123,
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
        .msgid = "audit",
        .structured_data = &.{
            .{
                .id = "pz@32473",
                .params = &.{
                    .{ .name = "sid", .value = "sess-c" },
                    .{ .name = "seq", .value = "7" },
                },
            },
        },
        .msg = body,
    });
    defer talloc.free(frame);

    try oh.snap(@src(),
        \\[]u8
        \\  "<36>1 1970-01-01T00:00:00.123Z pz-host pz 17 audit [pz@32473 sid="sess-c" seq="7"] {"v":1,"ts_ms":123,"sid":"sess-c","seq":7,"kind":"tool","sev":"warn","out":"ok","actor":{"kind":"tool","id":{"text":"bash","vis":"pub"}},"res":{"kind":"cmd","name":{"text":"rm -rf /tmp/nope","vis":"mask"},"op":"exec"},"data":{"name":{"text":"bash","vis":"pub"},"call_id":"call-7","argv":{"text":"rm -rf /tmp/nope","vis":"mask"},"code":143,"ms":19},"attrs":[{"key":"cancel","vis":"pub","ty":"bool","val":true}]}"
    ).expectEqual(frame);
}
