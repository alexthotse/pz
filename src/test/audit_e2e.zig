const std = @import("std");
const testing = std.testing;
const audit = @import("../core/audit.zig");
const audit_integrity = @import("../core/audit_integrity.zig");
const syslog = @import("../core/syslog.zig");
const auth = @import("../core/providers/auth.zig");
const bg = @import("../app/bg.zig");
const syslog_mock = @import("syslog_mock.zig");

const Rows = struct {
    rows: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *Rows, alloc: std.mem.Allocator) void {
        for (self.rows.items) |row| alloc.free(row);
        self.rows.deinit(alloc);
        self.* = undefined;
    }

    fn emit(ctx: *anyopaque, alloc: std.mem.Allocator, ent: audit.Entry) !void {
        const self: *Rows = @ptrCast(@alignCast(ctx));
        try self.appendEntry(alloc, ent);
    }

    fn appendEntry(self: *Rows, alloc: std.mem.Allocator, ent: audit.Entry) !void {
        const raw = try audit.encodeAlloc(alloc, ent);
        try self.rows.append(alloc, raw);
    }
};

const AuditHdrDoc = struct {
    ts_ms: i64,
    sid: []const u8,
    seq: u64,
    sev: audit.Sev,
};

const AuditSealDoc = struct {
    mac: []const u8,
    body: []const u8,
};

fn e2eAuditKey() audit_integrity.Key {
    return .{
        .id = 7,
        .bytes = [_]u8{0x37} ** audit_integrity.mac_len,
    };
}

fn e2eFrameOpts() audit.FrameOpts {
    return .{
        .hostname = "pz-host",
        .app_name = "pz",
        .procid = "17",
        .msgid = "audit",
    };
}

fn shipAuditRows(alloc: std.mem.Allocator, sender: *syslog.Sender, rows: []const []const u8) !void {
    const key = e2eAuditKey();
    var prev: ?audit_integrity.Tag = null;

    for (rows) |row| {
        const hdr = try std.json.parseFromSlice(AuditHdrDoc, alloc, row, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer hdr.deinit();

        const sealed = try audit_integrity.sealAlloc(alloc, key, prev, row);
        defer alloc.free(sealed);

        const doc = try std.json.parseFromSlice(AuditSealDoc, alloc, sealed, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer doc.deinit();

        var next: audit_integrity.Tag = undefined;
        _ = try std.fmt.hexToBytes(next[0..], doc.value.mac);

        const frame = try audit.encodeFrameBodyAlloc(alloc, e2eFrameOpts(), .{
            .ts_ms = hdr.value.ts_ms,
            .sid = hdr.value.sid,
            .seq = hdr.value.seq,
            .sev = hdr.value.sev,
        }, sealed);
        defer alloc.free(frame);

        try sender.sendRaw(frame);
        prev = next;
    }
}

fn extractSyslogMsg(raw: []const u8) ![]const u8 {
    const idx = std.mem.indexOf(u8, raw, "] {") orelse return error.InvalidFrame;
    return raw[idx + 2 ..];
}

fn joinShippedLinesAlloc(alloc: std.mem.Allocator, collector: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (0..collector.msgCount()) |i| {
        try out.appendSlice(alloc, try extractSyslogMsg(collector.messageAt(i)));
        try out.append(alloc, '\n');
    }
    return try out.toOwnedSlice(alloc);
}

fn joinShippedBodiesAlloc(alloc: std.mem.Allocator, collector: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (0..collector.msgCount()) |i| {
        const raw = try extractSyslogMsg(collector.messageAt(i));
        const doc = try std.json.parseFromSlice(AuditSealDoc, alloc, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        });
        defer doc.deinit();

        if (i > 0) try out.append(alloc, '\n');
        try out.appendSlice(alloc, doc.value.body);
    }
    return try out.toOwnedSlice(alloc);
}

fn waitWake(fd: std.posix.fd_t, timeout_ms: i32) !bool {
    var fds = [1]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const n = try std.posix.poll(&fds, timeout_ms);
    if (n <= 0) return false;
    return (fds[0].revents & std.posix.POLL.IN) != 0;
}

fn addManualRows(rows: *Rows) !void {
    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 101,
        .sid = "runtime-ctl",
        .seq = 1,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = "runtime", .vis = .@"pub" },
            .op = "resume",
        },
        .msg = .{ .text = "runtime control success", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "runtime", .vis = .@"pub" },
                .call_id = "resume",
                .argv = .{ .text = "/tmp/runtime-secret/42.jsonl", .vis = .mask },
            },
        },
        .attrs = &.{
            .{ .key = "mode", .val = .{ .str = "rpc" } },
            .{ .key = "provider", .val = .{ .str = "openai" } },
        },
    });

    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 111,
        .sid = "export-ctl",
        .seq = 1,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .file,
            .name = .{ .text = "/tmp/export-secret/report.md", .vis = .mask },
            .op = "write",
        },
        .msg = .{ .text = "export start", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "export", .vis = .@"pub" },
                .call_id = "sess-export",
                .argv = .{ .text = "/tmp/export-secret/report.md", .vis = .mask },
            },
        },
    });
    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 112,
        .sid = "export-ctl",
        .seq = 2,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .file,
            .name = .{ .text = "/tmp/export-secret/report.md", .vis = .mask },
            .op = "write",
        },
        .msg = .{ .text = "export complete", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "export", .vis = .@"pub" },
                .call_id = "sess-export",
                .argv = .{ .text = "/tmp/export-secret/report.md", .vis = .mask },
            },
        },
    });

    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 121,
        .sid = "share-ctl",
        .seq = 1,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .net,
            .name = .{ .text = "https://gist.github.com/joel/abc123", .vis = .hash },
            .op = "publish",
        },
        .msg = .{ .text = "share complete", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "share", .vis = .@"pub" },
                .call_id = "share",
                .argv = .{ .text = "/tmp/share-secret/report.md", .vis = .mask },
            },
        },
        .attrs = &.{
            .{ .key = "visibility", .val = .{ .str = "private" } },
        },
    });

    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 131,
        .sid = "upgrade",
        .seq = 1,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = "upgrade", .vis = .@"pub" },
            .op = "run",
        },
        .msg = .{ .text = "upgrade start", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "upgrade", .vis = .@"pub" },
                .call_id = "upgrade",
            },
        },
    });
    try rows.appendEntry(testing.allocator, .{
        .ts_ms = 132,
        .sid = "upgrade",
        .seq = 2,
        .out = .deny,
        .sev = .warn,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = "upgrade", .vis = .@"pub" },
            .op = "run",
        },
        .msg = .{ .text = "policy denied", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "upgrade", .vis = .@"pub" },
                .call_id = "upgrade",
                .argv = .{ .text = ".pz/policy.json", .vis = .mask },
            },
        },
    });
}

fn addAuthRows(rows: *Rows) !void {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(home);

    try auth.saveApiKeyWithHooks(testing.allocator, .openai, "sk-openai-secret", .{
        .home_override = home,
        .emit_audit_ctx = rows,
        .emit_audit = Rows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 211;
            }
        }.f,
    });
}

fn addBgRows(rows: *Rows) !void {
    var mgr = try bg.Mgr.initWithOpts(testing.allocator, .{
        .emit_audit_ctx = rows,
        .emit_audit = Rows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 311;
            }
        }.f,
    });
    defer mgr.deinit();

    const id = try mgr.start("printf done", "/tmp/bg-secret");

    const stop = try mgr.stop(id);
    try testing.expect(stop == .sent or stop == .already_done);

    const woke = try waitWake(mgr.wakeFd(), 5000);
    try testing.expect(woke);

    const done = try mgr.drainDone(testing.allocator);
    defer bg.deinitViews(testing.allocator, done);
    try testing.expectEqual(@as(usize, 1), done.len);
}

fn buildRows() !Rows {
    var rows = Rows{};
    errdefer rows.deinit(testing.allocator);

    try addManualRows(&rows);
    try addAuthRows(&rows);
    try addBgRows(&rows);

    return rows;
}

fn assertCleartextMissing(collector: anytype) !void {
    const ban = [_][]const u8{
        "/tmp/runtime-secret/42.jsonl",
        "/tmp/export-secret/report.md",
        "/tmp/share-secret/report.md",
        "https://gist.github.com/joel/abc123",
        ".pz/policy.json",
        "sk-openai-secret",
        "printf done",
        "/tmp/bg-secret",
        "/tmp/pz-bg-",
    };

    for (0..collector.msgCount()) |i| {
        const raw = collector.messageAt(i);
        try testing.expect(std.mem.indexOf(u8, raw, "[pz@32473 sid=\"") != null);
        for (ban) |needle| {
            try testing.expect(std.mem.indexOf(u8, raw, needle) == null);
        }
    }
}

fn verifyRoundTrip(collector: anytype, rows: []const []const u8) !void {
    try testing.expectEqual(rows.len, collector.msgCount());

    const shipped_lines = try joinShippedLinesAlloc(testing.allocator, collector);
    defer testing.allocator.free(shipped_lines);

    const got_chain = try audit_integrity.verifyLogAlloc(testing.allocator, shipped_lines, &.{e2eAuditKey()});
    switch (got_chain) {
        .ok => |ok| {
            try testing.expectEqual(@as(u64, @intCast(rows.len)), ok.lines);
            try testing.expectEqual(@as(?u32, e2eAuditKey().id), ok.last_key_id);
            try testing.expect(ok.last_mac != null);
        },
        .fail => return error.InvalidAuditChain,
    }

    const shipped_bodies = try joinShippedBodiesAlloc(testing.allocator, collector);
    defer testing.allocator.free(shipped_bodies);
    const expected = try std.mem.join(testing.allocator, "\n", rows);
    defer testing.allocator.free(expected);

    try testing.expectEqualStrings(expected, shipped_bodies);
    try assertCleartextMissing(collector);
}

test "audit e2e ships mixed privileged control rows over udp" {
    var rows = try buildRows();
    defer rows.deinit(testing.allocator);

    var collector = try syslog_mock.UdpCollector.init();
    defer collector.deinit();
    const t = try collector.spawnCount(rows.rows.items.len);

    var sender = try syslog.Sender.init(testing.allocator, .{
        .transport = .udp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try shipAuditRows(testing.allocator, &sender, rows.rows.items);
    t.join();

    try verifyRoundTrip(&collector, rows.rows.items);
}

test "audit e2e ships mixed privileged control rows over tcp" {
    var rows = try buildRows();
    defer rows.deinit(testing.allocator);

    var collector = try syslog_mock.TcpCollector.init();
    defer collector.deinit();
    const t = try collector.spawnCount(rows.rows.items.len);

    var sender = try syslog.Sender.init(testing.allocator, .{
        .transport = .tcp,
        .host = "127.0.0.1",
        .port = collector.port(),
    });
    defer sender.deinit();

    try shipAuditRows(testing.allocator, &sender, rows.rows.items);
    t.join();

    try verifyRoundTrip(&collector, rows.rows.items);
}
