//! Session export: convert JSONL session to markdown.
const std = @import("std");
const audit = @import("../audit.zig");
const utf8 = @import("../utf8.zig");
const reader_mod = @import("reader.zig");
const sid_path = @import("path.zig");

/// Optional callbacks for audit emission during export.
pub const AuditHooks = struct {
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = nowMs,
};

/// Export a session to markdown.
/// Returns the absolute path to the written file (caller owns).
pub fn toMarkdown(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    out_path: ?[]const u8,
) ![]u8 {
    return toMarkdownWith(alloc, dir, sid, out_path, .{});
}

pub fn toMarkdownAudited(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    out_path: ?[]const u8,
    hooks: AuditHooks,
) ![]u8 {
    return toMarkdownWith(alloc, dir, sid, out_path, hooks);
}

fn toMarkdownWith(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    out_path: ?[]const u8,
    hooks: AuditHooks,
) ![]u8 {
    var rdr = try reader_mod.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    // Header
    try buf.appendSlice(alloc, "# Session ");
    try buf.appendSlice(alloc, sid);
    try buf.appendSlice(alloc, "\n\n");

    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| {
                try appendSection(alloc, &buf, "User", p.text);
            },
            .text => |t| {
                try appendSection(alloc, &buf, "Assistant", t.text);
            },
            .thinking => |t| {
                try buf.appendSlice(alloc, "<details><summary>Thinking</summary>\n\n");
                try appendFence(alloc, &buf, t.text);
                try buf.appendSlice(alloc, "\n</details>\n\n");
            },
            .tool_call => |tc| {
                try buf.appendSlice(alloc, "### Tool: ");
                const safe_name = try redactLossyAlloc(alloc, tc.name, .@"pub");
                defer alloc.free(safe_name);
                try buf.appendSlice(alloc, safe_name);
                try buf.appendSlice(alloc, "\n\n");
                try appendFence(alloc, &buf, tc.args);
                try buf.appendSlice(alloc, "\n");
            },
            .tool_result => |tr| {
                try buf.appendSlice(alloc, if (tr.is_err) "#### Error\n\n" else "#### Result\n\n");
                // Truncate very long tool output
                const max_out = 2000;
                const raw_out = if (tr.output.len > max_out) tr.output[0..max_out] else tr.output;
                try appendFence(alloc, &buf, raw_out);
                if (tr.output.len > max_out) {
                    const trunc_msg = try std.fmt.allocPrint(alloc, "\n... ({d} bytes truncated)", .{tr.output.len - max_out});
                    defer alloc.free(trunc_msg);
                    try buf.appendSlice(alloc, trunc_msg);
                }
                try buf.appendSlice(alloc, "\n");
            },
            .err => |e| {
                try appendSection(alloc, &buf, "Error", e.text);
            },
            .usage, .stop, .noop => {},
        }
    }

    // Determine output path (resolve relative to cwd)
    const dest = if (out_path) |p| blk: {
        if (std.fs.path.isAbsolute(p)) {
            break :blk try alloc.dupe(u8, p);
        }
        const cwd = try std.fs.cwd().realpathAlloc(alloc, ".");
        defer alloc.free(cwd);
        break :blk try std.fs.path.join(alloc, &.{ cwd, p });
    } else blk: {
        const fname = try sid_path.sidExtAlloc(alloc, sid, ".md");
        defer alloc.free(fname);
        // Write next to the session directory
        const real = try dir.realpathAlloc(alloc, ".");
        defer alloc.free(real);
        break :blk try std.fs.path.join(alloc, &.{ real, fname });
    };
    errdefer alloc.free(dest);

    try emitAudit(alloc, hooks, audit.Entry{
        .ts_ms = hooks.now_ms(),
        .sid = sid,
        .seq = 1,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .file,
            .name = .{ .text = dest, .vis = .mask },
            .op = "write",
        },
        .msg = .{ .text = "export start", .vis = .@"pub" },
        .data = .{
            .tool = .{
                .name = .{ .text = "export", .vis = .@"pub" },
                .call_id = sid,
                .argv = .{ .text = dest, .vis = .mask },
            },
        },
    });

    const file = std.fs.createFileAbsolute(dest, .{ .truncate = true }) catch |err| {
        try emitAudit(alloc, hooks, exportOutcomeAudit(sid, dest, hooks.now_ms(), .fail, @errorName(err)));
        return err;
    };
    defer file.close();
    file.writeAll(buf.items) catch |err| {
        try emitAudit(alloc, hooks, exportOutcomeAudit(sid, dest, hooks.now_ms(), .fail, @errorName(err)));
        return err;
    };

    try emitAudit(alloc, hooks, exportOutcomeAudit(sid, dest, hooks.now_ms(), .ok, null));

    return dest;
}

fn appendSection(alloc: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), title: []const u8, txt: []const u8) !void {
    try buf.appendSlice(alloc, "## ");
    try buf.appendSlice(alloc, title);
    try buf.appendSlice(alloc, "\n\n");
    try appendFence(alloc, buf, txt);
    try buf.appendSlice(alloc, "\n");
}

fn appendFence(alloc: std.mem.Allocator, buf: *std.ArrayListUnmanaged(u8), txt: []const u8) !void {
    const safe = try redactLossyAlloc(alloc, txt, .@"pub");
    defer alloc.free(safe);

    const n = fenceLen(safe);
    var fence = std.ArrayListUnmanaged(u8){};
    defer fence.deinit(alloc);
    try fence.resize(alloc, n);
    @memset(fence.items, '`');

    try buf.appendSlice(alloc, fence.items);
    try buf.appendSlice(alloc, "\n");
    try buf.appendSlice(alloc, safe);
    if (safe.len == 0 or safe[safe.len - 1] != '\n') try buf.appendSlice(alloc, "\n");
    try buf.appendSlice(alloc, fence.items);
    try buf.appendSlice(alloc, "\n\n");
}

fn redactLossyAlloc(alloc: std.mem.Allocator, txt: []const u8, vis: audit.Vis) ![]u8 {
    var safe = try utf8.Lossy.init(alloc, txt);
    defer safe.deinit(alloc);
    return audit.redactTextAlloc(alloc, safe.text, vis);
}

fn fenceLen(txt: []const u8) usize {
    var best: usize = 0;
    var run: usize = 0;
    for (txt) |c| {
        if (c == '`') {
            run += 1;
            if (run > best) best = run;
        } else {
            run = 0;
        }
    }
    return @max(@as(usize, 3), best + 1);
}

fn exportOutcomeAudit(sid: []const u8, dest: []const u8, ts_ms: i64, out: audit.Outcome, err_name: ?[]const u8) audit.Entry {
    return .{
        .ts_ms = ts_ms,
        .sid = sid,
        .seq = 2,
        .outcome = out,
        .severity = if (out == .ok) .info else .err,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .file,
            .name = .{ .text = dest, .vis = .mask },
            .op = "write",
        },
        .msg = .{ .text = if (out == .ok) "export complete" else err_name.?, .vis = if (out == .ok) .@"pub" else .mask },
        .data = .{
            .tool = .{
                .name = .{ .text = "export", .vis = .@"pub" },
                .call_id = sid,
                .argv = .{ .text = dest, .vis = .mask },
            },
        },
    };
}

fn emitAudit(alloc: std.mem.Allocator, hooks: AuditHooks, ent: audit.Entry) !void {
    if (hooks.emit_audit) |emit| try emit(hooks.emit_audit_ctx.?, alloc, ent);
}

fn nowMs() i64 {
    return std.time.milliTimestamp();
}

fn normalizeMd(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(alloc);
    var nl_run: usize = 0;
    for (raw) |c| {
        if (c == '\n') {
            nl_run += 1;
            if (nl_run > 2) continue;
        } else {
            nl_run = 0;
        }
        try out.append(alloc, c);
    }
    while (out.items.len > 0 and out.items[out.items.len - 1] == '\n') {
        out.items.len -= 1;
    }
    return try out.toOwnedSlice(alloc);
}

const utf8_case = @import("../../test/utf8_case.zig");

test "export session to markdown" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const writer_mod = @import("writer.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("ex1", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "Authorization: Bearer sk-secret" } } });
    try wr.append("ex1", .{ .at_ms = 2, .data = .{ .text = .{ .text = "# hi\n<script>alert(1)</script>" } } });
    try wr.append("ex1", .{ .at_ms = 3, .data = .{ .thinking = .{ .text = "```internal```" } } });
    try wr.append("ex1", .{ .at_ms = 4, .data = .{ .tool_call = .{ .id = "c1", .name = "bash", .args = "cat ~/.pz/auth.json" } } });
    try wr.append("ex1", .{ .at_ms = 5, .data = .{ .tool_result = .{ .id = "c1", .output = "```\nraw\n```", .is_err = false } } });
    try wr.append("ex1", .{ .at_ms = 6, .data = .{ .stop = .{ .reason = .done } } });

    // Export to a specific path
    const real = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(real);
    const dest = try std.fs.path.join(std.testing.allocator, &.{ real, "out.md" });
    defer std.testing.allocator.free(dest);

    const path = try toMarkdown(std.testing.allocator, tmp.dir, "ex1", dest);
    defer std.testing.allocator.free(path);

    try std.testing.expectEqualStrings(dest, path);

    // Read back and verify
    const content = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer content.close();
    const md = try content.readToEndAlloc(std.testing.allocator, 64 * 1024);
    defer std.testing.allocator.free(md);
    const snap = try normalizeMd(std.testing.allocator, md);
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "# Session ex1
        \\
        \\## User
        \\
        \\```
        \\[secret:427dbdce96c1386f]
        \\```
        \\
        \\## Assistant
        \\
        \\```
        \\# hi
        \\<script>alert(1)</script>
        \\```
        \\
        \\<details><summary>Thinking</summary>
        \\
        \\````
        \\```internal```
        \\````
        \\
        \\</details>
        \\
        \\### Tool: bash
        \\
        \\```
        \\[path:edaee5b4fbed2103]
        \\```
        \\
        \\#### Result
        \\
        \\````
        \\```
        \\raw
        \\```
        \\````"
    ).expectEqual(snap);
}

test "export default path uses sid.md" {
    const writer_mod = @import("writer.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("s2", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "q" } } });
    try wr.append("s2", .{ .at_ms = 2, .data = .{ .text = .{ .text = "a" } } });
    try wr.append("s2", .{ .at_ms = 3, .data = .{ .stop = .{ .reason = .done } } });

    const path = try toMarkdown(std.testing.allocator, tmp.dir, "s2", null);
    defer std.testing.allocator.free(path);

    // Should end with s2.md
    try std.testing.expect(std.mem.endsWith(u8, path, "s2.md"));

    // File should exist
    const f = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    f.close();
}

test "export markdown redacts secrets and neutralizes markdown" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const writer_mod = @import("writer.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });
    try wr.append("sec1", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "# heading\nsk-live-secret" } } });
    try wr.append("sec1", .{ .at_ms = 2, .data = .{ .text = .{ .text = "<script>alert(1)</script>\n```boom```" } } });
    try wr.append("sec1", .{ .at_ms = 3, .data = .{ .tool_call = .{ .id = "c1", .name = "bash", .args = "cat ~/.pz/auth.json" } } });
    try wr.append("sec1", .{ .at_ms = 4, .data = .{ .tool_result = .{ .id = "c1", .output = "authorization: bearer sk-test", .is_err = true } } });

    const real = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(real);
    const dest = try std.fs.path.join(std.testing.allocator, &.{ real, "sec1.md" });
    defer std.testing.allocator.free(dest);

    const path = try toMarkdown(std.testing.allocator, tmp.dir, "sec1", dest);
    defer std.testing.allocator.free(path);
    const content = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer content.close();
    const md = try content.readToEndAlloc(std.testing.allocator, 64 * 1024);
    defer std.testing.allocator.free(md);
    const snap = try normalizeMd(std.testing.allocator, md);
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "# Session sec1
        \\
        \\## User
        \\
        \\```
        \\[secret:f5576993961d7f31]
        \\```
        \\
        \\## Assistant
        \\
        \\````
        \\<script>alert(1)</script>
        \\```boom```
        \\````
        \\
        \\### Tool: bash
        \\
        \\```
        \\[path:edaee5b4fbed2103]
        \\```
        \\
        \\#### Error
        \\
        \\```
        \\[secret:7ac2c068fc811ef1]
        \\```"
    ).expectEqual(snap);
}

test "export markdown replaces invalid utf8 from persisted tool output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const writer_mod = @import("writer.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });
    try wr.append("utf8", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "run" } } });
    try wr.append("utf8", .{ .at_ms = 2, .data = .{ .tool_result = .{
        .id = "c1",
        .output = utf8_case.bad_tool_out[0..],
        .is_err = false,
    } } });

    const raw = try tmp.dir.readFileAlloc(std.testing.allocator, "utf8.jsonl", 4096);
    defer std.testing.allocator.free(raw);
    try std.testing.expect(std.mem.indexOfScalar(u8, raw, 0xff) == null);
    try std.testing.expect(std.mem.indexOf(u8, raw, utf8_case.lossy_tool_out) != null);

    const real = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(real);
    const dest = try std.fs.path.join(std.testing.allocator, &.{ real, "utf8.md" });
    defer std.testing.allocator.free(dest);

    const path = try toMarkdown(std.testing.allocator, tmp.dir, "utf8", dest);
    defer std.testing.allocator.free(path);

    const content = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer content.close();
    const md = try content.readToEndAlloc(std.testing.allocator, 64 * 1024);
    defer std.testing.allocator.free(md);
    const snap = try normalizeMd(std.testing.allocator, md);
    defer std.testing.allocator.free(snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "# Session utf8
        \\
        \\## User
        \\
        \\```
        \\run
        \\```
        \\
        \\#### Result
        \\
        \\```
        \\o?k?
        \\```"
    ).expectEqual(snap);
}

test "export audit emits start and success entries" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const writer_mod = @import("writer.zig");

    const Capture = struct {
        rows: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
            for (self.rows.items) |row| alloc.free(row);
            self.rows.deinit(alloc);
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });
    try wr.append("ex2", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "hello" } } });
    try wr.append("ex2", .{ .at_ms = 2, .data = .{ .text = .{ .text = "world" } } });

    var cap = Capture{};
    defer cap.deinit(std.testing.allocator);
    const real = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(real);
    const dest = try std.fs.path.join(std.testing.allocator, &.{ real, "audit.md" });
    defer std.testing.allocator.free(dest);

    const path = try toMarkdownWith(std.testing.allocator, tmp.dir, "ex2", dest, .{
        .emit_audit_ctx = &cap,
        .emit_audit = struct {
            fn f(ctx: *anyopaque, alloc: std.mem.Allocator, ent: audit.Entry) !void {
                const cap_ptr: *Capture = @ptrCast(@alignCast(ctx));
                const raw = try audit.encodeAlloc(alloc, ent);
                try cap_ptr.rows.append(alloc, raw);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 123;
            }
        }.f,
    });
    defer std.testing.allocator.free(path);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    const scrubbed = try scrubExportAudit(std.testing.allocator, joined);
    defer std.testing.allocator.free(scrubbed);

    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":123,"sid":"ex2","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export start","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"ex2","argv":{"text":"[mask:PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":123,"sid":"ex2","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export complete","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"ex2","argv":{"text":"[mask:PATH]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(scrubbed);
}

test "export audit emits failure entry on write failure" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const writer_mod = @import("writer.zig");

    const Capture = struct {
        rows: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
            for (self.rows.items) |row| alloc.free(row);
            self.rows.deinit(alloc);
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });
    try wr.append("ex3", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "hello" } } });

    var cap = Capture{};
    defer cap.deinit(std.testing.allocator);
    const real = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(real);
    const bad = try std.fs.path.join(std.testing.allocator, &.{ real, "missing", "audit.md" });
    defer std.testing.allocator.free(bad);

    try std.testing.expectError(error.FileNotFound, toMarkdownWith(std.testing.allocator, tmp.dir, "ex3", bad, .{
        .emit_audit_ctx = &cap,
        .emit_audit = struct {
            fn f(ctx: *anyopaque, alloc: std.mem.Allocator, ent: audit.Entry) !void {
                const cap_ptr: *Capture = @ptrCast(@alignCast(ctx));
                const raw = try audit.encodeAlloc(alloc, ent);
                try cap_ptr.rows.append(alloc, raw);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 456;
            }
        }.f,
    }));

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    const scrubbed = try scrubExportAudit(std.testing.allocator, joined);
    defer std.testing.allocator.free(scrubbed);

    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":456,"sid":"ex3","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:PATH]","vis":"mask"},"op":"write"},"msg":{"text":"export start","vis":"pub"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"ex3","argv":{"text":"[mask:PATH]","vis":"mask"}},"attrs":[]}
        \\{"v":1,"ts_ms":456,"sid":"ex3","seq":2,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"file","name":{"text":"[mask:PATH]","vis":"mask"},"op":"write"},"msg":{"text":"[mask:e0d43158cc95b24d]","vis":"mask"},"data":{"name":{"text":"export","vis":"pub"},"call_id":"ex3","argv":{"text":"[mask:PATH]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(scrubbed);
}

fn scrubExportAudit(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var cur = try alloc.dupe(u8, raw);
    const pats = [_][]const u8{
        "\"res\":{\"kind\":\"file\",\"name\":{\"text\":\"",
        "\"argv\":{\"text\":\"",
    };
    for (pats) |pat| {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(alloc);
        var off: usize = 0;
        while (std.mem.indexOfPos(u8, cur, off, pat)) |idx| {
            const start = idx + pat.len;
            const end = std.mem.indexOfScalarPos(u8, cur, start, '"') orelse break;
            try out.appendSlice(alloc, cur[off..start]);
            try out.appendSlice(alloc, "[mask:PATH]");
            off = end;
        }
        try out.appendSlice(alloc, cur[off..]);
        alloc.free(cur);
        cur = try out.toOwnedSlice(alloc);
    }
    return cur;
}

test "scrubExportAudit property: targeted paths normalize to mask" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            sid: zc.Id,
            call_id: zc.Id,
            file: zc.Id,
            argv: zc.Id,
        }) bool {
            const alloc = std.testing.allocator;
            const file_path = std.fmt.allocPrint(alloc, "/tmp/{s}", .{args.file.slice()}) catch return false;
            defer alloc.free(file_path);
            const argv_path = std.fmt.allocPrint(alloc, "/bin/{s}", .{args.argv.slice()}) catch return false;
            defer alloc.free(argv_path);
            const raw = std.fmt.allocPrint(
                alloc,
                "{{\"v\":1,\"ts_ms\":1,\"sid\":\"{s}\",\"seq\":1,\"kind\":\"tool\",\"sev\":\"info\",\"out\":\"ok\",\"actor\":{{\"kind\":\"sys\"}},\"res\":{{\"kind\":\"file\",\"name\":{{\"text\":\"{s}\",\"vis\":\"sec\"}},\"op\":\"write\"}},\"msg\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"data\":{{\"name\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"call_id\":\"{s}\",\"argv\":{{\"text\":\"{s}\",\"vis\":\"sec\"}}}},\"attrs\":[]}}",
                .{ args.sid.slice(), file_path, args.call_id.slice(), argv_path },
            ) catch return false;
            defer alloc.free(raw);
            const want = std.fmt.allocPrint(
                alloc,
                "{{\"v\":1,\"ts_ms\":1,\"sid\":\"{s}\",\"seq\":1,\"kind\":\"tool\",\"sev\":\"info\",\"out\":\"ok\",\"actor\":{{\"kind\":\"sys\"}},\"res\":{{\"kind\":\"file\",\"name\":{{\"text\":\"[mask:PATH]\",\"vis\":\"sec\"}},\"op\":\"write\"}},\"msg\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"data\":{{\"name\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"call_id\":\"{s}\",\"argv\":{{\"text\":\"[mask:PATH]\",\"vis\":\"sec\"}}}},\"attrs\":[]}}",
                .{ args.sid.slice(), args.call_id.slice() },
            ) catch return false;
            defer alloc.free(want);
            const got = scrubExportAudit(alloc, raw) catch return false;
            defer alloc.free(got);
            return std.mem.eql(u8, got, want) and
                std.mem.count(u8, got, "[mask:PATH]") == 2 and
                std.mem.indexOf(u8, got, file_path) == null and
                std.mem.indexOf(u8, got, argv_path) == null;
        }
    }.prop, .{ .iterations = 200 });
}

test "scrubExportAudit property: masked targeted rows stay stable" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { sid: zc.Id, call_id: zc.Id }) bool {
            const alloc = std.testing.allocator;
            const raw = std.fmt.allocPrint(
                alloc,
                "{{\"v\":1,\"ts_ms\":1,\"sid\":\"{s}\",\"seq\":1,\"kind\":\"tool\",\"sev\":\"info\",\"out\":\"ok\",\"actor\":{{\"kind\":\"sys\"}},\"res\":{{\"kind\":\"file\",\"name\":{{\"text\":\"[mask:PATH]\",\"vis\":\"mask\"}},\"op\":\"write\"}},\"msg\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"data\":{{\"name\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"call_id\":\"{s}\",\"argv\":{{\"text\":\"[mask:PATH]\",\"vis\":\"mask\"}}}},\"attrs\":[]}}",
                .{ args.sid.slice(), args.call_id.slice() },
            ) catch return false;
            defer alloc.free(raw);
            const got = scrubExportAudit(alloc, raw) catch return false;
            defer alloc.free(got);
            return std.mem.eql(u8, got, raw);
        }
    }.prop, .{ .iterations = 200 });
}

test "scrubExportAudit property: safe rows stay stable" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            sid: zc.Id,
            file: zc.Id,
            argv: zc.Id,
        }) bool {
            const alloc = std.testing.allocator;
            const file_path = std.fmt.allocPrint(alloc, "/tmp/{s}", .{args.file.slice()}) catch return false;
            defer alloc.free(file_path);
            const argv_path = std.fmt.allocPrint(alloc, "/bin/{s}", .{args.argv.slice()}) catch return false;
            defer alloc.free(argv_path);
            const raw = std.fmt.allocPrint(
                alloc,
                "{{\"v\":1,\"ts_ms\":1,\"sid\":\"{s}\",\"seq\":1,\"kind\":\"tool\",\"sev\":\"info\",\"out\":\"ok\",\"actor\":{{\"kind\":\"sys\"}},\"res\":{{\"kind\":\"cmd\",\"name\":{{\"text\":\"{s}\",\"vis\":\"sec\"}},\"op\":\"run\"}},\"msg\":{{\"text\":\"run {s}\",\"vis\":\"sec\"}},\"data\":{{\"name\":{{\"text\":\"export\",\"vis\":\"pub\"}},\"argv\":\"{s}\"}},\"attrs\":[]}}",
                .{ args.sid.slice(), file_path, argv_path, argv_path },
            ) catch return false;
            defer alloc.free(raw);
            const got = scrubExportAudit(alloc, raw) catch return false;
            defer alloc.free(got);
            return std.mem.eql(u8, got, raw);
        }
    }.prop, .{ .iterations = 200 });
}
