const std = @import("std");
const audit = @import("../audit.zig");
const schema = @import("schema.zig");
const reader_mod = @import("reader.zig");
const sid_path = @import("path.zig");

const Hooks = struct {
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

fn toMarkdownWith(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    out_path: ?[]const u8,
    hooks: Hooks,
) ![]u8 {
    var rdr = try reader_mod.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(alloc);

    // Header
    try buf.appendSlice(alloc, "# Session ");
    try buf.appendSlice(alloc, sid);
    try buf.appendSlice(alloc, "\n\n");

    var in_tool = false;
    while (try rdr.next()) |ev| {
        switch (ev.data) {
            .prompt => |p| {
                if (in_tool) {
                    try buf.appendSlice(alloc, "```\n\n");
                    in_tool = false;
                }
                try buf.appendSlice(alloc, "## User\n\n");
                try buf.appendSlice(alloc, p.text);
                try buf.appendSlice(alloc, "\n\n");
            },
            .text => |t| {
                if (in_tool) {
                    try buf.appendSlice(alloc, "```\n\n");
                    in_tool = false;
                }
                try buf.appendSlice(alloc, "## Assistant\n\n");
                try buf.appendSlice(alloc, t.text);
                try buf.appendSlice(alloc, "\n\n");
            },
            .thinking => |t| {
                if (in_tool) {
                    try buf.appendSlice(alloc, "```\n\n");
                    in_tool = false;
                }
                try buf.appendSlice(alloc, "<details><summary>Thinking</summary>\n\n");
                try buf.appendSlice(alloc, t.text);
                try buf.appendSlice(alloc, "\n\n</details>\n\n");
            },
            .tool_call => |tc| {
                if (in_tool) {
                    try buf.appendSlice(alloc, "```\n\n");
                }
                try buf.appendSlice(alloc, "### Tool: ");
                try buf.appendSlice(alloc, tc.name);
                try buf.appendSlice(alloc, "\n\n```\n");
                in_tool = true;
                try buf.appendSlice(alloc, tc.args);
                try buf.appendSlice(alloc, "\n");
            },
            .tool_result => |tr| {
                if (tr.is_err) {
                    try buf.appendSlice(alloc, "ERROR: ");
                }
                // Truncate very long tool output
                const max_out = 2000;
                if (tr.out.len > max_out) {
                    try buf.appendSlice(alloc, tr.out[0..max_out]);
                    const trunc_msg = try std.fmt.allocPrint(alloc, "\n... ({d} bytes truncated)", .{tr.out.len - max_out});
                    defer alloc.free(trunc_msg);
                    try buf.appendSlice(alloc, trunc_msg);
                } else {
                    try buf.appendSlice(alloc, tr.out);
                }
                try buf.appendSlice(alloc, "\n");
            },
            .err => |e| {
                if (in_tool) {
                    try buf.appendSlice(alloc, "```\n\n");
                    in_tool = false;
                }
                try buf.appendSlice(alloc, "> **Error:** ");
                try buf.appendSlice(alloc, e.text);
                try buf.appendSlice(alloc, "\n\n");
            },
            .usage, .stop, .noop => {},
        }
    }
    if (in_tool) {
        try buf.appendSlice(alloc, "```\n\n");
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

fn exportOutcomeAudit(sid: []const u8, dest: []const u8, ts_ms: i64, out: audit.Out, err_name: ?[]const u8) audit.Entry {
    return .{
        .ts_ms = ts_ms,
        .sid = sid,
        .seq = 2,
        .out = out,
        .sev = if (out == .ok) .info else .err,
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

fn emitAudit(alloc: std.mem.Allocator, hooks: Hooks, ent: audit.Entry) !void {
    if (hooks.emit_audit) |emit| try emit(hooks.emit_audit_ctx.?, alloc, ent);
}

fn nowMs() i64 {
    return std.time.milliTimestamp();
}

test "export session to markdown" {
    const writer_mod = @import("writer.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer_mod.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("ex1", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "hello" } } });
    try wr.append("ex1", .{ .at_ms = 2, .data = .{ .text = .{ .text = "Hi there!" } } });
    try wr.append("ex1", .{ .at_ms = 3, .data = .{ .tool_call = .{ .id = "c1", .name = "bash", .args = "ls -la" } } });
    try wr.append("ex1", .{ .at_ms = 4, .data = .{ .tool_result = .{ .id = "c1", .out = "file.txt\ndir/", .is_err = false } } });
    try wr.append("ex1", .{ .at_ms = 5, .data = .{ .stop = .{ .reason = .done } } });

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

    try std.testing.expect(std.mem.indexOf(u8, md, "# Session ex1") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "## User") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "## Assistant") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "Hi there!") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "### Tool: bash") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "ls -la") != null);
    try std.testing.expect(std.mem.indexOf(u8, md, "file.txt") != null);
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
