const std = @import("std");
const schema = @import("schema.zig");
const reader = @import("reader.zig");
const sid_path = @import("path.zig");

pub const checkpoint_version: u16 = 1;

pub const Checkpoint = struct {
    version: u16 = checkpoint_version,
    in_lines: u64 = 0,
    out_lines: u64 = 0,
    in_bytes: u64 = 0,
    out_bytes: u64 = 0,
    compacted_at_ms: i64 = 0,
};

pub fn run(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    compacted_at_ms: i64,
) !Checkpoint {
    const src_path = try sid_path.sidJsonlAlloc(alloc, sid);
    defer alloc.free(src_path);

    const tmp_path = try sid_path.sidExtAlloc(alloc, sid, ".jsonl.compact.tmp");
    defer alloc.free(tmp_path);
    errdefer dir.deleteFile(tmp_path) catch |err| {
        std.debug.print("warning: temp file cleanup failed: {s}\n", .{@errorName(err)});
    };

    const in_file = try dir.openFile(src_path, .{ .mode = .read_only });
    const in_bytes = try in_file.getEndPos();
    in_file.close();

    var rdr = try reader.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var out_file = try dir.createFile(tmp_path, .{
        .truncate = true,
    });
    defer out_file.close();

    var in_lines: u64 = 0;
    var out_lines: u64 = 0;
    var out_bytes: u64 = 0;
    while (try rdr.next()) |ev| {
        in_lines += 1;
        if (ev.data == .noop) continue;

        const raw = try schema.encodeAlloc(alloc, ev);
        defer alloc.free(raw);

        try out_file.writeAll(raw);
        try out_file.writeAll("\n");
        out_lines += 1;
        out_bytes += raw.len + 1;
    }
    try out_file.sync();

    try dir.rename(tmp_path, src_path);

    const ck = Checkpoint{
        .in_lines = in_lines,
        .out_lines = out_lines,
        .in_bytes = in_bytes,
        .out_bytes = out_bytes,
        .compacted_at_ms = compacted_at_ms,
    };
    try saveCheckpoint(alloc, dir, sid, ck);
    return ck;
}

pub fn loadCheckpoint(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
) !?Checkpoint {
    const path = try sid_path.sidExtAlloc(alloc, sid, ".compact.json");
    defer alloc.free(path);

    const raw = dir.readFileAlloc(alloc, path, 64 * 1024) catch |read_err| switch (read_err) {
        error.FileNotFound => return null,
        else => return read_err,
    };
    defer alloc.free(raw);

    const parsed = try std.json.parseFromSlice(Checkpoint, alloc, raw, .{
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    if (parsed.value.version != checkpoint_version) return error.UnsupportedCheckpointVersion;
    return parsed.value;
}

fn saveCheckpoint(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    ck: Checkpoint,
) !void {
    const path = try sid_path.sidExtAlloc(alloc, sid, ".compact.json");
    defer alloc.free(path);

    const raw = try std.json.Stringify.valueAlloc(alloc, ck, .{});
    defer alloc.free(raw);

    var file = try dir.createFile(path, .{
        .truncate = true,
    });
    defer file.close();
    try file.writeAll(raw);
    try file.writeAll("\n");
    try file.sync();
}

fn collectSemanticJson(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
) ![][]u8 {
    var rdr = try reader.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (out.items) |item| alloc.free(item);
        out.deinit(alloc);
    }

    while (try rdr.next()) |ev| {
        if (ev.data == .noop) continue;
        const raw = try schema.encodeAlloc(alloc, ev);
        try out.append(alloc, raw);
    }

    return try out.toOwnedSlice(alloc);
}

fn freeJsonSlice(alloc: std.mem.Allocator, rows: [][]u8) void {
    for (rows) |row| alloc.free(row);
    alloc.free(rows);
}

pub fn escapeXml(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    var len: usize = 0;
    for (input) |c| {
        len += switch (c) {
            '&' => 5, // &amp;
            '<' => 4, // &lt;
            '>' => 4, // &gt;
            '"' => 6, // &quot;
            '\'' => 6, // &apos;
            else => 1,
        };
    }

    const buf = try alloc.alloc(u8, len);
    var i: usize = 0;
    for (input) |c| {
        switch (c) {
            '&' => {
                @memcpy(buf[i..][0..5], "&amp;");
                i += 5;
            },
            '<' => {
                @memcpy(buf[i..][0..4], "&lt;");
                i += 4;
            },
            '>' => {
                @memcpy(buf[i..][0..4], "&gt;");
                i += 4;
            },
            '"' => {
                @memcpy(buf[i..][0..6], "&quot;");
                i += 6;
            },
            '\'' => {
                @memcpy(buf[i..][0..6], "&apos;");
                i += 6;
            },
            else => {
                buf[i] = c;
                i += 1;
            },
        }
    }
    return buf;
}

// -- File operations extraction (F1) --

const FileOps = struct {
    read: []const []const u8,
    modified: []const []const u8,
};

const read_tools = [_][]const u8{ "read", "grep", "find", "ls" };
const write_tools = [_][]const u8{ "write", "edit" };

fn isToolKind(name: []const u8, comptime table: []const []const u8) bool {
    inline for (table) |t| {
        if (std.mem.eql(u8, name, t)) return true;
    }
    return false;
}

fn extractPath(alloc: std.mem.Allocator, args: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(
        struct { path: ?[]const u8 = null, file_path: ?[]const u8 = null },
        alloc,
        args,
        .{ .allocate = .alloc_always },
    ) catch return null;
    defer parsed.deinit();
    const p = parsed.value.path orelse parsed.value.file_path orelse return null;
    if (p.len == 0) return null;
    return try alloc.dupe(u8, p);
}

/// Extract read and modified file paths from tool_call events.
/// Files appearing in both read and write are placed only in modified.
fn extractFileOps(alloc: std.mem.Allocator, events: []const schema.Event) !?FileOps {
    var read_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (read_set.keys()) |k| alloc.free(k);
        read_set.deinit(alloc);
    }
    var mod_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (mod_set.keys()) |k| alloc.free(k);
        mod_set.deinit(alloc);
    }

    for (events) |ev| {
        const tc = switch (ev.data) {
            .tool_call => |tc| tc,
            else => continue,
        };
        const p = try extractPath(alloc, tc.args) orelse continue;
        if (isToolKind(tc.name, &write_tools)) {
            if (read_set.fetchOrderedRemove(p)) |kv| {
                alloc.free(kv.key);
            }
            const gop = try mod_set.getOrPut(alloc, p);
            if (gop.found_existing) alloc.free(p);
        } else if (isToolKind(tc.name, &read_tools)) {
            if (mod_set.contains(p)) {
                alloc.free(p);
                continue;
            }
            const gop = try read_set.getOrPut(alloc, p);
            if (gop.found_existing) alloc.free(p);
        } else {
            alloc.free(p);
        }
    }

    if (read_set.count() == 0 and mod_set.count() == 0) return null;

    // Transfer ownership to caller
    const r = try alloc.dupe([]const u8, read_set.keys());
    errdefer alloc.free(r);
    read_set.clearRetainingCapacity();

    const m = try alloc.dupe([]const u8, mod_set.keys());
    errdefer alloc.free(m);
    mod_set.clearRetainingCapacity();

    return FileOps{ .read = r, .modified = m };
}

fn freeFileOps(alloc: std.mem.Allocator, ops: FileOps) void {
    for (ops.read) |p| alloc.free(p);
    alloc.free(ops.read);
    for (ops.modified) |p| alloc.free(p);
    alloc.free(ops.modified);
}

// .off: summarization is mechanical; thinking tokens waste output budget
/// Format file operations as XML-style tags for compaction summaries.
/// Returns null if no file operations found.
pub fn formatFileOps(alloc: std.mem.Allocator, events: []const schema.Event) !?[]const u8 {
    const ops = try extractFileOps(alloc, events) orelse return null;
    defer freeFileOps(alloc, ops);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    if (ops.read.len > 0) {
        try buf.appendSlice(alloc, "<read-files>\n");
        for (ops.read) |p| {
            try buf.appendSlice(alloc, p);
            try buf.append(alloc, '\n');
        }
        try buf.appendSlice(alloc, "</read-files>\n");
    }
    if (ops.modified.len > 0) {
        try buf.appendSlice(alloc, "<modified-files>\n");
        for (ops.modified) |p| {
            try buf.appendSlice(alloc, p);
            try buf.append(alloc, '\n');
        }
        try buf.appendSlice(alloc, "</modified-files>\n");
    }

    return try buf.toOwnedSlice(alloc);
}

test "compaction rewrites stream and preserves semantic events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const writer = @import("writer.zig");
    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("s1", .{
        .at_ms = 1,
        .data = .{ .prompt = .{ .text = "a" } },
    });
    try wr.append("s1", .{
        .at_ms = 2,
        .data = .{ .noop = {} },
    });
    try wr.append("s1", .{
        .at_ms = 3,
        .data = .{ .text = .{ .text = "b" } },
    });
    try wr.append("s1", .{
        .at_ms = 4,
        .data = .{ .noop = {} },
    });
    try wr.append("s1", .{
        .at_ms = 5,
        .data = .{ .stop = .{ .reason = .done } },
    });

    const before = try collectSemanticJson(std.testing.allocator, tmp.dir, "s1");
    defer freeJsonSlice(std.testing.allocator, before);

    const ck = try run(std.testing.allocator, tmp.dir, "s1", 777);
    try std.testing.expectEqual(@as(u64, 5), ck.in_lines);
    try std.testing.expectEqual(@as(u64, 3), ck.out_lines);
    try std.testing.expectEqual(@as(i64, 777), ck.compacted_at_ms);
    try std.testing.expect(ck.in_bytes > ck.out_bytes);

    const after = try collectSemanticJson(std.testing.allocator, tmp.dir, "s1");
    defer freeJsonSlice(std.testing.allocator, after);

    try std.testing.expectEqual(before.len, after.len);
    for (before, after) |lhs, rhs| {
        try std.testing.expectEqualStrings(lhs, rhs);
    }

    const loaded = (try loadCheckpoint(std.testing.allocator, tmp.dir, "s1")) orelse {
        return error.TestUnexpectedResult;
    };
    try std.testing.expectEqual(@as(u16, checkpoint_version), loaded.version);
    try std.testing.expectEqual(@as(u64, 5), loaded.in_lines);
    try std.testing.expectEqual(@as(u64, 3), loaded.out_lines);
}

test "compaction checkpoint returns null when absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect((try loadCheckpoint(std.testing.allocator, tmp.dir, "missing")) == null);
}

test "escapeXml escapes mixed content" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "A<B&C");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("A&lt;B&amp;C", out);
}

test "escapeXml no escapes returns same content" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "no escapes");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("no escapes", out);
}

test "escapeXml all five special chars" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "&<>\"'");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("&amp;&lt;&gt;&quot;&apos;", out);
}

// Property: escapeXml output never contains raw special chars
test "escapeXml property: no raw specials in output" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            const s = args.input.slice();
            const out = escapeXml(std.testing.allocator, s) catch return true;
            defer std.testing.allocator.free(out);
            // Verify no raw & < > " ' remain (they must be entity-encoded)
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const c = out[i];
                if (c == '&') {
                    // Must be start of entity: &amp; &lt; &gt; &quot; &apos;
                    if (std.mem.startsWith(u8, out[i..], "&amp;") or
                        std.mem.startsWith(u8, out[i..], "&lt;") or
                        std.mem.startsWith(u8, out[i..], "&gt;") or
                        std.mem.startsWith(u8, out[i..], "&quot;") or
                        std.mem.startsWith(u8, out[i..], "&apos;")) continue;
                    return false; // bare &
                }
                if (c == '<' or c == '>' or c == '"' or c == '\'') return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 500 });
}

// Property: escapeXml output length >= input length
test "escapeXml property: output never shorter than input" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            const s = args.input.slice();
            const out = escapeXml(std.testing.allocator, s) catch return true;
            defer std.testing.allocator.free(out);
            return out.len >= s.len;
        }
    }.prop, .{ .iterations = 500 });
}

fn mkEv(name: []const u8, args: []const u8) schema.Event {
    return .{ .at_ms = 1, .data = .{ .tool_call = .{
        .id = "c1",
        .name = name,
        .args = args,
    } } };
}

test "formatFileOps mixed read and write" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/a.zig\"}"),
        mkEv("grep", "{\"path\":\"/src/b.zig\"}"),
        mkEv("write", "{\"path\":\"/src/c.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/d.zig\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/src/a.zig
        \\/src/b.zig
        \\</read-files>
        \\<modified-files>
        \\/src/c.zig
        \\/src/d.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps read only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/x.zig\"}"),
        mkEv("find", "{\"path\":\"/y\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/x.zig
        \\/y
        \\</read-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps write only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("write", "{\"path\":\"/out.txt\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<modified-files>
        \\/out.txt
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps returns null when no file tools" {
    const evs = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
        mkEv("bash", "{\"cmd\":\"ls\"}"),
    };
    try std.testing.expect(try formatFileOps(std.testing.allocator, &evs) == null);
}

test "formatFileOps deduplicates read+write to modified only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/f.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/f.zig\"}"),
        mkEv("read", "{\"path\":\"/src/g.zig\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/src/g.zig
        \\</read-files>
        \\<modified-files>
        \\/src/f.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}
