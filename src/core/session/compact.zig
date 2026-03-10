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

pub fn sortPaths(paths: [][]const u8) void {
    std.sort.pdq([]const u8, paths, {}, struct {
        fn cmp(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.cmp);
}

// -- File operations extraction (F1) --

const file_tools = [_][]const u8{ "read", "write", "edit", "glob", "grep", "bash" };

fn isFileTool(name: []const u8) bool {
    for (file_tools) |t| {
        if (std.mem.eql(u8, name, t)) return true;
    }
    return false;
}

fn extractPath(tc: schema.Event.ToolCall) ?[]const u8 {
    if (!isFileTool(tc.name)) return null;

    const parsed = std.json.parseFromSlice(
        struct {
            file_path: ?[]const u8 = null,
            path: ?[]const u8 = null,
            pattern: ?[]const u8 = null,
            command: ?[]const u8 = null,
        },
        std.heap.page_allocator,
        tc.args,
        .{ .allocate = .alloc_if_needed, .ignore_unknown_fields = true },
    ) catch return null;
    defer parsed.deinit();

    const v = parsed.value;
    return v.file_path orelse v.path orelse v.pattern orelse v.command;
}

/// Extract deduplicated, sorted file paths from tool_call events.
pub fn extractFileOps(alloc: std.mem.Allocator, events: []const schema.Event) ![][]const u8 {
    var set: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var it = set.keyIterator();
        while (it.next()) |k| alloc.free(@constCast(k.*));
        set.deinit(alloc);
    }

    for (events) |ev| {
        switch (ev.data) {
            .tool_call => |tc| {
                const path = extractPath(tc) orelse continue;
                if (set.contains(path)) continue;
                const owned = try alloc.dupe(u8, path);
                errdefer alloc.free(owned);
                try set.put(alloc, owned, {});
            },
            else => {},
        }
    }

    // Drain into sorted slice, transferring ownership
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer list.deinit(alloc);

    var it = set.keyIterator();
    while (it.next()) |k| try list.append(alloc, k.*);

    std.sort.pdq([]const u8, list.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);

    set.clearRetainingCapacity();
    return try list.toOwnedSlice(alloc);
}

pub fn freeFileOps(alloc: std.mem.Allocator, paths: [][]const u8) void {
    for (paths) |p| alloc.free(@constCast(p));
    alloc.free(paths);
}

/// Stub: future LLM-based session summary.
pub fn generateSummary(_: std.mem.Allocator, _: []const schema.Event) ?[]u8 {
    return null;
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

test "sortPaths sorts file paths" {
    var paths = [_][]const u8{ "src/main.zig", "build.zig", "README.md", "src/app.zig" };
    sortPaths(&paths);
    try std.testing.expectEqualStrings("README.md", paths[0]);
    try std.testing.expectEqualStrings("build.zig", paths[1]);
    try std.testing.expectEqualStrings("src/app.zig", paths[2]);
    try std.testing.expectEqualStrings("src/main.zig", paths[3]);
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

test "extractFileOps deduplicates and sorts" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .tool_call = .{ .id = "1", .name = "read", .args = "{\"path\":\"/b.txt\"}" } } },
        .{ .data = .{ .tool_call = .{ .id = "2", .name = "write", .args = "{\"file_path\":\"/a.txt\"}" } } },
        .{ .data = .{ .tool_call = .{ .id = "3", .name = "read", .args = "{\"path\":\"/b.txt\"}" } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);

    try std.testing.expectEqual(@as(usize, 2), ops.len);
    try std.testing.expectEqualStrings("/a.txt", ops[0]);
    try std.testing.expectEqualStrings("/b.txt", ops[1]);
}

test "extractFileOps handles glob and grep" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .tool_call = .{ .id = "1", .name = "glob", .args = "{\"pattern\":\"*.zig\"}" } } },
        .{ .data = .{ .tool_call = .{ .id = "2", .name = "grep", .args = "{\"path\":\"src/\"}" } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);

    try std.testing.expectEqual(@as(usize, 2), ops.len);
    try std.testing.expectEqualStrings("*.zig", ops[0]);
    try std.testing.expectEqualStrings("src/", ops[1]);
}

test "extractFileOps handles bash command" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .tool_call = .{ .id = "1", .name = "bash", .args = "{\"command\":\"ls -la\"}" } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);

    try std.testing.expectEqual(@as(usize, 1), ops.len);
    try std.testing.expectEqualStrings("ls -la", ops[0]);
}

test "extractFileOps skips non-tool events" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .text = .{ .text = "hello" } } },
        .{ .data = .{ .stop = .{ .reason = .done } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);
    try std.testing.expectEqual(@as(usize, 0), ops.len);
}

test "extractFileOps skips unknown tools" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .tool_call = .{ .id = "1", .name = "unknown", .args = "{\"path\":\"/x\"}" } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);
    try std.testing.expectEqual(@as(usize, 0), ops.len);
}

test "extractFileOps handles malformed JSON" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .data = .{ .tool_call = .{ .id = "1", .name = "read", .args = "{bad json" } } },
    };
    const ops = try extractFileOps(alloc, &events);
    defer freeFileOps(alloc, ops);
    try std.testing.expectEqual(@as(usize, 0), ops.len);
}

test "generateSummary returns null" {
    const alloc = std.testing.allocator;
    try std.testing.expect(generateSummary(alloc, &.{}) == null);
}
