const std = @import("std");
const schema = @import("schema.zig");
const sid_path = @import("path.zig");

pub const Event = schema.Event;

pub const Opts = struct {
    max_line_bytes: usize = 1024 * 1024,
};

pub const ReplayReader = struct {
    alloc: std.mem.Allocator,
    file: std.fs.File,
    io_buf: [8192]u8 = undefined,
    io_pos: usize = 0,
    io_len: usize = 0,
    eof: bool = false,
    line_buf: std.ArrayList(u8) = .empty,
    line_too_long: bool = false,
    arena: std.heap.ArenaAllocator,
    max_line_bytes: usize,
    line_no: usize = 0,

    pub fn init(alloc: std.mem.Allocator, dir: std.fs.Dir, sid: []const u8, opts: Opts) !ReplayReader {
        if (opts.max_line_bytes == 0) return error.InvalidMaxLineBytes;

        const path = try sid_path.sidJsonlAlloc(alloc, sid);
        defer alloc.free(path);

        const file = try dir.openFile(path, .{ .mode = .read_only });

        return .{
            .alloc = alloc,
            .file = file,
            .arena = std.heap.ArenaAllocator.init(alloc),
            .max_line_bytes = opts.max_line_bytes,
        };
    }

    /// Returns an event whose string slices borrow from the reader arena.
    /// That storage is invalidated by the next `next()` or `nextDup()` call.
    pub fn next(self: *ReplayReader) !?Event {
        self.arena.deinit();
        self.arena = std.heap.ArenaAllocator.init(self.alloc);

        while (true) {
            if (self.io_pos >= self.io_len) {
                if (self.eof) {
                    if (self.line_buf.items.len == 0 and !self.line_too_long) return null;
                    if (self.line_too_long) {
                        const ev = try self.finishLine();
                        return ev;
                    }
                    return error.TornReplayLine;
                }

                self.io_len = try self.file.read(&self.io_buf);
                self.io_pos = 0;
                if (self.io_len == 0) {
                    self.eof = true;
                }
                continue;
            }

            const slice = self.io_buf[self.io_pos..self.io_len];
            if (std.mem.indexOfScalar(u8, slice, '\n')) |rel| {
                try self.appendLinePart(slice[0..rel]);
                self.io_pos += rel + 1;
                const ev = try self.finishLine();
                return ev;
            }

            try self.appendLinePart(slice);
            self.io_pos = self.io_len;
        }
    }

    /// Returns an event fully detached from the reader arena.
    pub fn nextDup(self: *ReplayReader, alloc: std.mem.Allocator) !?Event {
        const ev = (try self.next()) orelse return null;
        return try ev.dupe(alloc);
    }

    pub fn line(self: *const ReplayReader) usize {
        return self.line_no;
    }

    pub fn deinit(self: *ReplayReader) void {
        self.arena.deinit();
        self.line_buf.deinit(self.alloc);
        self.file.close();
    }

    fn appendLinePart(self: *ReplayReader, part: []const u8) !void {
        if (self.line_too_long) return;
        if (self.line_buf.items.len + part.len > self.max_line_bytes) {
            self.line_too_long = true;
            return;
        }
        try self.line_buf.appendSlice(self.alloc, part);
    }

    fn finishLine(self: *ReplayReader) !Event {
        self.line_no += 1;
        defer {
            self.line_buf.clearRetainingCapacity();
            self.line_too_long = false;
        }

        if (self.line_too_long) return error.ReplayLineTooLong;
        if (self.line_buf.items.len == 0) return error.EmptyReplayLine;

        const parsed = schema.decodeSlice(self.arena.allocator(), self.line_buf.items) catch |err| switch (err) {
            error.UnsupportedVersion => return error.UnsupportedVersion,
            else => return error.MalformedReplayLine,
        };
        // Don't deinit parsed — string slices in the Event reference memory
        // owned by self.arena, which resets at the start of the next next() call.
        return parsed.value;
    }
};

fn appendEventJson(
    alloc: std.mem.Allocator,
    rows: *std.ArrayListUnmanaged([]u8),
    ev: Event,
) !void {
    const raw = try schema.encodeAlloc(alloc, ev);
    errdefer alloc.free(raw);
    try rows.append(alloc, raw);
}

fn freeJsonRows(alloc: std.mem.Allocator, rows: [][]u8) void {
    for (rows) |row| alloc.free(row);
    alloc.free(rows);
}

fn encodeLine(file: std.fs.File, ev: Event) !void {
    const raw = try schema.encodeAlloc(std.testing.allocator, ev);
    defer std.testing.allocator.free(raw);

    try file.writeAll(raw);
    try file.writeAll("\n");
}

fn textEvent(at_ms: i64, text: []const u8) Event {
    return .{
        .at_ms = at_ms,
        .data = .{ .text = .{ .text = text } },
    };
}

fn allocFill(alloc: std.mem.Allocator, len: usize, byte: u8) ![]u8 {
    const buf = try alloc.alloc(u8, len);
    @memset(buf, byte);
    return buf;
}

test "jsonl replay preserves event stream exactly" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const ReplaySnap = struct {
        rows: [][]u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const events = [_]Event{
        .{
            .at_ms = 1,
            .data = .{ .prompt = .{ .text = "alpha" } },
        },
        .{
            .at_ms = 2,
            .data = .{ .tool_call = .{
                .id = "c1",
                .name = "read",
                .args = "{\"path\":\"a.txt\"}",
            } },
        },
        .{
            .at_ms = 3,
            .data = .{ .usage = .{
                .in_tok = 11,
                .out_tok = 7,
                .tot_tok = 18,
            } },
        },
        .{
            .at_ms = 4,
            .data = .{ .stop = .{ .reason = .done } },
        },
    };

    {
        const file = try tmp.dir.createFile("s1.jsonl", .{});
        defer file.close();
        for (events) |ev| try encodeLine(file, ev);
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "s1", .{});
    defer rdr.deinit();

    var rows: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (rows.items) |row| std.testing.allocator.free(row);
        rows.deinit(std.testing.allocator);
    }
    while (try rdr.next()) |ev| {
        try appendEventJson(std.testing.allocator, &rows, ev);
    }

    try oh.snap(@src(),
        \\core.session.reader.test.jsonl replay preserves event stream exactly.ReplaySnap
        \\  .rows: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"alpha"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":2,"data":{"tool_call":{"id":"c1","name":"read","args":"{\"path\":\"a.txt\"}"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"usage":{"in_tok":11,"out_tok":7,"tot_tok":18,"cache_read":0,"cache_write":0}}}"
        \\    [3]: []u8
        \\      "{"version":1,"at_ms":4,"data":{"stop":{"reason":"done"}}}"
    ).expectEqual(ReplaySnap{ .rows = rows.items });
}

test "nextDup keeps prior event stable across later reads" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const ReplaySnap = struct {
        rows: [][]u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const events = [_]Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "first borrowed payload" } } },
        .{ .at_ms = 2, .data = .{ .text = .{ .text = "second borrowed payload" } } },
        .{ .at_ms = 3, .data = .{ .tool_call = .{
            .id = "tc-1",
            .name = "bash",
            .args = "{\"cmd\":\"echo hi\"}",
        } } },
    };

    {
        const file = try tmp.dir.createFile("own.jsonl", .{});
        defer file.close();
        for (events) |ev| try encodeLine(file, ev);
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "own", .{});
    defer rdr.deinit();

    const first = (try rdr.nextDup(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    defer first.free(std.testing.allocator);
    const second = (try rdr.nextDup(std.testing.allocator)) orelse return error.TestUnexpectedResult;
    defer second.free(std.testing.allocator);
    const third = (try rdr.next()) orelse return error.TestUnexpectedResult;

    var rows: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (rows.items) |row| std.testing.allocator.free(row);
        rows.deinit(std.testing.allocator);
    }
    try appendEventJson(std.testing.allocator, &rows, first);
    try appendEventJson(std.testing.allocator, &rows, second);
    try appendEventJson(std.testing.allocator, &rows, third);

    try oh.snap(@src(),
        \\core.session.reader.test.nextDup keeps prior event stable across later reads.ReplaySnap
        \\  .rows: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"text":{"text":"first borrowed payload"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":2,"data":{"text":{"text":"second borrowed payload"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"tool_call":{"id":"tc-1","name":"bash","args":"{\"cmd\":\"echo hi\"}"}}}"
    ).expectEqual(ReplaySnap{ .rows = rows.items });
}

fn expectMalformedReplay(dir: std.fs.Dir) !void {
    var rdr = try ReplayReader.init(std.testing.allocator, dir, "bad", .{});
    defer rdr.deinit();

    _ = (try rdr.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), rdr.line());
    try std.testing.expectError(error.MalformedReplayLine, rdr.next());
    try std.testing.expectEqual(@as(usize, 2), rdr.line());
}

test "jsonl replay fails malformed line deterministically" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const file = try tmp.dir.createFile("bad.jsonl", .{});
        defer file.close();

        try encodeLine(file, .{
            .at_ms = 1,
            .data = .{ .text = .{ .text = "ok" } },
        });
        try file.writeAll("{\"version\":1,\"at_ms\":2,\"data\":{\"text\":{\"text\":\"oops\"}}\n");
        try encodeLine(file, .{
            .at_ms = 3,
            .data = .{ .err = .{ .text = "never" } },
        });
    }

    try expectMalformedReplay(tmp.dir);
    try expectMalformedReplay(tmp.dir);
}

test "jsonl replay rejects unsupported event version" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const file = try tmp.dir.createFile("ver.jsonl", .{});
        defer file.close();
        try file.writeAll("{\"version\":7,\"at_ms\":1,\"data\":{\"noop\":{}}}\n");
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "ver", .{});
    defer rdr.deinit();

    try std.testing.expectError(error.UnsupportedVersion, rdr.next());
}

test "jsonl replay rejects invalid session id" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(error.InvalidSessionId, ReplayReader.init(
        std.testing.allocator,
        tmp.dir,
        "",
        .{},
    ));
    try std.testing.expectError(error.InvalidSessionId, ReplayReader.init(
        std.testing.allocator,
        tmp.dir,
        "a/b",
        .{},
    ));
}

test "jsonl replay rejects zero max line bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(error.InvalidMaxLineBytes, ReplayReader.init(
        std.testing.allocator,
        tmp.dir,
        "s1",
        .{ .max_line_bytes = 0 },
    ));
}

test "jsonl replay rejects final line without trailing newline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const file = try tmp.dir.createFile("tail.jsonl", .{});
        defer file.close();
        const ev = Event{
            .at_ms = 1,
            .data = .{ .text = .{ .text = "ok" } },
        };
        const raw = try schema.encodeAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw); // no trailing '\n'
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "tail", .{});
    defer rdr.deinit();

    try std.testing.expectError(error.TornReplayLine, rdr.next());
    try std.testing.expectEqual(@as(usize, 0), rdr.line());
}

test "jsonl replay keeps committed rows and rejects torn tail" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const ReplaySnap = struct {
        rows: [][]u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const ev = Event{
        .at_ms = 1,
        .data = .{ .text = .{ .text = "ok" } },
    };
    const raw = try schema.encodeAlloc(std.testing.allocator, ev);
    defer std.testing.allocator.free(raw);

    {
        const file = try tmp.dir.createFile("tail2.jsonl", .{});
        defer file.close();
        try file.writeAll(raw);
        try file.writeAll("\n");
        try file.writeAll(raw[0 .. raw.len / 2]);
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "tail2", .{});
    defer rdr.deinit();

    const first = (try rdr.next()) orelse return error.TestUnexpectedResult;
    var rows = try std.testing.allocator.alloc([]u8, 1);
    defer freeJsonRows(std.testing.allocator, rows);
    rows[0] = try schema.encodeAlloc(std.testing.allocator, first);
    try oh.snap(@src(),
        \\core.session.reader.test.jsonl replay keeps committed rows and rejects torn tail.ReplaySnap
        \\  .rows: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"text":{"text":"ok"}}}"
    ).expectEqual(ReplaySnap{ .rows = rows });
    try std.testing.expectEqual(@as(usize, 1), rdr.line());
    try std.testing.expectError(error.TornReplayLine, rdr.next());
    try std.testing.expectEqual(@as(usize, 1), rdr.line());
}

test "jsonl replay enforces max line bytes in streaming mode" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const file = try tmp.dir.createFile("long.jsonl", .{});
        defer file.close();
        // Write a line that is definitely larger than max_line_bytes.
        try file.writeAll("{\"version\":1,\"at_ms\":1,\"data\":{\"text\":{\"text\":\"");
        var pad: [256]u8 = undefined;
        @memset(&pad, 'a');
        try file.writeAll(&pad);
        try file.writeAll("\"}}}\n");
    }

    var rdr = try ReplayReader.init(std.testing.allocator, tmp.dir, "long", .{
        .max_line_bytes = 64,
    });
    defer rdr.deinit();

    try std.testing.expectError(error.ReplayLineTooLong, rdr.next());
}

test "jsonl replay property preserves text stream across io buffer splits" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u16, b: u16, c: u16 }) bool {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();

            const alloc = std.testing.allocator;
            const lens = [_]usize{
                8200 + @as(usize, args.a % 1024),
                32 + @as(usize, args.b % 512),
                4096 + @as(usize, args.c % 1024),
            };
            const fills = [_]u8{ 'a', 'b', 'c' };
            var texts: [3][]u8 = undefined;
            for (&texts, lens, fills) |*text, len, fill| {
                text.* = allocFill(alloc, len, fill) catch return false;
            }
            defer for (texts) |text| alloc.free(text);

            const events = [_]Event{
                textEvent(1, texts[0]),
                textEvent(2, texts[1]),
                textEvent(3, texts[2]),
            };

            {
                const file = tmp.dir.createFile("prop.jsonl", .{}) catch return false;
                defer file.close();
                for (events) |ev| encodeLine(file, ev) catch return false;
            }

            var rdr = ReplayReader.init(alloc, tmp.dir, "prop", .{}) catch return false;
            defer rdr.deinit();

            var idx: usize = 0;
            while (rdr.next() catch return false) |ev| : (idx += 1) {
                if (idx >= events.len) return false;
                const want = schema.encodeAlloc(alloc, events[idx]) catch return false;
                defer alloc.free(want);
                const got = schema.encodeAlloc(alloc, ev) catch return false;
                defer alloc.free(got);
                if (!std.mem.eql(u8, want, got)) return false;
            }
            return idx == events.len;
        }
    }.prop, .{
        .iterations = 256,
        .seed = 0x5eed_1234,
    });
}

test "jsonl replay property rejects encoded lines above max bytes" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { len: u16, slack: u8 }) bool {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();

            const alloc = std.testing.allocator;
            const text = allocFill(alloc, 128 + @as(usize, args.len % 2048), 'x') catch return false;
            defer alloc.free(text);

            const raw = schema.encodeAlloc(alloc, textEvent(1, text)) catch return false;
            defer alloc.free(raw);

            {
                const file = tmp.dir.createFile("over.jsonl", .{}) catch return false;
                defer file.close();
                file.writeAll(raw) catch return false;
                file.writeAll("\n") catch return false;
            }

            const delta = 1 + @as(usize, args.slack % 8);
            const max_line_bytes = if (raw.len > delta) raw.len - delta else raw.len - 1;
            var rdr = ReplayReader.init(alloc, tmp.dir, "over", .{
                .max_line_bytes = max_line_bytes,
            }) catch return false;
            defer rdr.deinit();

            std.testing.expectError(error.ReplayLineTooLong, rdr.next()) catch return false;
            return true;
        }
    }.prop, .{
        .iterations = 512,
        .seed = 0x0be7_f10a,
    });
}

test "jsonl replay property survives crap-and-mutate of valid rows" {
    const zc = @import("zcheck");
    const pbt = @import("../prop_test.zig");

    try zc.check(struct {
        fn prop(args: struct { len: u16, seed: u64, slack: u8 }) bool {
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();

            const alloc = std.testing.allocator;
            const text = allocFill(alloc, 16 + @as(usize, args.len % 128), 'x') catch return false;
            defer alloc.free(text);

            const raw = schema.encodeAlloc(alloc, textEvent(1, text)) catch return false;
            defer alloc.free(raw);
            const mut = pbt.Mut.crapOrMutateAlloc(alloc, raw, args.seed, raw.len + @as(usize, args.slack % 8)) catch return false;
            defer alloc.free(mut);

            {
                const file = tmp.dir.createFile("mut.jsonl", .{}) catch return false;
                defer file.close();
                var buf = alloc.alloc(u8, mut.len + 1) catch return false;
                defer alloc.free(buf);
                for (mut, 0..) |b, i| buf[i] = if (b == '\n') '!' else b;
                buf[mut.len] = '\n';
                file.writeAll(buf) catch return false;
            }

            var rdr = ReplayReader.init(alloc, tmp.dir, "mut", .{}) catch return false;
            defer rdr.deinit();

            _ = rdr.next() catch |err| switch (err) {
                error.MalformedReplayLine,
                error.UnsupportedVersion,
                error.ReplayLineTooLong,
                error.EmptyReplayLine,
                error.TornReplayLine,
                => return true,
                else => return false,
            };
            return true;
        }
    }.prop, .{
        .iterations = 512,
        .seed = 0x57e5_10c2,
    });
}
