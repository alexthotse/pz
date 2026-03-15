//! Session file lifecycle: create, close, orphan cleanup.
const std = @import("std");
const builtin = @import("builtin");
const fs_secure = @import("../fs_secure.zig");
const sid_path = @import("path.zig");

/// Wraps a session file path with lifecycle tracking.
/// If `close()` is never called, `deinit()` logs a warning and deletes the orphan.
pub const File = struct {
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    path: []const u8,
    closed: bool = false,

    pub fn init(alloc: std.mem.Allocator, dir: std.fs.Dir, path: []const u8) !File {
        const owned = try alloc.dupe(u8, path);
        errdefer alloc.free(owned);

        // Confined create: O_NOFOLLOW + hardlink check for .pz state.
        var f = try fs_secure.createConfined(dir, owned, .{ .truncate = false });
        errdefer dir.deleteFile(owned) catch {};
        f.close();

        return .{
            .alloc = alloc,
            .dir = dir,
            .path = owned,
        };
    }

    pub fn close(self: *File) void {
        self.closed = true;
    }

    pub fn deinit(self: *File) void {
        if (!self.closed) {
            if (!builtin.is_test) {
                std.debug.print("warning: session file not closed, deleting orphan: {s}\n", .{self.path});
            }
            self.dir.deleteFile(self.path) catch |err| {
                if (!builtin.is_test) {
                    std.debug.print("warning: orphan cleanup failed: {s}\n", .{@errorName(err)});
                }
            };
        }
        self.alloc.free(self.path);
        self.* = undefined;
    }
};

pub fn createSessionFile(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    ext: []const u8,
) !File {
    const path = try sid_path.sidExtAlloc(alloc, sid, ext);
    defer alloc.free(path);
    return File.init(alloc, dir, path);
}

/// Delete any orphaned `.compact.tmp` files left by interrupted compactions.
pub fn cleanOrphanTmpFiles(dir: std.fs.Dir) void {
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.endsWith(u8, entry.name, ".compact.tmp")) {
            dir.deleteFile(entry.name) catch |err| {
                std.debug.print("warning: orphan tmp cleanup failed for {s}: {s}\n", .{ entry.name, @errorName(err) });
            };
        }
    }
}

test "deinit without close deletes the file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var sf = try File.init(std.testing.allocator, tmp.dir, "test-sess.jsonl");
    // Do NOT call close — simulate abnormal exit.
    sf.deinit();

    // File should be gone.
    try std.testing.expectError(
        error.FileNotFound,
        tmp.dir.statFile("test-sess.jsonl"),
    );
}

test "close then deinit preserves the file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var sf = try File.init(std.testing.allocator, tmp.dir, "test-sess.jsonl");
    sf.close();
    sf.deinit();

    // File should still exist.
    const stat = try tmp.dir.statFile("test-sess.jsonl");
    try std.testing.expect(stat.size == 0);
}

test "session file uses 0600 mode" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var sf = try File.init(std.testing.allocator, tmp.dir, "test-sess.jsonl");
    sf.close();
    sf.deinit();

    const stat = try tmp.dir.statFile("test-sess.jsonl");
    try std.testing.expectEqual(@as(std.fs.File.Mode, fs_secure.file_mode), stat.mode & 0o777);
}

test "cleanOrphanTmpFiles removes compact.tmp files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create orphan tmp files and a normal session file.
    {
        var f = try tmp.dir.createFile("s1.jsonl.compact.tmp", .{});
        f.close();
    }
    {
        var f = try tmp.dir.createFile("s2.jsonl.compact.tmp", .{});
        f.close();
    }
    {
        var f = try tmp.dir.createFile("s1.jsonl", .{});
        f.close();
    }

    cleanOrphanTmpFiles(tmp.dir);

    // Tmp files should be gone.
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("s1.jsonl.compact.tmp"));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("s2.jsonl.compact.tmp"));

    // Normal file should survive.
    _ = try tmp.dir.statFile("s1.jsonl");
}

test "createSessionFile uses session id plus extension" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var sf = try createSessionFile(std.testing.allocator, tmp.dir, "s1", ".jsonl.compact.tmp");
    defer sf.deinit();

    try std.testing.expectEqualStrings("s1.jsonl.compact.tmp", sf.path);
}
