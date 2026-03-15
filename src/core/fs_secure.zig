//! Secure filesystem helpers: restrictive modes, safe dir creation,
//! openat/O_NOFOLLOW confinement, hardlink rejection, atomic writes.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const dir_mode: std.fs.File.Mode = 0o700;
pub const file_mode: std.fs.File.Mode = 0o600;

pub fn ensureDirAt(dir: std.fs.Dir, sub_path: []const u8) !void {
    try dir.makePath(sub_path);
    var sub = try dir.openDir(sub_path, .{ .iterate = true });
    defer sub.close();
    try sub.chmod(dir_mode);
}

pub fn ensureDirPath(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        if (builtin.os.tag == .windows) return error.Unsupported;
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        try root.makePath(std.mem.trimLeft(u8, path, "/"));
        var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
        defer dir.close();
        try dir.chmod(dir_mode);
    } else {
        try std.fs.cwd().makePath(path);
        var dir = try std.fs.cwd().openDir(path, .{ .iterate = true });
        defer dir.close();
        try dir.chmod(dir_mode);
    }
}

pub fn createFileAt(dir: std.fs.Dir, sub_path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    var secure = flags;
    secure.mode = file_mode;
    return dir.createFile(sub_path, secure);
}

pub fn createFilePath(path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    var secure = flags;
    secure.mode = file_mode;
    if (std.fs.path.isAbsolute(path)) return std.fs.createFileAbsolute(path, secure);
    return std.fs.cwd().createFile(path, secure);
}

// ---------------------------------------------------------------------------
// openat/O_NOFOLLOW confined open + hardlink rejection
// ---------------------------------------------------------------------------

/// Open an existing file confined to `dir` with O_NOFOLLOW and hardlink
/// check.  Rejects symlinks and files with nlink != 1.
pub fn openConfined(dir: std.fs.Dir, name: []const u8, flags: std.fs.File.OpenFlags) !std.fs.File {
    if (builtin.os.tag == .windows) return dir.openFile(name, flags);
    try validateLeaf(name);

    var os_flags: posix.O = .{
        .ACCMODE = switch (flags.mode) {
            .read_only => .RDONLY,
            .write_only => .WRONLY,
            .read_write => .RDWR,
        },
        .NOFOLLOW = true,
    };
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;

    const fd = try posix.openat(dir.fd, name, os_flags, 0);
    errdefer posix.close(fd);
    try rejectBadFile(fd);
    return .{ .handle = fd };
}

/// Create or open a file confined to `dir` with O_NOFOLLOW, O_CREAT,
/// hardlink check, and secure mode.
pub fn createConfined(dir: std.fs.Dir, name: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    if (builtin.os.tag == .windows) return createFileAt(dir, name, flags);
    try validateLeaf(name);

    var os_flags: posix.O = .{
        .ACCMODE = if (flags.read) .RDWR else .WRONLY,
        .CREAT = true,
        .EXCL = flags.exclusive,
        .NOFOLLOW = true,
    };
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;

    const fd = try posix.openat(dir.fd, name, os_flags, file_mode);
    errdefer posix.close(fd);
    // Skip hardlink check for newly created exclusive files (nlink is 1
    // by definition and fstat is redundant).
    if (!flags.exclusive) try rejectBadFile(fd);

    var file: std.fs.File = .{ .handle = fd };
    if (flags.truncate) try file.setEndPos(0);
    return file;
}

/// Validate that `name` is a plain leaf (no path separators, not empty,
/// not "." or "..").
fn validateLeaf(name: []const u8) !void {
    if (name.len == 0) return error.AccessDenied;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.AccessDenied;
    for (name) |c| {
        if (c == '/' or c == '\\' or c == 0) return error.AccessDenied;
    }
}

/// Reject non-regular files and hardlinks (nlink > 1).
fn rejectBadFile(fd: posix.fd_t) !void {
    const st = posix.fstat(fd) catch return error.AccessDenied;
    if ((st.mode & posix.S.IFMT) != posix.S.IFREG) return error.AccessDenied;
    if (st.nlink != 1) return error.AccessDenied;
}

// ---------------------------------------------------------------------------
// Atomic write: temp + fsync + rename
// ---------------------------------------------------------------------------

/// Atomically write `data` into `dir/name` via a temp file.
/// Steps: delete stale tmp -> create exclusive -> write -> fsync -> rename.
pub fn atomicWriteAt(dir: std.fs.Dir, name: []const u8, data: []const u8) !void {
    try validateLeaf(name);

    var tmp_buf: [256]u8 = undefined;
    const tmp_name = tmpName(name, &tmp_buf) catch return error.NameTooLong;

    // Clean up stale temp from prior interrupted writes.
    dir.deleteFile(tmp_name) catch {};

    var tmp_file = try createConfined(dir, tmp_name, .{
        .exclusive = true,
        .truncate = true,
    });
    errdefer {
        tmp_file.close();
        dir.deleteFile(tmp_name) catch {};
    }

    try tmp_file.writeAll(data);
    try tmp_file.sync();
    tmp_file.close();

    try dir.rename(tmp_name, name);
}

/// Streaming atomic write via callback, for large data.
pub fn atomicWriteAtFn(
    dir: std.fs.Dir,
    name: []const u8,
    ctx: anytype,
    writeFn: fn (@TypeOf(ctx), std.fs.File) anyerror!void,
) !void {
    try validateLeaf(name);

    var tmp_buf: [256]u8 = undefined;
    const tmp_name = tmpName(name, &tmp_buf) catch return error.NameTooLong;

    dir.deleteFile(tmp_name) catch {};

    var tmp_file = try createConfined(dir, tmp_name, .{
        .exclusive = true,
        .truncate = true,
    });
    errdefer {
        tmp_file.close();
        dir.deleteFile(tmp_name) catch {};
    }

    try writeFn(ctx, tmp_file);
    try tmp_file.sync();
    tmp_file.close();

    try dir.rename(tmp_name, name);
}

fn tmpName(name: []const u8, buf: *[256]u8) ![]const u8 {
    const needed = 1 + name.len + 4;
    if (needed > buf.len) return error.NameTooLong;
    buf[0] = '.';
    @memcpy(buf[1 .. 1 + name.len], name);
    @memcpy(buf[1 + name.len .. 1 + name.len + 4], ".tmp");
    return buf[0..needed];
}

// ============================================================================
// Tests
// ============================================================================

test "ensureDirAt locks directory mode to 0700" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try ensureDirAt(tmp.dir, "state");
    const st = try tmp.dir.statFile("state");
    try std.testing.expectEqual(@as(std.fs.File.Mode, dir_mode), st.mode & 0o777);
}

test "ensureDirPath creates nested absolute directories" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "a", "b", "c" });
    defer std.testing.allocator.free(path);

    try ensureDirPath(path);
    var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer dir.close();
    const st = try dir.stat();
    try std.testing.expectEqual(@as(std.fs.File.Mode, dir_mode), st.mode & 0o777);
}

test "createFileAt locks file mode to 0600" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try createFileAt(tmp.dir, "state.json", .{ .truncate = true });
    file.close();

    const st = try tmp.dir.statFile("state.json");
    try std.testing.expectEqual(@as(std.fs.File.Mode, file_mode), st.mode & 0o777);
}

test "openConfined rejects symlinks" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("real.txt", .{});
    f.close();
    try tmp.dir.symLink("real.txt", "link.txt", .{});

    try std.testing.expectError(error.SymLinkLoop, openConfined(tmp.dir, "link.txt", .{}));
}

test "openConfined rejects path traversal" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(error.AccessDenied, openConfined(tmp.dir, "..", .{}));
    try std.testing.expectError(error.AccessDenied, openConfined(tmp.dir, "a/b", .{}));
    try std.testing.expectError(error.AccessDenied, openConfined(tmp.dir, "", .{}));
}

test "createConfined rejects symlinks" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.symLink("target.txt", "link.txt", .{});
    try std.testing.expectError(error.SymLinkLoop, createConfined(tmp.dir, "link.txt", .{}));
}

test "openConfined rejects hardlinks" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try tmp.dir.createFile("orig.txt", .{});
    try f.writeAll("data");
    f.close();

    posix.linkat(tmp.dir.fd, "orig.txt", tmp.dir.fd, "hard.txt", 0) catch return;
    try std.testing.expectError(error.AccessDenied, openConfined(tmp.dir, "hard.txt", .{}));
    try std.testing.expectError(error.AccessDenied, openConfined(tmp.dir, "orig.txt", .{}));
}

test "atomicWriteAt creates file atomically" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try atomicWriteAt(tmp.dir, "out.json", "{\"ok\":true}\n");

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "out.json", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("{\"ok\":true}\n", content);

    const st = try tmp.dir.statFile("out.json");
    try std.testing.expectEqual(@as(std.fs.File.Mode, file_mode), st.mode & 0o777);
}

test "atomicWriteAt overwrites existing file" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try atomicWriteAt(tmp.dir, "f.txt", "old");
    try atomicWriteAt(tmp.dir, "f.txt", "new");

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "f.txt", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("new", content);
}

test "atomicWriteAt rejects path traversal" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expectError(error.AccessDenied, atomicWriteAt(tmp.dir, "../escape", "x"));
    try std.testing.expectError(error.AccessDenied, atomicWriteAt(tmp.dir, "a/b", "x"));
}

test "atomicWriteAtFn streams large data" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const Ctx = struct {
        fn write(_: *const @This(), file: std.fs.File) !void {
            try file.writeAll("chunk1");
            try file.writeAll("chunk2");
        }
    };
    const ctx = Ctx{};
    try atomicWriteAtFn(tmp.dir, "streamed.txt", &ctx, Ctx.write);

    const content = try tmp.dir.readFileAlloc(std.testing.allocator, "streamed.txt", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("chunk1chunk2", content);
}

test "createConfined enforces 0600 mode" {
    if (builtin.os.tag == .windows) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var f = try createConfined(tmp.dir, "sec.txt", .{});
    f.close();

    const st = try tmp.dir.statFile("sec.txt");
    try std.testing.expectEqual(@as(std.fs.File.Mode, file_mode), st.mode & 0o777);
}
