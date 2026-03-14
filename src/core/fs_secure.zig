//! Secure filesystem helpers: restrictive modes, safe dir creation.
const std = @import("std");
const builtin = @import("builtin");

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
