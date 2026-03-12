const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;

const native_os = builtin.os.tag;

const RaceHook = struct {
    ctx: *anyopaque,
    after_open: *const fn (*anyopaque, std.fs.Dir, []const u8) anyerror!void,
};

var race_mu: std.Thread.Mutex = .{};
var race_hook: ?RaceHook = null;

pub const CwdGuard = struct {
    prev: std.fs.Dir,

    var mu: std.Thread.Mutex = .{};

    pub fn enter(dir: std.fs.Dir) !CwdGuard {
        mu.lock();
        errdefer mu.unlock();

        var prev = try std.fs.cwd().openDir(".", .{});
        errdefer prev.close();

        try dir.setAsCwd();
        return .{ .prev = prev };
    }

    pub fn deinit(self: *CwdGuard) void {
        self.prev.setAsCwd() catch unreachable;
        self.prev.close();
        mu.unlock();
        self.* = undefined;
    }
};

pub const RaceGuard = struct {
    pub fn deinit(self: *RaceGuard) void {
        race_hook = null;
        race_mu.unlock();
        self.* = undefined;
    }
};

pub fn installRaceHook(
    ctx: *anyopaque,
    after_open: *const fn (*anyopaque, std.fs.Dir, []const u8) anyerror!void,
) RaceGuard {
    race_mu.lock();
    race_hook = .{
        .ctx = ctx,
        .after_open = after_open,
    };
    return .{};
}

pub fn openDir(path: []const u8, opts: std.fs.Dir.OpenOptions) !std.fs.Dir {
    const rel = try relPath(path);
    if (rel.len == 0) return std.fs.cwd().openDir(".", opts);

    var parent = try openParentDir(rel);
    errdefer parent.dir.close();

    const leaf = parent.leaf orelse return error.FileNotFound;
    const dir = parent.dir.openDir(leaf, noFollowDirOpts(opts)) catch |err|
        return mapParentDirErr(parent.dir, leaf, err);
    parent.dir.close();
    return dir;
}

pub fn openFile(path: []const u8, flags: std.fs.File.OpenFlags) !std.fs.File {
    const rel = try relPath(path);
    if (rel.len == 0) return error.FileNotFound;

    var parent = try openParentDir(rel);
    defer parent.dir.close();

    const leaf = parent.leaf orelse return error.FileNotFound;
    return switch (native_os) {
        .windows => error.AccessDenied,
        else => openFileAt(parent.dir.fd, leaf, flags),
    };
}

pub fn openFileInDir(dir: std.fs.Dir, name: []const u8, flags: std.fs.File.OpenFlags) !std.fs.File {
    const leaf = try leafName(name);
    return switch (native_os) {
        .windows => error.AccessDenied,
        else => openFileAt(dir.fd, leaf, flags),
    };
}

pub fn createFileInDir(dir: std.fs.Dir, name: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    const leaf = try leafName(name);
    return switch (native_os) {
        .windows => error.AccessDenied,
        else => createFileAt(dir.fd, leaf, flags),
    };
}

pub fn createFile(path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    const rel = try relPath(path);
    if (rel.len == 0) return error.FileNotFound;

    var parent = try openParentDir(rel);
    defer parent.dir.close();

    const leaf = parent.leaf orelse return error.FileNotFound;
    return switch (native_os) {
        .windows => error.AccessDenied,
        else => createFileAt(parent.dir.fd, leaf, flags),
    };
}

const ParentDir = struct {
    dir: std.fs.Dir,
    leaf: ?[]const u8,
};

fn openParentDir(rel_path: []const u8) !ParentDir {
    var dir = try std.fs.cwd().openDir(".", .{ .access_sub_paths = true });
    errdefer dir.close();

    var it = try std.fs.path.componentIterator(rel_path);
    var leaf: ?[]const u8 = null;
    while (it.next()) |part| {
        if (isDot(part.name)) continue;
        if (isDotDot(part.name)) return error.AccessDenied;

        if (leaf) |name| {
            const next = dir.openDir(name, .{
                .access_sub_paths = true,
                .no_follow = true,
            }) catch |err| return mapParentDirErr(dir, name, err);
            dir.close();
            dir = next;
        }
        leaf = part.name;
    }

    return .{
        .dir = dir,
        .leaf = leaf,
    };
}

fn mapParentDirErr(dir: std.fs.Dir, name: []const u8, err: anyerror) anyerror {
    if (err != error.NotDir) return err;
    if (native_os == .windows) return err;

    const st = posix.fstatat(dir.fd, name, posix.AT.SYMLINK_NOFOLLOW) catch |stat_err| switch (stat_err) {
        error.AccessDenied, error.PermissionDenied, error.SymLinkLoop => return error.AccessDenied,
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    if ((st.mode & posix.S.IFMT) == posix.S.IFLNK) return error.AccessDenied;
    return error.FileNotFound;
}

fn relPath(path: []const u8) ![]const u8 {
    if (!std.fs.path.isAbsolute(path)) return path;

    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try std.fs.cwd().realpath(".", &root_buf);

    if (path.len < root.len) return error.AccessDenied;
    if (!std.mem.eql(u8, path[0..root.len], root)) return error.AccessDenied;
    if (path.len == root.len) return "";
    if (!std.fs.path.isSep(path[root.len])) return error.AccessDenied;

    var rel = path[root.len..];
    while (rel.len > 0 and std.fs.path.isSep(rel[0])) rel = rel[1..];
    return rel;
}

fn noFollowDirOpts(opts: std.fs.Dir.OpenOptions) std.fs.Dir.OpenOptions {
    var out = opts;
    out.no_follow = true;
    return out;
}

fn isDot(name: []const u8) bool {
    return name.len == 1 and name[0] == '.';
}

fn isDotDot(name: []const u8) bool {
    return name.len == 2 and name[0] == '.' and name[1] == '.';
}

fn leafName(name: []const u8) ![]const u8 {
    if (name.len == 0) return error.AccessDenied;
    if (isDot(name) or isDotDot(name)) return error.AccessDenied;
    for (name) |c| {
        if (std.fs.path.isSep(c)) return error.AccessDenied;
    }
    return name;
}

fn openFileAt(dir_fd: posix.fd_t, path: []const u8, flags: std.fs.File.OpenFlags) !std.fs.File {
    var os_flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = flags.mode != .write_only,
            .write = flags.mode != .read_only,
        },
        else => .{
            .ACCMODE = switch (flags.mode) {
                .read_only => .RDONLY,
                .write_only => .WRONLY,
                .read_write => .RDWR,
            },
            .NOFOLLOW = true,
        },
    };
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "NOCTTY")) os_flags.NOCTTY = !flags.allow_ctty;

    const has_flock_open_flags = @hasField(posix.O, "EXLOCK");
    if (has_flock_open_flags) switch (flags.lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
    };

    const fd = try posix.openat(dir_fd, path, os_flags, 0);
    errdefer posix.close(fd);

    if (@TypeOf(posix.system.flock) != void and !has_flock_open_flags and flags.lock != .none) {
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        try posix.flock(fd, switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        });
    }

    if (has_flock_open_flags and flags.lock_nonblocking) {
        var fl_flags = posix.fcntl(fd, posix.F.GETFL, 0) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
        fl_flags &= ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK"));
        _ = posix.fcntl(fd, posix.F.SETFL, fl_flags) catch |err| switch (err) {
            error.FileBusy => unreachable,
            error.Locked => unreachable,
            error.PermissionDenied => unreachable,
            error.DeadLock => unreachable,
            error.LockedRegionLimitExceeded => unreachable,
            else => |e| return e,
        };
    }

    try maybeRace(dir_fd, path);
    try ensureStableFile(dir_fd, path, fd);

    return .{ .handle = fd };
}

fn createFileAt(dir_fd: posix.fd_t, path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    var os_flags: posix.O = .{
        .ACCMODE = if (flags.read) .RDWR else .WRONLY,
        .CREAT = true,
        .TRUNC = false,
        .EXCL = flags.exclusive,
        .NOFOLLOW = true,
    };
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;

    const has_flock_open_flags = @hasField(posix.O, "EXLOCK");
    if (has_flock_open_flags) switch (flags.lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = flags.lock_nonblocking;
        },
    };

    const fd = try posix.openat(dir_fd, path, os_flags, flags.mode);
    errdefer posix.close(fd);

    if (@TypeOf(posix.system.flock) != void and !has_flock_open_flags and flags.lock != .none) {
        const lock_nonblocking: i32 = if (flags.lock_nonblocking) posix.LOCK.NB else 0;
        try posix.flock(fd, switch (flags.lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | lock_nonblocking,
            .exclusive => posix.LOCK.EX | lock_nonblocking,
        });
    }

    try maybeRace(dir_fd, path);
    try ensureStableFile(dir_fd, path, fd);
    if (flags.truncate) {
        var file: std.fs.File = .{ .handle = fd };
        try file.setEndPos(0);
    }

    return .{ .handle = fd };
}

fn maybeRace(dir_fd: posix.fd_t, path: []const u8) !void {
    if (race_hook) |hook| {
        try hook.after_open(hook.ctx, .{ .fd = dir_fd }, path);
    }
}

fn ensureStableFile(dir_fd: posix.fd_t, path: []const u8, fd: posix.fd_t) !void {
    const got = posix.fstat(fd) catch return error.AccessDenied;
    if (!isReg(got.mode)) return error.AccessDenied;
    if (got.nlink != 1) return error.AccessDenied;

    const want = posix.fstatat(dir_fd, path, posix.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.FileNotFound,
        error.AccessDenied,
        error.PermissionDenied,
        error.SymLinkLoop,
        => return error.AccessDenied,
        else => return err,
    };
    if (!isReg(want.mode)) return error.AccessDenied;
    if (want.nlink != 1) return error.AccessDenied;
    if (!sameFile(got, want)) return error.AccessDenied;
}

fn isReg(mode: posix.mode_t) bool {
    return (mode & posix.S.IFMT) == posix.S.IFREG;
}

fn sameFile(a: posix.Stat, b: posix.Stat) bool {
    return a.dev == b.dev and a.ino == b.ino;
}

test "openFile denies hardlinked leaf" {
    if (native_os == .windows or native_os == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "base.txt", .data = "secret\n" });
    try posix.linkat(tmp.dir.fd, "base.txt", tmp.dir.fd, "alias.txt", 0);

    try std.testing.expectError(error.AccessDenied, openFile("alias.txt", .{ .mode = .read_only }));
}

test "createFile denies hardlinked leaf before truncation" {
    if (native_os == .windows or native_os == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "base.txt", .data = "secret\n" });
    try posix.linkat(tmp.dir.fd, "base.txt", tmp.dir.fd, "alias.txt", 0);

    try std.testing.expectError(error.AccessDenied, createFile("alias.txt", .{ .truncate = true }));
    const kept = try tmp.dir.readFileAlloc(std.testing.allocator, "base.txt", 64);
    defer std.testing.allocator.free(kept);
    try std.testing.expectEqualStrings("secret\n", kept);
}

test "openFile denies replaced leaf after open" {
    if (native_os == .windows or native_os == .wasi) return;

    const Ctx = struct {
        fn run(_: *anyopaque, dir: std.fs.Dir, path: []const u8) !void {
            try dir.rename(path, "gone.txt");
            try dir.rename("swap.txt", path);
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "victim.txt", .data = "keep\n" });
    try tmp.dir.writeFile(.{ .sub_path = "swap.txt", .data = "swap\n" });

    var ctx: u8 = 0;
    var guard = installRaceHook(&ctx, Ctx.run);
    defer guard.deinit();

    try std.testing.expectError(error.AccessDenied, openFile("victim.txt", .{ .mode = .read_only }));
    const now = try tmp.dir.readFileAlloc(std.testing.allocator, "victim.txt", 64);
    defer std.testing.allocator.free(now);
    try std.testing.expectEqualStrings("swap\n", now);
}

test "createFile denies replaced leaf before truncation" {
    if (native_os == .windows or native_os == .wasi) return;

    const Ctx = struct {
        fn run(_: *anyopaque, dir: std.fs.Dir, path: []const u8) !void {
            try dir.rename(path, "gone.txt");
            try dir.rename("swap.txt", path);
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "victim.txt", .data = "keep\n" });
    try tmp.dir.writeFile(.{ .sub_path = "swap.txt", .data = "swap\n" });

    var ctx: u8 = 0;
    var guard = installRaceHook(&ctx, Ctx.run);
    defer guard.deinit();

    try std.testing.expectError(error.AccessDenied, createFile("victim.txt", .{ .truncate = true }));
    const now = try tmp.dir.readFileAlloc(std.testing.allocator, "victim.txt", 64);
    defer std.testing.allocator.free(now);
    try std.testing.expectEqualStrings("swap\n", now);
}
