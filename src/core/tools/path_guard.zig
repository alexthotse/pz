const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;

const native_os = builtin.os.tag;

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

pub fn openDir(path: []const u8, opts: std.fs.Dir.OpenOptions) !std.fs.Dir {
    const rel = try relPath(path);
    if (rel.len == 0) return std.fs.cwd().openDir(".", opts);

    var parent = try openParentDir(rel);
    errdefer parent.dir.close();

    const leaf = parent.leaf orelse return error.FileNotFound;
    const dir = try parent.dir.openDir(leaf, noFollowDirOpts(opts));
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
            const next = try dir.openDir(name, .{
                .access_sub_paths = true,
                .no_follow = true,
            });
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

    return .{ .handle = fd };
}

fn createFileAt(dir_fd: posix.fd_t, path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    var os_flags: posix.O = .{
        .ACCMODE = if (flags.read) .RDWR else .WRONLY,
        .CREAT = true,
        .TRUNC = flags.truncate,
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

    return .{ .handle = fd };
}
