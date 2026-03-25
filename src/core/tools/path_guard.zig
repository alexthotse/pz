//! TOCTOU-safe path resolution and directory traversal guard.
const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;

const native_os = builtin.os.tag;

pub const RaceHook = struct {
    vt: *const Vt,

    pub const Vt = struct {
        after_open: *const fn (self: *RaceHook, dir: std.fs.Dir, path: []const u8) anyerror!void,
    };

    pub fn call(self: *RaceHook, dir: std.fs.Dir, path: []const u8) !void {
        return self.vt.after_open(self, dir, path);
    }

    pub fn Bind(comptime T: type, comptime after_open_fn: fn (*T, std.fs.Dir, []const u8) anyerror!void) type {
        return struct {
            pub const vt = Vt{
                .after_open = afterOpenFn,
            };
            fn afterOpenFn(rh: *RaceHook, dir: std.fs.Dir, path: []const u8) anyerror!void {
                const self_ptr: *T = @fieldParentPtr("race_hook", rh);
                return after_open_fn(self_ptr, dir, path);
            }
        };
    }
};

var race_mu: std.Thread.Mutex = .{};
var race_hook: ?*RaceHook = null;

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
        self.prev.setAsCwd() catch |err| {
            std.log.warn("CwdGuard: failed to restore cwd: {}", .{err});
        };
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

pub fn installRaceHook(hook: *RaceHook) RaceGuard {
    race_mu.lock();
    race_hook = hook;
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

fn setPortableFlags(os_flags: *posix.O) void {
    if (@hasField(posix.O, "CLOEXEC")) os_flags.CLOEXEC = true;
    if (@hasField(posix.O, "LARGEFILE")) os_flags.LARGEFILE = true;
}

const LockKind = enum { none, shared, exclusive };

fn setFlockOpenFlags(os_flags: *posix.O, lock: LockKind, nonblocking: bool) bool {
    const has = @hasField(posix.O, "EXLOCK");
    if (has) switch (lock) {
        .none => {},
        .shared => {
            os_flags.SHLOCK = true;
            os_flags.NONBLOCK = nonblocking;
        },
        .exclusive => {
            os_flags.EXLOCK = true;
            os_flags.NONBLOCK = nonblocking;
        },
    };
    return has;
}

fn applyFlock(fd: posix.fd_t, has_flock_open_flags: bool, lock: LockKind, nonblocking: bool) !void {
    if (@TypeOf(posix.system.flock) != void and !has_flock_open_flags and lock != .none) {
        const nb: i32 = if (nonblocking) posix.LOCK.NB else 0;
        try posix.flock(fd, switch (lock) {
            .none => unreachable,
            .shared => posix.LOCK.SH | nb,
            .exclusive => posix.LOCK.EX | nb,
        });
    }

    if (has_flock_open_flags and nonblocking) {
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
    setPortableFlags(&os_flags);
    if (@hasField(posix.O, "NOCTTY")) os_flags.NOCTTY = !flags.allow_ctty;

    const lock: LockKind = switch (flags.lock) {
        .none => .none,
        .shared => .shared,
        .exclusive => .exclusive,
    };
    const has_flock_open = setFlockOpenFlags(&os_flags, lock, flags.lock_nonblocking);

    const fd = try posix.openat(dir_fd, path, os_flags, 0);
    errdefer posix.close(fd);

    try applyFlock(fd, has_flock_open, lock, flags.lock_nonblocking);
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
    setPortableFlags(&os_flags);

    const lock: LockKind = switch (flags.lock) {
        .none => .none,
        .shared => .shared,
        .exclusive => .exclusive,
    };
    const has_flock_open = setFlockOpenFlags(&os_flags, lock, flags.lock_nonblocking);

    const fd = try posix.openat(dir_fd, path, os_flags, flags.mode);
    errdefer posix.close(fd);

    try applyFlock(fd, has_flock_open, lock, flags.lock_nonblocking);
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
        try hook.call(.{ .fd = dir_fd }, path);
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

/// Resolve `path` component-by-component under `root`, following symlinks at
/// each step via readlinkat, and verify the final resolved path stays within
/// `root`. Returns error.AccessDenied if any symlink resolves outside root.
pub fn resolveConfined(
    alloc: std.mem.Allocator,
    root: []const u8,
    path: []const u8,
) ![]u8 {
    if (native_os == .windows) return error.AccessDenied;

    // Normalize root to realpath
    var root_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_root = try std.fs.cwd().realpath(root, &root_buf);

    // Build resolved path component by component
    var resolved: std.ArrayListUnmanaged(u8) = .empty;
    defer resolved.deinit(alloc);
    try resolved.appendSlice(alloc, real_root);

    var it = try std.fs.path.componentIterator(path);
    var hops: usize = 0;
    const max_hops: usize = 40; // symlink follow limit

    while (it.next()) |part| {
        if (isDot(part.name)) continue;
        if (isDotDot(part.name)) {
            // Walk up, but not above root
            if (resolved.items.len > real_root.len) {
                // Strip last component
                while (resolved.items.len > real_root.len and
                    !std.fs.path.isSep(resolved.items[resolved.items.len - 1]))
                {
                    _ = resolved.pop();
                }
                // Strip trailing sep (but keep root)
                while (resolved.items.len > real_root.len and
                    std.fs.path.isSep(resolved.items[resolved.items.len - 1]))
                {
                    _ = resolved.pop();
                }
            }
            continue;
        }

        // Append separator + component
        try resolved.append(alloc, '/');
        try resolved.appendSlice(alloc, part.name);

        // Check if this component is a symlink
        var link_buf: [std.fs.max_path_bytes]u8 = undefined;
        const link_target = posix.readlinkat(
            posix.AT.FDCWD,
            resolved.items,
            &link_buf,
        ) catch |err| switch (err) {
            error.NotLink => continue, // regular file/dir, keep going
            else => return error.AccessDenied,
        };

        hops += 1;
        if (hops > max_hops) return error.AccessDenied;

        if (std.fs.path.isAbsolute(link_target)) {
            // Absolute symlink: replace resolved entirely
            resolved.clearRetainingCapacity();
            try resolved.appendSlice(alloc, link_target);
        } else {
            // Relative symlink: pop component, append target
            while (resolved.items.len > 0 and
                !std.fs.path.isSep(resolved.items[resolved.items.len - 1]))
            {
                _ = resolved.pop();
            }
            // Keep the separator
            try resolved.appendSlice(alloc, link_target);
        }

        // Re-resolve to realpath to canonicalize
        var canon_buf: [std.fs.max_path_bytes]u8 = undefined;
        const canon = std.fs.cwd().realpath(resolved.items, &canon_buf) catch
            return error.AccessDenied;
        resolved.clearRetainingCapacity();
        try resolved.appendSlice(alloc, canon);

        // Confinement check
        if (!isConfined(resolved.items, real_root))
            return error.AccessDenied;
    }

    // Final confinement check
    var final_buf: [std.fs.max_path_bytes]u8 = undefined;
    const final_path = std.fs.cwd().realpath(resolved.items, &final_buf) catch
        return error.AccessDenied;

    if (!isConfined(final_path, real_root))
        return error.AccessDenied;

    return try alloc.dupe(u8, final_path);
}

fn isConfined(path: []const u8, root: []const u8) bool {
    if (path.len < root.len) return false;
    if (!std.mem.eql(u8, path[0..root.len], root)) return false;
    if (path.len == root.len) return true;
    return std.fs.path.isSep(path[root.len]);
}

test "resolveConfined allows path within root" {
    if (native_os == .windows or native_os == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("sub/deep");
    try tmp.dir.writeFile(.{ .sub_path = "sub/deep/file.txt", .data = "ok" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    const resolved = try resolveConfined(std.testing.allocator, root, "sub/deep/file.txt");
    defer std.testing.allocator.free(resolved);

    const expected = try std.fs.path.join(std.testing.allocator, &.{ root, "sub/deep/file.txt" });
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, resolved);
}

test "resolveConfined denies symlink chain escaping root" {
    if (native_os == .windows or native_os == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create root/jail and an outside directory
    try tmp.dir.makePath("jail/sub");
    try tmp.dir.makePath("outside");
    try tmp.dir.writeFile(.{ .sub_path = "outside/secret.txt", .data = "stolen" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "jail");
    defer std.testing.allocator.free(root);

    const outside_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "outside");
    defer std.testing.allocator.free(outside_abs);

    // Create symlink chain: jail/sub/link1 -> link2, jail/sub/link2 -> /outside
    try tmp.dir.symLink(outside_abs, "jail/sub/escape", .{});

    // Attempt to resolve through symlink that escapes
    try std.testing.expectError(
        error.AccessDenied,
        resolveConfined(std.testing.allocator, root, "sub/escape/secret.txt"),
    );
}

test "resolveConfined denies dotdot escape" {
    if (native_os == .windows or native_os == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("jail/sub");
    try tmp.dir.writeFile(.{ .sub_path = "outside.txt", .data = "secret" });

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, "jail");
    defer std.testing.allocator.free(root);

    // ../../outside.txt should be confined to root (dotdot stops at root)
    // The resolved path would be jail/outside.txt which doesn't exist
    try std.testing.expectError(
        error.AccessDenied,
        resolveConfined(std.testing.allocator, root, "sub/../../outside.txt"),
    );
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
        race_hook: RaceHook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), dir: std.fs.Dir, path: []const u8) !void {
            try dir.rename(path, "gone.txt");
            try dir.rename("swap.txt", path);
        }
        const Bind = RaceHook.Bind(@This(), run);
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "victim.txt", .data = "keep\n" });
    try tmp.dir.writeFile(.{ .sub_path = "swap.txt", .data = "swap\n" });

    var ctx = Ctx{};
    var guard = installRaceHook(&ctx.race_hook);
    defer guard.deinit();

    try std.testing.expectError(error.AccessDenied, openFile("victim.txt", .{ .mode = .read_only }));
    const now = try tmp.dir.readFileAlloc(std.testing.allocator, "victim.txt", 64);
    defer std.testing.allocator.free(now);
    try std.testing.expectEqualStrings("swap\n", now);
}

test "createFile denies replaced leaf before truncation" {
    if (native_os == .windows or native_os == .wasi) return;

    const Ctx = struct {
        race_hook: RaceHook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), dir: std.fs.Dir, path: []const u8) !void {
            try dir.rename(path, "gone.txt");
            try dir.rename("swap.txt", path);
        }
        const Bind = RaceHook.Bind(@This(), run);
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{ .sub_path = "victim.txt", .data = "keep\n" });
    try tmp.dir.writeFile(.{ .sub_path = "swap.txt", .data = "swap\n" });

    var ctx = Ctx{};
    var guard = installRaceHook(&ctx.race_hook);
    defer guard.deinit();

    try std.testing.expectError(error.AccessDenied, createFile("victim.txt", .{ .truncate = true }));
    const now = try tmp.dir.readFileAlloc(std.testing.allocator, "victim.txt", 64);
    defer std.testing.allocator.free(now);
    try std.testing.expectEqualStrings("swap\n", now);
}
