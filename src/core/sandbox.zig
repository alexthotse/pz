//! Command sandbox: allowlist-based execution gating.
const builtin = @import("builtin");
const std = @import("std");

pub const Err = error{
    Denied,
    NotFound,
    Io,
    OutOfMemory,
};

const system_exec_roots = [_][]const u8{
    "/bin",
    "/sbin",
    "/private/var/select",
    "/usr/bin",
    "/usr/lib",
    "/usr/libexec",
    "/usr/sbin",
    "/System",
    "/Library/Apple/System",
};

pub const BashPlan = struct {
    argv: []const []const u8,
    cwd: ?[]const u8,
    profile: []u8,

    pub fn deinit(self: *BashPlan, alloc: std.mem.Allocator) void {
        alloc.free(self.argv);
        alloc.free(self.profile);
        if (self.cwd) |cwd| alloc.free(cwd);
        self.* = undefined;
    }
};

pub fn prepareBash(
    alloc: std.mem.Allocator,
    env: *const std.process.EnvMap,
    raw_cwd: ?[]const u8,
    cmd: []const u8,
) Err!BashPlan {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) @compileError("bash sandbox requires macOS or linux");

    const root = std.fs.cwd().realpathAlloc(alloc, ".") catch |err| return mapFsErr(err);
    defer alloc.free(root);

    var cwd: ?[]const u8 = try alloc.dupe(u8, root);
    errdefer if (cwd) |path| alloc.free(path);
    if (raw_cwd) |path| {
        const base = cwd.?;
        cwd = null;
        alloc.free(base);
        cwd = try resolveCwd(alloc, root, path);
    }

    const exec_roots = try collectExecRoots(alloc, env, root);
    defer freeRoots(alloc, exec_roots);

    const profile = try buildBashProfile(alloc, root, exec_roots, env.get("HOME"));
    errdefer alloc.free(profile);

    if (builtin.os.tag == .macos) {
        const argv = try alloc.alloc([]const u8, 8);
        errdefer alloc.free(argv);

        argv[0] = "/usr/bin/sandbox-exec";
        argv[1] = "-p";
        argv[2] = profile;
        argv[3] = "/bin/bash";
        argv[4] = "--noprofile";
        argv[5] = "--norc";
        argv[6] = "-lc";
        argv[7] = cmd;

        return .{
            .argv = argv,
            .cwd = cwd,
            .profile = profile,
        };
    } else {
        const argv = try alloc.alloc([]const u8, 5);
        errdefer alloc.free(argv);

        argv[0] = "bash";
        argv[1] = "--noprofile";
        argv[2] = "--norc";
        argv[3] = "-lc";
        argv[4] = cmd;

        return .{
            .argv = argv,
            .cwd = cwd,
            .profile = profile,
        };
    }
}

fn resolveCwd(alloc: std.mem.Allocator, root: []const u8, path: []const u8) Err![]const u8 {
    const resolved = std.fs.cwd().realpathAlloc(alloc, path) catch |err| return mapFsErr(err);
    errdefer alloc.free(resolved);
    if (!isWithin(root, resolved)) return error.Denied;
    return resolved;
}

fn collectExecRoots(
    alloc: std.mem.Allocator,
    env: *const std.process.EnvMap,
    root: []const u8,
) Err![][]u8 {
    var roots = std.ArrayList([]u8).empty;
    errdefer {
        for (roots.items) |path| alloc.free(path);
        roots.deinit(alloc);
    }

    try pushRoot(alloc, &roots, root);
    for (system_exec_roots) |path| {
        try pushRealOrRawRoot(alloc, &roots, path);
    }

    if (env.get("PATH")) |path_env| {
        var it = std.mem.splitScalar(u8, path_env, ':');
        while (it.next()) |entry| {
            if (entry.len == 0) continue;
            try pushPathRoot(alloc, &roots, entry);
        }
    }

    return try roots.toOwnedSlice(alloc);
}

fn pushPathRoot(alloc: std.mem.Allocator, roots: *std.ArrayList([]u8), path: []const u8) Err!void {
    const abs = std.fs.cwd().realpathAlloc(alloc, path) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied, error.PermissionDenied => return,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Io,
    };
    defer alloc.free(abs);

    const norm = execRoot(abs);
    try pushRoot(alloc, roots, norm);
}

fn pushRealOrRawRoot(alloc: std.mem.Allocator, roots: *std.ArrayList([]u8), path: []const u8) Err!void {
    const abs = std.fs.cwd().realpathAlloc(alloc, path) catch |err| switch (err) {
        error.FileNotFound, error.NotDir, error.AccessDenied, error.PermissionDenied => {
            try pushRoot(alloc, roots, path);
            return;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Io,
    };
    defer alloc.free(abs);

    try pushRoot(alloc, roots, execRoot(abs));
}

fn pushRoot(alloc: std.mem.Allocator, roots: *std.ArrayList([]u8), path: []const u8) Err!void {
    for (roots.items) |cur| {
        if (std.mem.eql(u8, cur, path)) return;
    }
    try roots.append(alloc, try alloc.dupe(u8, path));
}

fn execRoot(path: []const u8) []const u8 {
    return path;
}

fn freeRoots(alloc: std.mem.Allocator, roots: [][]u8) void {
    for (roots) |path| alloc.free(path);
    alloc.free(roots);
}

fn buildBashProfile(
    alloc: std.mem.Allocator,
    root: []const u8,
    exec_roots: []const []const u8,
    home: ?[]const u8,
) Err![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    try w.writeAll(
        \\(version 1)
        \\(deny default)
        \\(import "system.sb")
        \\
        \\(allow process-fork)
        \\(allow signal)
        \\
    );
    if (home) |home_path| {
        try w.writeAll(
            \\(deny file-read* file-write* process-exec*
            \\    (require-all
            \\
        );
        try appendSubpath(&buf, alloc, home_path);
        try w.writeAll(
            \\        (require-not
            \\
        );
        try appendSubpath(&buf, alloc, root);
        try w.writeAll(
            \\        )
            \\    )
            \\)
            \\
        );
    }
    try w.writeAll(
        \\(allow file-read* file-write*
        \\
    );
    try appendSubpath(&buf, alloc, root);
    try w.writeAll(
        \\)
        \\
        \\(allow file-read-metadata file-test-existence
        \\
    );
    try appendPathAncestors(&buf, alloc, root);
    try w.writeAll(
        \\)
        \\
        \\(allow file-read* file-map-executable process-exec*
        \\
    );
    for (exec_roots) |path| {
        try appendSubpath(&buf, alloc, path);
    }
    try w.writeAll(
        \\)
        \\
    );
    return try buf.toOwnedSlice(alloc);
}

fn appendSubpath(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, path: []const u8) Err!void {
    try buf.writer(alloc).writeAll("    (subpath ");
    try appendQuoted(buf, alloc, path);
    try buf.writer(alloc).writeAll(")\n");
}

fn appendPathAncestors(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, path: []const u8) Err!void {
    try buf.writer(alloc).writeAll("    (path-ancestors ");
    try appendQuoted(buf, alloc, path);
    try buf.writer(alloc).writeAll(")\n");
}

fn appendQuoted(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, txt: []const u8) Err!void {
    try buf.append(alloc, '"');
    for (txt) |c| switch (c) {
        '\\', '"' => {
            try buf.append(alloc, '\\');
            try buf.append(alloc, c);
        },
        else => try buf.append(alloc, c),
    };
    try buf.append(alloc, '"');
}

fn isWithin(root: []const u8, path: []const u8) bool {
    if (path.len < root.len) return false;
    if (!std.mem.eql(u8, root, path[0..root.len])) return false;
    if (path.len == root.len) return true;
    return std.fs.path.isSep(path[root.len]);
}

/// Environment variable keys that must be scrubbed before spawning
/// sandboxed children. These may leak credentials or config into
/// untrusted subprocesses.
pub const sensitive_env = [_][]const u8{
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "PZ_API_KEY",
    "PZ_AUTH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
};

/// Remove sensitive keys from env map in-place.
pub fn scrubEnv(env: *std.process.EnvMap) void {
    for (sensitive_env) |key| {
        env.remove(key);
    }
}

fn mapFsErr(err: anyerror) Err {
    return switch (err) {
        error.FileNotFound, error.NotDir => error.NotFound,
        error.AccessDenied, error.PermissionDenied, error.SymLinkLoop => error.Denied,
        error.OutOfMemory => error.OutOfMemory,
        else => error.Io,
    };
}

test "prepareBash wraps bash with sandbox-exec and resolves cwd inside workspace" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.makePath("sub");

    const path_guard = @import("tools/path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("PATH", "/opt/homebrew/bin:/usr/bin:/bin");

    var plan = try prepareBash(std.testing.allocator, &env, "sub", "printf ok");
    defer plan.deinit(std.testing.allocator);

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const sub = try tmp.dir.realpathAlloc(std.testing.allocator, "sub");
    defer std.testing.allocator.free(sub);

    if (builtin.os.tag == .macos) {
        try std.testing.expectEqual(@as(usize, 8), plan.argv.len);
        try std.testing.expectEqualStrings("/usr/bin/sandbox-exec", plan.argv[0]);
        try std.testing.expectEqualStrings("-p", plan.argv[1]);
        try std.testing.expectEqualStrings(plan.profile, plan.argv[2]);
        try std.testing.expectEqualStrings("/bin/bash", plan.argv[3]);
        try std.testing.expectEqualStrings("--noprofile", plan.argv[4]);
        try std.testing.expectEqualStrings("--norc", plan.argv[5]);
        try std.testing.expectEqualStrings("-lc", plan.argv[6]);
        try std.testing.expectEqualStrings("printf ok", plan.argv[7]);
    } else {
        try std.testing.expectEqual(@as(usize, 5), plan.argv.len);
        try std.testing.expectEqualStrings("bash", plan.argv[0]);
        try std.testing.expectEqualStrings("--noprofile", plan.argv[1]);
        try std.testing.expectEqualStrings("--norc", plan.argv[2]);
        try std.testing.expectEqualStrings("-lc", plan.argv[3]);
        try std.testing.expectEqualStrings("printf ok", plan.argv[4]);
    }
    try std.testing.expectEqualStrings(sub, plan.cwd.?);
    try std.testing.expect(std.mem.indexOf(u8, plan.profile, root) != null);
    if (builtin.os.tag == .macos) {
        try std.testing.expect(std.mem.indexOf(u8, plan.profile, "/opt/homebrew") != null);
    }
}

test "prepareBash denies cwd escapes" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var outer = std.testing.tmpDir(.{ .iterate = true });
    defer outer.cleanup();

    const path_guard = @import("tools/path_guard.zig");
    var cwd_guard = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd_guard.deinit();

    const outer_root = try outer.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outer_root);
    try tmp.dir.symLink(outer_root, "escape", .{ .is_directory = true });

    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("PATH", "/usr/bin:/bin");

    try std.testing.expectError(error.Denied, prepareBash(std.testing.allocator, &env, "escape", "true"));
}

test "scrubEnv removes sensitive keys and preserves others" {
    var env = std.process.EnvMap.init(std.testing.allocator);
    defer env.deinit();
    try env.put("PATH", "/usr/bin");
    try env.put("ANTHROPIC_API_KEY", "sk-secret");
    try env.put("OPENAI_API_KEY", "sk-openai");
    try env.put("HOME", "/home/user");
    try env.put("GITHUB_TOKEN", "ghp_tok");

    scrubEnv(&env);

    try std.testing.expect(env.get("ANTHROPIC_API_KEY") == null);
    try std.testing.expect(env.get("OPENAI_API_KEY") == null);
    try std.testing.expect(env.get("GITHUB_TOKEN") == null);
    try std.testing.expectEqualStrings("/usr/bin", env.get("PATH").?);
    try std.testing.expectEqualStrings("/home/user", env.get("HOME").?);
}
