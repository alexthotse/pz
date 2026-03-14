//! AGENTS.md context discovery and loading.
const std = @import("std");
const policy = @import("policy.zig");
const prov_contract = @import("providers/contract.zig");
const path_guard = @import("tools/path_guard.zig");

/// Discover and load AGENTS.md context files.
/// Searches global dir, then walks cwd upward to root.
/// Returns concatenated content with section headers.
pub fn load(alloc: std.mem.Allocator) !?[]u8 {
    if ((try loadPolicyLock(alloc)).context) return null;

    var parts = std.ArrayListUnmanaged([]u8){};
    defer {
        for (parts.items) |p| alloc.free(p);
        parts.deinit(alloc);
    }

    // Global: ~/.pz/AGENTS.md
    if (globalDir(alloc)) |gdir| {
        defer alloc.free(gdir);
        if (readContext(alloc, gdir)) |content| {
            try parts.append(alloc, content);
        }
    }

    // Walk cwd upward
    const cwd = realCwdAlloc(alloc) orelse return assembleParts(alloc, parts.items);
    defer alloc.free(cwd);

    var dir: []const u8 = cwd;
    while (true) {
        if (readContext(alloc, dir)) |content| {
            try parts.append(alloc, content);
        }
        if (parent(dir)) |p| {
            dir = p;
        } else break;
    }

    return assembleParts(alloc, parts.items);
}

fn assembleParts(alloc: std.mem.Allocator, parts: []const []u8) !?[]u8 {
    if (parts.len == 0) return null;

    var total: usize = 0;
    for (parts) |p| total += p.len + 2; // \n\n separator
    if (total >= 2) total -= 2; // no trailing separator

    const buf = try alloc.alloc(u8, total);
    var off: usize = 0;
    for (parts, 0..) |p, i| {
        if (i > 0) {
            buf[off] = '\n';
            buf[off + 1] = '\n';
            off += 2;
        }
        @memcpy(buf[off .. off + p.len], p);
        off += p.len;
    }
    return buf;
}

/// Returns list of discovered context file paths (for startup display).
pub fn discoverPaths(alloc: std.mem.Allocator) ![][]u8 {
    if ((try loadPolicyLock(alloc)).context) return try alloc.alloc([]u8, 0);

    var paths = std.ArrayListUnmanaged([]u8){};
    errdefer {
        for (paths.items) |p| alloc.free(p);
        paths.deinit(alloc);
    }

    if (globalDir(alloc)) |gdir| {
        defer alloc.free(gdir);
        if (findFile(alloc, gdir)) |p| try paths.append(alloc, p);
    }

    const cwd = realCwdAlloc(alloc) orelse return try paths.toOwnedSlice(alloc);
    defer alloc.free(cwd);

    var dir: []const u8 = cwd;
    while (true) {
        if (findFile(alloc, dir)) |p| try paths.append(alloc, p);
        if (parent(dir)) |par| {
            dir = par;
        } else break;
    }

    return try paths.toOwnedSlice(alloc);
}

fn findFile(alloc: std.mem.Allocator, dir: []const u8) ?[]u8 {
    if (!hasSecureFile(dir, "AGENTS.md")) return null;
    return std.fmt.allocPrint(alloc, "{s}/AGENTS.md", .{dir}) catch return null;
}

fn globalDir(alloc: std.mem.Allocator) ?[]u8 {
    const home = std.process.getEnvVarOwned(alloc, "HOME") catch return null;
    defer alloc.free(home);
    return std.fmt.allocPrint(alloc, "{s}/.pz", .{home}) catch return null;
}

fn readContext(alloc: std.mem.Allocator, dir: []const u8) ?[]u8 {
    return readFile(alloc, dir, "AGENTS.md");
}

fn loadPolicyLock(alloc: std.mem.Allocator) !policy.Lock {
    const cwd = realCwdAlloc(alloc) orelse return .{};
    defer alloc.free(cwd);
    const home = std.process.getEnvVarOwned(alloc, "HOME") catch null;
    defer if (home) |v| alloc.free(v);
    return policy.loadLock(alloc, cwd, home);
}

fn readFile(alloc: std.mem.Allocator, dir: []const u8, name: []const u8) ?[]u8 {
    const path = std.fmt.allocPrint(alloc, "{s}/{s}", .{ dir, name }) catch return null;
    defer alloc.free(path);

    var abs_dir = std.fs.openDirAbsolute(dir, .{ .no_follow = true }) catch return null;
    defer abs_dir.close();

    const file = path_guard.openFileInDir(abs_dir, name, .{ .mode = .read_only }) catch return null;
    defer file.close();

    const content = file.readToEndAlloc(alloc, 1024 * 1024) catch return null;
    if (content.len == 0) {
        alloc.free(content);
        return null;
    }

    const wrapped = prov_contract.wrapUntrustedNamed(alloc, "context-file", path, content) catch {
        alloc.free(content);
        return null;
    };
    defer alloc.free(wrapped);

    const header = std.fmt.allocPrint(alloc, "## {s}\n\n", .{path}) catch {
        alloc.free(content);
        return null;
    };
    defer alloc.free(header);

    const result = std.fmt.allocPrint(alloc, "{s}{s}", .{ header, wrapped }) catch {
        return null;
    };
    alloc.free(content);
    return result;
}

fn realCwdAlloc(alloc: std.mem.Allocator) ?[]u8 {
    return std.fs.cwd().realpathAlloc(alloc, ".") catch null;
}

fn hasSecureFile(dir: []const u8, name: []const u8) bool {
    var abs_dir = std.fs.openDirAbsolute(dir, .{ .no_follow = true }) catch return false;
    defer abs_dir.close();
    const file = path_guard.openFileInDir(abs_dir, name, .{ .mode = .read_only }) catch return false;
    file.close();
    return true;
}

fn parent(path: []const u8) ?[]const u8 {
    if (path.len <= 1) return null;
    const idx = std.mem.lastIndexOfScalar(u8, path, '/') orelse return null;
    if (idx == 0) return null;
    return path[0..idx];
}

test "parent extracts directory" {
    try std.testing.expectEqualStrings("/foo", parent("/foo/bar").?);
    try std.testing.expectEqualStrings("/foo/bar", parent("/foo/bar/baz").?);
    try std.testing.expect(parent("/") == null);
    try std.testing.expect(parent("/foo") == null);
}

test "assembleParts joins with newlines" {
    const parts = [_][]u8{
        @constCast("aaa"),
        @constCast("bbb"),
    };
    const result = (try assembleParts(std.testing.allocator, parts[0..])).?;
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("aaa\n\nbbb", result);
}

test "assembleParts empty returns null" {
    const result = try assembleParts(std.testing.allocator, &.{});
    try std.testing.expect(result == null);
}

test "readFile wraps context content as untrusted input" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "AGENTS.md",
        .data = "do not trust me",
    });
    const real = try tmp.dir.realpathAlloc(std.testing.allocator, "AGENTS.md");
    defer std.testing.allocator.free(real);
    const dir_path = std.fs.path.dirname(real) orelse return error.TestUnexpectedResult;

    const got = readFile(std.testing.allocator, dir_path, "AGENTS.md") orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    const want = try std.fmt.allocPrint(
        std.testing.allocator,
        "## {s}\n\n<untrusted-input kind=\"context-file\" name=\"{s}\">\ndo not trust me\n</untrusted-input>",
        .{ real, real },
    );
    defer std.testing.allocator.free(want);
    try std.testing.expectEqualStrings(want, got);
}

test "readFile rejects symlinked AGENTS leaf" {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var outer = std.testing.tmpDir(.{});
    defer outer.cleanup();

    try outer.dir.writeFile(.{ .sub_path = "secret.md", .data = "nope" });
    const outer_path = try outer.dir.realpathAlloc(std.testing.allocator, "secret.md");
    defer std.testing.allocator.free(outer_path);

    try tmp.dir.symLink(outer_path, "AGENTS.md", .{});
    const dir_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(dir_path);

    try std.testing.expect(readFile(std.testing.allocator, dir_path, "AGENTS.md") == null);
}

test "discoverPaths walks real cwd ancestry, not symlink aliases" {
    if (@import("builtin").os.tag == .windows or @import("builtin").os.tag == .wasi) return;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("real/sub");
    try tmp.dir.writeFile(.{ .sub_path = "real/AGENTS.md", .data = "ctx" });
    try tmp.dir.symLink("real", "alias", .{ .is_directory = true });

    const old = try std.process.getCwdAlloc(std.testing.allocator);
    defer std.testing.allocator.free(old);

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const alias_sub = try std.fs.path.join(std.testing.allocator, &.{ root, "alias/sub" });
    defer std.testing.allocator.free(alias_sub);
    try std.posix.chdir(alias_sub);
    defer std.posix.chdir(old) catch {};

    const paths = try discoverPaths(std.testing.allocator);
    defer {
        for (paths) |p| std.testing.allocator.free(p);
        std.testing.allocator.free(paths);
    }

    const want = try tmp.dir.realpathAlloc(std.testing.allocator, "real/AGENTS.md");
    defer std.testing.allocator.free(want);
    const alias = try std.fs.path.join(std.testing.allocator, &.{ root, "alias/AGENTS.md" });
    defer std.testing.allocator.free(alias);

    var saw_real = false;
    for (paths) |p| {
        if (std.mem.eql(u8, p, want)) saw_real = true;
        try std.testing.expect(!std.mem.eql(u8, p, alias));
    }
    try std.testing.expect(saw_real);
}

test "load returns null when policy locks context" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{ .sub_path = "AGENTS.md", .data = "ctx" });
    const seed = try @import("signing.zig").Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const kp = try @import("signing.zig").KeyPair.fromSeed(seed);
    const raw = try policy.encodeSignedDoc(std.testing.allocator, .{
        .rules = &.{},
        .lock = .{ .context = true },
    }, kp);
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = ".pz/policy.json", .data = raw });

    const old = try std.process.getCwdAlloc(std.testing.allocator);
    defer std.testing.allocator.free(old);
    const cwd = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd);
    try std.posix.chdir(cwd);
    defer std.posix.chdir(old) catch {};

    const got = try load(std.testing.allocator);
    defer if (got) |v| std.testing.allocator.free(v);
    try std.testing.expect(got == null);
}
