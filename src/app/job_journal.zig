//! Persistent job journal: track active background jobs across restarts.
const builtin = @import("builtin");
const std = @import("std");
const fs_secure = @import("../core/fs_secure.zig");

pub const Active = struct {
    id: u64,
    pid: i32,
    cmd: []u8,
    log_path: []u8,
    started_at_ms: i64,
};

pub fn deinitActives(alloc: std.mem.Allocator, actives: []Active) void {
    for (actives) |a| {
        alloc.free(a.cmd);
        alloc.free(a.log_path);
    }
    alloc.free(actives);
}

pub const Opts = struct {
    state_dir: ?[]const u8 = null,
    enabled: ?bool = null,
    home: ?[]const u8 = null,
    pz_state_dir: ?[]const u8 = null,
    xdg_state_home: ?[]const u8 = null,
};

pub const Journal = struct {
    alloc: std.mem.Allocator,
    dir_path: ?[]u8 = null,
    file_path: ?[]u8 = null,
    file: ?std.fs.File = null,
    mu: std.Thread.Mutex = .{},

    pub fn init(alloc: std.mem.Allocator, opts: Opts) !Journal {
        const enabled = opts.enabled orelse !builtin.is_test;
        if (!enabled and opts.state_dir == null) {
            return .{ .alloc = alloc };
        }

        const base_dir = if (opts.state_dir) |override|
            try alloc.dupe(u8, override)
        else
            try resolveStateDirOpts(alloc, opts);
        defer alloc.free(base_dir);

        try fs_secure.ensureDirPath(base_dir);

        const pz_dir = try std.fs.path.join(alloc, &.{ base_dir, "pz" });
        defer alloc.free(pz_dir);
        std.fs.makeDirAbsolute(pz_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const jobs_dir = try std.fs.path.join(alloc, &.{ pz_dir, "jobs" });
        errdefer alloc.free(jobs_dir);
        std.fs.makeDirAbsolute(jobs_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const events_path = try std.fs.path.join(alloc, &.{ jobs_dir, "events.jsonl" });
        errdefer alloc.free(events_path);

        const f = std.fs.createFileAbsolute(events_path, .{
            .read = true,
            .truncate = false,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => try std.fs.openFileAbsolute(events_path, .{ .mode = .read_write }),
            else => return err,
        };
        try f.seekFromEnd(0);

        return .{
            .alloc = alloc,
            .dir_path = jobs_dir,
            .file_path = events_path,
            .file = f,
        };
    }

    pub fn deinit(self: *Journal) void {
        if (self.file) |f| f.close();
        if (self.file_path) |p| self.alloc.free(p);
        if (self.dir_path) |p| self.alloc.free(p);
        self.* = undefined;
    }

    pub fn appendLaunch(
        self: *Journal,
        id: u64,
        pid: i32,
        cmd: []const u8,
        log_path: []const u8,
        started_at_ms: i64,
    ) !void {
        const line = .{
            .kind = "launch",
            .id = id,
            .pid = pid,
            .cmd = cmd,
            .log_path = log_path,
            .started_at_ms = started_at_ms,
        };
        return self.appendLine(line);
    }

    pub fn appendExit(
        self: *Journal,
        id: u64,
        state: []const u8,
        code: ?i32,
        ended_at_ms: i64,
        err_name: ?[]const u8,
    ) !void {
        const line = .{
            .kind = "exit",
            .id = id,
            .state = state,
            .code = code,
            .ended_at_ms = ended_at_ms,
            .err_name = err_name,
        };
        return self.appendLine(line);
    }

    pub fn appendCleanup(self: *Journal, id: u64, reason: []const u8) !void {
        const line = .{
            .kind = "cleanup",
            .id = id,
            .reason = reason,
        };
        return self.appendLine(line);
    }

    pub fn replayActive(self: *Journal, alloc: std.mem.Allocator) ![]Active {
        const path = self.file_path orelse return alloc.alloc(Active, 0);
        const f = std.fs.openFileAbsolute(path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return alloc.alloc(Active, 0),
            else => return err,
        };
        defer f.close();
        const raw = try f.readToEndAlloc(alloc, 8 * 1024 * 1024);
        defer alloc.free(raw);

        var out: std.ArrayListUnmanaged(Active) = .empty;
        errdefer {
            for (out.items) |a| {
                alloc.free(a.cmd);
                alloc.free(a.log_path);
            }
            out.deinit(alloc);
        }

        var it = std.mem.splitScalar(u8, raw, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            var arena = std.heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            const aa = arena.allocator();

            const parsed = std.json.parseFromSliceLeaky(Line, aa, line, .{
                .ignore_unknown_fields = true,
            }) catch continue;

            if (std.mem.eql(u8, parsed.kind, "launch")) {
                removeActive(alloc, &out, parsed.id);
                const cmd = try alloc.dupe(u8, parsed.cmd);
                errdefer alloc.free(cmd);
                const log_path = try alloc.dupe(u8, parsed.log_path);
                errdefer alloc.free(log_path);
                try out.append(alloc, .{
                    .id = parsed.id,
                    .pid = parsed.pid,
                    .cmd = cmd,
                    .log_path = log_path,
                    .started_at_ms = parsed.started_at_ms,
                });
                continue;
            }

            if (std.mem.eql(u8, parsed.kind, "exit") or std.mem.eql(u8, parsed.kind, "cleanup")) {
                removeActive(alloc, &out, parsed.id);
            }
        }

        return try out.toOwnedSlice(alloc);
    }

    fn appendLine(self: *Journal, line: anytype) !void {
        const f = self.file orelse return;
        const raw = try std.json.Stringify.valueAlloc(self.alloc, line, .{});
        defer self.alloc.free(raw);

        self.mu.lock();
        defer self.mu.unlock();

        try f.seekFromEnd(0);
        try f.writeAll(raw);
        try f.writeAll("\n");
        try f.sync();
    }
};

const Line = struct {
    kind: []const u8,
    id: u64,
    pid: i32 = 0,
    cmd: []const u8 = "",
    log_path: []const u8 = "",
    started_at_ms: i64 = 0,
};

fn removeActive(alloc: std.mem.Allocator, out: *std.ArrayListUnmanaged(Active), id: u64) void {
    var i: usize = 0;
    while (i < out.items.len) : (i += 1) {
        if (out.items[i].id != id) continue;
        const removed = out.orderedRemove(i);
        alloc.free(removed.cmd);
        alloc.free(removed.log_path);
        return;
    }
}

const StateEnv = struct {
    pz_state_dir: ?[]const u8 = null,
    xdg_state_home: ?[]const u8 = null,
    home: ?[]const u8 = null,
};

fn resolveStateDirOpts(alloc: std.mem.Allocator, opts: Opts) ![]u8 {
    return resolveStateDirEnv(alloc, .{
        .pz_state_dir = opts.pz_state_dir,
        .xdg_state_home = opts.xdg_state_home,
        .home = opts.home,
    });
}

fn resolveStateDirEnv(alloc: std.mem.Allocator, env: StateEnv) ![]u8 {
    if (env.pz_state_dir) |state_dir| {
        return alloc.dupe(u8, state_dir);
    }

    if (builtin.os.tag == .macos) {
        const home = env.home orelse return error.EnvironmentVariableNotFound;
        return std.fs.path.join(alloc, &.{ home, "Library", "Application Support" });
    }

    if (env.xdg_state_home) |xdg_state| {
        return alloc.dupe(u8, xdg_state);
    }

    const home = env.home orelse return error.EnvironmentVariableNotFound;
    return std.fs.path.join(alloc, &.{ home, ".local", "state" });
}

test "resolveStateDirEnv honors explicit override" {
    const got = try resolveStateDirEnv(std.testing.allocator, .{
        .pz_state_dir = "/tmp/pz-state",
        .xdg_state_home = "/tmp/xdg",
        .home = "/tmp/home",
    });
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("/tmp/pz-state", got);
}

test "resolveStateDirEnv is home-overrideable" {
    const got = try resolveStateDirEnv(std.testing.allocator, .{
        .home = "/tmp/home",
    });
    defer std.testing.allocator.free(got);
    if (builtin.os.tag == .macos) {
        try std.testing.expectEqualStrings("/tmp/home/Library/Application Support", got);
    } else {
        try std.testing.expectEqualStrings("/tmp/home/.local/state", got);
    }
}

test "journal replay tracks active launches only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        len: usize,
        id: u64,
        pid: i32,
        cmd: []const u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    var j = try Journal.init(std.testing.allocator, .{
        .state_dir = abs,
        .enabled = true,
    });
    defer j.deinit();

    try j.appendLaunch(1, 111, "sleep 10", "/tmp/j1.log", 10);
    try j.appendExit(1, "exited", 0, 20, null);
    try j.appendLaunch(2, 222, "sleep 20", "/tmp/j2.log", 30);

    const active = try j.replayActive(std.testing.allocator);
    defer deinitActives(std.testing.allocator, active);

    try oh.snap(@src(),
        \\app.job_journal.test.journal replay tracks active launches only.Snap
        \\  .len: usize = 1
        \\  .id: u64 = 2
        \\  .pid: i32 = 222
        \\  .cmd: []const u8
        \\    "sleep 20"
    ).expectEqual(Snap{
        .len = active.len,
        .id = active[0].id,
        .pid = active[0].pid,
        .cmd = active[0].cmd,
    });
}

test "journal cleanup removes active launch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    var j = try Journal.init(std.testing.allocator, .{
        .state_dir = abs,
        .enabled = true,
    });
    defer j.deinit();

    try j.appendLaunch(7, 777, "sleep 99", "/tmp/j7.log", 77);
    try j.appendCleanup(7, "startup_reap");

    const active = try j.replayActive(std.testing.allocator);
    defer deinitActives(std.testing.allocator, active);
    try std.testing.expectEqual(@as(usize, 0), active.len);
}

test "journal replay ignores malformed lines" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        len: usize,
        id: u64,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);

    var j = try Journal.init(std.testing.allocator, .{
        .state_dir = abs,
        .enabled = true,
    });
    defer j.deinit();

    const path = j.file_path orelse return error.TestUnexpectedResult;
    const f = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    defer f.close();
    try f.seekFromEnd(0);
    try f.writeAll("{bad-json}\n");
    try f.sync();

    try j.appendLaunch(11, 111, "sleep 1", "/tmp/j11.log", 11);

    const active = try j.replayActive(std.testing.allocator);
    defer deinitActives(std.testing.allocator, active);
    try oh.snap(@src(),
        \\app.job_journal.test.journal replay ignores malformed lines.Snap
        \\  .len: usize = 1
        \\  .id: u64 = 11
    ).expectEqual(Snap{
        .len = active.len,
        .id = active[0].id,
    });
}

test "journal init creates nested absolute state dirs" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        has_dir: bool,
        ends_with_jobs: bool,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(abs);
    const nested = try std.fs.path.join(std.testing.allocator, &.{ abs, "Library", "Application Support" });
    defer std.testing.allocator.free(nested);

    var j = try Journal.init(std.testing.allocator, .{
        .state_dir = nested,
        .enabled = true,
    });
    defer j.deinit();

    try oh.snap(@src(),
        \\app.job_journal.test.journal init creates nested absolute state dirs.Snap
        \\  .has_dir: bool = true
        \\  .ends_with_jobs: bool = true
    ).expectEqual(Snap{
        .has_dir = j.dir_path != null,
        .ends_with_jobs = j.dir_path != null and std.mem.endsWith(u8, j.dir_path.?, "/pz/jobs"),
    });
}
