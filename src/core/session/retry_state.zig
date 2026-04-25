//! Persisted retry state: survive restarts across transient failures.
const std = @import("std");
const sid_path = @import("path.zig");
const fs_secure = @import("../fs_secure.zig");

pub const version_current: u16 = 1;

pub const ErrKind = enum {
    none,
    transient,
    fatal,
    parse,
    tool,
    internal,
};

pub const State = struct {
    version: u16 = version_current,
    tries_done: u16 = 0,
    fail_count: u16 = 0,
    next_wait_ms: u64 = 0,
    last_err: ErrKind = .none,
};

pub fn save(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    state: State,
) !void {
    var out = state;
    out.version = version_current;
    if (out.fail_count > out.tries_done) return error.InvalidRetryState;

    const path = try sid_path.sidExtAlloc(alloc, sid, ".retry.json");
    defer alloc.free(path);

    const raw = try std.json.Stringify.valueAlloc(alloc, out, .{});
    defer alloc.free(raw);

    var file = try fs_secure.createFileAt(dir, path, .{
        .truncate = true,
    });
    defer file.close();
    try file.writeAll(raw);
    try file.writeAll("\n");
    try file.sync();
}

pub fn load(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
) !?State {
    const path = try sid_path.sidExtAlloc(alloc, sid, ".retry.json");
    defer alloc.free(path);

    const raw = dir.readFileAlloc(alloc, path, 64 * 1024) catch |read_err| switch (read_err) {
        error.FileNotFound => return null,
        else => return read_err,
    };
    defer alloc.free(raw);
    if (raw.len == 0 or raw[raw.len - 1] != '\n') return error.TornRetryState;

    const parsed = try std.json.parseFromSlice(State, alloc, raw, .{
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    if (parsed.value.version != version_current) return error.UnsupportedRetryStateVersion;
    if (parsed.value.fail_count > parsed.value.tries_done) return error.InvalidRetryState;

    return parsed.value;
}

test "retry state persists and restores counters after reload" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const in = State{
        .tries_done = 4,
        .fail_count = 3,
        .next_wait_ms = 250,
        .last_err = .transient,
    };
    try save(std.testing.allocator, tmp.dir, "s1", in);

    const out = (try load(std.testing.allocator, tmp.dir, "s1")) orelse {
        return error.TestUnexpectedResult;
    };
    try oh.snap(@src(),
        \\core.session.retry_state.State
        \\  .version: u16 = 1
        \\  .tries_done: u16 = 4
        \\  .fail_count: u16 = 3
        \\  .next_wait_ms: u64 = 250
        \\  .last_err: core.session.retry_state.ErrKind = .transient
    ).expectEqual(out);
    if (@import("builtin").os.tag != .windows) {
        const st = try tmp.dir.statFile("s1.retry.json");
        try std.testing.expectEqual(@as(std.fs.File.Mode, fs_secure.file_mode), st.mode & 0o777);
    }
}

test "retry state load returns null when file is absent" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try std.testing.expect((try load(std.testing.allocator, tmp.dir, "missing")) == null);
}

test "retry state rejects invalid counters" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try std.testing.expectError(error.InvalidRetryState, save(
        std.testing.allocator,
        tmp.dir,
        "s1",
        .{
            .tries_done = 1,
            .fail_count = 2,
        },
    ));
}

test "retry state rejects torn file without trailing newline" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "s1.retry.json",
        .data = "{\"version\":1,\"tries_done\":1,\"fail_count\":1,\"next_wait_ms\":0,\"last_err\":\"none\"}",
    });

    try std.testing.expectError(error.TornRetryState, load(std.testing.allocator, tmp.dir, "s1"));
}
