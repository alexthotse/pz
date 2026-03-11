const std = @import("std");
const testing = std.testing;

pub const Kind = enum {
    write,
    rename,
    delete,
};

pub const Ev = struct {
    kind: Kind,
    path: []const u8,
};

pub const Sink = struct {
    ctx: *anyopaque,
    vt: *const Vt,

    pub const Vt = struct {
        onEvent: *const fn (ctx: *anyopaque, ev: Ev) void,
    };

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime on_event: fn (ctx: *T, ev: Ev) void,
    ) Sink {
        const Wrap = struct {
            fn call(raw: *anyopaque, ev: Ev) void {
                const typed: *T = @ptrCast(@alignCast(raw));
                on_event(typed, ev);
            }

            const vt = Vt{
                .onEvent = call,
            };
        };

        return .{
            .ctx = ctx,
            .vt = &Wrap.vt,
        };
    }

    pub fn onEvent(self: Sink, ev: Ev) void {
        self.vt.onEvent(self.ctx, ev);
    }
};

pub const InitError = std.fs.Dir.StatFileError || error{
    EmptyPathSet,
    EmptyPath,
    InvalidPollMs,
    OutOfMemory,
};

pub const Watcher = struct {
    alloc: std.mem.Allocator,
    poll_ns: u64,
    debounce_ns: i128,
    paths: [][]u8,
    states: []State,

    const Self = @This();

    pub const Init = struct {
        paths: []const []const u8,
        poll_ms: u32 = 25,
        debounce_ms: u32 = 100,
    };

    const Snap = struct {
        exists: bool = false,
        size: u64 = 0,
        mtime: i128 = 0,
    };

    const State = struct {
        snap: Snap = .{},
        pending: ?Kind = null,
        dirty_at_ns: ?i128 = null,
    };

    pub fn init(alloc: std.mem.Allocator, cfg: Init) InitError!Self {
        if (cfg.paths.len == 0) return error.EmptyPathSet;
        if (cfg.poll_ms == 0) return error.InvalidPollMs;

        const paths = try alloc.alloc([]u8, cfg.paths.len);
        errdefer alloc.free(paths);

        const states = try alloc.alloc(State, cfg.paths.len);
        errdefer alloc.free(states);

        var i: usize = 0;
        errdefer {
            var n: usize = 0;
            while (n < i) : (n += 1) alloc.free(paths[n]);
        }

        while (i < cfg.paths.len) : (i += 1) {
            const raw = cfg.paths[i];
            if (raw.len == 0) return error.EmptyPath;
            paths[i] = try alloc.dupe(u8, raw);
            errdefer alloc.free(paths[i]);
            states[i] = .{
                .snap = try snapPath(paths[i]),
            };
        }

        return .{
            .alloc = alloc,
            .poll_ns = @as(u64, cfg.poll_ms) * std.time.ns_per_ms,
            .debounce_ns = @as(i128, cfg.debounce_ms) * std.time.ns_per_ms,
            .paths = paths,
            .states = states,
        };
    }

    pub fn watchLoop(self: *Self, stop: *const std.atomic.Value(bool), sink: Sink) !void {
        while (!stop.load(.acquire)) {
            const now = std.time.nanoTimestamp();
            var i: usize = 0;
            while (i < self.paths.len) : (i += 1) {
                try self.scanOne(i, now, sink);
            }
            std.Thread.sleep(self.poll_ns);
        }
    }

    pub fn deinit(self: *Self) void {
        for (self.paths) |path| self.alloc.free(path);
        self.alloc.free(self.paths);
        self.alloc.free(self.states);
        self.* = undefined;
    }

    fn scanOne(self: *Self, idx: usize, now: i128, sink: Sink) !void {
        const next = try snapPath(self.paths[idx]);
        var state = &self.states[idx];

        if (changeKind(state.snap, next)) |kind| {
            if (state.pending) |pending| {
                state.pending = mergeKind(pending, kind);
            } else {
                state.pending = kind;
                state.dirty_at_ns = now;
            }
        }
        state.snap = next;

        if (state.pending) |pending| {
            const dirty_at = state.dirty_at_ns orelse now;
            if (now - dirty_at >= self.debounce_ns) {
                sink.onEvent(.{
                    .kind = pending,
                    .path = self.paths[idx],
                });
                state.pending = null;
                state.dirty_at_ns = null;
            }
        }
    }
};

fn snapPath(path: []const u8) std.fs.Dir.StatFileError!Watcher.Snap {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    return .{
        .exists = true,
        .size = stat.size,
        .mtime = stat.mtime,
    };
}

fn changeKind(prev: Watcher.Snap, next: Watcher.Snap) ?Kind {
    if (prev.exists and !next.exists) return .delete;
    if (!prev.exists and next.exists) return .write;
    if (!prev.exists and !next.exists) return null;
    if (prev.size != next.size or prev.mtime != next.mtime) return .write;
    return null;
}

fn mergeKind(a: Kind, b: Kind) Kind {
    if (a == .delete or b == .delete) return .delete;
    if (a == .rename or b == .rename) return .rename;
    return .write;
}

const OhSnap = @import("ohsnap");

const EvSnap = struct {
    kind: Kind,
    base: []const u8,
};

const Recorder = struct {
    stop: *std.atomic.Value(bool),
    count: usize = 0,
    snap: ?EvSnap = null,

    fn onEvent(self: *Recorder, ev: Ev) void {
        self.count += 1;
        self.snap = .{
            .kind = ev.kind,
            .base = std.fs.path.basename(ev.path),
        };
        self.stop.store(true, .release);
    }
};

const WriteCtx = struct {
    dir: std.fs.Dir,
    sub_path: []const u8,
    data: []const u8,
    delay_ms: u64,
    ok: bool = true,

    fn run(self: *WriteCtx) void {
        std.Thread.sleep(self.delay_ms * std.time.ns_per_ms);
        self.dir.writeFile(.{
            .sub_path = self.sub_path,
            .data = self.data,
        }) catch {
            self.ok = false;
        };
    }
};

const DeleteCtx = struct {
    dir: std.fs.Dir,
    sub_path: []const u8,
    delay_ms: u64,
    ok: bool = true,

    fn run(self: *DeleteCtx) void {
        std.Thread.sleep(self.delay_ms * std.time.ns_per_ms);
        self.dir.deleteFile(self.sub_path) catch {
            self.ok = false;
        };
    }
};

const DeadlineCtx = struct {
    stop: *std.atomic.Value(bool),
    delay_ms: u64,

    fn run(self: *DeadlineCtx) void {
        var left = self.delay_ms;
        while (left > 0 and !self.stop.load(.acquire)) {
            const step: u64 = if (left < 5) left else 5;
            std.Thread.sleep(step * std.time.ns_per_ms);
            left -= step;
        }
        if (!self.stop.load(.acquire)) self.stop.store(true, .release);
    }
};

test "watcher init rejects empty path set" {
    try testing.expectError(error.EmptyPathSet, Watcher.init(testing.allocator, .{
        .paths = &.{},
    }));
}

test "watchLoop emits debounced write event" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "watched.txt",
        .data = "a",
    });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "watched.txt");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, .{
        .paths = &.{path},
        .poll_ms = 5,
        .debounce_ms = 20,
    });
    defer watcher.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var rec = Recorder{ .stop = &stop };
    var write_ctx = WriteCtx{
        .dir = tmp.dir,
        .sub_path = "watched.txt",
        .data = "b",
        .delay_ms = 40,
    };
    var deadline_ctx = DeadlineCtx{
        .stop = &stop,
        .delay_ms = 1000,
    };

    const writer = try std.Thread.spawn(.{}, WriteCtx.run, .{&write_ctx});
    const deadline = try std.Thread.spawn(.{}, DeadlineCtx.run, .{&deadline_ctx});
    defer writer.join();
    defer deadline.join();

    try watcher.watchLoop(&stop, Sink.from(Recorder, &rec, Recorder.onEvent));

    try testing.expect(write_ctx.ok);
    try testing.expectEqual(@as(usize, 1), rec.count);

    const oh = OhSnap{};
    const snap = rec.snap orelse return error.MissingEvent;
    try oh.snap(@src(),
        \\core.watcher.EvSnap
        \\  .kind: core.watcher.Kind
        \\    .write
        \\  .base: []const u8
        \\    "watched.txt"
    ).expectEqual(snap);
}

test "watchLoop emits delete event" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "watched.txt",
        .data = "a",
    });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "watched.txt");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, .{
        .paths = &.{path},
        .poll_ms = 5,
        .debounce_ms = 20,
    });
    defer watcher.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var rec = Recorder{ .stop = &stop };
    var delete_ctx = DeleteCtx{
        .dir = tmp.dir,
        .sub_path = "watched.txt",
        .delay_ms = 40,
    };
    var deadline_ctx = DeadlineCtx{
        .stop = &stop,
        .delay_ms = 1000,
    };

    const deleter = try std.Thread.spawn(.{}, DeleteCtx.run, .{&delete_ctx});
    const deadline = try std.Thread.spawn(.{}, DeadlineCtx.run, .{&deadline_ctx});
    defer deleter.join();
    defer deadline.join();

    try watcher.watchLoop(&stop, Sink.from(Recorder, &rec, Recorder.onEvent));

    try testing.expect(delete_ctx.ok);
    try testing.expectEqual(@as(usize, 1), rec.count);

    const oh = OhSnap{};
    const snap = rec.snap orelse return error.MissingEvent;
    try oh.snap(@src(),
        \\core.watcher.EvSnap
        \\  .kind: core.watcher.Kind
        \\    .delete
        \\  .base: []const u8
        \\    "watched.txt"
    ).expectEqual(snap);
}
