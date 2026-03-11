const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;
const is_macos = builtin.os.tag == .macos;

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
} || if (is_macos) std.posix.KQueueError || std.posix.OpenError || std.posix.KEventError else error{};

const Backend = if (is_macos) struct {
    kq: std.posix.fd_t,
    fds: []?std.posix.fd_t,

    const vnode_filter: i16 = -4;
    const ev_add: u16 = 0x0001;
    const ev_enable: u16 = 0x0004;
    const ev_clear: u16 = 0x0020;
    const ev_error: u16 = 0x4000;

    const note_delete: u32 = 0x00000001;
    const note_write: u32 = 0x00000002;
    const note_extend: u32 = 0x00000004;
    const note_attrib: u32 = 0x00000008;
    const note_rename: u32 = 0x00000020;
    const note_revoke: u32 = 0x00000040;
    const watch_mask = note_delete | note_write | note_extend | note_attrib | note_rename | note_revoke;
    const close_mask = note_delete | note_rename | note_revoke;

    fn init(alloc: std.mem.Allocator, len: usize) InitError!@This() {
        const fds = try alloc.alloc(?std.posix.fd_t, len);
        errdefer alloc.free(fds);
        @memset(fds, null);

        const kq = try std.posix.kqueue();
        errdefer std.posix.close(kq);

        return .{
            .kq = kq,
            .fds = fds,
        };
    }

    fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        for (self.fds) |fd| {
            if (fd) |live| std.posix.close(live);
        }
        alloc.free(self.fds);
        std.posix.close(self.kq);
        self.* = undefined;
    }

    fn ensurePath(self: *@This(), idx: usize, path: []const u8) (std.posix.OpenError || std.posix.KEventError)!bool {
        if (self.fds[idx] != null) return true;

        const fd = std.posix.open(path, .{
            .ACCMODE = .RDONLY,
            .EVTONLY = true,
            .CLOEXEC = true,
        }, 0) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        errdefer std.posix.close(fd);

        var out: [0]std.posix.Kevent = .{};
        const change = [_]std.posix.Kevent{.{
            .ident = @intCast(fd),
            .filter = vnode_filter,
            .flags = ev_add | ev_enable | ev_clear,
            .fflags = watch_mask,
            .data = 0,
            .udata = idx + 1,
        }};
        _ = try std.posix.kevent(self.kq, change[0..], out[0..], null);
        self.fds[idx] = fd;
        return true;
    }

    fn drop(self: *@This(), idx: usize) void {
        if (self.fds[idx]) |fd| {
            std.posix.close(fd);
            self.fds[idx] = null;
        }
    }
} else struct {};

pub const Watcher = struct {
    alloc: std.mem.Allocator,
    poll_ns: u64,
    quiet_ns: i128,
    max_ns: i128,
    paths: [][]u8,
    states: []State,
    backend: Backend,

    const Self = @This();

    pub const Init = struct {
        paths: []const []const u8,
        poll_ms: u32 = 25,
        quiet_ms: u32 = 100,
        max_ms: u32 = 1000,
    };

    const Snap = struct {
        exists: bool = false,
        size: u64 = 0,
        mtime: i128 = 0,
    };

    const State = struct {
        snap: Snap = .{},
        pending: ?Kind = null,
        first_dirty_at_ns: ?i128 = null,
        last_dirty_at_ns: ?i128 = null,
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

        var backend: Backend = if (is_macos) try Backend.init(alloc, cfg.paths.len) else .{};
        errdefer if (is_macos) backend.deinit(alloc);

        while (i < cfg.paths.len) : (i += 1) {
            const raw = cfg.paths[i];
            if (raw.len == 0) return error.EmptyPath;
            paths[i] = try alloc.dupe(u8, raw);
            errdefer alloc.free(paths[i]);
            states[i] = .{
                .snap = try snapPath(paths[i]),
            };
            if (is_macos and states[i].snap.exists) {
                const opened = try backend.ensurePath(i, paths[i]);
                if (!opened) states[i].snap = .{};
            }
        }

        return .{
            .alloc = alloc,
            .poll_ns = @as(u64, cfg.poll_ms) * std.time.ns_per_ms,
            .quiet_ns = @as(i128, cfg.quiet_ms) * std.time.ns_per_ms,
            .max_ns = @as(i128, cfg.max_ms) * std.time.ns_per_ms,
            .paths = paths,
            .states = states,
            .backend = backend,
        };
    }

    pub fn watchLoop(self: *Self, stop: *const std.atomic.Value(bool), sink: Sink) !void {
        if (is_macos) return self.watchLoopKqueue(stop, sink);

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
        if (is_macos) self.backend.deinit(self.alloc);
        for (self.paths) |path| self.alloc.free(path);
        self.alloc.free(self.paths);
        self.alloc.free(self.states);
        self.* = undefined;
    }

    fn scanOne(self: *Self, idx: usize, now: i128, sink: Sink) !void {
        const next = try snapPath(self.paths[idx]);
        if (changeKind(self.states[idx].snap, next)) |kind| self.queueKind(idx, now, kind);
        self.states[idx].snap = next;
        self.flushOne(idx, now, sink);
    }

    fn watchLoopKqueue(self: *Self, stop: *const std.atomic.Value(bool), sink: Sink) !void {
        var events: [16]std.posix.Kevent = undefined;
        const changes = [_]std.posix.Kevent{};

        while (!stop.load(.acquire)) {
            const pre_wait = std.time.nanoTimestamp();

            var i: usize = 0;
            while (i < self.paths.len) : (i += 1) {
                try self.refreshMacPath(i, pre_wait);
                self.flushOne(i, pre_wait, sink);
            }

            var timeout = nsToTimespec(self.poll_ns);
            const count = try std.posix.kevent(self.backend.kq, changes[0..], events[0..], &timeout);
            const now = std.time.nanoTimestamp();

            var n: usize = 0;
            while (n < count) : (n += 1) {
                try self.handleMacEvent(events[n], now);
            }

            i = 0;
            while (i < self.paths.len) : (i += 1) self.flushOne(i, now, sink);
        }
    }

    fn refreshMacPath(self: *Self, idx: usize, now: i128) !void {
        if (self.backend.fds[idx] != null) return;

        const next = try snapPath(self.paths[idx]);
        if (changeKind(self.states[idx].snap, next)) |kind| self.queueKind(idx, now, kind);
        self.states[idx].snap = next;
        if (!next.exists) return;

        const opened = try self.backend.ensurePath(idx, self.paths[idx]);
        if (!opened) self.states[idx].snap = .{};
    }

    fn handleMacEvent(self: *Self, ev: std.posix.Kevent, now: i128) !void {
        if (ev.udata == 0 or ev.udata > self.paths.len) return;
        const idx = ev.udata - 1;

        if ((ev.flags & Backend.ev_error) != 0) {
            self.backend.drop(idx);
            self.states[idx].snap = try snapPath(self.paths[idx]);
            return;
        }

        if (vnodeKind(ev.fflags)) |kind| self.queueKind(idx, now, kind);
        if ((ev.fflags & Backend.close_mask) != 0) self.backend.drop(idx);

        self.states[idx].snap = try snapPath(self.paths[idx]);
        if (!self.states[idx].snap.exists) self.backend.drop(idx);
    }

    fn queueKind(self: *Self, idx: usize, now: i128, kind: Kind) void {
        var state = &self.states[idx];
        if (state.pending) |pending| {
            state.pending = mergeKind(pending, kind);
            state.last_dirty_at_ns = now;
            return;
        }
        state.pending = kind;
        state.first_dirty_at_ns = now;
        state.last_dirty_at_ns = now;
    }

    fn flushOne(self: *Self, idx: usize, now: i128, sink: Sink) void {
        var state = &self.states[idx];
        if (state.pending) |pending| {
            const first_dirty_at = state.first_dirty_at_ns orelse now;
            const last_dirty_at = state.last_dirty_at_ns orelse first_dirty_at;
            const quiet_ok = now - last_dirty_at >= self.quiet_ns;
            const max_ok = now - first_dirty_at >= self.max_ns;
            if (!quiet_ok and !max_ok) return;
            sink.onEvent(.{
                .kind = pending,
                .path = self.paths[idx],
            });
            state.pending = null;
            state.first_dirty_at_ns = null;
            state.last_dirty_at_ns = null;
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

fn vnodeKind(fflags: u32) ?Kind {
    if (!is_macos) return null;
    if ((fflags & (Backend.note_delete | Backend.note_revoke)) != 0) return .delete;
    if ((fflags & Backend.note_rename) != 0) return .rename;
    if ((fflags & (Backend.note_write | Backend.note_extend | Backend.note_attrib)) != 0) return .write;
    return null;
}

fn nsToTimespec(ns: u64) std.posix.timespec {
    return .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
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

const BurstWriteCtx = struct {
    dir: std.fs.Dir,
    sub_path: []const u8,
    start_ms: u64,
    step_ms: u64,
    count: usize,
    ok: bool = true,

    fn run(self: *BurstWriteCtx) void {
        std.Thread.sleep(self.start_ms * std.time.ns_per_ms);
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            var buf: [32]u8 = undefined;
            const data = std.fmt.bufPrint(buf[0..], "storm-{d}", .{i}) catch {
                self.ok = false;
                return;
            };
            self.dir.writeFile(.{
                .sub_path = self.sub_path,
                .data = data,
            }) catch {
                self.ok = false;
                return;
            };
            if (i + 1 < self.count) std.Thread.sleep(self.step_ms * std.time.ns_per_ms);
        }
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

const RenameCtx = struct {
    dir: std.fs.Dir,
    from: []const u8,
    to: []const u8,
    delay_ms: u64,
    ok: bool = true,

    fn run(self: *RenameCtx) void {
        std.Thread.sleep(self.delay_ms * std.time.ns_per_ms);
        self.dir.rename(self.from, self.to) catch {
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
        .quiet_ms = 20,
        .max_ms = 100,
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

test "watchLoop flushes write storm after max window" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "watched.txt",
        .data = "seed",
    });
    const path = try tmp.dir.realpathAlloc(testing.allocator, "watched.txt");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, .{
        .paths = &.{path},
        .poll_ms = 5,
        .quiet_ms = 100,
        .max_ms = 180,
    });
    defer watcher.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var rec = Recorder{ .stop = &stop };
    var burst_ctx = BurstWriteCtx{
        .dir = tmp.dir,
        .sub_path = "watched.txt",
        .start_ms = 20,
        .step_ms = 40,
        .count = 6,
    };
    var deadline_ctx = DeadlineCtx{
        .stop = &stop,
        .delay_ms = 1000,
    };

    const writer = try std.Thread.spawn(.{}, BurstWriteCtx.run, .{&burst_ctx});
    const deadline = try std.Thread.spawn(.{}, DeadlineCtx.run, .{&deadline_ctx});
    defer writer.join();
    defer deadline.join();

    try watcher.watchLoop(&stop, Sink.from(Recorder, &rec, Recorder.onEvent));

    try testing.expect(burst_ctx.ok);
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
        .quiet_ms = 20,
        .max_ms = 100,
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

test "watchLoop emits write event when missing path appears" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir_path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(dir_path);
    const path = try std.fs.path.join(testing.allocator, &.{ dir_path, "late.txt" });
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, .{
        .paths = &.{path},
        .poll_ms = 5,
        .quiet_ms = 20,
        .max_ms = 100,
    });
    defer watcher.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var rec = Recorder{ .stop = &stop };
    var write_ctx = WriteCtx{
        .dir = tmp.dir,
        .sub_path = "late.txt",
        .data = "x",
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
        \\    "late.txt"
    ).expectEqual(snap);
}

test "watchLoop emits rename event on macOS" {
    if (!is_macos) return error.SkipZigTest;

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
        .quiet_ms = 20,
        .max_ms = 100,
    });
    defer watcher.deinit();

    var stop = std.atomic.Value(bool).init(false);
    var rec = Recorder{ .stop = &stop };
    var rename_ctx = RenameCtx{
        .dir = tmp.dir,
        .from = "watched.txt",
        .to = "moved.txt",
        .delay_ms = 40,
    };
    var deadline_ctx = DeadlineCtx{
        .stop = &stop,
        .delay_ms = 1000,
    };

    const renamer = try std.Thread.spawn(.{}, RenameCtx.run, .{&rename_ctx});
    const deadline = try std.Thread.spawn(.{}, DeadlineCtx.run, .{&deadline_ctx});
    defer renamer.join();
    defer deadline.join();

    try watcher.watchLoop(&stop, Sink.from(Recorder, &rec, Recorder.onEvent));

    try testing.expect(rename_ctx.ok);
    try testing.expectEqual(@as(usize, 1), rec.count);

    const oh = OhSnap{};
    const snap = rec.snap orelse return error.MissingEvent;
    try oh.snap(@src(),
        \\core.watcher.EvSnap
        \\  .kind: core.watcher.Kind
        \\    .rename
        \\  .base: []const u8
        \\    "watched.txt"
    ).expectEqual(snap);
}
