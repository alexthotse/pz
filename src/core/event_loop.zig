//! Platform-native event loop: kqueue (macOS/BSD) or epoll (Linux).
const std = @import("std");
const posix = std.posix;

const native_os = @import("builtin").os.tag;
const is_kqueue = native_os.isDarwin() or native_os == .freebsd or native_os == .netbsd or native_os == .openbsd;
const is_epoll = native_os == .linux;

comptime {
    if (!is_kqueue and !is_epoll) @compileError("unsupported OS: need kqueue or epoll");
}

pub const Interest = enum { read, write };

pub const Event = struct {
    fd: posix.fd_t,
    readable: bool,
    writable: bool,
};

/// Max events returned per wait call.
pub const max_events = 64;

pub const EventLoop = struct {
    backend: posix.fd_t,
    wake_r: posix.fd_t,
    wake_w: posix.fd_t,

    pub fn init() !EventLoop {
        const pipe = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
        errdefer {
            posix.close(pipe[0]);
            posix.close(pipe[1]);
        }
        const fd = try backendCreate();
        errdefer posix.close(fd);
        var self = EventLoop{
            .backend = fd,
            .wake_r = pipe[0],
            .wake_w = pipe[1],
        };
        try self.registerFd(pipe[0], .read);
        return self;
    }

    pub fn deinit(self: *EventLoop) void {
        posix.close(self.backend);
        posix.close(self.wake_r);
        posix.close(self.wake_w);
        self.* = undefined;
    }

    pub fn register(self: *EventLoop, fd: posix.fd_t, interest: Interest) !void {
        try self.registerFd(fd, interest);
    }

    pub fn unregister(self: *EventLoop, fd: posix.fd_t) !void {
        try self.unregisterFd(fd);
    }

    /// Block until fds are ready or timeout expires. Returns ready events.
    /// `timeout_ms`: -1 for infinite, 0 for poll, >0 for ms.
    /// Caller must use returned slice before next call to wait.
    pub fn wait(self: *EventLoop, timeout_ms: i32, buf: *[max_events]Event) ![]Event {
        var n: usize = 0;
        if (is_kqueue) {
            var kev: [max_events]std.posix.Kevent = undefined;
            const ts: ?*const std.posix.timespec = if (timeout_ms >= 0) &.{
                .sec = @divTrunc(timeout_ms, 1000),
                .nsec = @rem(timeout_ms, 1000) * 1_000_000,
            } else null;
            const count = try kqueueWait(self.backend, &kev, ts);
            for (kev[0..count]) |ev| {
                const fd: posix.fd_t = @intCast(ev.ident);
                if (fd == self.wake_r) {
                    drain(self.wake_r);
                    continue;
                }
                buf[n] = .{
                    .fd = fd,
                    .readable = ev.filter == std.posix.system.EVFILT.READ,
                    .writable = ev.filter == std.posix.system.EVFILT.WRITE,
                };
                n += 1;
            }
        } else {
            var epev: [max_events]std.os.linux.epoll_event = undefined;
            const count = try epollWait(self.backend, &epev, timeout_ms);
            for (epev[0..count]) |ev| {
                const fd = ev.data.fd;
                if (fd == self.wake_r) {
                    drain(self.wake_r);
                    continue;
                }
                buf[n] = .{
                    .fd = fd,
                    .readable = (ev.events & std.os.linux.EPOLL.IN) != 0,
                    .writable = (ev.events & std.os.linux.EPOLL.OUT) != 0,
                };
                n += 1;
            }
        }
        return buf[0..n];
    }

    /// Interrupt a blocking wait() from another thread or signal handler.
    pub fn wake(self: *EventLoop) void {
        _ = posix.write(self.wake_w, "\x01") catch return;
    }

    // -- platform impl --

    fn registerFd(self: *EventLoop, fd: posix.fd_t, interest: Interest) !void {
        if (is_kqueue) {
            const filter: i16 = switch (interest) {
                .read => std.posix.system.EVFILT.READ,
                .write => std.posix.system.EVFILT.WRITE,
            };
            const changelist = [1]std.posix.Kevent{.{
                .ident = @intCast(fd),
                .filter = filter,
                .flags = std.posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = try kqueueWaitChanges(self.backend, &changelist, &.{}, null);
        } else {
            const events: u32 = switch (interest) {
                .read => std.os.linux.EPOLL.IN,
                .write => std.os.linux.EPOLL.OUT,
            };
            var ev = std.os.linux.epoll_event{
                .events = events,
                .data = .{ .fd = fd },
            };
            const rc = std.os.linux.epoll_ctl(@intCast(self.backend), std.os.linux.EPOLL.CTL_ADD, @intCast(fd), &ev);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {},
                .BADF => return error.BadFd,
                .EXIST => return error.AlreadyRegistered,
                .INVAL => return error.InvalidArg,
                .NOMEM => return error.OutOfMemory,
                else => return error.Unexpected,
            }
        }
    }

    fn unregisterFd(self: *EventLoop, fd: posix.fd_t) !void {
        if (is_kqueue) {
            // Remove both read and write filters; ignore ENOENT for the one not registered.
            inline for ([_]i16{ std.posix.system.EVFILT.READ, std.posix.system.EVFILT.WRITE }) |filter| {
                const changelist = [1]std.posix.Kevent{.{
                    .ident = @intCast(fd),
                    .filter = filter,
                    .flags = std.posix.system.EV.DELETE,
                    .fflags = 0,
                    .data = 0,
                    .udata = 0,
                }};
                _ = kqueueWaitChanges(self.backend, &changelist, &.{}, null) catch {};
            }
        } else {
            const rc = std.os.linux.epoll_ctl(@intCast(self.backend), std.os.linux.EPOLL.CTL_DEL, @intCast(fd), null);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {},
                .BADF => return error.BadFd,
                .NOENT => return error.NotRegistered,
                .INVAL => return error.InvalidArg,
                else => return error.Unexpected,
            }
        }
    }
};

fn backendCreate() !posix.fd_t {
    if (is_kqueue) {
        return try posix.kqueue();
    } else {
        const rc = std.os.linux.epoll_create1(std.os.linux.EPOLL.CLOEXEC);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .MFILE, .NFILE => return error.ProcessFdQuotaExceeded,
            .NOMEM => return error.OutOfMemory,
            else => return error.Unexpected,
        }
    }
}

fn kqueueWait(kq: posix.fd_t, events: []std.posix.Kevent, ts: ?*const std.posix.timespec) !usize {
    return kqueueWaitChanges(kq, &.{}, events, ts);
}

fn kqueueWaitChanges(kq: posix.fd_t, changelist: []const std.posix.Kevent, events: []std.posix.Kevent, ts: ?*const std.posix.timespec) !usize {
    while (true) {
        const rc = posix.system.kevent(
            kq,
            changelist.ptr,
            @intCast(changelist.len),
            events.ptr,
            @intCast(events.len),
            ts,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .BADF => return error.BadFd,
            .INVAL => return error.InvalidArg,
            else => |e| return posix.unexpectedErrno(e),
        }
    }
}

fn epollWait(epfd: posix.fd_t, events: []std.os.linux.epoll_event, timeout_ms: i32) !usize {
    while (true) {
        const rc = std.os.linux.epoll_wait(@intCast(epfd), events.ptr, @intCast(events.len), timeout_ms);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .BADF => return error.BadFd,
            .INVAL => return error.InvalidArg,
            else => |e| return posix.unexpectedErrno(e),
        }
    }
}

fn drain(fd: posix.fd_t) void {
    var buf: [64]u8 = undefined;
    while (true) {
        _ = posix.read(fd, &buf) catch return;
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

test "register pipe, write, wait returns ready" {
    var el = try EventLoop.init();
    defer el.deinit();

    // Create a pipe to monitor.
    const pipe = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    try el.register(pipe[0], .read);

    // Write to pipe so read end becomes ready.
    _ = try posix.write(pipe[1], "x");

    var buf: [max_events]Event = undefined;
    const events = try el.wait(1000, &buf);
    try std.testing.expect(events.len >= 1);
    try std.testing.expectEqual(pipe[0], events[0].fd);
    try std.testing.expect(events[0].readable);
}

test "wait times out with no events" {
    var el = try EventLoop.init();
    defer el.deinit();

    var buf: [max_events]Event = undefined;
    const events = try el.wait(0, &buf);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "wake interrupts blocking wait" {
    var el = try EventLoop.init();
    defer el.deinit();

    // Spawn thread that wakes after short delay.
    const t = try std.Thread.spawn(.{}, struct {
        fn run(loop: *EventLoop) void {
            std.Thread.sleep(10 * std.time.ns_per_ms);
            loop.wake();
        }
    }.run, .{&el});

    var buf: [max_events]Event = undefined;
    // Should return quickly (wake consumed internally), no user events.
    const events = try el.wait(5000, &buf);
    try std.testing.expectEqual(@as(usize, 0), events.len);
    t.join();
}

test "unregister removes fd" {
    var el = try EventLoop.init();
    defer el.deinit();

    const pipe = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(pipe[0]);
    defer posix.close(pipe[1]);

    try el.register(pipe[0], .read);
    try el.unregister(pipe[0]);

    // Write to pipe — should NOT appear in events since unregistered.
    _ = try posix.write(pipe[1], "y");

    var buf: [max_events]Event = undefined;
    const events = try el.wait(0, &buf);
    try std.testing.expectEqual(@as(usize, 0), events.len);
}

test "multiple fds" {
    var el = try EventLoop.init();
    defer el.deinit();

    const p1 = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p1[0]);
    defer posix.close(p1[1]);
    const p2 = try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
    defer posix.close(p2[0]);
    defer posix.close(p2[1]);

    try el.register(p1[0], .read);
    try el.register(p2[0], .read);

    _ = try posix.write(p1[1], "a");
    _ = try posix.write(p2[1], "b");

    var buf: [max_events]Event = undefined;
    const events = try el.wait(1000, &buf);
    try std.testing.expectEqual(@as(usize, 2), events.len);

    // Both fds should be present (order not guaranteed).
    var saw_p1 = false;
    var saw_p2 = false;
    for (events) |ev| {
        if (ev.fd == p1[0]) saw_p1 = true;
        if (ev.fd == p2[0]) saw_p2 = true;
    }
    try std.testing.expect(saw_p1);
    try std.testing.expect(saw_p2);
}
