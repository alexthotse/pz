const std = @import("std");
const providers = @import("../core/providers.zig");

pub const Step = union(enum) {
    ev: providers.Ev,
    block: void,
};

pub const ScriptedProvider = struct {
    steps: []const Step,
    idx: usize = 0,
    wake_r: std.posix.fd_t,
    wake_w: std.posix.fd_t,

    pub fn init(steps: []const Step) !ScriptedProvider {
        const pipe = try std.posix.pipe2(.{
            .CLOEXEC = true,
            .NONBLOCK = true,
        });
        return .{
            .steps = steps,
            .wake_r = pipe[0],
            .wake_w = pipe[1],
        };
    }

    pub fn deinit(self: *ScriptedProvider) void {
        std.posix.close(self.wake_r);
        std.posix.close(self.wake_w);
        self.* = undefined;
    }

    pub fn asProvider(self: *ScriptedProvider) providers.Provider {
        return providers.Provider.from(
            ScriptedProvider,
            self,
            ScriptedProvider.start,
        );
    }

    fn start(self: *ScriptedProvider, _: providers.Req) !providers.Stream {
        self.reset();
        return providers.Stream.fromAbortable(
            ScriptedProvider,
            self,
            ScriptedProvider.next,
            ScriptedProvider.streamDeinit,
            ScriptedProvider.abort,
        );
    }

    fn next(self: *ScriptedProvider) !?providers.Ev {
        if (self.idx >= self.steps.len) return null;
        const step = self.steps[self.idx];
        self.idx += 1;
        return switch (step) {
            .ev => |ev| ev,
            .block => blk: {
                var fds = [1]std.posix.pollfd{.{
                    .fd = self.wake_r,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                }};
                _ = try std.posix.poll(&fds, -1);
                var buf: [8]u8 = undefined;
                _ = std.posix.read(self.wake_r, &buf) catch {};
                break :blk null;
            },
        };
    }

    fn abort(self: *ScriptedProvider) void {
        _ = std.posix.write(self.wake_w, "\x01") catch {};
    }

    fn streamDeinit(_: *ScriptedProvider) void {}

    fn reset(self: *ScriptedProvider) void {
        self.idx = 0;
        var buf: [32]u8 = undefined;
        while (true) {
            _ = std.posix.read(self.wake_r, &buf) catch break;
        }
    }
};

test "scripted provider emits events then aborts blocked stream" {
    const steps = [_]Step{
        .{ .ev = .{ .text = "hello" } },
        .{ .block = {} },
    };
    var provider = try ScriptedProvider.init(steps[0..]);
    defer provider.deinit();

    var stream = try provider.start(.{
        .model = "m",
        .provider = null,
        .msgs = &.{},
        .tools = &.{},
        .opts = .{},
    });
    defer stream.deinit();

    const one = (try stream.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello", one.text);

    const thr = try std.Thread.spawn(.{}, ScriptedProvider.abort, .{&provider});
    defer thr.join();
    try std.testing.expect((try stream.next()) == null);
}
