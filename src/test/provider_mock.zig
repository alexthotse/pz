//! Test mock: scripted provider with canned responses.
const std = @import("std");
const providers = @import("../core/providers.zig");

pub const Step = union(enum) {
    ev: providers.Event,
    block: void,
};

pub const ScriptedProvider = struct {
    provider: providers.Provider = .{ .vt = &provider_vt },
    stream: providers.Stream = .{ .vt = &StreamBind.vt },
    aborter: providers.Aborter = .{ .vt = &StreamBind.aborter_vt },
    steps: []const Step,
    idx: usize = 0,
    wake_r: std.posix.fd_t,
    wake_w: std.posix.fd_t,

    const provider_vt = providers.Provider.Vt{
        .start = providerStart,
    };

    const StreamBind = providers.Stream.BindAbortable(ScriptedProvider, streamNextImpl, streamDeinitImpl, streamAbortImpl);

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

    fn providerStart(p: *providers.Provider, _: providers.Request) !*providers.Stream {
        const self: *ScriptedProvider = @fieldParentPtr("provider", p);
        self.reset();
        return &self.stream;
    }

    fn streamNextImpl(self: *ScriptedProvider) anyerror!?providers.Event {
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
                _ = std.posix.read(self.wake_r, &buf) catch {}; // test: error irrelevant
                break :blk null;
            },
        };
    }

    pub fn streamAbortImpl(self: *ScriptedProvider) void {
        _ = std.posix.write(self.wake_w, "\x01") catch {}; // test: error irrelevant
    }

    fn streamDeinitImpl(_: *ScriptedProvider) void {}

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

    var stream = try provider.provider.start(.{
        .model = "m",
        .provider = null,
        .msgs = &.{},
        .tools = &.{},
        .opts = .{},
    });
    defer stream.deinit();

    const one = (try stream.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("hello", one.text);

    const thr = try std.Thread.spawn(.{}, ScriptedProvider.streamAbortImpl, .{&provider});
    defer thr.join();
    try std.testing.expect((try stream.next()) == null);
}
