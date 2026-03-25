//! Mode interface: type-erased run context and dispatch.
const std = @import("std");
const core = @import("../core.zig");

pub const Ctx = struct {
    alloc: std.mem.Allocator,
    provider: *core.providers.Provider,
    store: *core.session.SessionStore,
    sid: []const u8,
    prompt: []const u8,
    model: []const u8 = "default",
};

pub fn Mode(comptime T: type, comptime run_fn: fn (ctx: *T, run_ctx: Ctx) anyerror!void) type {
    return struct {
        ctx: *T,

        const Self = @This();

        pub fn init(ctx: *T) Self {
            return .{ .ctx = ctx };
        }

        pub fn run(self: Self, run_ctx: Ctx) !void {
            return run_fn(self.ctx, run_ctx);
        }
    };
}
