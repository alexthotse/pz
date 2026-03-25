//! No-op session store for --no-session mode.
const std = @import("std");
const session = @import("../session.zig");

pub const Store = struct {
    session_store: session.SessionStore = .{ .vt = &session.SessionStore.Bind(@This(), @This().append, @This().replay, @This().deinitStore).vt },

    pub fn init() Store {
        return .{};
    }

    pub fn sessionStore(self: *Store) *session.SessionStore {
        return &self.session_store;
    }

    fn append(_: *Store, _: []const u8, _: session.Event) !void {}

    fn replay(_: *Store, _: []const u8) !*session.Reader {
        return error.FileNotFound;
    }

    fn deinitStore(self: *Store) void {
        self.deinit();
    }

    pub fn deinit(_: *Store) void {}
};

test "null store append is no-op and replay behaves as missing session" {
    var store_impl = Store.init();
    const store = store_impl.sessionStore();

    try store.append("sid", .{
        .at_ms = 1,
        .data = .{ .prompt = .{ .text = "hi" } },
    });
    try std.testing.expectError(error.FileNotFound, store.replay("sid"));

    store.deinit();
}
