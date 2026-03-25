//! Filesystem-backed session store.
const std = @import("std");
const session = @import("../session.zig");
const writer = @import("writer.zig");
const reader = @import("reader.zig");

pub const Store = struct {
    session_store: session.SessionStore = .{ .vt = &session.SessionStore.Bind(@This(), @This().append, @This().replay, @This().deinitStore).vt },
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    wr: writer.Writer,
    replay_opts: reader.Opts,

    pub const Init = struct {
        alloc: std.mem.Allocator,
        dir: std.fs.Dir,
        flush: writer.FlushPolicy = .{ .always = {} },
        replay: reader.Opts = .{},
    };

    pub fn init(cfg: Init) !Store {
        const wr = try writer.Writer.init(cfg.alloc, cfg.dir, .{
            .flush = cfg.flush,
        });
        return .{
            .alloc = cfg.alloc,
            .dir = cfg.dir,
            .wr = wr,
            .replay_opts = cfg.replay,
        };
    }

    pub fn sessionStore(self: *Store) *session.SessionStore {
        return &self.session_store;
    }

    fn append(self: *Store, sid: []const u8, ev: session.Event) !void {
        try self.wr.append(sid, ev);
    }

    fn replay(self: *Store, sid: []const u8) !*session.Reader {
        const owned = try self.alloc.create(OwnedReplay);
        errdefer self.alloc.destroy(owned);

        owned.* = .{
            .alloc = self.alloc,
            .rdr = try reader.ReplayReader.init(self.alloc, self.dir, sid, self.replay_opts),
        };

        return &owned.reader;
    }

    fn deinitStore(self: *Store) void {
        self.deinit();
    }

    pub fn deinit(self: *Store) void {
        self.dir.close();
        self.* = undefined;
    }
};

const OwnedReplay = struct {
    reader: session.Reader = .{ .vt = &session.Reader.Bind(@This(), @This().next, @This().deinit).vt },
    alloc: std.mem.Allocator,
    rdr: reader.ReplayReader,

    fn next(self: *OwnedReplay) !?session.Event {
        return self.rdr.next();
    }

    fn deinit(self: *OwnedReplay) void {
        self.rdr.deinit();
        const alloc = self.alloc;
        alloc.destroy(self);
    }
};

test "fs store append and replay roundtrip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir = try tmp.dir.openDir(".", .{});
    var fs_store = try Store.init(.{
        .alloc = std.testing.allocator,
        .dir = dir,
    });
    defer fs_store.deinit();

    const store = fs_store.sessionStore();
    try store.append("s1", .{
        .at_ms = 10,
        .data = .{ .prompt = .{ .text = "hi" } },
    });
    try store.append("s1", .{
        .at_ms = 11,
        .data = .{ .text = .{ .text = "hello" } },
    });

    const rdr = try store.replay("s1");
    defer rdr.deinit();

    const ev0 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev0.data) {
        .prompt => |v| try std.testing.expectEqualStrings("hi", v.text),
        else => return error.TestUnexpectedResult,
    }

    const ev1 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev1.data) {
        .text => |v| try std.testing.expectEqualStrings("hello", v.text),
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect((try rdr.next()) == null);
}

test "fs store replay missing sid returns file-not-found error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const dir = try tmp.dir.openDir(".", .{});
    var fs_store = try Store.init(.{
        .alloc = std.testing.allocator,
        .dir = dir,
    });
    defer fs_store.deinit();

    const store = fs_store.sessionStore();
    try std.testing.expectError(error.FileNotFound, store.replay("missing"));
}
