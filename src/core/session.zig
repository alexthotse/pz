//! Session layer: JSONL persistence, replay, compaction, export.
const std = @import("std");
const schema = @import("session/schema.zig");
pub const writer = @import("session/writer.zig");
pub const reader = @import("session/reader.zig");
pub const fs_store = @import("session/fs_store.zig");
pub const null_store = @import("session/null_store.zig");
pub const selector = @import("session/selector.zig");
pub const path = @import("session/path.zig");
pub const compact = @import("session/compact.zig");
pub const summary = @import("session/summary.zig");
pub const @"export" = @import("session/export.zig");
pub const retry_state = @import("session/retry_state.zig");
pub const regress = @import("session/regress.zig");
pub const golden = @import("session/golden.zig");
pub const session_file = @import("session/session_file.zig");

pub const File = session_file.File;
pub const cleanOrphanTmpFiles = session_file.cleanOrphanTmpFiles;

pub const Event = schema.Event;
pub const event_version = schema.version_current;
pub const encodeEventAlloc = schema.encodeAlloc;
pub const decodeEventSlice = schema.decodeSlice;
pub const Writer = writer.Writer;
pub const FlushPolicy = writer.FlushPolicy;
pub const ReplayReader = reader.ReplayReader;
pub const ReplayOpts = reader.Opts;
pub const FsStore = fs_store.Store;
pub const NullStore = null_store.Store;
pub const CompactCheckpoint = compact.Checkpoint;
pub const compactSession = compact.run;
pub const loadCompactCheckpoint = compact.loadCheckpoint;
pub const GeneratedSummary = compact.GeneratedSummary;
pub const generateSummary = compact.generateSummary;
pub const freeGeneratedSummary = compact.freeGeneratedSummary;
pub const exportMarkdown = @"export".toMarkdown;
pub const RetryState = retry_state.State;
pub const saveRetryState = retry_state.save;
pub const loadRetryState = retry_state.load;

pub const Reader = struct {
    vt: *const Vt,

    pub const Vt = struct {
        next: *const fn (self: *Reader) anyerror!?Event,
        deinit: *const fn (self: *Reader) void,
    };

    pub fn next(self: *Reader) !?Event {
        return self.vt.next(self);
    }

    pub fn deinit(self: *Reader) void {
        self.vt.deinit(self);
    }

    pub fn Bind(
        comptime T: type,
        comptime next_fn: fn (*T) anyerror!?Event,
        comptime deinit_fn: fn (*T) void,
    ) type {
        return struct {
            pub const vt = Vt{
                .next = nextFn,
                .deinit = deinitFn,
            };
            fn nextFn(r: *Reader) anyerror!?Event {
                const self: *T = @fieldParentPtr("reader", r);
                return next_fn(self);
            }
            fn deinitFn(r: *Reader) void {
                const self: *T = @fieldParentPtr("reader", r);
                deinit_fn(self);
            }
        };
    }
};

pub const SessionStore = struct {
    vt: *const Vt,

    pub const Vt = struct {
        append: *const fn (self: *SessionStore, sid: []const u8, ev: Event) anyerror!void,
        replay: *const fn (self: *SessionStore, sid: []const u8) anyerror!*Reader,
        deinit: *const fn (self: *SessionStore) void,
    };

    pub fn append(self: *SessionStore, sid: []const u8, ev: Event) !void {
        return self.vt.append(self, sid, ev);
    }

    pub fn replay(self: *SessionStore, sid: []const u8) !*Reader {
        return self.vt.replay(self, sid);
    }

    pub fn deinit(self: *SessionStore) void {
        self.vt.deinit(self);
    }

    pub fn Bind(
        comptime T: type,
        comptime append_fn: fn (*T, []const u8, Event) anyerror!void,
        comptime replay_fn: fn (*T, []const u8) anyerror!*Reader,
        comptime deinit_fn: fn (*T) void,
    ) type {
        return struct {
            pub const vt = Vt{
                .append = appendFn,
                .replay = replayFn,
                .deinit = deinitFn,
            };
            fn appendFn(ss: *SessionStore, sid: []const u8, ev: Event) anyerror!void {
                const self: *T = @fieldParentPtr("session_store", ss);
                return append_fn(self, sid, ev);
            }
            fn replayFn(ss: *SessionStore, sid: []const u8) anyerror!*Reader {
                const self: *T = @fieldParentPtr("session_store", ss);
                return replay_fn(self, sid);
            }
            fn deinitFn(ss: *SessionStore) void {
                const self: *T = @fieldParentPtr("session_store", ss);
                deinit_fn(self);
            }
        };
    }
};

pub const Store = SessionStore;

test "session store contract dispatches through vtable" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        first: bool,
        second_null: bool,
        append_ct: usize,
        replay_ct: usize,
        sid_len: usize,
        deinit_ct: usize,
    };
    const ReaderImpl = struct {
        reader: Reader = .{ .vt = &Reader.Bind(@This(), @This().next, @This().deinit).vt },
        left: u8 = 0,

        fn next(self: *@This()) !?Event {
            if (self.left == 0) return null;
            self.left -= 1;
            return .{};
        }

        fn deinit(_: *@This()) void {}
    };

    const StoreImpl = struct {
        session_store: SessionStore = .{ .vt = &SessionStore.Bind(@This(), @This().append, @This().replay, @This().deinit).vt },
        append_ct: usize = 0,
        replay_ct: usize = 0,
        deinit_ct: usize = 0,
        sid_len: usize = 0,
        rdr: ReaderImpl = .{},

        fn append(self: *@This(), sid: []const u8, _: Event) !void {
            self.append_ct += 1;
            self.sid_len = sid.len;
        }

        fn replay(self: *@This(), sid: []const u8) !*Reader {
            self.replay_ct += 1;
            self.sid_len = sid.len;
            self.rdr.left = 1;
            return &self.rdr.reader;
        }

        fn deinit(self: *@This()) void {
            self.deinit_ct += 1;
        }
    };

    var impl = StoreImpl{};
    var store = &impl.session_store;

    try store.append("abc", .{});
    const rdr = try store.replay("abc");
    defer rdr.deinit();

    const first = (try rdr.next()) != null;
    const second_null = (try rdr.next()) == null;
    store.deinit();
    try oh.snap(@src(),
        \\core.session.test.session store contract dispatches through vtable.Snap
        \\  .first: bool = true
        \\  .second_null: bool = true
        \\  .append_ct: usize = 1
        \\  .replay_ct: usize = 1
        \\  .sid_len: usize = 3
        \\  .deinit_ct: usize = 1
    ).expectEqual(Snap{
        .first = first,
        .second_null = second_null,
        .append_ct = impl.append_ct,
        .replay_ct = impl.replay_ct,
        .sid_len = impl.sid_len,
        .deinit_ct = impl.deinit_ct,
    });
}
