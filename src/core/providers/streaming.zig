//! Streaming response reader with retry and chunk reassembly.
const std = @import("std");
const providers = @import("api.zig");
const retry = @import("retry.zig");
const stream_parse = @import("stream_parse.zig");
const types = @import("types.zig");

pub const Err = types.Err;

/// Retry policy instantiated for provider errors.
pub const Policy = retry.Policy(Err);

pub fn retryable(err: Err) bool {
    return types.retryable(err);
}

pub const RunResult = struct {
    arena: std.heap.ArenaAllocator,
    evs: []providers.Event,
    tries: u16,

    pub fn deinit(self: *RunResult) void {
        self.arena.deinit();
    }
};

pub fn run(
    comptime Tr: type,
    comptime Slp: type,
    alloc: std.mem.Allocator,
    tr: *Tr,
    req: providers.Request,
    pol: Policy,
    slp: ?*Slp,
) (retry.StepErr || Err)!RunResult {
    var tries: u16 = 0;
    while (true) {
        tries += 1;

        var arena = std.heap.ArenaAllocator.init(alloc);
        const ar = arena.allocator();
        const res = runOnce(Tr, ar, tr, req);
        if (res) |evs| {
            return .{
                .arena = arena,
                .evs = evs,
                .tries = tries,
            };
        } else |err| {
            arena.deinit();

            const step = try pol.next(err, tries);
            switch (step) {
                .retry_after_ms => |wait_ms| {
                    if (slp) |s| s.wait(wait_ms);
                },
                .fail => return err,
            }
        }
    }
}

/// ChunkIter: the return type of Tr.start(). Must have next() -> Err!?[]const u8 and deinit().
fn runOnce(comptime Tr: type, alloc: std.mem.Allocator, tr: *Tr, req: providers.Request) Err![]providers.Event {
    var stream = try tr.start(req);
    defer stream.deinit();

    var p = stream_parse.Parser{};
    defer p.deinit(alloc);

    var evs: std.ArrayListUnmanaged(providers.Event) = .{};
    errdefer evs.deinit(alloc);

    while (try stream.next()) |chunk| {
        try p.feed(alloc, &evs, chunk);
    }
    try p.finish(alloc, &evs);

    return evs.toOwnedSlice(alloc);
}

const Attempt = struct {
    start_err: ?Err = null,
    chunks: []const []const u8 = &.{},
    fail_after: ?usize = null,
    fail_err: Err = error.TransportTransient,
};

const MockChunk = struct {
    at: ?*const Attempt = null,
    idx: usize = 0,
    did_fail: bool = false,

    pub fn next(self: *MockChunk) Err!?[]const u8 {
        const at = self.at orelse return error.TransportFatal;

        if (!self.did_fail) {
            if (at.fail_after) |fail_after| {
                if (self.idx == fail_after) {
                    self.did_fail = true;
                    return at.fail_err;
                }
            }
        }

        if (self.idx >= at.chunks.len) return null;
        const out = at.chunks[self.idx];
        self.idx += 1;
        return out;
    }

    pub fn deinit(_: *MockChunk) void {}
};

const MockTr = struct {
    atts: []const Attempt,
    start_ct: usize = 0,
    stream: MockChunk = .{},

    fn init(atts: []const Attempt) MockTr {
        return .{
            .atts = atts,
        };
    }

    pub fn start(self: *MockTr, _: providers.Request) Err!MockChunk {
        if (self.start_ct >= self.atts.len) return error.TransportFatal;
        const idx = self.start_ct;
        self.start_ct += 1;

        const at = &self.atts[idx];
        if (at.start_err) |err| return err;

        self.stream = .{
            .at = at,
            .idx = 0,
            .did_fail = false,
        };
        return self.stream;
    }
};

const WaitLog = struct {
    waits: [8]u64 = [_]u64{0} ** 8,
    len: usize = 0,

    pub fn wait(self: *WaitLog, wait_ms: u64) void {
        self.waits[self.len] = wait_ms;
        self.len += 1;
    }
};

fn reqStub() providers.Request {
    return .{
        .model = "stub",
        .msgs = &.{},
    };
}

fn mkPol(max_tries: u16) !Policy {
    return Policy.init(.{
        .max_tries = max_tries,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 60,
            .mul = 2,
        },
        .retryable = retryable,
    });
}

test "stream run retries transient transport and parses frames" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{
            .start_err = error.TransportTransient,
        },
        .{
            .chunks = &.{
                "text:he",
                "llo\nusage:3,5,8\nstop:done\n",
            },
        },
    };

    var tr = MockTr.init(atts[0..]);
    var waits = WaitLog{};
    const pol = try mkPol(3);

    var out = try run(
        MockTr,
        WaitLog,
        std.testing.allocator,
        &tr,
        reqStub(),
        pol,
        &waits,
    );
    defer out.deinit();
    const txt = switch (out.evs[0]) {
        .text => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const usage = switch (out.evs[1]) {
        .usage => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const stop = switch (out.evs[2]) {
        .stop => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "tries={d}\nstarts={d}\nwaits={d}|{d}\nevs={d}\ntext={s}\nusage={d}|{d}|{d}\nstop={s}\n", .{
        out.tries,
        tr.start_ct,
        waits.len,
        waits.waits[0],
        out.evs.len,
        txt,
        usage.in_tok,
        usage.out_tok,
        usage.tot_tok,
        @tagName(stop.reason),
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "tries=2
        \\starts=2
        \\waits=1|10
        \\evs=3
        \\text=hello
        \\usage=3|5|8
        \\stop=done
        \\"
    ).expectEqual(snap);
}

test "stream run drops partial events from failed retry attempt" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{
            .chunks = &.{"text:bad\n"},
            .fail_after = 1,
            .fail_err = error.TransportTransient,
        },
        .{
            .chunks = &.{"text:ok\nstop:done\n"},
        },
    };

    var tr = MockTr.init(atts[0..]);
    var waits = WaitLog{};
    const pol = try mkPol(3);

    var out = try run(
        MockTr,
        WaitLog,
        std.testing.allocator,
        &tr,
        reqStub(),
        pol,
        &waits,
    );
    defer out.deinit();
    const txt = switch (out.evs[0]) {
        .text => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const stop = switch (out.evs[1]) {
        .stop => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "tries={d}\nevs={d}\nwaits={d}\ntext={s}\nstop={s}\n", .{
        out.tries,
        out.evs.len,
        waits.len,
        txt,
        @tagName(stop.reason),
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "tries=2
        \\evs=2
        \\waits=1
        \\text=ok
        \\stop=done
        \\"
    ).expectEqual(snap);
}

test "stream run does not retry parser failures" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{
            .chunks = &.{"bad\n"},
        },
    };

    var tr = MockTr.init(atts[0..]);
    var waits = WaitLog{};
    const pol = try mkPol(3);

    try std.testing.expectError(
        error.BadFrame,
        run(
            MockTr,
            WaitLog,
            std.testing.allocator,
            &tr,
            reqStub(),
            pol,
            &waits,
        ),
    );
    const snap = try std.fmt.allocPrint(std.testing.allocator, "starts={d}\nwaits={d}\n", .{
        tr.start_ct,
        waits.len,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "starts=1
        \\waits=0
        \\"
    ).expectEqual(snap);
}

test "stream run stops at max tries for transient failures" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{
            .start_err = error.TransportTransient,
        },
        .{
            .start_err = error.TransportTransient,
        },
    };

    var tr = MockTr.init(atts[0..]);
    var waits = WaitLog{};
    const pol = try mkPol(2);

    try std.testing.expectError(
        error.TransportTransient,
        run(
            MockTr,
            WaitLog,
            std.testing.allocator,
            &tr,
            reqStub(),
            pol,
            &waits,
        ),
    );
    const snap = try std.fmt.allocPrint(std.testing.allocator, "starts={d}\nwaits={d}|{d}\n", .{
        tr.start_ct,
        waits.len,
        waits.waits[0],
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "starts=2
        \\waits=1|10
        \\"
    ).expectEqual(snap);
}
