//! Generic provider client: retry, streaming, transport.

const std = @import("std");
const providers = @import("api.zig");
const retry = @import("retry.zig");
const stream_parse = @import("stream_parse.zig");
const types = @import("types.zig");
const proc_wire = @import("proc_transport.zig");

pub const Err = types.Err;
pub const Policy = retry.Policy(Err);

/// Generic client parameterized by raw transport and error mapper types.
///
/// `RawTr` must have:
///   fn start(*RawTr, []const u8) anyerror!RawChunkIter
///   where RawChunkIter has fn next(*RawChunkIter) anyerror!?[]const u8 and fn deinit(*RawChunkIter).
///
/// `Map` must have:
///   fn map(*Map, anyerror) Err
pub fn Client(comptime RawTr: type, comptime Map: type, comptime Slp: type) type {
    // Resolve the raw chunk iterator type from RawTr.start return type.
    const RawChunkIter = RawChunkIterType(RawTr);

    return struct {
        alloc: std.mem.Allocator,
        tr: *RawTr,
        map: *Map,
        pol: Policy,
        slp: ?*Slp = null,

        const Self = @This();

        pub fn init(
            alloc: std.mem.Allocator,
            tr: *RawTr,
            map: *Map,
            pol: Policy,
        ) Self {
            return .{
                .alloc = alloc,
                .tr = tr,
                .map = map,
                .pol = pol,
            };
        }

        pub fn asProvider(self: *Self) providers.Provider {
            return providers.Provider.from(Self, self, Self.start);
        }

        fn start(self: *Self, req: providers.Request) anyerror!providers.Stream {
            const req_wire = try proc_wire.buildReq(self.alloc, req);
            defer self.alloc.free(req_wire);

            var run_tr = RunTr{
                .tr = self.tr,
                .map = self.map,
                .req_wire = req_wire,
            };

            const out = try streamRun(
                RunTr,
                Slp,
                self.alloc,
                &run_tr,
                req,
                self.pol,
                self.slp,
            );

            const st = try self.alloc.create(BufStream);
            st.* = .{
                .alloc = self.alloc,
                .out = out,
            };

            return providers.Stream.from(BufStream, st, BufStream.next, BufStream.deinit);
        }

        const ChunkCtx = struct {
            raw: RawChunkIter = undefined,
            has_raw: bool = false,
            map_ctx: *Map = undefined,

            pub fn next(self: *ChunkCtx) Err!?[]const u8 {
                if (!self.has_raw) return error.TransportFatal;
                return self.raw.next() catch |err| return self.map_ctx.map(err);
            }

            pub fn deinit(self: *ChunkCtx) void {
                if (self.has_raw) {
                    self.raw.deinit();
                    self.has_raw = false;
                }
            }
        };

        const RunTr = struct {
            tr: *RawTr,
            map: *Map,
            req_wire: []const u8,
            chunk: ChunkCtx = .{},

            pub fn start(self: *RunTr, _: providers.Request) Err!ChunkCtx {
                const raw = self.tr.start(self.req_wire) catch |err| return self.map.map(err);

                self.chunk = .{
                    .raw = raw,
                    .has_raw = true,
                    .map_ctx = self.map,
                };

                return self.chunk;
            }
        };

        const BufStream = struct {
            alloc: std.mem.Allocator,
            out: RunResult,
            idx: usize = 0,

            fn next(self: *BufStream) anyerror!?providers.Event {
                if (self.idx >= self.out.evs.len) return null;

                const ev = self.out.evs[self.idx];
                self.idx += 1;
                return ev;
            }

            fn deinit(self: *BufStream) void {
                self.out.deinit();
                self.alloc.destroy(self);
            }
        };
    };
}

/// A sleeper that does nothing — used as default when no real sleeper is needed.
pub const VoidSleeper = struct {
    pub fn wait(_: *VoidSleeper, _: u64) void {}
};

/// Extract the return type of RawTr.start (stripped of error union).
fn RawChunkIterType(comptime RawTr: type) type {
    const info = @typeInfo(@TypeOf(RawTr.start));
    const ReturnType = info.@"fn".return_type.?;
    // Unwrap error union to get the payload type
    return @typeInfo(ReturnType).error_union.payload;
}

// --- Streaming: retry loop with chunk reassembly (merged from streaming.zig) ---

const RunResult = struct {
    arena: std.heap.ArenaAllocator,
    evs: []providers.Event,
    tries: u16,

    pub fn deinit(self: *RunResult) void {
        self.arena.deinit();
    }
};

fn streamRun(
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
        const res = streamOnce(Tr, ar, tr, req);
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

fn streamOnce(comptime Tr: type, alloc: std.mem.Allocator, tr: *Tr, req: providers.Request) Err![]providers.Event {
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

// --- Tests ---

const RawErr = error{
    Timeout,
    Closed,
    WireBreak,
    BadGateway,
};

const MapCtx = struct {
    calls: usize = 0,

    pub fn map(self: *MapCtx, err: anyerror) Err {
        self.calls += 1;

        if (err == error.Timeout or err == error.WireBreak) return error.TransportTransient;
        if (err == error.Closed or err == error.BadGateway) return error.TransportFatal;
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return error.TransportFatal;
    }
};

const Attempt = struct {
    start_err: ?RawErr = null,
    chunks: []const []const u8 = &.{},
    fail_after: ?usize = null,
    fail_err: RawErr = error.WireBreak,
};

const MockRawChunk = struct {
    at: ?*const Attempt = null,
    idx: usize = 0,
    did_fail: bool = false,

    pub fn next(self: *MockRawChunk) RawErr!?[]const u8 {
        const at = self.at orelse return error.Closed;

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

    pub fn deinit(_: *MockRawChunk) void {}
};

const MockRawTr = struct {
    alloc: std.mem.Allocator,
    atts: []const Attempt,
    start_ct: usize = 0,
    stream: MockRawChunk = .{},
    reqs: std.ArrayListUnmanaged([]u8) = .{},

    fn init(alloc: std.mem.Allocator, atts: []const Attempt) MockRawTr {
        return .{
            .alloc = alloc,
            .atts = atts,
        };
    }

    fn deinit(self: *MockRawTr) void {
        for (self.reqs.items) |req_wire| {
            self.alloc.free(req_wire);
        }
        self.reqs.deinit(self.alloc);
    }

    pub fn start(self: *MockRawTr, req_wire: []const u8) anyerror!MockRawChunk {
        const req_copy = try self.alloc.dupe(u8, req_wire);
        try self.reqs.append(self.alloc, req_copy);

        if (self.start_ct >= self.atts.len) return error.Closed;
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

fn mkPol(max_tries: u16) !Policy {
    return Policy.init(.{
        .max_tries = max_tries,
        .backoff = .{
            .base_ms = 10,
            .max_ms = 60,
            .mul = 2,
        },
        .retryable = types.retryable,
    });
}

// --- streaming tests (merged from streaming.zig) ---

const StreamAttempt = struct {
    start_err: ?Err = null,
    chunks: []const []const u8 = &.{},
    fail_after: ?usize = null,
    fail_err: Err = error.TransportTransient,
};

const MockChunk = struct {
    at: ?*const StreamAttempt = null,
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
    atts: []const StreamAttempt,
    start_ct: usize = 0,
    stream: MockChunk = .{},

    fn init(atts: []const StreamAttempt) MockTr {
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

fn reqStub() providers.Request {
    return .{
        .model = "stub",
        .msgs = &.{},
    };
}

test "stream run retries transient transport and parses frames" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]StreamAttempt{
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

    var out = try streamRun(
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
    const atts = [_]StreamAttempt{
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

    var out = try streamRun(
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
    const atts = [_]StreamAttempt{
        .{
            .chunks = &.{"bad\n"},
        },
    };

    var tr = MockTr.init(atts[0..]);
    var waits = WaitLog{};
    const pol = try mkPol(3);

    try std.testing.expectError(
        error.BadFrame,
        streamRun(
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
    const atts = [_]StreamAttempt{
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
        streamRun(
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

// --- integration tests ---

test "first provider retries transient start and streams parsed events" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{ .start_err = error.Timeout },
        .{ .chunks = &.{"text:hello\nstop:done\n"} },
    };

    var tr = MockRawTr.init(std.testing.allocator, atts[0..]);
    defer tr.deinit();

    var waits = WaitLog{};
    const pol = try mkPol(3);

    var map_ctx = MapCtx{};
    const MockClient = Client(MockRawTr, MapCtx, WaitLog);
    var cli = MockClient.init(
        std.testing.allocator,
        &tr,
        &map_ctx,
        pol,
    );
    cli.slp = &waits;

    const req: providers.Request = .{
        .model = "first-model",
        .msgs = &.{},
    };

    var stream = try cli.asProvider().start(req);
    defer stream.deinit();

    const ev0 = (try stream.next()) orelse return error.TestUnexpectedResult;
    const ev1 = (try stream.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect((try stream.next()) == null);

    switch (ev0) {
        .text => |txt| try std.testing.expectEqualStrings("hello", txt),
        else => return error.TestUnexpectedResult,
    }
    switch (ev1) {
        .stop => |stop| try std.testing.expect(stop.reason == .done),
        else => return error.TestUnexpectedResult,
    }

    const snap = try std.fmt.allocPrint(std.testing.allocator, "starts={d}\nreqs={d}\nsame_req={any}\nreq0={s}\nwaits={d}|{d}\nmap_calls={d}\n", .{
        tr.start_ct,
        tr.reqs.items.len,
        std.mem.eql(u8, tr.reqs.items[0], tr.reqs.items[1]),
        tr.reqs.items[0],
        waits.len,
        waits.waits[0],
        map_ctx.calls,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "starts=2
        \\reqs=2
        \\same_req=true
        \\req0={"model":"first-model","msgs":[],"tools":[],"opts":{"stop":[]}}
        \\waits=1|10
        \\map_calls=1
        \\"
    ).expectEqual(snap);
}

test "first provider maps fatal transport errors without retry" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{ .start_err = error.BadGateway },
    };

    var tr = MockRawTr.init(std.testing.allocator, atts[0..]);
    defer tr.deinit();

    var waits = WaitLog{};
    const pol = try mkPol(3);

    var map_ctx = MapCtx{};
    const MockClient = Client(MockRawTr, MapCtx, WaitLog);
    var cli = MockClient.init(
        std.testing.allocator,
        &tr,
        &map_ctx,
        pol,
    );
    cli.slp = &waits;

    const req: providers.Request = .{
        .model = "m",
        .msgs = &.{},
    };

    try std.testing.expectError(error.TransportFatal, cli.asProvider().start(req));
    const snap = try std.fmt.allocPrint(std.testing.allocator, "starts={d}\nwaits={d}\nmap_calls={d}\n", .{
        tr.start_ct,
        waits.len,
        map_ctx.calls,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "starts=1
        \\waits=0
        \\map_calls=1
        \\"
    ).expectEqual(snap);
}

test "first provider retries on transient chunk read failures" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const atts = [_]Attempt{
        .{
            .chunks = &.{"text:bad\n"},
            .fail_after = 1,
            .fail_err = error.WireBreak,
        },
        .{
            .chunks = &.{"text:good\nstop:done\n"},
        },
    };

    var tr = MockRawTr.init(std.testing.allocator, atts[0..]);
    defer tr.deinit();

    var waits = WaitLog{};
    const pol = try mkPol(3);

    var map_ctx = MapCtx{};
    const MockClient = Client(MockRawTr, MapCtx, WaitLog);
    var cli = MockClient.init(
        std.testing.allocator,
        &tr,
        &map_ctx,
        pol,
    );
    cli.slp = &waits;

    const req: providers.Request = .{
        .model = "m",
        .msgs = &.{},
    };

    var stream = try cli.asProvider().start(req);
    defer stream.deinit();

    const ev0 = (try stream.next()) orelse return error.TestUnexpectedResult;
    const ev1 = (try stream.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expect((try stream.next()) == null);

    switch (ev0) {
        .text => |txt| try std.testing.expectEqualStrings("good", txt),
        else => return error.TestUnexpectedResult,
    }
    switch (ev1) {
        .stop => |stop| try std.testing.expect(stop.reason == .done),
        else => return error.TestUnexpectedResult,
    }

    const snap = try std.fmt.allocPrint(std.testing.allocator, "starts={d}\nwaits={d}|{d}\nmap_calls={d}\n", .{
        tr.start_ct,
        waits.len,
        waits.waits[0],
        map_ctx.calls,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "starts=2
        \\waits=1|10
        \\map_calls=1
        \\"
    ).expectEqual(snap);
}
