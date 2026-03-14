//! Generic provider client: retry, streaming, transport.

const std = @import("std");
const providers = @import("api.zig");
const retry = @import("retry.zig");
const streaming = @import("streaming.zig");
const types = @import("types.zig");

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
            const req_wire = try buildReq(self.alloc, req);
            defer self.alloc.free(req_wire);

            var run_tr = RunTr{
                .tr = self.tr,
                .map = self.map,
                .req_wire = req_wire,
            };

            const out = try streaming.run(
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
            out: streaming.RunResult,
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

pub fn buildReq(alloc: std.mem.Allocator, req: providers.Request) Err![]u8 {
    var out: std.io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    var js: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };

    writeReq(&js, req) catch return error.OutOfMemory;

    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn writeReq(js: *std.json.Stringify, req: providers.Request) anyerror!void {
    try js.beginObject();

    try js.objectField("model");
    try js.write(req.model);

    if (req.provider) |provider| {
        try js.objectField("provider");
        try js.write(provider);
    }

    try js.objectField("msgs");
    try js.beginArray();
    for (req.msgs) |msg| {
        try js.beginObject();

        try js.objectField("role");
        try js.write(@tagName(msg.role));

        try js.objectField("parts");
        try js.beginArray();
        for (msg.parts) |part| {
            try writePart(js, part);
        }
        try js.endArray();

        try js.endObject();
    }
    try js.endArray();

    try js.objectField("tools");
    try js.beginArray();
    for (req.tools) |tool| {
        try js.beginObject();
        try js.objectField("name");
        try js.write(tool.name);
        try js.objectField("desc");
        try js.write(tool.desc);
        try js.objectField("schema");
        try js.write(tool.schema);
        try js.endObject();
    }
    try js.endArray();

    try js.objectField("opts");
    try js.beginObject();

    if (req.opts.temp) |temp| {
        try js.objectField("temp");
        try js.write(temp);
    }
    if (req.opts.top_p) |top_p| {
        try js.objectField("top_p");
        try js.write(top_p);
    }
    if (req.opts.max_out) |max_out| {
        try js.objectField("max_out");
        try js.write(max_out);
    }

    try js.objectField("stop");
    try js.beginArray();
    for (req.opts.stop) |stop_tok| {
        try js.write(stop_tok);
    }
    try js.endArray();

    try js.endObject();

    try js.endObject();
}

fn writePart(js: *std.json.Stringify, part: providers.Part) anyerror!void {
    try js.beginObject();

    switch (part) {
        .text => |txt| {
            try js.objectField("type");
            try js.write("text");
            try js.objectField("text");
            try js.write(txt);
        },
        .tool_call => |tc| {
            try js.objectField("type");
            try js.write("tool_call");
            try js.objectField("id");
            try js.write(tc.id);
            try js.objectField("name");
            try js.write(tc.name);
            try js.objectField("args");
            try js.write(tc.args);
        },
        .tool_result => |tr| {
            try js.objectField("type");
            try js.write("tool_result");
            try js.objectField("id");
            try js.write(tr.id);
            try js.objectField("out");
            try js.write(tr.output);
            try js.objectField("is_err");
            try js.write(tr.is_err);
        },
    }

    try js.endObject();
}

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

fn expectString(v: std.json.Value, want: []const u8) !void {
    switch (v) {
        .string => |got| try std.testing.expectEqualStrings(want, got),
        else => return error.TestUnexpectedResult,
    }
}

fn expectInt(v: std.json.Value, want: i64) !void {
    switch (v) {
        .integer => |got| try std.testing.expectEqual(want, got),
        else => return error.TestUnexpectedResult,
    }
}

fn expectFloat(v: std.json.Value, want: f64) !void {
    switch (v) {
        .float => |got| try std.testing.expectApproxEqAbs(want, got, 0.0001),
        .integer => |got| try std.testing.expectApproxEqAbs(want, @as(f64, @floatFromInt(got)), 0.0001),
        else => return error.TestUnexpectedResult,
    }
}

fn expectSnap(comptime src: std.builtin.SourceLocation, got: []u8, comptime want: []const u8) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    try oh.snap(src, want).expectEqual(got);
}

test "buildReq emits request fixture JSON" {
    const user_parts = [_]providers.Part{
        .{ .text = "hello" },
        .{ .tool_call = .{ .id = "c1", .name = "read", .args = "{\"path\":\"/tmp\"}" } },
    };
    const tool_parts = [_]providers.Part{
        .{ .tool_result = .{ .id = "c1", .output = "ok", .is_err = false } },
    };
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = user_parts[0..] },
        .{ .role = .tool, .parts = tool_parts[0..] },
    };
    const tools = [_]providers.Tool{
        .{ .name = "read", .desc = "Read file", .schema = "{}" },
    };
    const stops = [_][]const u8{ "DONE", "ERR" };

    const req: providers.Request = .{
        .model = "first-model",
        .msgs = msgs[0..],
        .tools = tools[0..],
        .opts = .{
            .temp = 0.25,
            .top_p = 0.9,
            .max_out = 128,
            .stop = stops[0..],
        },
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"first-model","msgs":[{"role":"user","parts":[{"type":"text","text":"hello"},{"type":"tool_call","id":"c1","name":"read","args":"{\"path\":\"/tmp\"}"}]},{"role":"tool","parts":[{"type":"tool_result","id":"c1","out":"ok","is_err":false}]}],"tools":[{"name":"read","desc":"Read file","schema":"{}"}],"opts":{"temp":0.25,"top_p":0.8999999761581421,"max_out":128,"stop":["DONE","ERR"]}}"
    );
}

test "buildReq includes provider field when set" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const req: providers.Request = .{
        .model = "m1",
        .provider = "anthropic",
        .msgs = msgs[0..],
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"m1","provider":"anthropic","msgs":[{"role":"user","parts":[{"type":"text","text":"hi"}]}],"tools":[],"opts":{"stop":[]}}"
    );
}

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
