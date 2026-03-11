const std = @import("std");
const registry = @import("registry.zig");

pub fn bind(
    comptime Kind: type,
    comptime Spec: type,
    comptime Call: type,
    comptime Event: type,
    comptime Result: type,
) type {
    comptime validateTypes(Call, Event, Result);

    const reg = registry.bind(Kind, Spec, Call, Event, Result);

    return struct {
        pub const Err = reg.Err;
        pub const Sink = reg.Sink;
        pub const Dispatch = reg.Dispatch;
        pub const Entry = reg.Entry;

        pub const Registry = struct {
            entries: []const Entry,
            inner: reg.Registry,

            pub fn init(entries: []const Entry) Registry {
                return .{
                    .entries = entries,
                    .inner = reg.Registry.init(entries),
                };
            }

            pub fn byName(self: Registry, name: []const u8) ?*const Entry {
                return self.inner.byName(name);
            }

            pub fn byKind(self: Registry, kind: Kind) ?*const Entry {
                return self.inner.byKind(kind);
            }

            pub fn run(
                self: Registry,
                name: []const u8,
                call: Call,
                sink: Sink,
            ) (Err || anyerror)!Result {
                const ent = self.byName(name) orelse return Err.NotFound;
                if (call.kind != ent.kind) return Err.KindMismatch;

                try sink.push(.{
                    .start = .{
                        .call = call,
                        .at_ms = call.at_ms,
                    },
                });

                const res = try ent.dispatch.run(call, sink);

                for (res.out) |out| {
                    try sink.push(.{ .output = out });
                }

                try sink.push(.{ .finish = res });
                return res;
            }
        };
    };
}

fn validateTypes(comptime Call: type, comptime Event: type, comptime Result: type) void {
    if (!@hasField(Call, "at_ms")) {
        @compileError("runtime call type must define `at_ms`");
    }
    if (@FieldType(Call, "at_ms") != i64) {
        @compileError("runtime call.at_ms must be i64");
    }

    if (!@hasField(Result, "out")) {
        @compileError("runtime result type must define `out`");
    }

    const out_ty = @FieldType(Result, "out");
    const out_info = @typeInfo(out_ty);
    if (out_info != .pointer or out_info.pointer.size != .slice) {
        @compileError("runtime result.out must be a slice");
    }
    const Out = out_info.pointer.child;

    if (!@hasField(Event, "start")) {
        @compileError("runtime event type must define `start`");
    }
    if (!@hasField(Event, "output")) {
        @compileError("runtime event type must define `output`");
    }
    if (!@hasField(Event, "finish")) {
        @compileError("runtime event type must define `finish`");
    }

    const Start = @FieldType(Event, "start");
    if (!@hasField(Start, "call")) {
        @compileError("runtime start event must define `call`");
    }
    if (@FieldType(Start, "call") != Call) {
        @compileError("runtime start.call must match call type");
    }
    if (!@hasField(Start, "at_ms")) {
        @compileError("runtime start event must define `at_ms`");
    }
    if (@FieldType(Start, "at_ms") != i64) {
        @compileError("runtime start.at_ms must be i64");
    }

    if (@FieldType(Event, "output") != Out) {
        @compileError("runtime output event must match result.out element type");
    }
    if (@FieldType(Event, "finish") != Result) {
        @compileError("runtime finish event must match result type");
    }
}

const TKind = enum {
    alpha,
    beta,
};

const TSpec = struct {};

const TCall = struct {
    id: []const u8,
    kind: TKind,
    at_ms: i64,
    value: i32,
};

const TOut = struct {
    seq: u32,
    chunk: []const u8,
};

const TResult = struct {
    out: []const TOut,
    code: i32,
};

const TEv = union(enum) {
    start: Start,
    output: TOut,
    finish: TResult,

    const Start = struct {
        call: TCall,
        at_ms: i64,
    };
};

const TRt = bind(TKind, TSpec, TCall, TEv, TResult);

test "runtime emits start output finish in order" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkImpl = struct {
        start_seen: bool = false,
        evs: [8]TEv = undefined,
        ct: usize = 0,

        fn push(self: *@This(), ev: TEv) !void {
            if (self.ct >= self.evs.len) return error.OutOfMemory;
            if (ev == .start) self.start_seen = true;
            self.evs[self.ct] = ev;
            self.ct += 1;
        }
    };

    const DispatchImpl = struct {
        start_seen: *bool,
        out: []const TOut,
        ct: usize = 0,

        fn run(self: *@This(), call: TCall, _: TRt.Sink) !TResult {
            self.ct += 1;
            if (!self.start_seen.*) return error.StartNotSeen;
            return .{
                .out = self.out,
                .code = call.value + 5,
            };
        }
    };

    var sink_impl = SinkImpl{};
    const sink = TRt.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const out = [_]TOut{
        .{
            .seq = 0,
            .chunk = "x",
        },
        .{
            .seq = 1,
            .chunk = "y",
        },
    };

    var dispatch_impl = DispatchImpl{
        .start_seen = &sink_impl.start_seen,
        .out = out[0..],
    };

    const entries = [_]TRt.Entry{
        .{
            .name = "beta",
            .kind = .beta,
            .spec = .{},
            .dispatch = TRt.Dispatch.from(DispatchImpl, &dispatch_impl, DispatchImpl.run),
        },
    };
    const reg = TRt.Registry.init(entries[0..]);

    const call: TCall = .{
        .id = "c1",
        .kind = .beta,
        .at_ms = 77,
        .value = 2,
    };

    const res = try reg.run("beta", call, sink);
    const start = switch (sink_impl.evs[0]) {
        .start => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const out0 = switch (sink_impl.evs[1]) {
        .output => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const out1 = switch (sink_impl.evs[2]) {
        .output => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const fin = switch (sink_impl.evs[3]) {
        .finish => |ev| ev,
        else => return error.TestUnexpectedResult,
    };
    const snap = try std.fmt.allocPrint(std.testing.allocator, "ct={d}\nstart={d}|{s}|{s}|{d}\nout0={d}|{s}\nout1={d}|{s}\nfinish={d}|{d}\ndispatch={d}\nres={d}|{d}\n", .{
        sink_impl.ct,
        start.at_ms,
        start.call.id,
        @tagName(start.call.kind),
        start.call.at_ms,
        out0.seq,
        out0.chunk,
        out1.seq,
        out1.chunk,
        fin.out.len,
        fin.code,
        dispatch_impl.ct,
        res.out.len,
        res.code,
    });
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "ct=4
        \\start=77|c1|beta|77
        \\out0=0|x
        \\out1=1|y
        \\finish=2|7
        \\dispatch=1
        \\res=2|7
        \\"
    ).expectEqual(snap);
}

test "runtime emits start and finish when handler has no output" {
    const SinkImpl = struct {
        evs: [4]TEv = undefined,
        ct: usize = 0,

        fn push(self: *@This(), ev: TEv) !void {
            if (self.ct >= self.evs.len) return error.OutOfMemory;
            self.evs[self.ct] = ev;
            self.ct += 1;
        }
    };

    const DispatchImpl = struct {
        fn run(_: *@This(), _: TCall, _: TRt.Sink) !TResult {
            return .{
                .out = &.{},
                .code = 0,
            };
        }
    };

    var sink_impl = SinkImpl{};
    const sink = TRt.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    var dispatch_impl = DispatchImpl{};
    const entries = [_]TRt.Entry{
        .{
            .name = "alpha",
            .kind = .alpha,
            .spec = .{},
            .dispatch = TRt.Dispatch.from(DispatchImpl, &dispatch_impl, DispatchImpl.run),
        },
    };
    const reg = TRt.Registry.init(entries[0..]);

    _ = try reg.run("alpha", .{
        .id = "c2",
        .kind = .alpha,
        .at_ms = 11,
        .value = 0,
    }, sink);

    try std.testing.expectEqual(@as(usize, 2), sink_impl.ct);
    try std.testing.expect(sink_impl.evs[0] == .start);
    try std.testing.expect(sink_impl.evs[1] == .finish);
}

test "runtime preserves handler error type and does not emit finish" {
    const SinkImpl = struct {
        start_seen: bool = false,
        evs: [4]TEv = undefined,
        ct: usize = 0,

        fn push(self: *@This(), ev: TEv) !void {
            if (self.ct >= self.evs.len) return error.OutOfMemory;
            if (ev == .start) self.start_seen = true;
            self.evs[self.ct] = ev;
            self.ct += 1;
        }
    };

    const DispatchImpl = struct {
        start_seen: *bool,

        fn run(self: *@This(), _: TCall, _: TRt.Sink) error{ StartNotSeen, HandlerFailed }!TResult {
            if (!self.start_seen.*) return error.StartNotSeen;
            return error.HandlerFailed;
        }
    };

    var sink_impl = SinkImpl{};
    const sink = TRt.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    var dispatch_impl = DispatchImpl{
        .start_seen = &sink_impl.start_seen,
    };
    const entries = [_]TRt.Entry{
        .{
            .name = "alpha",
            .kind = .alpha,
            .spec = .{},
            .dispatch = TRt.Dispatch.from(DispatchImpl, &dispatch_impl, DispatchImpl.run),
        },
    };
    const reg = TRt.Registry.init(entries[0..]);

    try std.testing.expectError(error.HandlerFailed, reg.run("alpha", .{
        .id = "c3",
        .kind = .alpha,
        .at_ms = 12,
        .value = 0,
    }, sink));

    try std.testing.expectEqual(@as(usize, 1), sink_impl.ct);
    try std.testing.expect(sink_impl.evs[0] == .start);
}
