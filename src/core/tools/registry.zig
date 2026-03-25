//! Comptime tool registry: kind-keyed dispatch table generation.
const std = @import("std");


pub fn bind(
    comptime Kind: type,
    comptime Spec: type,
    comptime Call: type,
    comptime Event: type,
    comptime Result: type,
) type {
    comptime {
        if (!@hasField(Call, "kind")) {
            @compileError("registry call type must define `kind`");
        }

        const probe: Call = undefined;
        if (@TypeOf(probe.kind) != Kind) {
            @compileError("registry call.kind must match registry kind type");
        }
    }

    return struct {
        pub const Err = error{
            NotFound,
            KindMismatch,
        };

        pub const Sink = struct {
            vt: *const Vt,

            pub const Vt = struct {
                push: *const fn (self: *Sink, ev: Event) anyerror!void,
            };

            pub fn push(self: *Sink, ev: Event) !void {
                return self.vt.push(self, ev);
            }

            pub fn Bind(comptime T: type, comptime push_fn: fn (*T, Event) anyerror!void) type {
                return struct {
                    pub const vt = Vt{
                        .push = pushFn,
                    };
                    fn pushFn(s: *Sink, ev: Event) anyerror!void {
                        const self: *T = @fieldParentPtr("sink", s);
                        return push_fn(self, ev);
                    }
                };
            }
        };

        pub const Dispatch = struct {
            vt: *const Vt,

            pub const Vt = struct {
                run: *const fn (self: *Dispatch, call: Call, sink: *Sink) anyerror!Result,
            };

            pub fn run(self: *Dispatch, call: Call, sink: *Sink) !Result {
                return self.vt.run(self, call, sink);
            }

            pub fn Bind(comptime T: type, comptime run_fn: fn (*T, Call, *Sink) anyerror!Result) type {
                return struct {
                    pub const vt = Vt{
                        .run = runFn,
                    };
                    fn runFn(d: *Dispatch, call: Call, sink: *Sink) anyerror!Result {
                        const self: *T = @fieldParentPtr("dispatch", d);
                        return run_fn(self, call, sink);
                    }
                };
            }
        };

        pub const Entry = struct {
            name: []const u8,
            kind: Kind,
            spec: Spec,
            dispatch: *Dispatch,
        };

        pub const Registry = struct {
            entries: []const Entry,

            pub fn init(entries: []const Entry) Registry {
                return .{
                    .entries = entries,
                };
            }

            pub fn byName(self: Registry, name: []const u8) ?*const Entry {
                for (self.entries) |*entry| {
                    if (std.mem.eql(u8, entry.name, name)) return entry;
                }
                return null;
            }

            pub fn byKind(self: Registry, kind: Kind) ?*const Entry {
                for (self.entries) |*entry| {
                    if (entry.kind == kind) return entry;
                }
                return null;
            }

            pub fn run(
                self: Registry,
                name: []const u8,
                call: Call,
                sink: *Sink,
            ) (Err || anyerror)!Result {
                const entry = self.byName(name) orelse return Err.NotFound;
                if (call.kind != entry.kind) return Err.KindMismatch;
                return entry.dispatch.run(call, sink);
            }
        };
    };
}

const TKind = enum {
    read,
    write,
};

const TSpec = struct {
    timeout_ms: u32 = 0,
};

const TCall = struct {
    kind: TKind,
    value: i32,
};

const TEv = struct {
    id: u8,
};

const TResult = struct {
    code: i32,
};

const TReg = bind(TKind, TSpec, TCall, TEv, TResult);

test "registry lookup resolves by name and kind" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        read_is_read: bool,
        write_is_write: bool,
        write_name: []const u8,
        missing: bool,
    };
    const DispatchImpl = struct {
        dispatch: TReg.Dispatch = .{ .vt = &Bind.vt },
        fn run(_: *@This(), call: TCall, _: *TReg.Sink) !TResult {
            return .{ .code = call.value };
        }
        const Bind = TReg.Dispatch.Bind(@This(), run);
    };

    var read_impl = DispatchImpl{};
    var write_impl = DispatchImpl{};
    const entries = [_]TReg.Entry{
        .{
            .name = "read",
            .kind = .read,
            .spec = .{ .timeout_ms = 10 },
            .dispatch = &read_impl.dispatch,
        },
        .{
            .name = "write",
            .kind = .write,
            .spec = .{ .timeout_ms = 20 },
            .dispatch = &write_impl.dispatch,
        },
    };
    const reg = TReg.Registry.init(entries[0..]);

    const read = reg.byName("read") orelse return error.TestUnexpectedResult;
    const write = reg.byKind(.write) orelse return error.TestUnexpectedResult;

    try oh.snap(@src(),
        \\core.tools.registry.test.registry lookup resolves by name and kind.Snap
        \\  .read_is_read: bool = true
        \\  .write_is_write: bool = true
        \\  .write_name: []const u8
        \\    "write"
        \\  .missing: bool = true
    ).expectEqual(Snap{
        .read_is_read = read.kind == .read,
        .write_is_write = write.kind == .write,
        .write_name = write.name,
        .missing = reg.byName("missing") == null,
    });
}

test "registry run dispatches to named handler" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SinkSnap = struct {
        ct: usize,
        last: u8,
    };
    const Snap = struct {
        res: TResult,
        missing: []const u8,
        mismatch: []const u8,
        read_ct: usize,
        write_ct: usize,
        sink: SinkSnap,
    };
    const SinkImpl = struct {
        sink: TReg.Sink = .{ .vt = &Bind.vt },
        ct: usize = 0,
        last: u8 = 0,

        fn push(self: *@This(), ev: TEv) !void {
            self.ct += 1;
            self.last = ev.id;
        }
        const Bind = TReg.Sink.Bind(@This(), push);
    };

    const DispatchImpl = struct {
        dispatch: TReg.Dispatch = .{ .vt = &Bind.vt },
        ct: usize = 0,
        add: i32,
        ev_id: u8,

        fn run(self: *@This(), call: TCall, sink: *TReg.Sink) !TResult {
            self.ct += 1;
            try sink.push(.{ .id = self.ev_id });
            return .{ .code = call.value + self.add };
        }
        const Bind = TReg.Dispatch.Bind(@This(), run);
    };

    var sink_impl = SinkImpl{};

    var read_impl = DispatchImpl{ .add = 10, .ev_id = 1 };
    var write_impl = DispatchImpl{ .add = 20, .ev_id = 2 };
    const entries = [_]TReg.Entry{
        .{
            .name = "read",
            .kind = .read,
            .spec = .{},
            .dispatch = &read_impl.dispatch,
        },
        .{
            .name = "write",
            .kind = .write,
            .spec = .{},
            .dispatch = &write_impl.dispatch,
        },
    };
    const reg = TReg.Registry.init(entries[0..]);

    const res = try reg.run("write", .{ .kind = .write, .value = 7 }, &sink_impl.sink);
    const missing = blk: {
        _ = reg.run("missing", .{ .kind = .read, .value = 1 }, &sink_impl.sink) catch |err| {
            if (err != TReg.Err.NotFound) return err;
            break :blk @errorName(err);
        };
        return error.TestUnexpectedResult;
    };
    const mismatch = blk: {
        _ = reg.run("read", .{ .kind = .write, .value = 1 }, &sink_impl.sink) catch |err| {
            if (err != TReg.Err.KindMismatch) return err;
            break :blk @errorName(err);
        };
        return error.TestUnexpectedResult;
    };
    const snap = Snap{
        .res = res,
        .missing = missing,
        .mismatch = mismatch,
        .read_ct = read_impl.ct,
        .write_ct = write_impl.ct,
        .sink = .{
            .ct = sink_impl.ct,
            .last = sink_impl.last,
        },
    };
    try oh.snap(@src(),
        \\core.tools.registry.test.registry run dispatches to named handler.Snap
        \\  .res: core.tools.registry.TResult
        \\    .code: i32 = 27
        \\  .missing: []const u8
        \\    "NotFound"
        \\  .mismatch: []const u8
        \\    "KindMismatch"
        \\  .read_ct: usize = 0
        \\  .write_ct: usize = 1
        \\  .sink: core.tools.registry.test.registry run dispatches to named handler.SinkSnap
        \\    .ct: usize = 1
        \\    .last: u8 = 2
    ).expectEqual(snap);
}
