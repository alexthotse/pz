const std = @import("std");
const zc = @import("zcheck");

pub const Str = zc.String;
pub const Id = zc.Id;
pub const Path = zc.FilePath;
pub const DrawCfg = zc.GenerateConfig;
pub const ShrinkCfg = struct {
    use_default_values: bool = true,
};

pub fn Slice(comptime T: type, comptime max_len: usize) type {
    return zc.BoundedSlice(T, max_len);
}

pub fn Bytes(comptime max_len: usize) type {
    return Slice(u8, max_len);
}

pub const Gen = struct {
    pub fn any(comptime T: type, seed: u64) T {
        return anyWith(T, seed, .{});
    }

    pub fn anyWith(comptime T: type, seed: u64, cfg0: DrawCfg) T {
        var prng = std.Random.DefaultPrng.init(seed);
        return zc.generateWithConfig(T, prng.random(), cfg0);
    }

    pub fn many(alloc: std.mem.Allocator, comptime T: type, n: usize, seed: u64) ![]T {
        return manyWith(alloc, T, n, seed, .{});
    }

    pub fn manyWith(
        alloc: std.mem.Allocator,
        comptime T: type,
        n: usize,
        seed: u64,
        cfg0: DrawCfg,
    ) ![]T {
        const out = try alloc.alloc(T, n);
        errdefer alloc.free(out);

        var prng = std.Random.DefaultPrng.init(seed);
        const rnd = prng.random();
        for (out) |*it| {
            it.* = zc.generateWithConfig(T, rnd, cfg0);
        }
        return out;
    }

    pub fn range(comptime T: type, seed: u64, min: T, max: T) T {
        var prng = std.Random.DefaultPrng.init(seed);
        return zc.intRange(T, prng.random(), min, max);
    }

    pub fn bytes(comptime len: usize, seed: u64) [len]u8 {
        var prng = std.Random.DefaultPrng.init(seed);
        return zc.bytes(len, prng.random());
    }
};

pub const Shrink = struct {
    pub fn one(comptime T: type, value: T) ?T {
        return oneWith(T, value, .{});
    }

    pub fn oneWith(comptime T: type, value: T, cfg0: ShrinkCfg) ?T {
        return shrinkOnce(T, value, cfg0);
    }

    pub fn loop(comptime T: type, value: T, max_steps: usize) T {
        return loopWith(T, value, max_steps, .{});
    }

    pub fn loopWith(comptime T: type, value: T, max_steps: usize, cfg0: ShrinkCfg) T {
        var out = value;
        var steps: usize = 0;
        while (steps < max_steps) : (steps += 1) {
            out = oneWith(T, out, cfg0) orelse break;
        }
        return out;
    }
};

pub const Fmt = struct {
    pub fn valueAlloc(alloc: std.mem.Allocator, value: anytype) ![]u8 {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(alloc);
        try writeVal(out.writer(alloc), value);
        return try out.toOwnedSlice(alloc);
    }

    pub fn failureAlloc(
        alloc: std.mem.Allocator,
        comptime prop: anytype,
        fail: FailureOf(prop),
    ) ![]u8 {
        var out = std.ArrayList(u8).empty;
        defer out.deinit(alloc);

        try std.fmt.format(out.writer(alloc), "seed={d}\niteration={d}\noriginal=", .{
            fail.seed,
            fail.iteration,
        });
        try writeVal(out.writer(alloc), fail.original);
        try out.appendSlice(alloc, "\nshrunk=");
        try writeVal(out.writer(alloc), fail.shrunk);
        try out.append(alloc, '\n');
        return try out.toOwnedSlice(alloc);
    }
};

pub const Opt = struct {
    iterations: usize = 200,
    seed: u64 = 0,
    max_shrinks: usize = 128,
    expect_failure: bool = false,
    print_failures: bool = false,
    use_default_values: bool = true,
    random: ?std.Random = null,
};

pub fn ArgsOf(comptime prop: anytype) type {
    const fn_info = @typeInfo(@TypeOf(prop)).@"fn";
    if (fn_info.params.len != 1) {
        @compileError("property must take exactly one argument");
    }
    const Args = fn_info.params[0].type orelse @compileError("property argument type is required");
    if (@typeInfo(Args) != .@"struct") {
        @compileError("property argument must be a struct");
    }
    return Args;
}

pub fn FailureOf(comptime prop: anytype) type {
    return zc.Failure(ArgsOf(prop));
}

pub fn run(comptime prop: anytype, opt: Opt) !void {
    try zc.check(prop, cfg(opt));
}

pub fn check(comptime prop: anytype, opt: Opt) ?FailureOf(prop) {
    return zc.checkResult(prop, cfg(opt));
}

pub fn expectFail(comptime prop: anytype, opt: Opt) !FailureOf(prop) {
    return check(prop, opt) orelse error.ExpectedFailure;
}

pub fn expectShrunk(comptime prop: anytype, opt: Opt) !FailureOf(prop) {
    const fail = try expectFail(prop, opt);
    if (std.meta.eql(fail.original, fail.shrunk)) return error.NotShrunk;
    return fail;
}

pub fn draw(comptime T: type, seed: u64) T {
    return Gen.any(T, seed);
}

pub fn drawWith(comptime T: type, seed: u64, cfg0: DrawCfg) T {
    return Gen.anyWith(T, seed, cfg0);
}

pub fn drawRange(comptime T: type, seed: u64, min: T, max: T) T {
    return Gen.range(T, seed, min, max);
}

pub fn drawBytes(comptime len: usize, seed: u64) [len]u8 {
    return Gen.bytes(len, seed);
}

pub fn drawN(alloc: std.mem.Allocator, comptime T: type, n: usize, seed: u64) ![]T {
    return Gen.many(alloc, T, n, seed);
}

pub fn drawNWith(
    alloc: std.mem.Allocator,
    comptime T: type,
    n: usize,
    seed: u64,
    cfg0: DrawCfg,
) ![]T {
    return Gen.manyWith(alloc, T, n, seed, cfg0);
}

pub fn valueAlloc(alloc: std.mem.Allocator, value: anytype) ![]u8 {
    return Fmt.valueAlloc(alloc, value);
}

pub fn reportAlloc(
    alloc: std.mem.Allocator,
    comptime prop: anytype,
    fail: FailureOf(prop),
) ![]u8 {
    return Fmt.failureAlloc(alloc, prop, fail);
}

fn cfg(opt: Opt) zc.Config {
    return .{
        .iterations = opt.iterations,
        .seed = opt.seed,
        .max_shrinks = opt.max_shrinks,
        .expect_failure = opt.expect_failure,
        .print_failures = opt.print_failures,
        .use_default_values = opt.use_default_values,
        .random = opt.random,
    };
}

pub fn shrink(comptime T: type, value: T) ?T {
    return Shrink.one(T, value);
}

pub fn shrinkWith(comptime T: type, value: T, cfg0: ShrinkCfg) ?T {
    return Shrink.oneWith(T, value, cfg0);
}

pub fn shrinkN(comptime T: type, value: T, max_steps: usize) T {
    return Shrink.loop(T, value, max_steps);
}

pub fn shrinkNWith(comptime T: type, value: T, max_steps: usize, cfg0: ShrinkCfg) T {
    return Shrink.loopWith(T, value, max_steps, cfg0);
}

fn shrinkOnce(comptime T: type, value: T, cfg0: ShrinkCfg) ?T {
    if (T == Str) return shrinkStr(value);
    if (T == Id) return shrinkId(value);
    if (T == Path) return shrinkPath(value);
    if (comptime isBoundedSlice(T)) return shrinkBoundedSlice(T, value);

    return switch (@typeInfo(T)) {
        .int => shrinkInt(T, value),
        .float => shrinkFloat(T, value),
        .bool => if (value) false else null,
        .optional => if (value != null) @as(T, null) else null,
        .array => |a| shrinkArray(a.child, a.len, value, cfg0),
        .@"struct" => |s| shrinkStruct(T, s, value, cfg0),
        .@"union" => |u| shrinkUnion(T, u, value, cfg0),
        .@"enum" => shrinkEnum(T, value),
        else => null,
    };
}

fn isBoundedSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => @hasDecl(T, "is_bounded_slice") and T.is_bounded_slice,
        else => false,
    };
}

fn writeVal(w: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Str or T == Id or T == Path) {
        try w.print("{f}", .{std.json.fmt(value.slice(), .{})});
        return;
    }
    if (comptime isBoundedSlice(T)) {
        try writeSeq(w, value.slice());
        return;
    }

    switch (@typeInfo(T)) {
        .int, .comptime_int => try w.print("{d}", .{value}),
        .float, .comptime_float => try w.print("{d}", .{value}),
        .bool => try w.writeAll(if (value) "true" else "false"),
        .@"enum" => try w.writeAll(@tagName(value)),
        .optional => {
            if (value) |item| {
                try writeVal(w, item);
            } else {
                try w.writeAll("null");
            }
        },
        .array => try writeSeq(w, &value),
        .@"struct" => |s| {
            try w.writeAll(".{");
            var first = true;
            inline for (s.fields) |field| {
                if (field.is_comptime) continue;
                if (!first) try w.writeAll(", ");
                first = false;
                try w.print("{s}=", .{field.name});
                try writeVal(w, @field(value, field.name));
            }
            try w.writeByte('}');
        },
        .@"union" => |u| {
            if (u.tag_type == null) @compileError("untagged union counterexamples are not supported");
            const tag = std.meta.activeTag(value);
            const tag_name = @tagName(tag);

            try w.writeAll(".{");
            try w.writeAll(tag_name);
            try w.writeAll("=");
            inline for (u.fields) |field| {
                if (std.mem.eql(u8, field.name, tag_name)) {
                    try writeVal(w, @field(value, field.name));
                }
            }
            try w.writeByte('}');
        },
        else => try w.print("{any}", .{value}),
    }
}

fn writeSeq(w: anytype, seq: anytype) !void {
    try w.writeByte('[');
    for (seq, 0..) |item, i| {
        if (i != 0) try w.writeAll(", ");
        try writeVal(w, item);
    }
    try w.writeByte(']');
}

fn shrinkStr(value: Str) ?Str {
    if (value.len == 0) return null;
    if (value.len > 1) {
        var out = value;
        out.len = value.len / 2;
        return out;
    }
    return Str{};
}

fn shrinkId(value: Id) ?Id {
    if (value.len <= Id.MIN_LEN) return null;
    var out = value;
    out.len = @max(Id.MIN_LEN, value.len / 2);
    return out;
}

fn shrinkPath(value: Path) ?Path {
    if (value.len == 0) return null;
    const path = value.slice();
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse return null;
    if (dot <= 1) return null;

    const name_len = dot - 1;
    if (name_len <= 1) return null;

    const ext_len = path.len - dot;
    const new_name_len = @max(@as(usize, 1), name_len / 2);
    var out = value;
    const new_ext = 1 + new_name_len;
    if (new_ext != dot) {
        std.mem.copyForwards(u8, out.buf[new_ext .. new_ext + ext_len], value.buf[dot .. dot + ext_len]);
    }
    out.len = new_ext + ext_len;
    return out;
}

fn shrinkBoundedSlice(comptime T: type, value: T) ?T {
    if (value.len == 0) return null;
    var out = value;
    out.len = value.len / 2;
    return out;
}

fn shrinkInt(comptime T: type, value: T) ?T {
    if (value == 0) return null;
    if (value > 0) {
        if (value == 1) return 0;
        return @divTrunc(value, 2);
    }
    if (value == -1) return 0;
    return @divTrunc(value, 2);
}

fn shrinkFloat(comptime T: type, value: T) ?T {
    if (value == 0.0) return null;
    if (@abs(value) < 0.001) return 0.0;
    return value / 2.0;
}

fn shrinkEnum(comptime T: type, value: T) ?T {
    const fields = @typeInfo(T).@"enum".fields;
    inline for (fields, 0..) |field, i| {
        if (@intFromEnum(value) == field.value) {
            if (i == 0) return null;
            return @as(T, @enumFromInt(fields[i - 1].value));
        }
    }
    return null;
}

fn shrinkArray(comptime Elem: type, comptime len: usize, value: [len]Elem, cfg0: ShrinkCfg) ?[len]Elem {
    var out = value;
    for (&out, 0..) |*elem, i| {
        if (shrinkOnce(Elem, value[i], cfg0)) |next| {
            elem.* = next;
            return out;
        }
    }
    return null;
}

fn shrinkStruct(
    comptime T: type,
    comptime s: std.builtin.Type.Struct,
    value: T,
    cfg0: ShrinkCfg,
) ?T {
    var out = value;
    inline for (s.fields) |field| {
        if (field.is_comptime) continue;
        const use_default = comptime (cfg0.use_default_values and field.defaultValue() != null);
        if (use_default) continue;
        if (shrinkOnce(field.type, @field(value, field.name), cfg0)) |next| {
            @field(out, field.name) = next;
            return out;
        }
    }
    return null;
}

fn shrinkUnion(
    comptime T: type,
    comptime u: std.builtin.Type.Union,
    value: T,
    cfg0: ShrinkCfg,
) ?T {
    if (u.tag_type == null) return null;

    const tag = std.meta.activeTag(value);
    inline for (u.fields) |field| {
        const field_tag = @field(u.tag_type.?, field.name);
        if (field_tag != tag) continue;
        if (shrinkOnce(field.type, @field(value, field.name), cfg0)) |next| {
            return @unionInit(T, field.name, next);
        }
        return null;
    }
    return null;
}

test "pbt drawN respects shared generator bounds" {
    const Sample = struct {
        s: Str,
        id: Id,
        path: Path,
        bytes: Bytes(8),
        nums: Slice(i16, 4),
    };

    const cases = try drawN(std.testing.allocator, Sample, 64, 0x5A17_C0DE);
    defer std.testing.allocator.free(cases);

    for (cases) |it| {
        const s = it.s.slice();
        try std.testing.expect(s.len <= Str.MAX_LEN);
        for (s) |c| {
            try std.testing.expect(c >= 32 and c <= 126);
        }

        const id = it.id.slice();
        try std.testing.expect(id.len >= Id.MIN_LEN);
        try std.testing.expect(id.len <= Id.MAX_LEN);
        for (id) |c| {
            const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
            try std.testing.expect(ok);
        }

        const path = it.path.slice();
        try std.testing.expect(path.len >= 3);
        try std.testing.expect(path[0] == '/');
        try std.testing.expect(std.mem.indexOfScalar(u8, path[1..], '.') != null);

        try std.testing.expect(it.bytes.len <= 8);
        try std.testing.expect(it.nums.len <= 4);
    }
}

test "pbt shared generator helpers stay deterministic" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Sample = struct {
        flag: bool = true,
        n: u8 = 7,
        word: Str,
    };

    const with_defaults = drawWith(Sample, 0xCAFE_BABE, .{});
    const without_defaults = drawWith(Sample, 0xCAFE_BABE, .{ .use_default_values = false });
    const range = drawRange(i16, 0xDEAD_BEEF, -9, 9);
    const bytes = drawBytes(8, 0xF00D_BAAD);

    try std.testing.expect(with_defaults.flag);
    try std.testing.expectEqual(@as(u8, 7), with_defaults.n);

    const got = try valueAlloc(std.testing.allocator, .{
        .with_defaults = with_defaults,
        .without_defaults = without_defaults,
        .range = range,
        .bytes = bytes,
    });
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]u8
        \\  ".{with_defaults=.{flag=true, n=7, word="<Wp/pj@;ALQ!w5/b4&Ki&3&fM`]ZZ[wL>~@}S-vWHvd2pvl"}, without_defaults=.{flag=false, n=78, word="/pj@;ALQ!w5/b4&Ki&3&fM`]ZZ[wL>~@}S-vWHvd2pvl*4e#\\@vXsQ7WHJ1C\"k"}, range=1, bytes=[72, 194, 111, 106, 99, 131, 250, 171]}"
    ).expectEqual(got);
}

test "pbt shared shrink helpers reach structural minima" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Bs = Bytes(8);
    const Sample = struct {
        n: i32,
        bytes: Bs,
    };

    const start = Sample{
        .n = 100,
        .bytes = Bs.fromSlice("abcdef"),
    };
    const one = shrink(Sample, start).?;
    const loop = shrinkN(Sample, start, 16);

    try std.testing.expectEqual(@as(i32, 50), one.n);
    try std.testing.expectEqual(@as(i32, 0), loop.n);
    try std.testing.expectEqual(@as(usize, 0), loop.bytes.len);

    const got = try valueAlloc(std.testing.allocator, .{
        .one = one,
        .loop = loop,
    });
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]u8
        \\  ".{one=.{n=50, bytes=[97, 98, 99, 100, 101, 102]}, loop=.{n=0, bytes=[]}}"
    ).expectEqual(got);
}

test "pbt expectShrunk yields stable minimal counterexamples" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Prop = struct {
        fn prop(args: struct { a: u8 }) bool {
            return args.a == 0;
        }
    };

    const fail_a = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });
    const fail_b = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });

    try std.testing.expectEqual(@as(u64, 12345), fail_a.seed);
    try std.testing.expectEqual(fail_a.seed, fail_b.seed);
    try std.testing.expectEqual(fail_a.iteration, fail_b.iteration);
    try std.testing.expectEqual(fail_a.original.a, fail_b.original.a);
    try std.testing.expectEqual(fail_a.shrunk.a, fail_b.shrunk.a);
    try std.testing.expect(fail_a.original.a != 0);
    try std.testing.expectEqual(@as(u8, 1), fail_a.shrunk.a);

    const Snap = struct {
        seed: u64,
        iteration: usize,
        original: u8,
        shrunk: u8,
    };
    const got = Snap{
        .seed = fail_a.seed,
        .iteration = fail_a.iteration,
        .original = fail_a.original.a,
        .shrunk = fail_a.shrunk.a,
    };
    try oh.snap(@src(),
        \\core.pbt.test.pbt expectShrunk yields stable minimal counterexamples.Snap
        \\  .seed: u64 = 12345
        \\  .iteration: usize = 0
        \\  .original: u8 = 160
        \\  .shrunk: u8 = 1
    ).expectEqual(got);
}

test "pbt run replays successful iterations deterministically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Prop = struct {
        var vals: [8]u8 = undefined;
        var n: usize = 0;

        fn reset() void {
            n = 0;
        }

        fn prop(args: struct { a: u8 }) bool {
            vals[n] = args.a;
            n += 1;
            return true;
        }
    };

    Prop.reset();
    try run(Prop.prop, .{
        .iterations = Prop.vals.len,
        .seed = 0xC0DE_1234,
    });
    const first = Prop.vals;
    const first_n = Prop.n;

    Prop.reset();
    try run(Prop.prop, .{
        .iterations = Prop.vals.len,
        .seed = 0xC0DE_1234,
    });
    const second = Prop.vals;
    const second_n = Prop.n;

    try std.testing.expectEqual(@as(usize, Prop.vals.len), first_n);
    try std.testing.expectEqual(first_n, second_n);
    try std.testing.expectEqualSlices(u8, first[0..first_n], second[0..second_n]);

    const got = try valueAlloc(std.testing.allocator, first);
    defer std.testing.allocator.free(got);
    try oh.snap(@src(),
        \\[]u8
        \\  "[230, 116, 6, 27, 0, 70, 79, 119]"
    ).expectEqual(got);
}

test "pbt reportAlloc formatting is deterministic" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Prop = struct {
        fn prop(args: struct { a: u8 }) bool {
            return args.a == 0;
        }
    };

    const fail_a = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });
    const fail_b = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });

    const report_a = try reportAlloc(std.testing.allocator, Prop.prop, fail_a);
    defer std.testing.allocator.free(report_a);
    const report_b = try reportAlloc(std.testing.allocator, Prop.prop, fail_b);
    defer std.testing.allocator.free(report_b);

    try std.testing.expectEqualStrings(report_a, report_b);
    try oh.snap(@src(),
        \\[]u8
        \\  "seed=12345
        \\iteration=0
        \\original=.{a=160}
        \\shrunk=.{a=1}
        \\"
    ).expectEqual(report_a);
}
