const std = @import("std");
const zc = @import("zcheck");

pub const Str = zc.String;
pub const Id = zc.Id;
pub const Path = zc.FilePath;

pub fn Slice(comptime T: type, comptime max_len: usize) type {
    return zc.BoundedSlice(T, max_len);
}

pub fn Bytes(comptime max_len: usize) type {
    return Slice(u8, max_len);
}

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
    var prng = std.Random.DefaultPrng.init(seed);
    return zc.generate(T, prng.random());
}

pub fn drawN(alloc: std.mem.Allocator, comptime T: type, n: usize, seed: u64) ![]T {
    const out = try alloc.alloc(T, n);
    errdefer alloc.free(out);

    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (out) |*it| {
        it.* = zc.generate(T, rnd);
    }
    return out;
}

pub fn valueAlloc(alloc: std.mem.Allocator, value: anytype) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    try writeVal(out.writer(alloc), value);
    return try out.toOwnedSlice(alloc);
}

pub fn reportAlloc(
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

fn isBoundedSlice(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => @hasDecl(T, "is_bounded_slice") and T.is_bounded_slice,
        else => false,
    };
}

fn writeVal(w: anytype, value: anytype) !void {
    const T = @TypeOf(value);
    if (T == Str or T == Id or T == Path) {
        try std.json.stringify(value.slice(), .{}, w);
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

test "pbt expectShrunk returns reduced counterexamples" {
    const Prop = struct {
        fn prop(args: struct { a: u8 }) bool {
            return args.a == 0;
        }
    };

    const fail = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });

    try std.testing.expectEqual(@as(u64, 12345), fail.seed);
    try std.testing.expect(fail.original.a != 0);
    try std.testing.expectEqual(@as(u8, 1), fail.shrunk.a);
}

test "pbt reportAlloc includes failure details" {
    const Prop = struct {
        fn prop(args: struct { a: u8 }) bool {
            return args.a == 0;
        }
    };

    const fail = try expectShrunk(Prop.prop, .{
        .iterations = 50,
        .seed = 12345,
    });

    const report = try reportAlloc(std.testing.allocator, Prop.prop, fail);
    defer std.testing.allocator.free(report);

    try std.testing.expect(std.mem.indexOf(u8, report, "seed=12345\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "original=") != null);
    try std.testing.expect(std.mem.indexOf(u8, report, "shrunk=.{a=1}\n") != null);
}
