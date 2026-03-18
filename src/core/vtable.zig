const std = @import("std");

/// Generate a type-erased trampoline fn pointer.
///
/// Replaces the manual `Wrap` struct pattern. Given a concrete `*T` method,
/// returns a `*const fn(*anyopaque, ...) Ret` that casts and forwards.
///
/// Usage:
///   pub fn from(comptime T: type, ptr: *T, comptime method: fn (*T) i64) TimeSrc {
///       return .{ .ctx = ptr, .now_ms_fn = wrap(T, method) };
///   }
pub fn wrap(comptime T: type, comptime method: anytype) ErasedPtr(@TypeOf(method)) {
    const M = @TypeOf(method);
    const info = @typeInfo(M).@"fn";
    const params = info.params;
    const Ret = info.return_type.?;

    if (params.len < 1) @compileError("method must take at least *T");
    if (params[0].type.? != *T) @compileError("first param must be *T");

    return &(switch (params.len) {
        1 => struct {
            fn call(raw: *anyopaque) Ret {
                return method(@ptrCast(@alignCast(raw)));
            }
        },
        2 => struct {
            fn call(raw: *anyopaque, a0: params[1].type.?) Ret {
                return method(@ptrCast(@alignCast(raw)), a0);
            }
        },
        3 => struct {
            fn call(raw: *anyopaque, a0: params[1].type.?, a1: params[2].type.?) Ret {
                return method(@ptrCast(@alignCast(raw)), a0, a1);
            }
        },
        4 => struct {
            fn call(raw: *anyopaque, a0: params[1].type.?, a1: params[2].type.?, a2: params[3].type.?) Ret {
                return method(@ptrCast(@alignCast(raw)), a0, a1, a2);
            }
        },
        else => @compileError("wrap: too many params (max 4)"),
    }).call;
}

/// Given `fn (*T, A, B) R`, returns `*const fn (*anyopaque, A, B) R`.
fn ErasedPtr(comptime M: type) type {
    const info = @typeInfo(M).@"fn";
    const params = info.params;
    const Ret = info.return_type.?;

    return *const switch (params.len) {
        1 => fn (*anyopaque) Ret,
        2 => fn (*anyopaque, params[1].type.?) Ret,
        3 => fn (*anyopaque, params[1].type.?, params[2].type.?) Ret,
        4 => fn (*anyopaque, params[1].type.?, params[2].type.?, params[3].type.?) Ret,
        else => @compileError("ErasedPtr: too many params (max 4)"),
    };
}

// --- Tests ---

const testing = std.testing;

test "wrap: zero extra args, i64 return" {
    const Clock = struct {
        ms: i64,
        fn nowMs(self: *@This()) i64 {
            return self.ms;
        }
    };

    var c = Clock{ .ms = 42 };
    const f = wrap(Clock, Clock.nowMs);
    try testing.expectEqual(@as(i64, 42), f(@ptrCast(&c)));
}

test "wrap: zero extra args, bool return" {
    const Flag = struct {
        val: bool,
        fn check(self: *@This()) bool {
            return self.val;
        }
    };

    var f = Flag{ .val = true };
    const erased = wrap(Flag, Flag.check);
    try testing.expect(erased(@ptrCast(&f)));

    f.val = false;
    try testing.expect(!erased(@ptrCast(&f)));
}

test "wrap: one extra arg" {
    const Adder = struct {
        base: i32,
        fn add(self: *@This(), n: i32) i32 {
            return self.base + n;
        }
    };

    var a = Adder{ .base = 10 };
    const erased = wrap(Adder, Adder.add);
    try testing.expectEqual(@as(i32, 15), erased(@ptrCast(&a), 5));
}

test "wrap: different concrete types produce same erased signature" {
    const A = struct {
        fn val(_: *@This()) i64 {
            return 1;
        }
    };
    const B = struct {
        n: i64,
        fn val(self: *@This()) i64 {
            return self.n;
        }
    };

    var a = A{};
    var b = B{ .n = 99 };

    // Both produce *const fn(*anyopaque) i64
    const fa = wrap(A, A.val);
    const fb = wrap(B, B.val);

    try testing.expectEqual(@as(i64, 1), fa(@ptrCast(&a)));
    try testing.expectEqual(@as(i64, 99), fb(@ptrCast(&b)));
}

test "wrap: used in vtable struct pattern" {
    // Demonstrates the intended usage pattern.
    const TimeSrc = struct {
        ctx: *anyopaque,
        now_ms_fn: *const fn (*anyopaque) i64,

        pub fn from(
            comptime T: type,
            ptr: *T,
            comptime method: fn (*T) i64,
        ) @This() {
            return .{ .ctx = ptr, .now_ms_fn = wrap(T, method) };
        }

        pub fn nowMs(self: @This()) i64 {
            return self.now_ms_fn(self.ctx);
        }
    };

    const Clock = struct {
        ms: i64,
        fn nowMs(self: *@This()) i64 {
            return self.ms;
        }
    };

    var c = Clock{ .ms = 777 };
    const ts = TimeSrc.from(Clock, &c, Clock.nowMs);
    try testing.expectEqual(@as(i64, 777), ts.nowMs());
}
