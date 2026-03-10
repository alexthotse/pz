const std = @import("std");

pub const Err = error{
    OutOfMemory,
    TransportTransient,
    TransportFatal,
    BadFrame,
    UnknownTag,
    InvalidUsage,
    UnknownStop,
    MissingStop,
};

pub const Class = enum {
    retryable_transport,
    fatal_transport,
    parse,
};

pub fn class(err: Err) Class {
    return switch (err) {
        error.TransportTransient => .retryable_transport,
        error.TransportFatal => .fatal_transport,
        error.OutOfMemory,
        error.BadFrame,
        error.UnknownTag,
        error.InvalidUsage,
        error.UnknownStop,
        error.MissingStop,
        => .parse,
    };
}

pub fn retryable(err: Err) bool {
    return err == error.TransportTransient;
}

pub fn mapAlloc(_: std.mem.Allocator.Error) Err {
    return error.OutOfMemory;
}

pub const Adapter = struct {
    ctx: *anyopaque,
    vt: *const Vt,

    pub const Vt = struct {
        map: *const fn (ctx: *anyopaque, err: anyerror) Err,
    };

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime map_fn: fn (ctx: *T, err: anyerror) Err,
    ) Adapter {
        const Wrap = struct {
            fn map(raw: *anyopaque, err: anyerror) Err {
                const typed: *T = @ptrCast(@alignCast(raw));
                return map_fn(typed, err);
            }

            const vt = Vt{
                .map = @This().map,
            };
        };

        return .{
            .ctx = ctx,
            .vt = &Wrap.vt,
        };
    }

    pub fn map(self: Adapter, err: anyerror) Err {
        return self.vt.map(self.ctx, err);
    }
};

pub fn isOverflowError(alloc: std.mem.Allocator, err_text: []const u8) bool {
    if (err_text.len == 0) return false;

    // 1. Try JSON parse
    if (std.json.parseFromSlice(std.json.Value, alloc, err_text, .{})) |parsed| {
        defer parsed.deinit();
        if (parsed.value == .object) {
            if (parsed.value.object.get("error")) |err_obj| {
                if (err_obj == .object) {
                    // Anthropic: error.type == "request_too_large"
                    if (err_obj.object.get("type")) |t| {
                        if (t == .string and std.mem.eql(u8, t.string, "request_too_large")) return true;
                    }
                    // OpenAI: error.code == "context_length_exceeded"
                    if (err_obj.object.get("code")) |c| {
                        if (c == .string and std.mem.eql(u8, c.string, "context_length_exceeded")) return true;
                    }
                }
            }
        }
    } else |_| {
        // Fall through to substring checks
    }

    // 2. Substring fallback
    if (std.mem.indexOf(u8, err_text, "request_too_large") != null) return true;
    if (std.mem.indexOf(u8, err_text, "context_length_exceeded") != null) return true;

    // 3. HTTP 413 prefix
    if (std.mem.startsWith(u8, err_text, "413")) return true;

    return false;
}

const MapCtx = struct {
    calls: usize = 0,
};

fn mapRaw(ctx: *MapCtx, err: anyerror) Err {
    ctx.calls += 1;

    if (err == error.Timeout or err == error.WireBreak) return error.TransportTransient;
    if (err == error.Closed) return error.TransportFatal;
    if (err == error.OutOfMemory) return error.OutOfMemory;
    return error.TransportFatal;
}

test "taxonomy class and retry classification" {
    try std.testing.expect(class(error.TransportTransient) == .retryable_transport);
    try std.testing.expect(class(error.TransportFatal) == .fatal_transport);
    try std.testing.expect(class(error.BadFrame) == .parse);

    try std.testing.expect(retryable(error.TransportTransient));
    try std.testing.expect(!retryable(error.TransportFatal));
    try std.testing.expect(!retryable(error.BadFrame));
}

test "adapter maps provider errors into canonical taxonomy" {
    var ctx = MapCtx{};
    const ad = Adapter.from(MapCtx, &ctx, mapRaw);

    try std.testing.expectEqual(error.TransportTransient, ad.map(error.Timeout));
    try std.testing.expectEqual(error.TransportTransient, ad.map(error.WireBreak));
    try std.testing.expectEqual(error.TransportFatal, ad.map(error.Closed));
    try std.testing.expectEqual(error.OutOfMemory, ad.map(error.OutOfMemory));
    try std.testing.expectEqual(@as(usize, 4), ctx.calls);
}

test "isOverflowError: anthropic JSON" {
    const a = std.testing.allocator;
    try std.testing.expect(isOverflowError(a,
        \\{"error":{"type":"request_too_large","message":"too big"}}
    ));
}

test "isOverflowError: openai JSON" {
    const a = std.testing.allocator;
    try std.testing.expect(isOverflowError(a,
        \\{"error":{"code":"context_length_exceeded","message":"too long"}}
    ));
}

test "isOverflowError: substring fallback" {
    const a = std.testing.allocator;
    try std.testing.expect(isOverflowError(a, "request_too_large blah"));
}

test "isOverflowError: HTTP 413" {
    const a = std.testing.allocator;
    try std.testing.expect(isOverflowError(a, "413 Request Entity Too Large"));
}

test "isOverflowError: reject generic 400" {
    const a = std.testing.allocator;
    try std.testing.expect(!isOverflowError(a, "400 Bad Request"));
}

test "isOverflowError: reject malformed JSON" {
    const a = std.testing.allocator;
    try std.testing.expect(!isOverflowError(a, "{not json"));
}

test "isOverflowError: empty string" {
    const a = std.testing.allocator;
    try std.testing.expect(!isOverflowError(a, ""));
}

// Property: isOverflowError never crashes on arbitrary input
test "isOverflowError property: no crash on random input" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            // Must not crash/panic on any input
            _ = isOverflowError(std.testing.allocator, args.input.slice());
            return true;
        }
    }.prop, .{ .iterations = 500 });
}
