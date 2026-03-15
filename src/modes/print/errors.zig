//! Print mode error types and result union.
const std = @import("std");
const core = @import("../../core.zig");

pub const Err = error{
    PromptWrite,
    ProviderStart,
    StreamRead,
    OutputFormat,
    EventWrite,
    OutputFlush,
};

pub const Result = union(enum) {
    ok,
    stop: core.providers.StopReason,
};

pub const Exit = struct {
    code: u8,
    msg: []const u8,
};

pub fn mapErr(err: Err) Exit {
    return switch (err) {
        error.PromptWrite => .{ .code = 10, .msg = "print: failed to persist prompt" },
        error.ProviderStart => .{ .code = 11, .msg = "print: provider failed to start stream" },
        error.StreamRead => .{ .code = 12, .msg = "print: provider stream read failed" },
        error.OutputFormat => .{ .code = 13, .msg = "print: failed to format output event" },
        error.EventWrite => .{ .code = 14, .msg = "print: failed to persist stream event" },
        error.OutputFlush => .{ .code = 15, .msg = "print: failed to flush formatted output" },
    };
}

pub fn mapResult(result: Result) ?Exit {
    return switch (result) {
        .ok => null,
        .stop => |reason| switch (reason) {
            .done => null,
            .max_out => .{ .code = 16, .msg = "print: provider stopped at max output" },
            .tool => .{ .code = 17, .msg = "print: provider stopped for tool handoff" },
            .canceled => .{ .code = 18, .msg = "print: provider stream canceled" },
            .err => .{ .code = 19, .msg = "print: provider reported terminal error" },
        },
    };
}

test "mapErr returns stable exit codes" {
    const cases = [_]struct { err: Err, code: u8 }{
        .{ .err = error.PromptWrite, .code = 10 },
        .{ .err = error.ProviderStart, .code = 11 },
        .{ .err = error.StreamRead, .code = 12 },
        .{ .err = error.OutputFormat, .code = 13 },
        .{ .err = error.EventWrite, .code = 14 },
        .{ .err = error.OutputFlush, .code = 15 },
    };
    for (cases) |c| {
        try std.testing.expectEqual(c.code, mapErr(c.err).code);
    }
}

test "mapResult ok returns null" {
    try std.testing.expectEqual(@as(?Exit, null), mapResult(.ok));
}

test "mapResult stop done returns null" {
    try std.testing.expectEqual(@as(?Exit, null), mapResult(.{ .stop = .done }));
}

test "mapResult stop non-done returns exit" {
    const cases = [_]struct { reason: core.providers.StopReason, code: u8 }{
        .{ .reason = .max_out, .code = 16 },
        .{ .reason = .tool, .code = 17 },
        .{ .reason = .canceled, .code = 18 },
        .{ .reason = .err, .code = 19 },
    };
    for (cases) |c| {
        const exit = mapResult(.{ .stop = c.reason }) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(c.code, exit.code);
    }
}
