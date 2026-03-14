const std = @import("std");
const core = @import("../../core/mod.zig");

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
