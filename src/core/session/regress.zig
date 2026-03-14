//! Session persistence regression tests.
const std = @import("std");
const writer = @import("writer.zig");
const reader = @import("reader.zig");
const compact = @import("compact.zig");
const retry_state = @import("retry_state.zig");

test "session persistence regression covers compacted replay and retry restore" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{
            .always = {},
        },
    });

    try wr.append("sid-1", .{
        .at_ms = 1,
        .data = .{
            .prompt = .{ .text = "ship" },
        },
    });
    try wr.append("sid-1", .{
        .at_ms = 2,
        .data = .{
            .noop = {},
        },
    });
    try wr.append("sid-1", .{
        .at_ms = 3,
        .data = .{
            .tool_result = .{
                .id = "c1",
                .output = "ok",
                .is_err = false,
            },
        },
    });

    try retry_state.save(std.testing.allocator, tmp.dir, "sid-1", .{
        .tries_done = 2,
        .fail_count = 1,
        .next_wait_ms = 100,
        .last_err = .transient,
    });

    _ = try compact.run(std.testing.allocator, tmp.dir, "sid-1", 999);

    var rdr = try reader.ReplayReader.init(std.testing.allocator, tmp.dir, "sid-1", .{});
    defer rdr.deinit();

    const ev0 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    switch (ev0.data) {
        .prompt => |prompt| try std.testing.expectEqualStrings("ship", prompt.text),
        else => return error.TestUnexpectedResult,
    }

    const ev1 = (try rdr.next()) orelse return error.TestUnexpectedResult;
    try oh.snap(@src(),
        \\core.session.schema.Event
        \\  .version: u16 = 1
        \\  .at_ms: i64 = 3
        \\  .data: core.session.schema.Event.Data
        \\    .tool_result: core.session.schema.Event.ToolResult
        \\      .id: []const u8
        \\        "c1"
        \\      .output: []const u8
        \\        "ok"
        \\      .is_err: bool = false
    ).expectEqual(ev1);
    try std.testing.expect((try rdr.next()) == null);

    const rs = (try retry_state.load(std.testing.allocator, tmp.dir, "sid-1")) orelse {
        return error.TestUnexpectedResult;
    };
    try oh.snap(@src(),
        \\core.session.retry_state.State
        \\  .version: u16 = 1
        \\  .tries_done: u16 = 2
        \\  .fail_count: u16 = 1
        \\  .next_wait_ms: u64 = 100
        \\  .last_err: core.session.retry_state.ErrKind = .transient
    ).expectEqual(rs);
}
