//! Test helper: tool result snapshot formatting.
const std = @import("std");

pub fn resultAlloc(alloc: std.mem.Allocator, res: anytype) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);

    const w = buf.writer(alloc);
    try w.print("call={s}\nstart={}\nend={}\nout={}\n", .{
        res.call_id,
        res.started_at_ms,
        res.ended_at_ms,
        res.out.len,
    });
    for (res.out, 0..) |row, i| {
        try w.print("{d}={s}|{d}|{s}|{}|{s}\n", .{
            i,
            row.call_id,
            row.at_ms,
            @tagName(row.stream),
            row.truncated,
            row.chunk,
        });
    }

    try w.print("final={s}", .{@tagName(std.meta.activeTag(res.final))});
    switch (res.final) {
        .ok => |ok| try w.print("|{d}\n", .{ok.code}),
        .failed => |failed| try w.print("|{s}|{s}|{}\n", .{
            @tagName(failed.kind),
            failed.msg,
            .{failed.code},
        }),
        .cancelled => |cancelled| try w.print("|{s}\n", .{@tagName(cancelled.reason)}),
        .timed_out => |timed_out| try w.print("|{d}\n", .{timed_out.limit_ms}),
    }
    return buf.toOwnedSlice(alloc);
}
