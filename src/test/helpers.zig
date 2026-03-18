const std = @import("std");
const OhSnap = @import("ohsnap");

pub fn expectSnapText(comptime src: std.builtin.SourceLocation, comptime body: []const u8, actual: anytype) !void {
    const oh = OhSnap{};
    const snap = comptime std.fmt.comptimePrint("{s}\n  \"{s}\"", .{
        @typeName(@TypeOf(actual)),
        body,
    });
    try oh.snap(src, snap).expectEqual(actual);
}

test {
    _ = OhSnap;
}
