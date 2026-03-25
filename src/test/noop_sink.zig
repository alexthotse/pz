//! Shared noop event sink for tool tests.
const tools = @import("../core/tools.zig");

pub const Impl = struct {
    sink: tools.Sink = .{ .vt = &Bind.vt },
    pub fn push(_: *@This(), _: tools.Event) !void {}
    const Bind = tools.Sink.Bind(@This(), push);
};

var global_impl: Impl = .{};

/// Return a `*tools.Sink` that silently discards all events.
pub fn sink() *tools.Sink {
    return &global_impl.sink;
}
