//! Shared noop event sink for tool tests.
const tools = @import("../core/tools.zig");

pub const Impl = struct {
    pub fn push(_: *@This(), _: tools.Event) !void {}
};

/// Return a `tools.Sink` that silently discards all events.
pub fn sink() tools.Sink {
    const S = struct {
        var impl: Impl = .{};
    };
    return tools.Sink.from(Impl, &S.impl, Impl.push);
}
