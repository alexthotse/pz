const std = @import("std");
const agent = @import("core_agent");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const alloc = arena.allocator();
    const argv = try std.process.argsAlloc(alloc);
    if (argv.len != 2) return error.InvalidArgs;

    if (std.mem.eql(u8, argv[1], "version")) {
        agent.exitOnVersionMismatch(error.UnsupportedVersion);
        return error.TestUnexpectedResult;
    }
    if (std.mem.eql(u8, argv[1], "other")) {
        agent.exitOnVersionMismatch(error.EmptyPrompt);
        return;
    }

    return error.InvalidArgs;
}
