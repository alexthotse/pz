//! Test harness: agent exit-code scenarios.
const std = @import("std");
const agent = @import("core_agent");

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const alloc = arena.allocator();
    
    var args_it = try init.minimal.args.iterateAllocator(alloc);
    defer args_it.deinit();

    var argv_list = std.ArrayList([]const u8).init(alloc);
    defer argv_list.deinit();
    while (args_it.next()) |arg| {
        try argv_list.append(arg);
    }
    const argv = argv_list.items;
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
