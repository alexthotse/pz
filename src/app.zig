//! Application layer: CLI parsing, config, and runtime orchestration.
const std = @import("std");

pub const args = @import("app/args.zig");
pub const cli = @import("app/cli.zig");
pub const config = @import("app/config.zig");
pub const report = @import("app/report.zig");
pub const runtime = @import("app/runtime.zig");
pub const update = @import("app/update.zig");

pub fn run(init: std.process.Init) !void {
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
    var env = try config.Env.fromProcess(alloc);
    defer env.deinit(alloc);
    var out = std.fs.File.stdout().deprecatedWriter();

    var cmd = cli.parse(alloc, std.fs.cwd(), argv[1..], env) catch |err| {
        if (err == error.OutOfMemory) return err;
        const msg = try report.cli(alloc, "parse arguments", err);
        defer alloc.free(msg);
        try out.writeAll(msg);
        std.process.exit(1);
    };
    defer cmd.deinit(alloc);

    switch (cmd) {
        .help => |txt| try out.writeAll(txt),
        .version => |txt| try out.writeAll(txt),
        .changelog => |txt| try out.writeAll(txt),
        .upgrade => {
            const outcome = try update.runOutcome(alloc, env.home);
            defer outcome.deinit(alloc);
            try out.writeAll(outcome.msg);
        },
        .run => |run_cmd| {
            const sid = runtime.exec(alloc, run_cmd) catch |err| {
                if (err == error.OutOfMemory) return err;
                const msg = try report.cli(alloc, "run command", err);
                defer alloc.free(msg);
                try out.writeAll(msg);
                std.process.exit(1);
            };
            alloc.free(sid);
        },
    }
}
