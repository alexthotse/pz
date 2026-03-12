const builtin = @import("builtin");
const std = @import("std");
const agent = @import("core_agent");

const Mode = enum {
    hello,
    echo,
    mismatch,
    fd_report,
    pgid_report,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const alloc = arena.allocator();
    const argv = try std.process.argsAlloc(alloc);
    if (argv.len != 4) return error.InvalidArgs;

    const mode = std.meta.stringToEnum(Mode, argv[1]) orelse return error.InvalidArgs;
    const agent_id = argv[2];
    const pol_hash = argv[3];
    const stdout_file = std.fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout = stdout_file.writerStreaming(&stdout_buf);
    try writeHello(alloc, &stdout.interface, 1, agent_id, switch (mode) {
        .mismatch => try mutateHashAlloc(alloc, pol_hash),
        else => pol_hash,
    });
    if (mode == .hello or mode == .mismatch) return;

    var seq: u32 = 2;
    const stdin_file = std.fs.File.stdin();
    var stdin_buf: [4096]u8 = undefined;
    var stdin = stdin_file.readerStreaming(&stdin_buf);
    while (try readFrameAlloc(alloc, &stdin.interface)) |frame| {
        switch (frame.msg) {
            .hello => {},
            .run => |run| {
                const txt = switch (mode) {
                    .echo => try std.fmt.allocPrint(alloc, "echo:{s}", .{run.prompt}),
                    .fd_report => try listOpenFdsAlloc(alloc),
                    .pgid_report => try pgidReportAlloc(alloc),
                    else => unreachable,
                };
                try writeFrame(alloc, &stdout.interface, seq, .{
                    .out = .{
                        .id = run.id,
                        .kind = .info,
                        .text = txt,
                    },
                });
                seq += 1;
                try writeFrame(alloc, &stdout.interface, seq, .{
                    .done = .{
                        .id = run.id,
                        .stop = .done,
                    },
                });
                seq += 1;
            },
            .cancel => |cancel| {
                try writeFrame(alloc, &stdout.interface, seq, .{
                    .done = .{
                        .id = cancel.id,
                        .stop = .canceled,
                    },
                });
                seq += 1;
            },
            else => return error.UnexpectedMsg,
        }
    }
}

fn writeHello(
    alloc: std.mem.Allocator,
    stdout: anytype,
    seq: u32,
    agent_id: []const u8,
    pol_hash: []const u8,
) !void {
    try writeFrame(alloc, stdout, seq, .{
        .hello = .{
            .role = .child,
            .agent_id = agent_id,
            .policy_hash = pol_hash,
        },
    });
}

fn writeFrame(alloc: std.mem.Allocator, stdout: anytype, seq: u32, msg: agent.Msg) !void {
    const raw = try agent.encodeLineAlloc(alloc, .{
        .protocol_version = agent.protocol_version,
        .seq = seq,
        .msg = msg,
    });
    defer alloc.free(raw);
    try stdout.writeAll(raw);
    try stdout.flush();
}

fn readFrameAlloc(alloc: std.mem.Allocator, stdin: anytype) !?agent.Frame {
    const line = try stdin.takeDelimiter('\n');
    const raw = line orelse return null;
    const parsed = try agent.decodeSlice(alloc, raw);
    return parsed.value;
}

fn mutateHashAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]const u8 {
    var out = try alloc.dupe(u8, raw);
    out[0] = if (out[0] == '0') '1' else '0';
    return out;
}

fn listOpenFdsAlloc(alloc: std.mem.Allocator) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var first = true;
    var fd: std.posix.fd_t = 0;
    while (fd < 64) : (fd += 1) {
        switch (std.posix.errno(std.posix.system.fcntl(fd, std.posix.F.GETFD, @as(c_int, 0)))) {
            .SUCCESS => {},
            .BADF => continue,
            else => |err| return std.posix.unexpectedErrno(err),
        }
        if (!first) try out.append(alloc, ',');
        first = false;
        try out.writer(alloc).print("{d}", .{fd});
    }
    return out.toOwnedSlice(alloc);
}

fn pgidReportAlloc(alloc: std.mem.Allocator) ![]u8 {
    if (builtin.os.tag == .windows) return alloc.dupe(u8, "pid=0 pgid=0");
    const LibC = struct {
        extern "c" fn getpgrp() c_int;
    };
    const pid = std.c.getpid();
    const pgid = LibC.getpgrp();
    return std.fmt.allocPrint(alloc, "pid={d} pgid={d}", .{ pid, pgid });
}
