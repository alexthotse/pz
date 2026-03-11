const std = @import("std");
const policy = @import("../core/policy.zig");
const stream_parse = @import("../core/providers/stream_parse.zig");
const providers = @import("../core/providers/contract.zig");

test "perf fuzz policy evaluate sustains ten million ops" {
    const rules = [_]policy.Rule{
        .{ .pattern = "*", .effect = .allow },
        .{ .pattern = "*.audit.log", .effect = .deny },
        .{ .pattern = ".pz/*", .effect = .deny },
        .{ .pattern = "*.session", .effect = .deny },
        .{ .pattern = "src/*.zig", .effect = .allow, .tool = "read" },
        .{ .pattern = "src/*.zig", .effect = .deny, .tool = "write" },
    };

    var seed: u64 = 0xA11C_E55E_5EED_F12A;
    var buf: [32]u8 = undefined;
    var allow_ct: usize = 0;
    var deny_ct: usize = 0;

    var i: usize = 0;
    while (i < 10_000_000) : (i += 1) {
        seed = seed *% 6364136223846793005 +% 1;
        var n: usize = 0;
        while (n < 12) : (n += 1) {
            const x = @as(u8, @truncate(seed >> @intCast((n & 7) * 8)));
            buf[n] = "abcdefghijklmnopqrstuvwxyz0123456789._/"[x % 39];
        }
        const path = switch (i & 15) {
            0 => ".pz/auth",
            1 => "trace.audit.log",
            2 => "cache.session",
            else => buf[0..12],
        };
        const tool = switch (i & 3) {
            0 => null,
            1 => "read",
            2 => "write",
            else => "bash",
        };
        switch (policy.evaluate(&rules, path, tool)) {
            .allow => allow_ct += 1,
            .deny => deny_ct += 1,
        }
    }

    try std.testing.expect(allow_ct > 0);
    try std.testing.expect(deny_ct > 0);
}

test "perf fuzz stream parser malformed frames stay typed" {
    const iters: usize = 100_000;
    var prng = std.Random.DefaultPrng.init(0xC0DE_5EED_F12A);
    const rnd = prng.random();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var i: usize = 0;
    while (i < iters) : (i += 1) {
        _ = arena.reset(.retain_capacity);
        const ar = arena.allocator();

        var parser = stream_parse.Parser{};
        defer parser.deinit(ar);
        var evs: std.ArrayListUnmanaged(providers.Ev) = .empty;
        defer evs.deinit(ar);

        const n = rnd.intRangeAtMost(usize, 1, 48);
        var raw: [64]u8 = undefined;
        rnd.bytes(raw[0..n]);
        for (raw[0..n]) |*b| {
            if (b.* == '\n' or b.* == '\r' or b.* == 0) b.* = 'x';
        }

        var payload: [80]u8 = undefined;
        @memcpy(payload[0..n], raw[0..n]);
        @memcpy(payload[n .. n + 11], "\nstop:done\n");
        parser.feed(ar, &evs, payload[0 .. n + 11]) catch |err| switch (err) {
            error.BadFrame,
            error.UnknownTag,
            error.InvalidUsage,
            error.UnknownStop,
            error.OutOfMemory,
            => continue,
            else => return err,
        };
        parser.finish(ar, &evs) catch |err| switch (err) {
            error.BadFrame,
            error.UnknownTag,
            error.InvalidUsage,
            error.UnknownStop,
            error.OutOfMemory,
            => continue,
            else => return err,
        };
    }
}
