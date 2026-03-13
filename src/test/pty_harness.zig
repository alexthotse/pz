const std = @import("std");
const build_options = @import("build_options");
const vscreen = @import("../modes/tui/vscreen.zig");
const ansi_ast = @import("ansi_ast.zig");

const RunOut = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *RunOut, alloc: std.mem.Allocator) void {
        alloc.free(self.stdout);
        alloc.free(self.stderr);
        self.* = undefined;
    }
};

fn pzBinAlloc(alloc: std.mem.Allocator) ![]u8 {
    return try std.fs.cwd().realpathAlloc(alloc, build_options.pz_bin_path);
}

fn baseEnv(alloc: std.mem.Allocator, home_abs: []const u8) !std.process.EnvMap {
    var env = try std.process.getEnvMap(alloc);
    errdefer env.deinit();
    try env.put("HOME", home_abs);
    try env.put("TERM", "xterm-256color");
    try env.put("COLUMNS", "100");
    try env.put("LINES", "32");
    try env.put("PZ_SKIP_VERSION_CHECK", "1");
    return env;
}

fn runPty(
    alloc: std.mem.Allocator,
    cwd: []const u8,
    env: *const std.process.EnvMap,
    argv: []const []const u8,
    input: []const u8,
) !RunOut {
    var child = std.process.Child.init(argv, alloc);
    child.cwd = cwd;
    child.env_map = env;
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();

    if (child.stdin) |*stdin| {
        try stdin.writeAll(input);
        stdin.close();
        child.stdin = null;
    }

    const stdout = try (child.stdout orelse return error.TestUnexpectedResult).readToEndAlloc(alloc, 1024 * 1024);
    errdefer alloc.free(stdout);
    const stderr = try (child.stderr orelse return error.TestUnexpectedResult).readToEndAlloc(alloc, 256 * 1024);
    errdefer alloc.free(stderr);

    const term = try child.wait();
    return .{
        .term = term,
        .stdout = stdout,
        .stderr = stderr,
    };
}

fn runPzPty(
    alloc: std.mem.Allocator,
    cwd: []const u8,
    env: *const std.process.EnvMap,
    pz_args: []const []const u8,
    input: []const u8,
) !RunOut {
    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);
    try argv.appendSlice(alloc, &.{ "/usr/bin/script", "-q", "/dev/null", pz_bin });
    try argv.appendSlice(alloc, pz_args);
    return runPty(alloc, cwd, env, argv.items, input);
}

fn screenHasText(vs: *const vscreen.VScreen, alloc: std.mem.Allocator, needle: []const u8) !bool {
    var r: usize = 0;
    while (r < vs.h) : (r += 1) {
        const row = try vs.rowText(alloc, r);
        defer alloc.free(row);
        if (std.mem.indexOf(u8, row, needle) != null) return true;
    }
    return false;
}

fn countNonEmptyRows(vs: *const vscreen.VScreen, alloc: std.mem.Allocator) !usize {
    var out: usize = 0;
    var r: usize = 0;
    while (r < vs.h) : (r += 1) {
        const row = try vs.rowText(alloc, r);
        defer alloc.free(row);
        if (row.len > 0) out += 1;
    }
    return out;
}

test "real pz PTY startup renders tui frame and quits cleanly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPty(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-config", "--no-session" },
        "/quit\n",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "\x1b[?1049h") != null);

    var vs = try vscreen.VScreen.init(std.testing.allocator, 100, 32);
    defer vs.deinit();
    vs.feed(out.stdout);

    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const ops = try ansi_ast.parseAlloc(std.testing.allocator, out.stdout);
    defer ansi_ast.freeOps(std.testing.allocator, ops);

    var ctl_buf = std.ArrayList(u8).empty;
    defer ctl_buf.deinit(std.testing.allocator);
    var kept: usize = 0;
    for (ops) |op| {
        if (kept >= 10) break;
        switch (op) {
            .text => continue,
            .csi => |csi| {
                try ctl_buf.appendSlice(std.testing.allocator, "csi ");
                if (csi.prefix) |p| try ctl_buf.append(std.testing.allocator, p);
                try ctl_buf.append(std.testing.allocator, csi.final);
                try ctl_buf.append(std.testing.allocator, ' ');
                for (csi.params, 0..) |param, idx| {
                    if (idx > 0) try ctl_buf.append(std.testing.allocator, ',');
                    try ctl_buf.writer(std.testing.allocator).print("{d}", .{param});
                }
                try ctl_buf.append(std.testing.allocator, '\n');
            },
            .osc => |payload| {
                const head = std.mem.indexOfScalar(u8, payload, ';') orelse payload.len;
                try ctl_buf.appendSlice(std.testing.allocator, "osc ");
                try ctl_buf.appendSlice(std.testing.allocator, payload[0..head]);
                try ctl_buf.append(std.testing.allocator, '\n');
            },
            .esc => |raw| {
                try ctl_buf.writer(std.testing.allocator).print("esc {d}\n", .{raw.len});
            },
        }
        kept += 1;
    }
    const ctl = try ctl_buf.toOwnedSlice(std.testing.allocator);
    defer std.testing.allocator.free(ctl);

    try oh.snap(@src(),
        \\[]u8
        \\  "csi ?h 1049
        \\csi ?l 25
        \\csi ?h 2004
        \\csi >u 1
        \\osc 0
        \\osc 0
        \\csi u 0
        \\csi ?l 2004
        \\csi ?l 1006
        \\csi ?l 1000
        \\"
    ).expectEqual(ctl);

    try std.testing.expect((try countNonEmptyRows(&vs, std.testing.allocator)) >= 1);
}

test "real pz binary print mode works without tui" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    const provider_cmd = "cat >/dev/null; printf 'text:pong\\nstop:done\\n'";
    var out = try runPty(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-config",
            "--no-session",
            "--mode",
            "print",
            "--provider-cmd",
            provider_cmd,
            "--prompt",
            "ping",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "pong") != null);
}

test "real pz binary json mode consumes stdin prompts" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    const provider_cmd =
        "req=$(cat); " ++
        "model=$(printf '%s' \"$req\" | grep -o '\"model\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "prov=$(printf '%s' \"$req\" | grep -o '\"provider\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:model=%s provider=%s\\nstop:done\\n' \"$model\" \"$prov\"";
    var out = try runPty(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-config",
            "--no-session",
            "--mode",
            "json",
            "--model",
            "cfg-json-model",
            "--provider",
            "cfg-json-provider",
            "--provider-cmd",
            provider_cmd,
        },
        "from-stdin\n",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "\"type\":\"provider\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "model=cfg-json-model provider=cfg-json-provider") != null);
}

test "real pz binary json mode rejects empty stdin without prompt" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    var out = try runPty(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-config",
            "--no-session",
            "--mode",
            "json",
            "--provider-cmd",
            "cat >/dev/null; printf 'text:noop\\nstop:done\\n'",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "reason: EmptyPrompt") != null);
}

test "real pz PTY renders slash help over the live terminal path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPty(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-config", "--no-session" },
        "/help\n/quit\n",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "/help") != null);

    var vs = try vscreen.VScreen.init(std.testing.allocator, 100, 32);
    defer vs.deinit();
    vs.feed(out.stdout);
    try std.testing.expect((try countNonEmptyRows(&vs, std.testing.allocator)) >= 1);
}
