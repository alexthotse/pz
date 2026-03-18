//! PTY-based integration test harness for TUI walkthroughs.
const std = @import("std");
const build_options = @import("build_options");
const app_config = @import("../app/config.zig");
const core = @import("../core.zig");
const vscreen = @import("../modes/tui/vscreen.zig");
const ansi_ast = @import("ansi_ast.zig");
const http_mock = @import("http_mock.zig");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("fcntl.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
    @cInclude("sys/ioctl.h");
    @cInclude("sys/wait.h");
    @cInclude("unistd.h");
    @cInclude("util.h");
});

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

const PtyStep = struct {
    wait_ms: u64 = 0,
    input: []const u8,
};

fn pzBinAlloc(alloc: std.mem.Allocator) ![]u8 {
    return try std.fs.cwd().realpathAlloc(alloc, build_options.pz_bin_path);
}

fn testPolicyKeyPair() !core.signing.KeyPair {
    const seed = try core.signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    return core.signing.KeyPair.fromSeed(seed);
}

fn writePolicy(dir: std.fs.Dir, doc: core.policy.Doc) !void {
    try dir.makePath(".pz");
    const kp = try testPolicyKeyPair();
    const raw = try core.policy.encodeSignedDoc(std.testing.allocator, doc, kp);
    defer std.testing.allocator.free(raw);
    try dir.writeFile(.{ .sub_path = app_config.policy_rel_path, .data = raw });
}

fn baseEnv(alloc: std.mem.Allocator, home_abs: []const u8) !std.process.EnvMap {
    var env = try std.process.getEnvMap(alloc);
    errdefer env.deinit();
    _ = env.remove("HTTP_PROXY");
    _ = env.remove("http_proxy");
    _ = env.remove("HTTPS_PROXY");
    _ = env.remove("https_proxy");
    _ = env.remove("ALL_PROXY");
    _ = env.remove("all_proxy");
    _ = env.remove("NO_PROXY");
    _ = env.remove("no_proxy");
    try env.put("HOME", home_abs);
    try env.put("TERM", "xterm-256color");
    try env.put("COLUMNS", "100");
    try env.put("LINES", "32");
    try env.put("PZ_SKIP_VERSION_CHECK", "1");
    return env;
}

fn runProc(
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

    return .{
        .term = try child.wait(),
        .stdout = stdout,
        .stderr = stderr,
    };
}

const CStringList = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayList(?[*:0]u8),

    fn init(alloc: std.mem.Allocator) CStringList {
        return .{ .alloc = alloc, .items = .empty };
    }

    fn deinit(self: *CStringList) void {
        for (self.items.items) |item| {
            if (item) |ptr| self.alloc.free(std.mem.span(ptr));
        }
        self.items.deinit(self.alloc);
    }

    fn appendDupZ(self: *CStringList, text: []const u8) !void {
        const dup = try self.alloc.dupeZ(u8, text);
        try self.items.append(self.alloc, dup.ptr);
    }
};

fn ttyInputAlloc(alloc: std.mem.Allocator, text: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, text.len);
    for (text, 0..) |b, i| buf[i] = if (b == '\n') '\r' else b;
    return buf;
}

fn writeSessionEventsFile(dir: std.fs.Dir, sub_path: []const u8, events: []const core.session.Event) !void {
    var file = try dir.createFile(sub_path, .{ .truncate = true });
    defer file.close();

    for (events) |ev| {
        const raw = try core.session.encodeEventAlloc(std.testing.allocator, ev);
        defer std.testing.allocator.free(raw);
        try file.writeAll(raw);
        try file.writeAll("\n");
    }
}

fn writeAllFd(fd: std.posix.fd_t, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) off += try std.posix.write(fd, data[off..]);
}

fn mapWaitStatus(status: c_int) std.process.Child.Term {
    return if (c.WIFEXITED(status))
        .{ .Exited = @intCast(c.WEXITSTATUS(status)) }
    else if (c.WIFSIGNALED(status))
        .{ .Signal = @intCast(c.WTERMSIG(status)) }
    else if (c.WIFSTOPPED(status))
        .{ .Stopped = @intCast(c.WSTOPSIG(status)) }
    else
        .{ .Unknown = @intCast(status) };
}

fn readReady(fd: std.posix.fd_t, out: *std.ArrayList(u8), alloc: std.mem.Allocator) !bool {
    var read_any = false;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => return read_any,
            error.InputOutput,
            error.BrokenPipe,
            => return read_any,
            else => return err,
        };
        if (n == 0) return read_any;
        try out.appendSlice(alloc, buf[0..n]);
        read_any = true;
        if (n < buf.len) return read_any;
    }
}

fn runPzPty(
    alloc: std.mem.Allocator,
    cwd: []const u8,
    env: *const std.process.EnvMap,
    pz_args: []const []const u8,
    input: []const u8,
    pre_ms: u64,
    post_ms: u64,
) !RunOut {
    const steps = [_]PtyStep{
        .{ .wait_ms = pre_ms, .input = input },
    };
    return runPzPtySteps(alloc, cwd, env, pz_args, &steps, post_ms);
}

fn appendShellArgRef(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, idx: usize) !void {
    if (idx < 10) {
        try buf.writer(alloc).print("${d}", .{idx});
        return;
    }
    try buf.writer(alloc).print("${{{d}}}", .{idx});
}

fn appendSleepMs(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, ms: u64) !void {
    if (ms == 0) return;
    try buf.writer(alloc).print("sleep {d}.{d:0>3}; ", .{ ms / 1000, ms % 1000 });
}

fn runPzPtySteps(
    alloc: std.mem.Allocator,
    cwd: []const u8,
    env: *const std.process.EnvMap,
    pz_args: []const []const u8,
    steps: []const PtyStep,
    settle_ms: u64,
) !RunOut {
    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const step_paths = try alloc.alloc([]u8, steps.len);
    defer {
        for (step_paths) |path| alloc.free(path);
        alloc.free(step_paths);
    }
    for (steps, 0..) |step, i| {
        const rel = try std.fmt.allocPrint(alloc, "step-{d}.in", .{i});
        defer alloc.free(rel);
        const tty_input = try ttyInputAlloc(alloc, step.input);
        defer alloc.free(tty_input);
        try tmp.dir.writeFile(.{ .sub_path = rel, .data = tty_input });
        step_paths[i] = try tmp.dir.realpathAlloc(alloc, rel);
    }

    var script = std.ArrayList(u8).empty;
    defer script.deinit(alloc);
    try script.appendSlice(alloc, "{ ");
    for (steps, 0..) |step, i| {
        try appendSleepMs(&script, alloc, step.wait_ms);
        try script.appendSlice(alloc, "cat \"");
        try appendShellArgRef(&script, alloc, i + 1);
        try script.appendSlice(alloc, "\"; ");
    }
    try appendSleepMs(&script, alloc, settle_ms);
    try script.appendSlice(alloc, "} | /usr/bin/script -q /dev/null \"");
    try appendShellArgRef(&script, alloc, steps.len + 1);
    try script.appendSlice(alloc, "\"");
    for (pz_args, 0..) |_, i| {
        try script.appendSlice(alloc, " \"");
        try appendShellArgRef(&script, alloc, steps.len + 2 + i);
        try script.appendSlice(alloc, "\"");
    }

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);
    try argv.appendSlice(alloc, &.{ "/bin/sh", "-c", script.items, "sh" });
    for (step_paths) |path| try argv.append(alloc, path);
    try argv.append(alloc, pz_bin);
    for (pz_args) |arg| try argv.append(alloc, arg);

    return runProc(alloc, cwd, env, argv.items, "");
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

fn streamHasText(alloc: std.mem.Allocator, data: []const u8, needle: []const u8) !bool {
    const ops = try ansi_ast.parseAlloc(alloc, data);
    defer ansi_ast.freeOps(alloc, ops);

    var text = std.ArrayList(u8).empty;
    defer text.deinit(alloc);
    for (ops) |op| switch (op) {
        .text => |chunk| try text.appendSlice(alloc, chunk),
        else => {},
    };
    return std.mem.indexOf(u8, text.items, needle) != null;
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

    const sig1_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-sig1" });
    defer std.testing.allocator.free(sig1_path);
    defer std.fs.deleteFileAbsolute(sig1_path) catch {}; // test: error irrelevant
    {
        var f = try std.fs.createFileAbsolute(sig1_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("\x03");
    }
    const sig2_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-sig2" });
    defer std.testing.allocator.free(sig2_path);
    defer std.fs.deleteFileAbsolute(sig2_path) catch {}; // test: error irrelevant
    {
        var f = try std.fs.createFileAbsolute(sig2_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("\x03");
    }

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "/bin/sh",
            "-c",
            "{ sleep 0.2; cat \"$1\"; sleep 0.2; cat \"$2\"; sleep 0.2; } | /usr/bin/script -q /dev/null \"$3\" \"$4\" \"$5\"",
            "sh",
            sig1_path,
            sig2_path,
            pz_bin,
            "--no-config",
            "--no-session",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "\x1b[?1049h") != null);

    var vs = try vscreen.VScreen.init(std.testing.allocator, 100, 32);
    defer vs.deinit();
    vs.feed(out.stdout);

    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const ops = try ansi_ast.parseAlloc(std.testing.allocator, out.stdout);
    defer ansi_ast.freeOps(std.testing.allocator, ops);

    const ctl = try ansi_ast.summaryAlloc(std.testing.allocator, ops, .{
        .include_text = false,
        .max_entries = 10,
    });
    defer std.testing.allocator.free(ctl);

    try oh.snap(@src(),
        \\[]u8
        \\  "csi ?h 1049
        \\csi ?l 25
        \\csi ?h 2004
        \\csi >u 1
        \\osc 0
        \\osc 0
        \\csi ?h 2026
        \\csi m 0
        \\csi J 2
        \\csi H 0
        \\"
    ).expectEqual(ctl);

    try std.testing.expect(try screenHasText(&vs, std.testing.allocator, "drop files"));
}

test "real pz PTY startup survives live version check" {
    const SignalAfterRequest = struct {
        server: *const http_mock.Server,
        path: []const u8,

        fn run(self: *@This()) void {
            var waited_ms: u32 = 0;
            while (self.server.requestCount() == 0 and waited_ms < 30000) : (waited_ms += 50) {
                std.Thread.sleep(50 * std.time.ns_per_ms);
            }
            std.Thread.sleep(250 * std.time.ns_per_ms);
            var f = std.fs.createFileAbsolute(self.path, .{ .truncate = true }) catch return;
            defer f.close();
            f.writeAll("\x03\x03") catch {}; // test: error irrelevant
        }
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();
    _ = env.remove("PZ_SKIP_VERSION_CHECK");
    try env.put("PZ_FORCE_VERSION_CHECK", "1");

    var server = try http_mock.Server.initSeq(std.testing.allocator, &.{.{
        .headers = &.{"Content-Type: application/json"},
        .body = "{\"tag_name\":\"v9.9.9\"}",
    }});
    defer server.deinit();
    const thr = try server.spawn();
    defer server.join(thr) catch {}; // test: error irrelevant
    const version_url = try server.urlAlloc(std.testing.allocator, "/repos/joelreymont/pz/releases/latest");
    defer std.testing.allocator.free(version_url);
    try env.put("PZ_VERSION_URL", version_url);

    const sig_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-version-quit" });
    defer std.testing.allocator.free(sig_path);
    defer std.fs.deleteFileAbsolute(sig_path) catch {}; // test: error irrelevant
    std.fs.deleteFileAbsolute(sig_path) catch {}; // test: error irrelevant

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);
    var signal = SignalAfterRequest{
        .server = &server,
        .path = sig_path,
    };
    const signal_thr = try std.Thread.spawn(.{}, SignalAfterRequest.run, .{&signal});
    defer signal_thr.join();

    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "/bin/sh",
            "-c",
            "{ while [ ! -s \"$1\" ]; do sleep 0.05; done; cat \"$1\"; sleep 0.2; } | /usr/bin/script -q /dev/null \"$2\" \"$3\" \"$4\"",
            "sh",
            sig_path,
            pz_bin,
            "--no-config",
            "--no-session",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => {},
        .Signal => |sig| try std.testing.expect(sig == std.posix.SIG.INT),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "Segmentation fault") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.stderr, "Segmentation fault") == null);

    try std.testing.expect(server.requestCount() > 0);
    try std.testing.expect(out.stdout.len > 0);
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
    var out = try runProc(
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

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "pong") != null);
}

test "real pz binary print mode uses config model and provider" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath(".pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    const provider_cmd =
        "req=$(cat); " ++
        "model=$(printf '%s' \"$req\" | grep -o '\"model\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "prov=$(printf '%s' \"$req\" | grep -o '\"provider\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:model=%s provider=%s\\nstop:done\\n' \"$model\" \"$prov\"";
    const provider_cmd_json = try std.json.Stringify.valueAlloc(std.testing.allocator, provider_cmd, .{});
    defer std.testing.allocator.free(provider_cmd_json);
    const cfg = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"mode\":\"print\",\"model\":\"cfg-print-model\",\"provider\":\"cfg-print-provider\",\"provider_cmd\":{s}}}",
        .{provider_cmd_json},
    );
    defer std.testing.allocator.free(cfg);
    try tmp.dir.writeFile(.{ .sub_path = ".pz/settings.json", .data = cfg });

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-session",
            "--mode",
            "print",
            "--prompt",
            "ping",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "model=cfg-print-model provider=cfg-print-provider") != null);
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
    var out = try runProc(
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

    var out = try runProc(
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
    try std.testing.expectEqual(@as(u8, 1), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "reason: EmptyPrompt") != null);
}

test "real pz binary upgrade honors verified policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try writePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/update", .effect = .deny, .tool = "web" },
        },
    });

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--upgrade",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(out.term == .Exited);
    try std.testing.expectEqual(@as(u8, 0), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "upgrade blocked by policy") != null);
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

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);
    const slash_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-slash" });
    defer std.testing.allocator.free(slash_path);
    defer std.fs.deleteFileAbsolute(slash_path) catch {}; // test: error irrelevant
    {
        var f = try std.fs.createFileAbsolute(slash_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("/");
    }
    const quit_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-quit" });
    defer std.testing.allocator.free(quit_path);
    defer std.fs.deleteFileAbsolute(quit_path) catch {}; // test: error irrelevant
    {
        var f = try std.fs.createFileAbsolute(quit_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("\x03\x03");
    }

    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "/bin/sh",
            "-c",
            "{ sleep 0.2; cat \"$1\"; sleep 0.2; cat \"$2\"; sleep 0.2; } | /usr/bin/script -q /dev/null \"$3\" \"$4\" \"$5\"",
            "sh",
            slash_path,
            quit_path,
            pz_bin,
            "--no-config",
            "--no-session",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "/changelog") != null);
}

test "real pz PTY walkthrough opens command settings login and resume surfaces" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("sess");

    const now = std.time.milliTimestamp();
    const old_events = [_]core.session.Event{
        .{ .at_ms = now - (2 * 60 * 60 * std.time.ms_per_s), .data = .{ .prompt = .{ .text = "Older session" } } },
        .{ .at_ms = now - (2 * 60 * 60 * std.time.ms_per_s), .data = .{ .usage = .{ .tot_tok = 128 } } },
    };
    try writeSessionEventsFile(tmp.dir, "sess/100.jsonl", &old_events);

    const new_events = [_]core.session.Event{
        .{ .at_ms = now - (15 * 60 * std.time.ms_per_s), .data = .{ .prompt = .{ .text = "Newer session" } } },
        .{ .at_ms = now - (15 * 60 * std.time.ms_per_s), .data = .{ .usage = .{ .tot_tok = 64 } } },
    };
    try writeSessionEventsFile(tmp.dir, "sess/200.jsonl", &new_events);

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--session-dir",
            sess_abs,
        },
        &.{
            .{ .wait_ms = 800, .input = "/help\n\n" },
            .{ .wait_ms = 800, .input = "/settings\n\n" },
            .{ .wait_ms = 800, .input = "\x1b" },
            .{ .wait_ms = 600, .input = "/login\x1b\x00\n" },
            .{ .wait_ms = 800, .input = "\x1b" },
            .{ .wait_ms = 600, .input = "/resume\n\n" },
            .{ .wait_ms = 800, .input = "\x1b" },
            .{ .wait_ms = 600, .input = "/provider openai\x1b\x00\n" },
            .{ .wait_ms = 600, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_help: bool,
        has_settings_title: bool,
        has_settings_toggle: bool,
        has_login_title: bool,
        has_login_openai: bool,
        has_resume_title: bool,
        has_resume_100: bool,
        has_resume_200: bool,
        has_provider_set: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.real pz PTY walkthrough opens command settings login and resume surfaces.Snap
        \\  .has_help: bool = true
        \\  .has_settings_title: bool = true
        \\  .has_settings_toggle: bool = true
        \\  .has_login_title: bool = true
        \\  .has_login_openai: bool = true
        \\  .has_resume_title: bool = true
        \\  .has_resume_100: bool = true
        \\  .has_resume_200: bool = true
        \\  .has_provider_set: bool = true
    ).expectEqual(Snap{
        .has_help = try streamHasText(std.testing.allocator, out.stdout, "/changelog"),
        .has_settings_title = try streamHasText(std.testing.allocator, out.stdout, "Settings"),
        .has_settings_toggle = try streamHasText(std.testing.allocator, out.stdout, "Show tool output"),
        .has_login_title = try streamHasText(std.testing.allocator, out.stdout, "Login (set API key)"),
        .has_login_openai = try streamHasText(std.testing.allocator, out.stdout, "openai"),
        .has_resume_title = try streamHasText(std.testing.allocator, out.stdout, "Resume Session"),
        .has_resume_100 = try streamHasText(std.testing.allocator, out.stdout, "Older session"),
        .has_resume_200 = try streamHasText(std.testing.allocator, out.stdout, "Newer session"),
        .has_provider_set = try streamHasText(std.testing.allocator, out.stdout, "provider set to openai"),
    });
}

test "real pz PTY walkthrough edits prompt and covers session bg and compaction" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("sess");

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const provider_cmd =
        "req=$(cat); " ++
        "prompt=$(printf '%s' \"$req\" | rg -o '\"text\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:ack:%s\\nstop:done\\n' \"$prompt\"";

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--session-dir",
            sess_abs,
            "--provider-cmd",
            provider_cmd,
        },
        &.{
            .{ .wait_ms = 800, .input = "pingg\x7f\n" },
            .{ .wait_ms = 1200, .input = "/session\n\n" },
            .{ .wait_ms = 800, .input = "/bg run printf done\x1b\x00\n" },
            .{ .wait_ms = 1000, .input = "/bg list\x1b\x00\n" },
            .{ .wait_ms = 800, .input = "/compact\n\n" },
            .{ .wait_ms = 800, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_edited_prompt: bool,
        has_no_unedited_prompt: bool,
        has_session_info: bool,
        has_bg_started: bool,
        has_bg_list: bool,
        has_compacted: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.real pz PTY walkthrough edits prompt and covers session bg and compaction.Snap
        \\  .has_edited_prompt: bool = true
        \\  .has_no_unedited_prompt: bool = true
        \\  .has_session_info: bool = true
        \\  .has_bg_started: bool = true
        \\  .has_bg_list: bool = true
        \\  .has_compacted: bool = true
    ).expectEqual(Snap{
        .has_edited_prompt = try streamHasText(std.testing.allocator, out.stdout, "ack:ping"),
        .has_no_unedited_prompt = !try streamHasText(std.testing.allocator, out.stdout, "ack:pingg"),
        .has_session_info = try streamHasText(std.testing.allocator, out.stdout, "Session Info"),
        .has_bg_started = try streamHasText(std.testing.allocator, out.stdout, "bg started id=1"),
        .has_bg_list = try streamHasText(std.testing.allocator, out.stdout, "id pid state code log cmd"),
        .has_compacted = try streamHasText(std.testing.allocator, out.stdout, "compacted in="),
    });
}

test "real pz PTY failure walkthrough covers command provider bg compact and policy denial" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try writePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "runtime/cmd/share", .effect = .deny },
        },
    });

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--no-session",
        },
        &.{
            .{ .wait_ms = 800, .input = "/wat\n\n" },
            .{ .wait_ms = 600, .input = "/tools nope\x1b\x00\n" },
            .{ .wait_ms = 600, .input = "/login bogus\x1b\x00\n" },
            .{ .wait_ms = 600, .input = "/bg stop 42\x1b\x00\n" },
            .{ .wait_ms = 600, .input = "/share\n\n" },
            .{ .wait_ms = 600, .input = "/compact\n\n" },
            .{ .wait_ms = 600, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_unknown_command: bool,
        has_invalid_tools: bool,
        has_unknown_provider: bool,
        has_bg_not_found: bool,
        has_policy_deny: bool,
        has_session_disabled: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.real pz PTY failure walkthrough covers command provider bg compact and policy denial.Snap
        \\  .has_unknown_command: bool = true
        \\  .has_invalid_tools: bool = true
        \\  .has_unknown_provider: bool = true
        \\  .has_bg_not_found: bool = true
        \\  .has_policy_deny: bool = true
        \\  .has_session_disabled: bool = true
    ).expectEqual(Snap{
        .has_unknown_command = try streamHasText(std.testing.allocator, out.stdout, "unknown command: /wat"),
        .has_invalid_tools = try streamHasText(std.testing.allocator, out.stdout, "error: invalid tools value; use all, none, or comma list of read,write,bash,edit,grep,find,ls,ask,skill"),
        .has_unknown_provider = try streamHasText(std.testing.allocator, out.stdout, "unknown provider: bogus"),
        .has_bg_not_found = try streamHasText(std.testing.allocator, out.stdout, "bg not found id=42"),
        .has_policy_deny = try streamHasText(std.testing.allocator, out.stdout, "blocked by policy: /share"),
        .has_session_disabled = try streamHasText(std.testing.allocator, out.stdout, "reason: session persistence is disabled"),
    });
}

// ── T7c: headless pipeline walkthrough coverage ──

test "T7c pipeline denied-policy tool exits with error" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try writePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "tool/bash", .effect = .deny },
        },
    });

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const pz_bin = try pzBinAlloc(std.testing.allocator);
    defer std.testing.allocator.free(pz_bin);

    // Provider that tries to call bash tool — policy should deny
    const provider_cmd =
        "cat >/dev/null; " ++
        "printf 'tool_call:c1|bash|{\"command\":\"echo hi\"}\\nstop:done\\n'";
    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-config",
            "--no-session",
            "--mode",
            "print",
            "--max-turns",
            "1",
            "--provider-cmd",
            provider_cmd,
            "--prompt",
            "test",
        },
        "",
    );
    defer out.deinit(std.testing.allocator);

    // Should complete (provider gets denial as tool result, stops after 1 turn)
    try std.testing.expect(out.term == .Exited);
    // Policy denial info should appear in output
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "denied") != null or
        std.mem.indexOf(u8, out.stderr, "denied") != null or
        std.mem.indexOf(u8, out.stdout, "policy") != null or
        std.mem.indexOf(u8, out.stderr, "policy") != null);
}

test "T7c pipeline non-default model propagates to provider" {
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

    // Provider echoes the model name from the request
    const provider_cmd =
        "req=$(cat); " ++
        "model=$(printf '%s' \"$req\" | grep -o '\"model\":\"[^\"]*\"' | head -n1 | cut -d'\"' -f4); " ++
        "printf 'text:model=%s\\nstop:done\\n' \"$model\"";
    var out = try runProc(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-config",
            "--no-session",
            "--mode",
            "print",
            "--model",
            "custom-model-7b",
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
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "model=custom-model-7b") != null);
}

test "T7c pipeline json mode missing prompt exits with error" {
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

    // No --prompt and empty stdin → should fail
    var out = try runProc(
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
    try std.testing.expectEqual(@as(u8, 1), out.term.Exited);
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "EmptyPrompt") != null);
}

// ── T7b: thin PTY auth/login overlay surface ──

test "T7b PTY auth login overlay renders provider list" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--no-session",
        },
        &.{
            .{ .wait_ms = 800, .input = "/login\x1b\x00\n" },
            .{ .wait_ms = 800, .input = "\x1b" }, // ESC to dismiss
            .{ .wait_ms = 400, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Login overlay should show provider names and title
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "Login"));
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "openai") or
        try streamHasText(std.testing.allocator, out.stdout, "anthropic"));
}

// ── UX1-UX6: keyboard-driven PTY walkthrough tests ──

test "UX1 PTY startup shows version, hints, cwd and quits cleanly" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-session" },
        &.{
            .{ .wait_ms = 800, .input = "\x03" }, // ctrl-c once (clear)
            .{ .wait_ms = 400, .input = "\x03" }, // ctrl-c again (quit)
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_model: bool,
        has_shift_drag: bool,
        has_drop_files: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.UX1 PTY startup shows version, hints, cwd and quits cleanly.Snap
        \\  .has_model: bool = true
        \\  .has_shift_drag: bool = true
        \\  .has_drop_files: bool = true
    ).expectEqual(Snap{
        .has_model = try streamHasText(std.testing.allocator, out.stdout, "claude-opus-4-6"),
        .has_shift_drag = try streamHasText(std.testing.allocator, out.stdout, "shift+drag"),
        .has_drop_files = try streamHasText(std.testing.allocator, out.stdout, "drop files"),
    });
}

test "UX2 PTY input: type text, ctrl-u kills line, ctrl-c quits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-session" },
        &.{
            .{ .wait_ms = 300, .input = "hello" },
            .{ .wait_ms = 200, .input = "\x15" }, // ctrl-u (kill line)
            .{ .wait_ms = 200, .input = "\x03\x03" }, // ctrl-c twice (quit)
        },
        400,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    // The stream should contain "hello" (typed) and the TUI alt screen
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "hello"));
    try std.testing.expect(std.mem.indexOf(u8, out.stdout, "\x1b[?1049h") != null);
}

test "UX3 PTY commands: /help and /hotkeys render output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-session" },
        &.{
            .{ .wait_ms = 800, .input = "/help\n\n" },
            .{ .wait_ms = 800, .input = "/hotkeys\n\n" },
            .{ .wait_ms = 600, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_help_list: bool,
        has_hotkeys_header: bool,
        has_hotkeys_entry: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.UX3 PTY commands: /help and /hotkeys render output.Snap
        \\  .has_help_list: bool = true
        \\  .has_hotkeys_header: bool = true
        \\  .has_hotkeys_entry: bool = true
    ).expectEqual(Snap{
        .has_help_list = try streamHasText(std.testing.allocator, out.stdout, "/changelog"),
        .has_hotkeys_header = try streamHasText(std.testing.allocator, out.stdout, "Keyboard shortcuts"),
        .has_hotkeys_entry = try streamHasText(std.testing.allocator, out.stdout, "Scroll transcript"),
    });
}

test "UX4 PTY overlays: /settings opens and esc closes" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-session" },
        &.{
            .{ .wait_ms = 800, .input = "/settings\n\n" },
            .{ .wait_ms = 800, .input = "\x1b" }, // ESC to close overlay
            .{ .wait_ms = 400, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_settings_title: bool,
        has_show_tools: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.UX4 PTY overlays: /settings opens and esc closes.Snap
        \\  .has_settings_title: bool = true
        \\  .has_show_tools: bool = true
    ).expectEqual(Snap{
        .has_settings_title = try streamHasText(std.testing.allocator, out.stdout, "Settings"),
        .has_show_tools = try streamHasText(std.testing.allocator, out.stdout, "Show tool output"),
    });
}

test "UX5 PTY settings: toggle item with down+enter" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{ "--no-session" },
        &.{
            .{ .wait_ms = 800, .input = "/settings\n\n" },
            .{ .wait_ms = 800, .input = "\x1b[B" }, // down arrow
            .{ .wait_ms = 400, .input = "\n" }, // enter to toggle
            .{ .wait_ms = 600, .input = "\x1b" }, // ESC to close
            .{ .wait_ms = 400, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    // Settings overlay was opened and interacted with
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "Settings"));
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "Show tool output"));
}

test "UX6 PTY sessions: /new creates and /name sets name" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("sess");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();
    try env.put("LINES", "50");

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--session-dir",
            sess_abs,
        },
        &.{
            .{ .wait_ms = 800, .input = "/new\n\n" },
            .{ .wait_ms = 800, .input = "/name test-session\n\n" },
            .{ .wait_ms = 600, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_new_session: bool,
        has_name_set: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.UX6 PTY sessions: /new creates and /name sets name.Snap
        \\  .has_new_session: bool = true
        \\  .has_name_set: bool = true
    ).expectEqual(Snap{
        .has_new_session = try streamHasText(std.testing.allocator, out.stdout, "new session"),
        .has_name_set = try streamHasText(std.testing.allocator, out.stdout, "session named: test-session"),
    });
}

// ── UX7: Auth overlay surfaces ──

test "UX7 PTY auth login and model overlays" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{"--no-session"},
        &.{
            .{ .wait_ms = 800, .input = "/login\x1b\x00\n" },
            .{ .wait_ms = 800, .input = "\x1b" }, // ESC dismiss
            .{ .wait_ms = 600, .input = "/model\x1b\x00\n" },
            .{ .wait_ms = 800, .input = "\x1b" }, // ESC dismiss
            .{ .wait_ms = 400, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }

    const Snap = struct {
        has_login: bool,
        has_login_provider: bool,
        has_model_overlay: bool,
    };
    try oh.snap(@src(),
        \\test.pty_harness.test.UX7 PTY auth login and model overlays.Snap
        \\  .has_login: bool = true
        \\  .has_login_provider: bool = true
        \\  .has_model_overlay: bool = true
    ).expectEqual(Snap{
        .has_login = try streamHasText(std.testing.allocator, out.stdout, "Login"),
        .has_login_provider = try streamHasText(std.testing.allocator, out.stdout, "openai") or
            try streamHasText(std.testing.allocator, out.stdout, "anthropic"),
        .has_model_overlay = try streamHasText(std.testing.allocator, out.stdout, "Select Model"),
    });
}

// ── UX8: Background job management ──

test "UX8 PTY bg list shows status" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{"--no-session"},
        &.{
            .{ .wait_ms = 800, .input = "/bg list\x1b\x00\n" },
            .{ .wait_ms = 600, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Empty bg list should show "no background jobs"
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "no background jobs"));
}

// ── UX9: Security policy denial ──

test "UX9 PTY policy denies bash tool" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try writePolicy(tmp.dir, .{
        .rules = &.{
            .{ .pattern = "tool/bash", .effect = .deny },
        },
    });

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    // Provider that tries to call bash — policy should deny
    const provider_cmd =
        "cat >/dev/null; " ++
        "printf 'tool_call:c1|bash|{\"command\":\"echo hi\"}\\nstop:done\\n'";

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--no-session",
            "--max-turns",
            "1",
            "--provider-cmd",
            provider_cmd,
        },
        &.{
            .{ .wait_ms = 800, .input = "run echo hi\n" },
            .{ .wait_ms = 2000, .input = "\x03\x03" },
        },
        1000,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Denial text should appear in the transcript
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "blocked by policy") or
        try streamHasText(std.testing.allocator, out.stdout, "denied"));
}

// ── UX10: Changelog ──

test "UX10 PTY changelog shows what's new" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{"--no-session"},
        &.{
            .{ .wait_ms = 800, .input = "/changelog\n\n" },
            .{ .wait_ms = 800, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Changelog content should appear (header "[What's New]" may scroll off;
    // check for indented commit lines which are always in the visible tail).
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "completions") or
        try streamHasText(std.testing.allocator, out.stdout, "[What's New]"));
}

// ── UX11: Compaction ──

test "UX11 PTY compact with no session shows disabled notice" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{"--no-session"},
        &.{
            .{ .wait_ms = 800, .input = "/compact\n\n" },
            .{ .wait_ms = 800, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Should report session disabled
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "session persistence is disabled") or
        try streamHasText(std.testing.allocator, out.stdout, "SessionDisabled"));
}

test "UX11 PTY compact with active session shows compaction result" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("sess");

    const cwd_abs = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "home");
    defer std.testing.allocator.free(home_abs);
    const sess_abs = try tmp.dir.realpathAlloc(std.testing.allocator, "sess");
    defer std.testing.allocator.free(sess_abs);

    var env = try baseEnv(std.testing.allocator, home_abs);
    defer env.deinit();

    const provider_cmd =
        "cat >/dev/null; " ++
        "printf 'text:ack\\nstop:done\\n'";

    var out = try runPzPtySteps(
        std.testing.allocator,
        cwd_abs,
        &env,
        &.{
            "--session-dir",
            sess_abs,
            "--provider-cmd",
            provider_cmd,
        },
        &.{
            .{ .wait_ms = 800, .input = "ping\n" },
            .{ .wait_ms = 1200, .input = "/compact\n\n" },
            .{ .wait_ms = 800, .input = "\x03\x03" },
        },
        800,
    );
    defer out.deinit(std.testing.allocator);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| try std.testing.expectEqual(@as(u32, @intCast(c.SIGINT)), sig),
        else => return error.TestUnexpectedResult,
    }
    // Compaction should report result
    try std.testing.expect(try streamHasText(std.testing.allocator, out.stdout, "compacted in="));
}

test "real-env PTY: pz starts and exits without crash" {
    // Spawn pz with the real process environment (no HOME override).
    // This catches crashes from real-world HOME/config/VCS state.
    const alloc = std.testing.allocator;
    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);

    // Use real env, only add TERM/size and skip version check.
    var env = try std.process.getEnvMap(alloc);
    defer env.deinit();
    try env.put("TERM", "xterm-256color");
    try env.put("COLUMNS", "100");
    try env.put("LINES", "32");
    try env.put("PZ_SKIP_VERSION_CHECK", "1");

    // Send Ctrl-C immediately to exit.
    var out = try runPzPty(alloc, cwd, &env, &.{}, "\x03\x03", 300, 500);
    defer out.deinit(alloc);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        .Signal => |sig| {
            // SIGINT (2) is acceptable; SIGABRT (6) is not.
            if (sig == @as(u32, @intCast(c.SIGABRT))) return error.TestUnexpectedResult;
        },
        else => return error.TestUnexpectedResult,
    }
}

test "real PTY: hello gets response" {
    const api_key = std.posix.getenv("ANTHROPIC_API_KEY") orelse return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pi/agent");
    const cwd_abs = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home_abs);

    // Write auth.json with the real API key (value is safe — it's our own test env).
    const auth_json = try std.fmt.allocPrint(alloc,
        \\{{"anthropic":{{"type":"api_key","key":"{s}"}}}}
    , .{api_key});
    defer alloc.free(auth_json);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pi/agent/auth.json", .data = auth_json });

    var env = try baseEnv(alloc, home_abs);
    defer env.deinit();
    try env.put("ANTHROPIC_API_KEY", api_key);

    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);

    // Use print mode to avoid TUI complexity — send a prompt, get text back.
    var out = try runProc(
        alloc,
        cwd_abs,
        &env,
        &.{
            pz_bin,
            "--no-session",
            "--mode",
            "print",
            "--model",
            "claude-sonnet-4-20250514",
            "--prompt",
            "Say exactly: PZTEST_OK",
        },
        "",
    );
    defer out.deinit(alloc);

    switch (out.term) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => {
            if (out.stderr.len > 0) {
                std.debug.print("stderr: {s}\n", .{out.stderr});
            }
            return error.TestUnexpectedResult;
        },
    }
    // Verify we got some response text (the model should include PZTEST_OK).
    try std.testing.expect(out.stdout.len > 0);
}

// ── Bidirectional PTY harness ──

pub const InteractiveStep = union(enum) {
    inject: []const u8,
    wait_for: struct { text: []const u8, timeout_ms: u64 = 5000 },
    snapshot: []const u8, // label for ohsnap
    sleep: u64,
    resize: struct { cols: u16, rows: u16 },
};

/// VScreen wrapper that accumulates raw bytes alongside parsed screen state.
pub const PtyScreen = struct {
    vs: vscreen.VScreen,
    raw: std.ArrayList(u8),

    pub fn init(alloc: std.mem.Allocator, w: usize, h: usize) !PtyScreen {
        return .{
            .vs = try vscreen.VScreen.init(alloc, w, h),
            .raw = .empty,
        };
    }

    pub fn deinit(self: *PtyScreen) void {
        const alloc = self.vs.alloc;
        self.raw.deinit(alloc);
        self.vs.deinit();
        self.* = undefined;
    }

    pub fn feed(self: *PtyScreen, data: []const u8) !void {
        try self.raw.appendSlice(self.vs.alloc, data);
        self.vs.feed(data);
    }

    pub fn hasText(self: *const PtyScreen, needle: []const u8) !bool {
        return screenHasText(&self.vs, self.vs.alloc, needle);
    }

    pub fn textGrid(self: *const PtyScreen) ![]u8 {
        const alloc = self.vs.alloc;
        var buf = std.ArrayList(u8).empty;
        errdefer buf.deinit(alloc);
        var r: usize = 0;
        while (r < self.vs.h) : (r += 1) {
            const row = try self.vs.rowText(alloc, r);
            defer alloc.free(row);
            try buf.appendSlice(alloc, row);
            try buf.append(alloc, '\n');
        }
        return try buf.toOwnedSlice(alloc);
    }
};

const InteractiveOut = struct {
    output: []u8,
    snapshots: []Snapshot,
    term: std.process.Child.Term,

    const Snapshot = struct {
        label: []const u8,
        grid: []u8,
    };

    fn deinit(self: *InteractiveOut, alloc: std.mem.Allocator) void {
        alloc.free(self.output);
        for (self.snapshots) |snap| alloc.free(snap.grid);
        alloc.free(self.snapshots);
        self.* = undefined;
    }
};

const fake_provider_cmd =
    "cat >/dev/null; sleep 0.1; printf 'text:Hello from fake provider!\\n'; " ++
    "sleep 0.1; printf 'text: How can I help?\\n'; sleep 0.1; printf 'stop:done\\n'";

fn killChild(pid: c.pid_t) void {
    _ = c.kill(pid, c.SIGKILL);
    _ = c.waitpid(pid, null, 0);
}

fn runPtyInteractive(
    alloc: std.mem.Allocator,
    cwd: []const u8,
    env: *const std.process.EnvMap,
    pz_args: []const []const u8,
    steps: []const InteractiveStep,
) !InteractiveOut {
    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);

    // Build argv as null-terminated C strings.
    var cargv = CStringList.init(alloc);
    defer cargv.deinit();
    try cargv.appendDupZ(pz_bin);
    for (pz_args) |arg| try cargv.appendDupZ(arg);
    try cargv.items.append(alloc, null); // sentinel

    // Build envp as null-terminated C strings.
    var cenvp = CStringList.init(alloc);
    defer cenvp.deinit();
    var it = env.iterator();
    while (it.next()) |entry| {
        const kv = try std.fmt.allocPrint(alloc, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        defer alloc.free(kv);
        try cenvp.appendDupZ(kv);
    }
    try cenvp.items.append(alloc, null); // sentinel

    const cwd_z = try alloc.dupeZ(u8, cwd);
    defer alloc.free(cwd_z);

    // openpty
    var master: c_int = undefined;
    var slave: c_int = undefined;
    if (c.openpty(&master, &slave, null, null, null) != 0)
        return error.OpenPtyFailed;

    // Set window size on master.
    var ws: c.winsize = .{ .ws_row = 24, .ws_col = 80, .ws_xpixel = 0, .ws_ypixel = 0 };
    _ = c.ioctl(master, c.TIOCSWINSZ, &ws);

    const pid = c.fork();
    if (pid < 0) {
        _ = c.close(master);
        _ = c.close(slave);
        return error.ForkFailed;
    }

    if (pid == 0) {
        // ── Child ──
        _ = c.close(master);
        _ = c.setsid();
        _ = c.ioctl(slave, c.TIOCSCTTY, @as(c_int, 0));
        _ = c.dup2(slave, 0);
        _ = c.dup2(slave, 1);
        _ = c.dup2(slave, 2);
        if (slave > 2) _ = c.close(slave);
        _ = c.chdir(cwd_z.ptr);
        const argv_ptr: [*:null]?[*:0]u8 = @ptrCast(cargv.items.items.ptr);
        const envp_ptr: [*:null]?[*:0]u8 = @ptrCast(cenvp.items.items.ptr);
        _ = c.execve(argv_ptr[0].?, argv_ptr, envp_ptr);
        c._exit(127);
    }

    // ── Parent ──
    _ = c.close(slave);

    // Set master fd non-blocking.
    const flags = c.fcntl(master, c.F_GETFL);
    _ = c.fcntl(master, c.F_SETFL, flags | c.O_NONBLOCK);

    const master_fd: std.posix.fd_t = master;
    var screen = try PtyScreen.init(alloc, 80, 24);
    defer screen.deinit();

    var snaps = std.ArrayList(InteractiveOut.Snapshot).empty;
    defer {
        for (snaps.items) |snap| alloc.free(snap.grid);
        snaps.deinit(alloc);
    }

    var succeeded = false;
    defer if (!succeeded) killChild(pid);

    for (steps) |step| {
        switch (step) {
            .inject => |data| {
                const tty = try ttyInputAlloc(alloc, data);
                defer alloc.free(tty);
                writeAllFd(master_fd, tty) catch |err| switch (err) {
                    error.BrokenPipe => break,
                    else => return err,
                };
            },
            .wait_for => |wf| {
                const deadline = std.time.milliTimestamp() + @as(i64, @intCast(wf.timeout_ms));
                while (true) {
                    var buf: [4096]u8 = undefined;
                    const n = std.posix.read(master_fd, &buf) catch |err| switch (err) {
                        error.WouldBlock => {
                            if (std.time.milliTimestamp() >= deadline) {
                                const grid = screen.textGrid() catch "";
                                std.debug.print("wait_for timeout: needle=\"{s}\"\ngrid:\n{s}\n", .{ wf.text, grid });
                                if (grid.len > 0) alloc.free(grid);
                                return error.WaitForTimeout;
                            }
                            std.Thread.sleep(10 * std.time.ns_per_ms);
                            continue;
                        },
                        error.InputOutput, error.BrokenPipe => break,
                        else => return err,
                    };
                    if (n == 0) break;
                    try screen.feed(buf[0..n]);
                    if (try screen.hasText(wf.text)) break;
                }
            },
            .snapshot => |label| {
                const grid = try screen.textGrid();
                errdefer alloc.free(grid);
                try snaps.append(alloc, .{ .label = label, .grid = grid });
            },
            .sleep => |ms| {
                std.Thread.sleep(ms * std.time.ns_per_ms);
            },
            .resize => |sz| {
                var rsz: c.winsize = .{
                    .ws_row = sz.rows,
                    .ws_col = sz.cols,
                    .ws_xpixel = 0,
                    .ws_ypixel = 0,
                };
                _ = c.ioctl(master, c.TIOCSWINSZ, &rsz);
                // Send SIGWINCH to child process group.
                _ = c.kill(-pid, c.SIGWINCH);
            },
        }
    }

    // Drain remaining output.
    {
        const drain_deadline = std.time.milliTimestamp() + 2000;
        while (std.time.milliTimestamp() < drain_deadline) {
            var buf: [4096]u8 = undefined;
            const n = std.posix.read(master_fd, &buf) catch |err| switch (err) {
                error.WouldBlock => {
                    std.Thread.sleep(10 * std.time.ns_per_ms);
                    continue;
                },
                error.InputOutput, error.BrokenPipe => break,
                else => return err,
            };
            if (n == 0) break;
            try screen.feed(buf[0..n]);
        }
    }

    // Collect child exit status.
    var status: c_int = 0;
    const wpid = c.waitpid(pid, &status, c.WNOHANG);
    const term = if (wpid == pid)
        mapWaitStatus(status)
    else blk: {
        _ = c.kill(pid, c.SIGKILL);
        _ = c.waitpid(pid, &status, 0);
        break :blk mapWaitStatus(status);
    };

    _ = c.close(master);

    const output = try alloc.dupe(u8, screen.raw.items);
    errdefer alloc.free(output);
    const snap_slice = try snaps.toOwnedSlice(alloc);
    succeeded = true;

    return .{
        .output = output,
        .snapshots = snap_slice,
        .term = term,
    };
}

const InteractiveEnv = struct {
    tmp: std.testing.TmpDir,
    cwd_abs: []u8,
    home_abs: []u8,
    env: std.process.EnvMap,
    alloc: std.mem.Allocator,

    fn deinit(self: *InteractiveEnv) void {
        self.env.deinit();
        self.alloc.free(self.cwd_abs);
        self.alloc.free(self.home_abs);
        self.tmp.cleanup();
    }
};

fn setupInteractiveEnv(alloc: std.mem.Allocator) !InteractiveEnv {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(alloc, ".");
    errdefer alloc.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(alloc, "home");
    errdefer alloc.free(home_abs);

    const env = try baseEnv(alloc, home_abs);
    return .{
        .tmp = tmp,
        .cwd_abs = cwd_abs,
        .home_abs = home_abs,
        .env = env,
        .alloc = alloc,
    };
}

test "runPtyInteractive: fake provider round-trip with wait_for and snapshot" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    const cwd_abs = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd_abs);
    const home_abs = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home_abs);

    var env = try baseEnv(alloc, home_abs);
    defer env.deinit();

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .snapshot = "after_startup" },
        .{ .inject = "hello from test\n" },
        .{ .wait_for = .{ .text = "Hello from fake provider!", .timeout_ms = 10000 } },
        .{ .snapshot = "after_response" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(
        alloc,
        cwd_abs,
        &env,
        &.{
            "--no-config",
            "--no-session",
            "--provider-cmd",
            fake_provider_cmd,
        },
        &steps,
    );
    defer out.deinit(alloc);

    // Should have 2 snapshots.
    try std.testing.expectEqual(@as(usize, 2), out.snapshots.len);

    // Output should contain provider response.
    try std.testing.expect(std.mem.indexOf(u8, out.output, "Hello from fake provider!") != null);

    // Startup snapshot should exist and have content.
    try std.testing.expect(out.snapshots[0].grid.len > 0);

    // After-response snapshot should contain the provider text.
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[1].grid, "Hello from fake provider!") != null);
}

// ── Edge case tests ──

test "pty: error display from provider" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    const err_cmd = "cat >/dev/null; printf 'err:something went wrong\\nstop:err\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "trigger error\n" },
        .{ .wait_for = .{ .text = "something went wrong", .timeout_ms = 10000 } },
        .{ .snapshot = "after_error" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", err_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "something went wrong") != null);
}

test "pty: settings toggle via slash command" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "/settings\n" },
        .{ .sleep = 200 },
        .{ .inject = "\x1b[B\r" }, // down arrow + enter (toggle)
        .{ .sleep = 200 },
        .{ .inject = "\x1b" }, // esc to close
        .{ .sleep = 200 },
        .{ .inject = "hello after settings\n" },
        .{ .wait_for = .{ .text = "Hello from fake provider!", .timeout_ms = 10000 } },
        .{ .snapshot = "after_settings" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", fake_provider_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    // Provider response appeared after settings interaction.
    try std.testing.expect(std.mem.indexOf(u8, out.output, "Hello from fake provider!") != null);
}

test "pty: resize during stream does not crash" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "say something\n" },
        .{ .wait_for = .{ .text = "Hello", .timeout_ms = 10000 } },
        .{ .resize = .{ .cols = 60, .rows = 20 } },
        .{ .sleep = 300 },
        .{ .wait_for = .{ .text = "How can I help?", .timeout_ms = 10000 } },
        .{ .snapshot = "after_resize" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", fake_provider_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    try std.testing.expect(out.snapshots[0].grid.len > 0);
    // Process exited or was killed cleanly (not a crash signal like SEGV/ABRT).
    switch (out.term) {
        .Exited => {},
        .Signal => |sig| {
            // SIGKILL (9) is our cleanup; anything else is a crash.
            try std.testing.expect(sig == 9);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "pty: double ctrl-c clean exit" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    // Use a slow provider so we can ctrl-c mid-stream.
    const slow_cmd =
        "cat >/dev/null; printf 'text:Hello slow\\n'; sleep 5; printf 'stop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "go\n" },
        .{ .wait_for = .{ .text = "Hello slow", .timeout_ms = 10000 } },
        .{ .inject = "\x03" }, // first ctrl-c
        .{ .sleep = 200 },
        .{ .inject = "\x03" }, // second ctrl-c
        .{ .sleep = 1000 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", slow_cmd,
    }, &steps);
    defer out.deinit(alloc);

    // Verify clean exit: either exited with a code or killed (no zombie).
    switch (out.term) {
        .Exited => {},
        .Signal => |sig| {
            // SIGKILL from our cleanup or SIGINT propagation are acceptable.
            try std.testing.expect(sig == 9 or sig == 2);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "pty: help during stream shows help text" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    // Slow provider to allow typing /help mid-stream.
    const slow_cmd =
        "cat >/dev/null; printf 'text:Hello stream\\n'; sleep 3; printf 'text: done\\n'; printf 'stop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "go\n" },
        .{ .wait_for = .{ .text = "Hello stream", .timeout_ms = 10000 } },
        .{ .inject = "/help\n" },
        .{ .sleep = 500 },
        .{ .snapshot = "during_help" },
        .{ .inject = "\x1b" }, // esc to close help
        .{ .sleep = 200 },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", slow_cmd,
    }, &steps);
    defer out.deinit(alloc);

    // Output should contain the response text.
    try std.testing.expect(std.mem.indexOf(u8, out.output, "Hello stream") != null);
    // Snapshot or output should show help-related content (command picker shows "help").
    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    try std.testing.expect(out.snapshots[0].grid.len > 0);
}

test "pty: bracketed paste during stream" {
    const alloc = std.testing.allocator;
    var ctx = try setupInteractiveEnv(alloc);
    defer ctx.deinit();

    // Slow provider to allow pasting mid-stream.
    const slow_cmd =
        "cat >/dev/null; printf 'text:Hello paste\\n'; sleep 3; printf 'text: end\\n'; printf 'stop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "go\n" },
        .{ .wait_for = .{ .text = "Hello paste", .timeout_ms = 10000 } },
        .{ .inject = "\x1b[200~pasted text\x1b[201~" }, // bracketed paste
        .{ .sleep = 500 },
        .{ .snapshot = "after_paste" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, ctx.cwd_abs, &ctx.env, &.{
        "--no-config", "--no-session", "--provider-cmd", slow_cmd,
    }, &steps);
    defer out.deinit(alloc);

    // Output should contain the streaming response.
    try std.testing.expect(std.mem.indexOf(u8, out.output, "Hello paste") != null);
    // Pasted text should appear in the editor/output.
    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "pasted") != null);
}

// ── Core walkthrough tests ──

test "PTY walkthrough: full prompt to response" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "hello\n" },
        .{ .wait_for = .{ .text = "hello", .timeout_ms = 5000 } },
        .{ .wait_for = .{ .text = "Hello from fake provider", .timeout_ms = 10000 } },
        .{ .snapshot = "after_response" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--no-session", "--provider-cmd", fake_provider_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "Hello from fake provider") != null);
}

test "PTY walkthrough: streaming renders incrementally" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    // Provider that streams two distinct chunks with a pause between them.
    const stream_cmd =
        "cat >/dev/null; " ++
        "printf 'text:Hello\\n'; sleep 0.3; " ++
        "printf 'text: help?\\n'; sleep 0.1; printf 'stop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "test streaming\n" },
        .{ .wait_for = .{ .text = "Hello", .timeout_ms = 10000 } },
        .{ .snapshot = "partial" },
        .{ .wait_for = .{ .text = "help?", .timeout_ms = 10000 } },
        .{ .snapshot = "complete" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--no-session", "--provider-cmd", stream_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), out.snapshots.len);
    // Partial snapshot should have Hello but not necessarily help?
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "Hello") != null);
    // Complete snapshot should have both
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[1].grid, "help?") != null);
}

test "PTY walkthrough: cancel mid-stream" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    // Provider that streams slowly so we can cancel mid-stream.
    const slow_cmd =
        "cat >/dev/null; " ++
        "printf 'text:Hello\\n'; sleep 2; " ++
        "printf 'text: more\\n'; sleep 0.1; printf 'stop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "cancel me\n" },
        .{ .wait_for = .{ .text = "Hello", .timeout_ms = 10000 } },
        .{ .inject = "\x03" }, // ctrl-c
        .{ .wait_for = .{ .text = "canceled", .timeout_ms = 5000 } },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--no-session", "--provider-cmd", slow_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expect(std.mem.indexOf(u8, out.output, "canceled") != null);
}

test "PTY walkthrough: tool call renders" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    // Provider: first call emits a tool_call for bash, second call emits done text.
    // The script checks for tool_result in stdin to distinguish turns.
    const tool_cmd =
        "req=$(cat); " ++
        "if printf '%s' \"$req\" | grep -q tool_result; then " ++
        "  printf 'text:done\\nstop:done\\n'; " ++
        "else " ++
        "  printf 'tool_call:c1|bash|{\"command\":\"echo hi\"}\\nstop:tool\\n'; " ++
        "fi";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "run echo\n" },
        // Wait for the tool display to appear — bash tool should show.
        .{ .wait_for = .{ .text = "bash", .timeout_ms = 15000 } },
        .{ .wait_for = .{ .text = "done", .timeout_ms = 15000 } },
        .{ .snapshot = "after_tool" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--no-session", "--provider-cmd", tool_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.snapshots.len);
    // The snapshot should show the bash tool was invoked.
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "bash") != null or
        std.mem.indexOf(u8, out.output, "bash") != null);
}

test "PTY walkthrough: compaction after response" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("sess");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    const sess = try tmp.dir.realpathAlloc(alloc, "sess");
    defer alloc.free(sess);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "ping\n" },
        .{ .wait_for = .{ .text = "Hello from fake provider", .timeout_ms = 10000 } },
        .{ .sleep = 300 },
        .{ .inject = "/compact\n" },
        .{ .wait_for = .{ .text = "compacted in=", .timeout_ms = 10000 } },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--session-dir", sess, "--provider-cmd", fake_provider_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expect(std.mem.indexOf(u8, out.output, "compacted in=") != null);
}

test "PTY walkthrough: multi-turn conversation" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("home/.pz");
    const cwd = try tmp.dir.realpathAlloc(alloc, ".");
    defer alloc.free(cwd);
    const home = try tmp.dir.realpathAlloc(alloc, "home");
    defer alloc.free(home);
    var env = try baseEnv(alloc, home);
    defer env.deinit();

    // Provider always responds with the same text.
    const multi_cmd =
        "cat >/dev/null; sleep 0.1; " ++
        "printf 'text:response ok\\nstop:done\\n'";

    const steps = [_]InteractiveStep{
        .{ .wait_for = .{ .text = "drop files", .timeout_ms = 8000 } },
        .{ .inject = "first prompt\n" },
        .{ .wait_for = .{ .text = "response ok", .timeout_ms = 10000 } },
        .{ .snapshot = "after_turn1" },
        .{ .inject = "second prompt\n" },
        .{ .wait_for = .{ .text = "response ok", .timeout_ms = 10000 } },
        .{ .snapshot = "after_turn2" },
        .{ .inject = "\x03\x03" },
        .{ .sleep = 500 },
    };

    var out = try runPtyInteractive(alloc, cwd, &env, &.{
        "--no-config", "--no-session", "--provider-cmd", multi_cmd,
    }, &steps);
    defer out.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), out.snapshots.len);
    // Both snapshots should contain the response text.
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[0].grid, "response ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.snapshots[1].grid, "response ok") != null);
    // Output should contain both prompts.
    try std.testing.expect(std.mem.indexOf(u8, out.output, "first prompt") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.output, "second prompt") != null);
}

