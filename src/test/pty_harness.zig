const std = @import("std");
const build_options = @import("build_options");
const app_config = @import("../app/config.zig");
const core = @import("../core/mod.zig");
const vscreen = @import("../modes/tui/vscreen.zig");
const ansi_ast = @import("ansi_ast.zig");
const http_mock = @import("http_mock.zig");
const c = @cImport({
    @cInclude("errno.h");
    @cInclude("signal.h");
    @cInclude("stdlib.h");
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
    const pz_bin = try pzBinAlloc(alloc);
    defer alloc.free(pz_bin);
    const tty_input = try ttyInputAlloc(alloc, input);
    defer alloc.free(tty_input);

    var c_argv = CStringList.init(alloc);
    defer c_argv.deinit();
    try c_argv.appendDupZ(pz_bin);
    for (pz_args) |arg| try c_argv.appendDupZ(arg);
    try c_argv.items.append(alloc, null);

    var envp = CStringList.init(alloc);
    defer envp.deinit();
    var it = env.iterator();
    while (it.next()) |entry| {
        const kv = try std.fmt.allocPrint(alloc, "{s}={s}", .{ entry.key_ptr.*, entry.value_ptr.* });
        defer alloc.free(kv);
        try envp.appendDupZ(kv);
    }
    try envp.items.append(alloc, null);

    const cwd_z = try alloc.dupeZ(u8, cwd);
    defer alloc.free(cwd_z);

    var master: c_int = -1;
    var ws = c.struct_winsize{
        .ws_row = 32,
        .ws_col = 100,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
    const pid = c.forkpty(&master, null, null, &ws);
    if (pid < 0) return error.TestUnexpectedResult;
    if (pid == 0) {
        _ = c.chdir(cwd_z.ptr);
        _ = c.execve(c_argv.items.items[0].?, @ptrCast(c_argv.items.items.ptr), @ptrCast(envp.items.items.ptr));
        c._exit(127);
    }

    const fd: std.posix.fd_t = @intCast(master);
    defer std.posix.close(fd);
    _ = try std.posix.fcntl(fd, std.posix.F.SETFL, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));

    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);

    var waited_ms: u32 = 0;
    while (out.items.len == 0 and waited_ms < 2000) : (waited_ms += 50) {
        var fds = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
            .revents = 0,
        }};
        _ = try std.posix.poll(&fds, 50);
        _ = try readReady(fd, &out, alloc);
    }

    if (pre_ms > 0) std.Thread.sleep(pre_ms * std.time.ns_per_ms);
    if (tty_input.len != 0) try writeAllFd(fd, tty_input);
    if (post_ms > 0) std.Thread.sleep(post_ms * std.time.ns_per_ms);

    var term: ?std.process.Child.Term = null;
    var loop_ms: u32 = 0;
    while (true) {
        var fds = [_]std.posix.pollfd{.{
            .fd = fd,
            .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
            .revents = 0,
        }};
        _ = try std.posix.poll(&fds, 100);
        loop_ms += 100;
        const read_any = try readReady(fd, &out, alloc);

        if (term == null) {
            var status: c_int = 0;
            const waited = c.waitpid(pid, &status, c.WNOHANG);
            if (waited < 0) return error.TestUnexpectedResult;
            if (waited == pid) term = mapWaitStatus(status);
        }

        if (term != null and !read_any and (fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR)) == 0) break;
        if (term == null and loop_ms >= 3000) {
            _ = c.kill(pid, c.SIGTERM);
            var status: c_int = 0;
            if (c.waitpid(pid, &status, 0) < 0) return error.TestUnexpectedResult;
            term = mapWaitStatus(status);
            _ = try readReady(fd, &out, alloc);
            break;
        }
    }

    if (term == null) {
        var status: c_int = 0;
        if (c.waitpid(pid, &status, 0) < 0) return error.TestUnexpectedResult;
        term = mapWaitStatus(status);
        _ = try readReady(fd, &out, alloc);
    }

    return .{
        .term = term.?,
        .stdout = try out.toOwnedSlice(alloc),
        .stderr = try alloc.dupe(u8, ""),
    };
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

    const sig1_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-sig1" });
    defer std.testing.allocator.free(sig1_path);
    defer std.fs.deleteFileAbsolute(sig1_path) catch {};
    {
        var f = try std.fs.createFileAbsolute(sig1_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("\x03");
    }
    const sig2_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-sig2" });
    defer std.testing.allocator.free(sig2_path);
    defer std.fs.deleteFileAbsolute(sig2_path) catch {};
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
        \\csi ?h 2026
        \\csi m 0
        \\csi J 2
        \\csi H 0
        \\"
    ).expectEqual(ctl);

    try std.testing.expect(try screenHasText(&vs, std.testing.allocator, "drop files"));
}

test "real pz PTY startup survives live version check" {
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

    var server = try http_mock.Server.initSeq(&.{.{
        .headers = &.{"Content-Type: application/json"},
        .body = "{\"tag_name\":\"v9.9.9\"}",
    }});
    defer server.deinit();
    const thr = try server.spawn();
    defer server.join(thr) catch {};
    const version_url = try server.urlAlloc(std.testing.allocator, "/repos/joelreymont/pz/releases/latest");
    defer std.testing.allocator.free(version_url);
    try env.put("PZ_VERSION_URL", version_url);

    const sig_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-version-quit" });
    defer std.testing.allocator.free(sig_path);
    defer std.fs.deleteFileAbsolute(sig_path) catch {};
    {
        var f = try std.fs.createFileAbsolute(sig_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("\x03\x03");
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
            "{ sleep 1.2; cat \"$1\"; sleep 0.2; } | /usr/bin/script -q /dev/null \"$2\" \"$3\" \"$4\"",
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
        .Exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(usize, 1), server.requestCount());

    var vs = try vscreen.VScreen.init(std.testing.allocator, 100, 32);
    defer vs.deinit();
    vs.feed(out.stdout);

    try std.testing.expect(try screenHasText(&vs, std.testing.allocator, "drop files"));
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
    const cfg = try std.fmt.allocPrint(std.testing.allocator,
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
    defer std.fs.deleteFileAbsolute(slash_path) catch {};
    {
        var f = try std.fs.createFileAbsolute(slash_path, .{ .truncate = true });
        defer f.close();
        try f.writeAll("/");
    }
    const quit_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_abs, ".pty-quit" });
    defer std.testing.allocator.free(quit_path);
    defer std.fs.deleteFileAbsolute(quit_path) catch {};
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
