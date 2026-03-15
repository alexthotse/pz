//! Child-process transport: pipe-based provider for local models.
const builtin = @import("builtin");
const std = @import("std");
const sandbox = @import("../sandbox.zig");
const shell = @import("../shell.zig");
const providers = @import("api.zig");
const types = @import("types.zig");

const Err = types.Err;

pub const Transport = struct {
    alloc: std.mem.Allocator,
    cmd: []u8,
    cwd: ?[]u8 = null,
    chunk_bytes: usize = 4096,

    pub const Init = struct {
        alloc: std.mem.Allocator,
        cmd: []const u8,
        cwd: ?[]const u8 = null,
        chunk_bytes: usize = 4096,
    };

    pub fn init(cfg: Init) !Transport {
        if (cfg.cmd.len == 0) return error.InvalidCommand;
        if (cfg.chunk_bytes == 0) return error.InvalidChunkSize;
        if (try shell.touchesProtectedPath(cfg.alloc, cfg.cmd)) return error.InvalidCommand;

        return .{
            .alloc = cfg.alloc,
            .cmd = try cfg.alloc.dupe(u8, cfg.cmd),
            .cwd = if (cfg.cwd) |cwd| try cfg.alloc.dupe(u8, cwd) else null,
            .chunk_bytes = cfg.chunk_bytes,
        };
    }

    pub fn deinit(self: *Transport) void {
        self.alloc.free(self.cmd);
        if (self.cwd) |cwd| self.alloc.free(cwd);
        self.* = undefined;
    }

    pub fn start(self: *Transport, req_wire: []const u8) !ProcChunk {
        return try ProcChunk.init(self.alloc, self.cmd, self.cwd, self.chunk_bytes, req_wire);
    }
};

pub const ProcChunk = struct {
    alloc: std.mem.Allocator,
    child: std.process.Child,
    stdout: std.fs.File,
    buf: []u8,
    done: bool = false,

    fn init(
        alloc: std.mem.Allocator,
        cmd: []const u8,
        cwd: ?[]const u8,
        chunk_bytes: usize,
        req_wire: []const u8,
    ) !ProcChunk {
        const argv = [_][]const u8{
            "/bin/bash",
            "-lc",
            cmd,
        };

        var env = std.process.getEnvMap(alloc) catch |err| return mapProcErr(err);
        defer env.deinit();
        sandbox.scrubEnv(&env);

        var child = std.process.Child.init(argv[0..], alloc);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        child.cwd = cwd;
        child.env_map = &env;
        if (builtin.os.tag != .windows and builtin.os.tag != .wasi) child.pgid = 0;

        child.spawn() catch |spawn_err| return mapProcErr(spawn_err);
        errdefer {
            killAndWait(&child) catch {};
        }

        var stdin = child.stdin orelse return error.Closed;
        child.stdin = null;
        defer stdin.close();
        stdin.writeAll(req_wire) catch |write_err| {
            return mapIoErr(write_err);
        };

        const stdout = child.stdout orelse return error.Closed;
        child.stdout = null;

        const buf = alloc.alloc(u8, chunk_bytes) catch |alloc_err| {
            stdout.close();
            return alloc_err;
        };

        return .{
            .alloc = alloc,
            .child = child,
            .stdout = stdout,
            .buf = buf,
        };
    }

    pub fn next(self: *ProcChunk) anyerror!?[]const u8 {
        if (self.done) return null;

        const n = self.stdout.read(self.buf) catch |read_err| return mapIoErr(read_err);
        if (n != 0) return self.buf[0..n];

        self.stdout.close();

        const term = self.child.wait() catch |wait_err| return mapProcErr(wait_err);
        self.done = true;

        switch (term) {
            .Exited => |code| {
                if (code == 0) return null;
                return error.BadGateway;
            },
            .Signal, .Stopped, .Unknown => return error.BadGateway,
        }
    }

    pub fn deinit(self: *ProcChunk) void {
        if (!self.done) {
            self.stdout.close();
            killAndWait(&self.child) catch |err| {
                std.debug.print("warning: child cleanup failed: {s}\n", .{@errorName(err)});
            };
            self.done = true;
        }

        self.alloc.free(self.buf);
    }
};

fn killAndWait(child: *std.process.Child) !void {
    const pid = child.id;

    // TERM the process group first.
    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        std.posix.kill(-pid, std.posix.SIG.TERM) catch |err| switch (err) {
            error.ProcessNotFound => {
                _ = child.wait() catch |wait_err| return mapProcErr(wait_err);
                return;
            },
            else => return mapProcErr(err),
        };

        // Poll with WNOHANG for ~150ms.
        var polls: u32 = 0;
        while (polls < 15) : (polls += 1) {
            const res = std.posix.waitpid(pid, std.c.W.NOHANG);
            if (res.pid != 0) {
                child.id = undefined;
                return;
            }
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }

        // Escalate to KILL on the process group.
        std.posix.kill(-pid, std.posix.SIG.KILL) catch |err| switch (err) {
            error.ProcessNotFound => {},
            else => return mapProcErr(err),
        };
    }

    _ = child.wait() catch |wait_err| return mapProcErr(wait_err);
}

fn mapProcErr(err: anyerror) anyerror {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Closed,
    };
}

fn mapIoErr(err: anyerror) anyerror {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.WireBreak,
    };
}

// --- Request wire serialization ---

pub fn buildReq(alloc: std.mem.Allocator, req: providers.Request) Err![]u8 {
    var out: std.io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    var js: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };

    writeReq(&js, req) catch return error.OutOfMemory;

    return out.toOwnedSlice() catch return error.OutOfMemory;
}

fn writeReq(js: *std.json.Stringify, req: providers.Request) anyerror!void {
    try js.beginObject();

    try js.objectField("model");
    try js.write(req.model);

    if (req.provider) |provider| {
        try js.objectField("provider");
        try js.write(provider);
    }

    try js.objectField("msgs");
    try js.beginArray();
    for (req.msgs) |msg| {
        try js.beginObject();

        try js.objectField("role");
        try js.write(@tagName(msg.role));

        try js.objectField("parts");
        try js.beginArray();
        for (msg.parts) |part| {
            try writePart(js, part);
        }
        try js.endArray();

        try js.endObject();
    }
    try js.endArray();

    try js.objectField("tools");
    try js.beginArray();
    for (req.tools) |tool| {
        try js.beginObject();
        try js.objectField("name");
        try js.write(tool.name);
        try js.objectField("desc");
        try js.write(tool.desc);
        try js.objectField("schema");
        try js.write(tool.schema);
        try js.endObject();
    }
    try js.endArray();

    try js.objectField("opts");
    try js.beginObject();

    if (req.opts.temp) |temp| {
        try js.objectField("temp");
        try js.write(temp);
    }
    if (req.opts.top_p) |top_p| {
        try js.objectField("top_p");
        try js.write(top_p);
    }
    if (req.opts.max_out) |max_out| {
        try js.objectField("max_out");
        try js.write(max_out);
    }

    try js.objectField("stop");
    try js.beginArray();
    for (req.opts.stop) |stop_tok| {
        try js.write(stop_tok);
    }
    try js.endArray();

    if (req.opts.thinking != .adaptive) {
        try js.objectField("thinking");
        try js.write(@tagName(req.opts.thinking));
    }
    if (req.opts.thinking_budget != 0) {
        try js.objectField("thinking_budget");
        try js.write(req.opts.thinking_budget);
    }

    try js.endObject();

    try js.endObject();
}

fn writePart(js: *std.json.Stringify, part: providers.Part) anyerror!void {
    try js.beginObject();

    switch (part) {
        .text => |txt| {
            try js.objectField("type");
            try js.write("text");
            try js.objectField("text");
            try js.write(txt);
        },
        .tool_call => |tc| {
            try js.objectField("type");
            try js.write("tool_call");
            try js.objectField("id");
            try js.write(tc.id);
            try js.objectField("name");
            try js.write(tc.name);
            try js.objectField("args");
            try js.write(tc.args);
        },
        .tool_result => |tr| {
            try js.objectField("type");
            try js.write("tool_result");
            try js.objectField("id");
            try js.write(tr.id);
            try js.objectField("out");
            try js.write(tr.output);
            try js.objectField("is_err");
            try js.write(tr.is_err);
        },
    }

    try js.endObject();
}

fn expectSnap(comptime src: std.builtin.SourceLocation, got: []u8, comptime want: []const u8) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    try oh.snap(src, want).expectEqual(got);
}

// --- Tests ---

test "proc transport streams stdout frames and exits cleanly" {
    var tr = try Transport.init(.{
        .alloc = std.testing.allocator,
        .cmd = "cat >/dev/null; printf 'text:ok\\nstop:done\\n'",
        .chunk_bytes = 5,
    });
    defer tr.deinit();

    var raw = try tr.start("{\"model\":\"m\"}");
    defer raw.deinit();

    var out: [128]u8 = undefined;
    var at: usize = 0;
    while (try raw.next()) |chunk| {
        if (at + chunk.len > out.len) return error.TestUnexpectedResult;
        @memcpy(out[at .. at + chunk.len], chunk);
        at += chunk.len;
    }

    try std.testing.expectEqualStrings("text:ok\nstop:done\n", out[0..at]);
}

test "proc transport rejects protected commands" {
    try std.testing.expectError(error.InvalidCommand, Transport.init(.{
        .alloc = std.testing.allocator,
        .cmd = "env FOO=1 bash -c 'cat ~/.pz/settings.json'",
    }));
}

test "proc transport reports bad gateway on non-zero exit" {
    var tr = try Transport.init(.{
        .alloc = std.testing.allocator,
        .cmd = "cat >/dev/null; printf 'text:ok\\n'; exit 9",
    });
    defer tr.deinit();

    var raw = try tr.start("{\"model\":\"m\"}");
    defer raw.deinit();

    _ = (try raw.next()) orelse return error.TestUnexpectedResult;
    try std.testing.expectError(error.BadGateway, raw.next());
}

// --- buildReq tests ---

test "buildReq emits request fixture JSON" {
    const user_parts = [_]providers.Part{
        .{ .text = "hello" },
        .{ .tool_call = .{ .id = "c1", .name = "read", .args = "{\"path\":\"/tmp\"}" } },
    };
    const tool_parts = [_]providers.Part{
        .{ .tool_result = .{ .id = "c1", .output = "ok", .is_err = false } },
    };
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = user_parts[0..] },
        .{ .role = .tool, .parts = tool_parts[0..] },
    };
    const tools = [_]providers.Tool{
        .{ .name = "read", .desc = "Read file", .schema = "{}" },
    };
    const stops = [_][]const u8{ "DONE", "ERR" };

    const req: providers.Request = .{
        .model = "first-model",
        .msgs = msgs[0..],
        .tools = tools[0..],
        .opts = .{
            .temp = 0.25,
            .top_p = 0.9,
            .max_out = 128,
            .stop = stops[0..],
        },
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"first-model","msgs":[{"role":"user","parts":[{"type":"text","text":"hello"},{"type":"tool_call","id":"c1","name":"read","args":"{\"path\":\"/tmp\"}"}]},{"role":"tool","parts":[{"type":"tool_result","id":"c1","out":"ok","is_err":false}]}],"tools":[{"name":"read","desc":"Read file","schema":"{}"}],"opts":{"temp":0.25,"top_p":0.8999999761581421,"max_out":128,"stop":["DONE","ERR"]}}"
    );
}

test "buildReq includes provider field when set" {
    const msgs = [_]providers.Msg{
        .{ .role = .user, .parts = &.{.{ .text = "hi" }} },
    };
    const req: providers.Request = .{
        .model = "m1",
        .provider = "anthropic",
        .msgs = msgs[0..],
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"m1","provider":"anthropic","msgs":[{"role":"user","parts":[{"type":"text","text":"hi"}]}],"tools":[],"opts":{"stop":[]}}"
    );
}

test "buildReq emits thinking budget mode" {
    const req: providers.Request = .{
        .model = "m1",
        .msgs = &.{},
        .opts = .{
            .thinking = .budget,
            .thinking_budget = 4096,
        },
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"m1","msgs":[],"tools":[],"opts":{"stop":[],"thinking":"budget","thinking_budget":4096}}"
    );
}

test "buildReq omits thinking when adaptive (default)" {
    const req: providers.Request = .{
        .model = "m1",
        .msgs = &.{},
        .opts = .{
            .thinking = .adaptive,
        },
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"m1","msgs":[],"tools":[],"opts":{"stop":[]}}"
    );
}

test "buildReq emits thinking off mode" {
    const req: providers.Request = .{
        .model = "m1",
        .msgs = &.{},
        .opts = .{
            .thinking = .off,
        },
    };

    const raw = try buildReq(std.testing.allocator, req);
    defer std.testing.allocator.free(raw);
    try expectSnap(@src(), raw,
        \\[]u8
        \\  "{"model":"m1","msgs":[],"tools":[],"opts":{"stop":[],"thinking":"off"}}"
    );
}
