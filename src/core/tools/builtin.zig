//! Built-in tool specs: parameter schemas and metadata.
const std = @import("std");
const tools = @import("../tools.zig");
const read = @import("read.zig");
const write = @import("write.zig");
const bash = @import("bash.zig");
const edit = @import("edit.zig");
const grep = @import("grep.zig");
const find = @import("find.zig");
const ls = @import("ls.zig");
const agent_tool = @import("agent.zig");
const path_guard = @import("path_guard.zig");
const skill = @import("skill.zig");
const tool_snap = @import("../../test/tool_snap.zig");

const default_max_bytes: usize = 64 * 1024;
pub const mask_read: u16 = 1 << 0;
pub const mask_write: u16 = 1 << 1;
pub const mask_bash: u16 = 1 << 2;
pub const mask_edit: u16 = 1 << 3;
pub const mask_grep: u16 = 1 << 4;
pub const mask_find: u16 = 1 << 5;
pub const mask_ls: u16 = 1 << 6;
pub const mask_agent: u16 = 1 << 7;
pub const mask_ask: u16 = 1 << 8;
pub const mask_skill: u16 = 1 << 9;
pub const mask_all: u16 =
    mask_read |
    mask_write |
    mask_bash |
    mask_edit |
    mask_grep |
    mask_find |
    mask_ls |
    mask_agent |
    mask_ask |
    mask_skill;

const read_params = [_]tools.Tool.Param{
    .{ .name = "path", .ty = .string, .required = true, .desc = "File path" },
    .{ .name = "from_line", .ty = .int, .required = false, .desc = "Start line (1-based)" },
    .{ .name = "to_line", .ty = .int, .required = false, .desc = "End line (inclusive)" },
};

const write_params = [_]tools.Tool.Param{
    .{ .name = "path", .ty = .string, .required = true, .desc = "File path" },
    .{ .name = "text", .ty = .string, .required = true, .desc = "Content to write" },
    .{ .name = "append", .ty = .bool, .required = false, .desc = "Append instead of truncating" },
};

const bash_params = [_]tools.Tool.Param{
    .{ .name = "cmd", .ty = .string, .required = true, .desc = "Shell command" },
    .{ .name = "cwd", .ty = .string, .required = false, .desc = "Working directory" },
    .{ .name = "env", .ty = .string, .required = false, .desc = "Environment variables (KEY=VALUE, one per line)" },
};

const edit_params = [_]tools.Tool.Param{
    .{ .name = "path", .ty = .string, .required = true, .desc = "File path" },
    .{ .name = "old", .ty = .string, .required = true, .desc = "Substring to replace" },
    .{ .name = "new", .ty = .string, .required = true, .desc = "Replacement text" },
    .{ .name = "all", .ty = .bool, .required = false, .desc = "Replace all matches" },
};

const grep_params = [_]tools.Tool.Param{
    .{ .name = "pattern", .ty = .string, .required = true, .desc = "Substring to match in file lines" },
    .{ .name = "path", .ty = .string, .required = false, .desc = "Root directory to search" },
    .{ .name = "ignore_case", .ty = .bool, .required = false, .desc = "Case-insensitive matching" },
    .{ .name = "max_results", .ty = .int, .required = false, .desc = "Maximum matches to return" },
};

const find_params = [_]tools.Tool.Param{
    .{ .name = "name", .ty = .string, .required = true, .desc = "Substring to match in entry names" },
    .{ .name = "path", .ty = .string, .required = false, .desc = "Root directory to walk" },
    .{ .name = "max_results", .ty = .int, .required = false, .desc = "Maximum paths to return" },
};

const ls_params = [_]tools.Tool.Param{
    .{ .name = "path", .ty = .string, .required = false, .desc = "Directory to list" },
    .{ .name = "all", .ty = .bool, .required = false, .desc = "Include hidden entries" },
};

const agent_params = [_]tools.Tool.Param{
    .{ .name = "agent_id", .ty = .string, .required = true, .desc = "Target child agent id" },
    .{ .name = "prompt", .ty = .string, .required = true, .desc = "Prompt forwarded to the child agent" },
};

const skill_params = [_]tools.Tool.Param{
    .{ .name = "name", .ty = .string, .required = true, .desc = "Skill directory name" },
    .{ .name = "args", .ty = .string, .required = false, .desc = "Optional user arguments appended to the skill body" },
};

const ask_schema =
    \\{
    \\  "type": "object",
    \\  "properties": {
    \\    "questions": {
    \\      "type": "array",
    \\      "items": {
    \\        "type": "object",
    \\        "properties": {
    \\          "id": { "type": "string", "description": "Stable question id" },
    \\          "header": { "type": "string", "description": "Short title shown above the question" },
    \\          "question": { "type": "string", "description": "Question prompt text" },
    \\          "allow_other": { "type": "boolean", "description": "Include a Type something else option (default true)" },
    \\          "options": {
    \\            "type": "array",
    \\            "items": {
    \\              "type": "object",
    \\              "properties": {
    \\                "label": { "type": "string", "description": "Option label" },
    \\                "description": { "type": "string", "description": "Optional option detail text" }
    \\              },
    \\              "required": ["label"]
    \\            }
    \\          }
    \\        },
    \\        "required": ["id", "question", "options"]
    \\      }
    \\    }
    \\  },
    \\  "required": ["questions"]
    \\}
;

pub const AskHook = struct {
    ctx: *anyopaque,
    run_fn: *const fn (ctx: *anyopaque, args: tools.Call.AskArgs) anyerror![]u8,

    pub fn from(
        comptime T: type,
        ctx: *T,
        comptime run_fn: fn (ctx: *T, args: tools.Call.AskArgs) anyerror![]u8,
    ) AskHook {
        const Wrap = struct {
            fn call(raw: *anyopaque, args: tools.Call.AskArgs) anyerror![]u8 {
                const typed: *T = @ptrCast(@alignCast(raw));
                return run_fn(typed, args);
            }
        };
        return .{
            .ctx = ctx,
            .run_fn = Wrap.call,
        };
    }

    pub fn run(self: AskHook, args: tools.Call.AskArgs) ![]u8 {
        return self.run_fn(self.ctx, args);
    }
};

pub const Opts = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize = default_max_bytes,
    tool_mask: u16 = mask_all,
    agent_hook: ?agent_tool.Hook = null,
    ask_hook: ?AskHook = null,
};

pub const Runtime = struct {
    alloc: std.mem.Allocator,
    max_bytes: usize,
    tool_mask: u16,
    agent_hook: ?agent_tool.Hook,
    ask_hook: ?AskHook,
    skill_cache: skill.Cache = .{},
    entries: [10]tools.Entry = undefined,
    selected: [10]tools.Entry = undefined,

    pub fn init(opts: Opts) Runtime {
        return .{
            .alloc = opts.alloc,
            .max_bytes = opts.max_bytes,
            .tool_mask = opts.tool_mask & mask_all,
            .agent_hook = opts.agent_hook,
            .ask_hook = opts.ask_hook,
        };
    }

    pub fn registry(self: *Runtime) tools.Registry {
        self.rebuildEntries();
        return tools.Registry.init(self.activeEntries());
    }

    pub fn deinit(self: *Runtime) void {
        self.skill_cache.deinit(self.alloc);
    }

    pub fn deinitResult(self: Runtime, res: tools.Result) void {
        if (!res.out_owned) return;
        for (res.out) |out| {
            if (out.owned) self.alloc.free(out.chunk);
        }
        self.alloc.free(res.out);
    }

    fn rebuildEntries(self: *Runtime) void {
        self.entries = .{
            .{
                .name = "read",
                .kind = .read,
                .spec = .{
                    .kind = .read,
                    .desc = "Read file contents",
                    .params = read_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 2000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runRead),
            },
            .{
                .name = "write",
                .kind = .write,
                .spec = .{
                    .kind = .write,
                    .desc = "Write file contents",
                    .params = write_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 2000,
                    .destructive = true,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runWrite),
            },
            .{
                .name = "bash",
                .kind = .bash,
                .spec = .{
                    .kind = .bash,
                    .desc = "Run bash command",
                    .params = bash_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = true,
                    },
                    .timeout_ms = 30000,
                    .destructive = true,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runBash),
            },
            .{
                .name = "edit",
                .kind = .edit,
                .spec = .{
                    .kind = .edit,
                    .desc = "Edit file by string replacement",
                    .params = edit_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 2000,
                    .destructive = true,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runEdit),
            },
            .{
                .name = "grep",
                .kind = .grep,
                .spec = .{
                    .kind = .grep,
                    .desc = "Search file contents recursively",
                    .params = grep_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 10000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runGrep),
            },
            .{
                .name = "find",
                .kind = .find,
                .spec = .{
                    .kind = .find,
                    .desc = "Find files and directories by name",
                    .params = find_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 10000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runFind),
            },
            .{
                .name = "ls",
                .kind = .ls,
                .spec = .{
                    .kind = .ls,
                    .desc = "List directory entries",
                    .params = ls_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 2000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runLs),
            },
            .{
                .name = "agent",
                .kind = .agent,
                .spec = .{
                    .kind = .agent,
                    .desc = "Run a child agent and return its bounded output",
                    .params = agent_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 120000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runAgent),
            },
            .{
                .name = "ask",
                .kind = .ask,
                .spec = .{
                    .kind = .ask,
                    .desc = "Ask one or more questions to collect user decisions",
                    .params = &.{},
                    .schema_json = ask_schema,
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 120000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runAsk),
            },
            .{
                .name = "skill",
                .kind = .skill,
                .spec = .{
                    .kind = .skill,
                    .desc = "Load a named skill into the model context",
                    .params = skill_params[0..],
                    .out = .{
                        .max_bytes = @intCast(self.max_bytes),
                        .stream = false,
                    },
                    .timeout_ms = 2000,
                    .destructive = false,
                },
                .dispatch = tools.Dispatch.from(Runtime, self, Runtime.runSkill),
            },
        };
    }

    fn activeEntries(self: *Runtime) []const tools.Entry {
        if (self.tool_mask == mask_all) return self.entries[0..];

        var len: usize = 0;
        if ((self.tool_mask & mask_read) != 0) {
            self.selected[len] = self.entries[0];
            len += 1;
        }
        if ((self.tool_mask & mask_write) != 0) {
            self.selected[len] = self.entries[1];
            len += 1;
        }
        if ((self.tool_mask & mask_bash) != 0) {
            self.selected[len] = self.entries[2];
            len += 1;
        }
        if ((self.tool_mask & mask_edit) != 0) {
            self.selected[len] = self.entries[3];
            len += 1;
        }
        if ((self.tool_mask & mask_grep) != 0) {
            self.selected[len] = self.entries[4];
            len += 1;
        }
        if ((self.tool_mask & mask_find) != 0) {
            self.selected[len] = self.entries[5];
            len += 1;
        }
        if ((self.tool_mask & mask_ls) != 0) {
            self.selected[len] = self.entries[6];
            len += 1;
        }
        if ((self.tool_mask & mask_agent) != 0) {
            self.selected[len] = self.entries[7];
            len += 1;
        }
        if ((self.tool_mask & mask_ask) != 0) {
            self.selected[len] = self.entries[8];
            len += 1;
        }
        if ((self.tool_mask & mask_skill) != 0) {
            self.selected[len] = self.entries[9];
            len += 1;
        }
        return self.selected[0..len];
    }

    fn runRead(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = read.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runWrite(_: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = write.Handler.init(.{
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runBash(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = bash.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runEdit(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = edit.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runGrep(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = grep.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runFind(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = find.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runLs(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = ls.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
        });
        return h.run(call, sink);
    }

    fn runAgent(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = agent_tool.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
            .hook = self.agent_hook,
        });
        return h.run(call, sink);
    }

    fn runAsk(self: *Runtime, call: tools.Call, _: tools.Sink) !tools.Result {
        if (call.kind != .ask or std.meta.activeTag(call.args) != .ask) return error.InvalidArgs;
        if (call.args.ask.questions.len == 0) {
            return .{
                .call_id = call.id,
                .started_at_ms = call.at_ms,
                .ended_at_ms = call.at_ms,
                .out = &.{},
                .final = .{
                    .failed = .{
                        .kind = .invalid_args,
                        .msg = "ask tool requires at least one question",
                    },
                },
            };
        }

        const hook = self.ask_hook orelse {
            return .{
                .call_id = call.id,
                .started_at_ms = call.at_ms,
                .ended_at_ms = call.at_ms,
                .out = &.{},
                .final = .{
                    .failed = .{
                        .kind = .invalid_args,
                        .msg = "ask tool requires interactive TUI mode",
                    },
                },
            };
        };

        const out_text = hook.run(call.args.ask) catch |err| {
            return .{
                .call_id = call.id,
                .started_at_ms = call.at_ms,
                .ended_at_ms = call.at_ms,
                .out = &.{},
                .final = .{
                    .failed = .{
                        .kind = .io,
                        .msg = @errorName(err),
                    },
                },
            };
        };
        errdefer self.alloc.free(out_text);

        const out = try self.alloc.alloc(tools.Output, 1);
        out[0] = .{
            .call_id = call.id,
            .seq = 0,
            .at_ms = call.at_ms,
            .stream = .stdout,
            .chunk = out_text,
            .owned = true,
            .truncated = false,
        };
        return .{
            .call_id = call.id,
            .started_at_ms = call.at_ms,
            .ended_at_ms = call.at_ms,
            .out = out,
            .out_owned = true,
            .final = if (askResultCancelled(out_text))
                .{ .cancelled = .{ .reason = .user } }
            else
                .{
                    .ok = .{ .code = 0 },
                },
        };
    }

    fn runSkill(self: *Runtime, call: tools.Call, sink: tools.Sink) !tools.Result {
        const h = skill.Handler.init(.{
            .alloc = self.alloc,
            .max_bytes = self.max_bytes,
            .now_ms = call.at_ms,
            .cache = &self.skill_cache,
        });
        return h.run(call, sink);
    }
};

fn askResultCancelled(raw: []const u8) bool {
    const Out = struct {
        cancelled: bool = false,
    };

    const parsed = std.json.parseFromSlice(Out, std.heap.smp_allocator, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();
    return parsed.value.cancelled;
}

pub fn maskForName(name: []const u8) ?u16 {
    const map = std.StaticStringMap(u16).initComptime(.{
        .{ "read", mask_read },
        .{ "write", mask_write },
        .{ "bash", mask_bash },
        .{ "edit", mask_edit },
        .{ "grep", mask_grep },
        .{ "find", mask_find },
        .{ "ls", mask_ls },
        .{ "agent", mask_agent },
        .{ "ask", mask_ask },
        .{ "skill", mask_skill },
    });
    return map.get(name);
}

const AskOutSnap = struct {
    call_id: []const u8,
    seq: u32,
    at_ms: i64,
    stream: tools.Output.Stream,
    chunk: []const u8,
    truncated: bool,
};

const AskFinalSnap = struct {
    tag: tools.Result.Tag,
    code: ?i32 = null,
    err_kind: ?tools.Result.ErrKind = null,
    msg: ?[]const u8 = null,
    reason: ?tools.Result.CancelReason = null,
    limit_ms: ?u32 = null,
};

const AskResultSnap = struct {
    call_id: []const u8,
    started_at_ms: i64,
    ended_at_ms: i64,
    final: AskFinalSnap,
    out: []AskOutSnap,
};

fn snapAskFinal(final: tools.Result.Final) AskFinalSnap {
    return switch (final) {
        .ok => |ok| .{
            .tag = .ok,
            .code = ok.code,
        },
        .failed => |failed| .{
            .tag = .failed,
            .err_kind = failed.kind,
            .msg = failed.msg,
        },
        .cancelled => |cancelled| .{
            .tag = .cancelled,
            .reason = cancelled.reason,
        },
        .timed_out => |timed_out| .{
            .tag = .timed_out,
            .limit_ms = timed_out.limit_ms,
        },
    };
}

fn snapAskResult(alloc: std.mem.Allocator, res: tools.Result) !AskResultSnap {
    var out = try alloc.alloc(AskOutSnap, res.out.len);
    for (res.out, 0..) |row, i| {
        out[i] = .{
            .call_id = row.call_id,
            .seq = row.seq,
            .at_ms = row.at_ms,
            .stream = row.stream,
            .chunk = row.chunk,
            .truncated = row.truncated,
        };
    }
    return .{
        .call_id = res.call_id,
        .started_at_ms = res.started_at_ms,
        .ended_at_ms = res.ended_at_ms,
        .final = snapAskFinal(res.final),
        .out = out,
    };
}

fn freeAskResultSnap(alloc: std.mem.Allocator, snap: AskResultSnap) void {
    alloc.free(snap.out);
}

test "builtin runtime registry exposes all core tools" {
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
    });
    const reg = rt.registry();

    try std.testing.expect(reg.byName("read") != null);
    try std.testing.expect(reg.byName("write") != null);
    try std.testing.expect(reg.byName("bash") != null);
    try std.testing.expect(reg.byName("edit") != null);
    try std.testing.expect(reg.byName("grep") != null);
    try std.testing.expect(reg.byName("find") != null);
    try std.testing.expect(reg.byName("ls") != null);
    try std.testing.expect(reg.byName("agent") != null);
    try std.testing.expect(reg.byName("ask") != null);

    try std.testing.expect(reg.byKind(.read) != null);
    try std.testing.expect(reg.byKind(.write) != null);
    try std.testing.expect(reg.byKind(.bash) != null);
    try std.testing.expect(reg.byKind(.edit) != null);
    try std.testing.expect(reg.byKind(.grep) != null);
    try std.testing.expect(reg.byKind(.find) != null);
    try std.testing.expect(reg.byKind(.ls) != null);
    try std.testing.expect(reg.byKind(.agent) != null);
    try std.testing.expect(reg.byKind(.ask) != null);
}

test "builtin runtime uses call timestamp in result envelope" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.writeFile(.{
        .sub_path = "in.txt",
        .data = "abc\n",
    });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "in.txt");
    defer std.testing.allocator.free(path);

    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    const reg = rt.registry();
    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const call: tools.Call = .{
        .id = "t1",
        .kind = .read,
        .args = .{
            .read = .{
                .path = path,
            },
        },
        .src = .system,
        .at_ms = 12345,
    };

    const res = try reg.run("read", call, sink);
    defer rt.deinitResult(res);
    const snap = try tool_snap.resultAlloc(std.testing.allocator, res);
    defer std.testing.allocator.free(snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "call=t1
        \\start=12345
        \\end=12345
        \\out=1
        \\0=t1|12345|stdout|false|abc
        \\
        \\final=ok|0
        \\"
    ).expectEqual(snap);
}

test "builtin runtime supports deterministic tool mask filtering" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        len: usize,
        first: []const u8,
        second: []const u8,
        has_write: bool,
    };
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_read | mask_agent,
    });
    const reg = rt.registry();

    try oh.snap(@src(),
        \\core.tools.builtin.test.builtin runtime supports deterministic tool mask filtering.Snap
        \\  .len: usize = 2
        \\  .first: []const u8
        \\    "read"
        \\  .second: []const u8
        \\    "agent"
        \\  .has_write: bool = false
    ).expectEqual(Snap{
        .len = reg.entries.len,
        .first = reg.entries[0].name,
        .second = reg.entries[1].name,
        .has_write = reg.byName("write") != null,
    });
}

test "agent tool uses runtime hook output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const AgentImpl = struct {
        seen: usize = 0,

        fn run(self: *@This(), args: tools.Call.AgentArgs) !@import("../agent.zig").ChildProc.RunResult {
            self.seen += 1;
            return .{
                .out = .{
                    .id = "req-1",
                    .kind = .text,
                    .text = args.prompt,
                },
                .done = .{
                    .id = "req-1",
                    .stop = .done,
                    .truncated = false,
                },
            };
        }
    };

    var impl = AgentImpl{};
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_agent,
        .agent_hook = agent_tool.Hook.from(AgentImpl, &impl, AgentImpl.run),
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const call: tools.Call = .{
        .id = "agent-hook",
        .kind = .agent,
        .args = .{
            .agent = .{
                .agent_id = "critic",
                .prompt = "delegated to child agent",
            },
        },
        .src = .model,
        .at_ms = 12,
    };

    const res = try reg.run("agent", call, sink);
    defer rt.deinitResult(res);
    try std.testing.expectEqual(@as(usize, 1), impl.seen);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "agent-hook"
        \\  .started_at_ms: i64 = 12
        \\  .ended_at_ms: i64 = 12
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .ok
        \\    .code: ?i32
        \\      0
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      null
        \\    .msg: ?[]const u8
        \\      null
        \\    .reason: ?core.tools.Result.CancelReason
        \\      null
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    [0]: core.tools.builtin.AskOutSnap
        \\      .call_id: []const u8
        \\        "agent-hook"
        \\      .seq: u32 = 0
        \\      .at_ms: i64 = 12
        \\      .stream: core.tools.Output.Stream
        \\        .stdout
        \\      .chunk: []const u8
        \\        "agent: critic
        \\kind: text
        \\stop: done
        \\truncated: false
        \\
        \\delegated to child agent"
        \\      .truncated: bool = false
    ).expectEqual(snap);
}

test "ask tool requires interactive hook" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_ask,
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const opts = [_]tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick one",
            .options = opts[0..],
        },
    };
    const call: tools.Call = .{
        .id = "ask-1",
        .kind = .ask,
        .args = .{
            .ask = .{ .questions = qs[0..] },
        },
        .src = .model,
        .at_ms = 1,
    };

    const res = try reg.run("ask", call, sink);
    defer rt.deinitResult(res);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "ask-1"
        \\  .started_at_ms: i64 = 1
        \\  .ended_at_ms: i64 = 1
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .failed
        \\    .code: ?i32
        \\      null
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      .invalid_args
        \\    .msg: ?[]const u8
        \\      "ask tool requires interactive TUI mode"
        \\    .reason: ?core.tools.Result.CancelReason
        \\      null
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    (empty)
    ).expectEqual(snap);
}

test "ask tool rejects empty question list" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_ask,
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const call: tools.Call = .{
        .id = "ask-empty",
        .kind = .ask,
        .args = .{
            .ask = .{ .questions = &.{} },
        },
        .src = .model,
        .at_ms = 7,
    };
    const res = try reg.run("ask", call, sink);
    defer rt.deinitResult(res);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "ask-empty"
        \\  .started_at_ms: i64 = 7
        \\  .ended_at_ms: i64 = 7
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .failed
        \\    .code: ?i32
        \\      null
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      .invalid_args
        \\    .msg: ?[]const u8
        \\      "ask tool requires at least one question"
        \\    .reason: ?core.tools.Result.CancelReason
        \\      null
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    (empty)
    ).expectEqual(snap);
}

test "ask tool uses hook output" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const AskImpl = struct {
        alloc: std.mem.Allocator,
        seen: usize = 0,

        fn run(self: *@This(), args: tools.Call.AskArgs) ![]u8 {
            self.seen += args.questions.len;
            return self.alloc.dupe(u8, "{\"cancelled\":false,\"answers\":[{\"id\":\"scope\",\"answer\":\"A\",\"index\":0}]}");
        }
    };

    var impl = AskImpl{ .alloc = std.testing.allocator };
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_ask,
        .ask_hook = AskHook.from(AskImpl, &impl, AskImpl.run),
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const opts = [_]tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick one",
            .options = opts[0..],
        },
    };
    const call: tools.Call = .{
        .id = "ask-2",
        .kind = .ask,
        .args = .{
            .ask = .{ .questions = qs[0..] },
        },
        .src = .model,
        .at_ms = 2,
    };

    const res = try reg.run("ask", call, sink);
    defer rt.deinitResult(res);
    try std.testing.expectEqual(@as(usize, 1), impl.seen);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "ask-2"
        \\  .started_at_ms: i64 = 2
        \\  .ended_at_ms: i64 = 2
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .ok
        \\    .code: ?i32
        \\      0
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      null
        \\    .msg: ?[]const u8
        \\      null
        \\    .reason: ?core.tools.Result.CancelReason
        \\      null
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    [0]: core.tools.builtin.AskOutSnap
        \\      .call_id: []const u8
        \\        "ask-2"
        \\      .seq: u32 = 0
        \\      .at_ms: i64 = 2
        \\      .stream: core.tools.Output.Stream
        \\        .stdout
        \\      .chunk: []const u8
        \\        "{"cancelled":false,"answers":[{"id":"scope","answer":"A","index":0}]}"
        \\      .truncated: bool = false
    ).expectEqual(snap);
}

test "ask tool reports hook failure" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const AskImpl = struct {
        fn run(_: *@This(), _: tools.Call.AskArgs) ![]u8 {
            return error.BadInput;
        }
    };

    var impl = AskImpl{};
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_ask,
        .ask_hook = AskHook.from(AskImpl, &impl, AskImpl.run),
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const opts = [_]tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick one",
            .options = opts[0..],
        },
    };
    const call: tools.Call = .{
        .id = "ask-fail",
        .kind = .ask,
        .args = .{
            .ask = .{ .questions = qs[0..] },
        },
        .src = .model,
        .at_ms = 8,
    };
    const res = try reg.run("ask", call, sink);
    defer rt.deinitResult(res);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "ask-fail"
        \\  .started_at_ms: i64 = 8
        \\  .ended_at_ms: i64 = 8
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .failed
        \\    .code: ?i32
        \\      null
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      .io
        \\    .msg: ?[]const u8
        \\      "BadInput"
        \\    .reason: ?core.tools.Result.CancelReason
        \\      null
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    (empty)
    ).expectEqual(snap);
}

test "ask tool maps cancelled hook output to cancelled final" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const AskImpl = struct {
        alloc: std.mem.Allocator,

        fn run(self: *@This(), _: tools.Call.AskArgs) ![]u8 {
            return self.alloc.dupe(u8, "{\"cancelled\":true,\"answers\":[{\"id\":\"scope\",\"answer\":\"A\",\"index\":0}]}");
        }
    };

    var impl = AskImpl{ .alloc = std.testing.allocator };
    var rt = Runtime.init(.{
        .alloc = std.testing.allocator,
        .tool_mask = mask_ask,
        .ask_hook = AskHook.from(AskImpl, &impl, AskImpl.run),
    });
    const reg = rt.registry();

    const SinkImpl = struct {
        fn push(_: *@This(), _: tools.Event) !void {}
    };
    var sink_impl = SinkImpl{};
    const sink = tools.Sink.from(SinkImpl, &sink_impl, SinkImpl.push);

    const opts = [_]tools.Call.AskArgs.Option{
        .{ .label = "A" },
        .{ .label = "B" },
    };
    const qs = [_]tools.Call.AskArgs.Question{
        .{
            .id = "scope",
            .question = "Pick one",
            .options = opts[0..],
        },
    };
    const call: tools.Call = .{
        .id = "ask-cancel",
        .kind = .ask,
        .args = .{
            .ask = .{ .questions = qs[0..] },
        },
        .src = .model,
        .at_ms = 9,
    };

    const res = try reg.run("ask", call, sink);
    defer rt.deinitResult(res);
    const snap = try snapAskResult(std.testing.allocator, res);
    defer freeAskResultSnap(std.testing.allocator, snap);
    try oh.snap(@src(),
        \\core.tools.builtin.AskResultSnap
        \\  .call_id: []const u8
        \\    "ask-cancel"
        \\  .started_at_ms: i64 = 9
        \\  .ended_at_ms: i64 = 9
        \\  .final: core.tools.builtin.AskFinalSnap
        \\    .tag: core.tools.Result.Tag
        \\      .cancelled
        \\    .code: ?i32
        \\      null
        \\    .err_kind: ?core.tools.Result.ErrKind
        \\      null
        \\    .msg: ?[]const u8
        \\      null
        \\    .reason: ?core.tools.Result.CancelReason
        \\      .user
        \\    .limit_ms: ?u32
        \\      null
        \\  .out: []core.tools.builtin.AskOutSnap
        \\    [0]: core.tools.builtin.AskOutSnap
        \\      .call_id: []const u8
        \\        "ask-cancel"
        \\      .seq: u32 = 0
        \\      .at_ms: i64 = 9
        \\      .stream: core.tools.Output.Stream
        \\        .stdout
        \\      .chunk: []const u8
        \\        "{"cancelled":true,"answers":[{"id":"scope","answer":"A","index":0}]}"
        \\      .truncated: bool = false
    ).expectEqual(snap);
}

test "maskForName validates builtin tool names" {
    try std.testing.expect(maskForName("read") != null);
    try std.testing.expect(maskForName("write") != null);
    try std.testing.expect(maskForName("bash") != null);
    try std.testing.expect(maskForName("edit") != null);
    try std.testing.expect(maskForName("grep") != null);
    try std.testing.expect(maskForName("find") != null);
    try std.testing.expect(maskForName("ls") != null);
    try std.testing.expect(maskForName("agent") != null);
    try std.testing.expect(maskForName("ask") != null);
    try std.testing.expect(maskForName("skill") != null);
    try std.testing.expect(maskForName("wat") == null);
}
