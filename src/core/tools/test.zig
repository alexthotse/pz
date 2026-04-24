//! Tool contract tests: verify all tools conform to registry interface.
const std = @import("std");
const OhSnap = @import("ohsnap");
const path_guard = @import("path_guard.zig");
const tools = @import("../tools.zig");
const noop = @import("../../test/noop_sink.zig");

const OutSnap = struct {
    call_id: []const u8,
    seq: u32,
    at_ms: i64,
    stream: tools.Output.Stream,
    truncated: bool,
};

const ResultSnap = struct {
    call_id: []const u8,
    started_at_ms: i64,
    ended_at_ms: i64,
    final: tools.Result.Tag,
    out: []OutSnap,
};

fn snapshotResult(alloc: std.mem.Allocator, res: tools.Result) !ResultSnap {
    var out = try alloc.alloc(OutSnap, res.out.len);
    for (res.out, 0..) |row, i| {
        out[i] = .{
            .call_id = row.call_id,
            .seq = row.seq,
            .at_ms = row.at_ms,
            .stream = row.stream,
            .truncated = row.truncated,
        };
    }
    return .{
        .call_id = res.call_id,
        .started_at_ms = res.started_at_ms,
        .ended_at_ms = res.ended_at_ms,
        .final = std.meta.activeTag(res.final),
        .out = out,
    };
}

test "tool contract handlers emit deterministic envelopes" {
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    const path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    const in_path = try std.fs.path.join(std.testing.allocator, &.{ path, "in.txt" });
    defer std.testing.allocator.free(in_path);
    try tmp.dir.writeFile(.{
        .sub_path = "in.txt",
        .data = "a\nb\n",
    });

    const out_path = try std.fs.path.join(std.testing.allocator, &.{ path, "out.txt" });
    defer std.testing.allocator.free(out_path);
    try tmp.dir.writeFile(.{
        .sub_path = "out.txt",
        .data = "x",
    });

    const edit_path = try std.fs.path.join(std.testing.allocator, &.{ path, "edit.txt" });
    defer std.testing.allocator.free(edit_path);
    try tmp.dir.writeFile(.{
        .sub_path = "edit.txt",
        .data = "abc abc",
    });
    try tmp.dir.makePath("tree/sub");
    try tmp.dir.writeFile(.{
        .sub_path = "tree/sub/hit.txt",
        .data = "needle\n",
    });

    const sink = noop.sink();

    const rd = @import("read.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 11,
    });
    const rd_call: tools.Call = .{
        .id = "r1",
        .kind = .read,
        .args = .{
            .read = .{
                .path = in_path,
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const rd_res = try rd.run(rd_call, sink);
    defer rd.deinitResult(rd_res);

    const wr = @import("write.zig").Handler.init(.{
        .now_ms = 22,
    });
    const wr_call: tools.Call = .{
        .id = "w1",
        .kind = .write,
        .args = .{
            .write = .{
                .path = out_path,
                .text = "ok",
                .append = false,
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const wr_res = try wr.run(wr_call, sink);

    const ed = @import("edit.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 33,
    });
    const ed_call: tools.Call = .{
        .id = "e1",
        .kind = .edit,
        .args = .{
            .edit = .{
                .path = edit_path,
                .old = "abc",
                .new = "z",
                .all = false,
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const ed_res = try ed.run(ed_call, sink);

    const sh = @import("bash.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 44,
    });
    const sh_call: tools.Call = .{
        .id = "b1",
        .kind = .bash,
        .args = .{
            .bash = .{
                .cmd = "printf out",
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const sh_res = try sh.run(sh_call, sink);
    defer sh.deinitResult(sh_res);

    const ls_h = @import("ls.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 66,
    });
    const ls_call: tools.Call = .{
        .id = "l1",
        .kind = .ls,
        .args = .{
            .ls = .{
                .path = path,
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const ls_res = try ls_h.run(ls_call, sink);
    defer ls_h.deinitResult(ls_res);

    const AgentImpl = struct {
        hook: @import("agent.zig").Hook = .{ .vt = &Bind.vt },
        fn run(_: *@This(), args: tools.Call.AgentArgs) !@import("../agent.zig").ChildProc.RunResult {
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
        const Bind = @import("agent.zig").Hook.Bind(@This(), run);
    };
    var agent_impl = AgentImpl{};
    const agent_h = @import("agent.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 70,
        .hook = &agent_impl.hook,
        .policy_hash = "test",
    });
    const agent_call: tools.Call = .{
        .id = "a1",
        .kind = .agent,
        .args = .{
            .agent = .{
                .agent_id = "critic",
                .prompt = "delegated to child agent",
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const agent_res = try agent_h.run(agent_call, sink);
    defer agent_h.deinitResult(agent_res);

    const find_h = @import("find.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 77,
    });
    const find_call: tools.Call = .{
        .id = "f1",
        .kind = .find,
        .args = .{
            .find = .{
                .path = path,
                .name = "hit",
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const find_res = try find_h.run(find_call, sink);
    defer find_h.deinitResult(find_res);

    const grep_h = @import("grep.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 4096,
        .now_ms = 88,
    });
    const grep_call: tools.Call = .{
        .id = "g1",
        .kind = .grep,
        .args = .{
            .grep = .{
                .path = path,
                .pattern = "needle",
            },
        },
        .src = .system,
        .at_ms = 0,
    };
    const grep_res = try grep_h.run(grep_call, sink);
    defer grep_h.deinitResult(grep_res);

    const snaps = [_]ResultSnap{
        try snapshotResult(std.testing.allocator, rd_res),
        try snapshotResult(std.testing.allocator, wr_res),
        try snapshotResult(std.testing.allocator, ed_res),
        try snapshotResult(std.testing.allocator, sh_res),
        try snapshotResult(std.testing.allocator, ls_res),
        try snapshotResult(std.testing.allocator, agent_res),
        try snapshotResult(std.testing.allocator, find_res),
        try snapshotResult(std.testing.allocator, grep_res),
    };
    defer for (snaps) |snap| std.testing.allocator.free(snap.out);
    try oh.snap(@src(),
        \\<!update>
        \\[8]core.tools.test.ResultSnap
        \\  [0]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "r1"
        \\    .started_at_ms: i64 = 11
        \\    .ended_at_ms: i64 = 11
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "r1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 11
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
        \\  [1]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "w1"
        \\    .started_at_ms: i64 = 22
        \\    .ended_at_ms: i64 = 22
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      (empty)
        \\  [2]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "e1"
        \\    .started_at_ms: i64 = 33
        \\    .ended_at_ms: i64 = 33
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      (empty)
        \\  [3]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "b1"
        \\    .started_at_ms: i64 = 44
        \\    .ended_at_ms: i64 = 44
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "b1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 44
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
        \\  [4]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "l1"
        \\    .started_at_ms: i64 = 66
        \\    .ended_at_ms: i64 = 66
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "l1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 66
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
        \\  [5]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "a1"
        \\    .started_at_ms: i64 = 70
        \\    .ended_at_ms: i64 = 70
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "a1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 70
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
        \\  [6]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "f1"
        \\    .started_at_ms: i64 = 77
        \\    .ended_at_ms: i64 = 77
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "f1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 77
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
        \\  [7]: core.tools.test.ResultSnap
        \\    .call_id: []const u8
        \\      "g1"
        \\    .started_at_ms: i64 = 88
        \\    .ended_at_ms: i64 = 88
        \\    .final: core.tools.Result.Tag
        \\      .ok
        \\    .out: []core.tools.test.OutSnap
        \\      [0]: core.tools.test.OutSnap
        \\        .call_id: []const u8
        \\          "g1"
        \\        .seq: u32 = 0
        \\        .at_ms: i64 = 88
        \\        .stream: core.tools.Output.Stream
        \\          .stdout
        \\        .truncated: bool = false
    ).expectEqual(snaps);
}

test "tool contract handlers deny nested symlink escapes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var outer = std.testing.tmpDir(.{});
    defer outer.cleanup();

    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath("safe/nest");
    try outer.dir.writeFile(.{ .sub_path = "secret.txt", .data = "top-secret\n" });

    const outer_root = try outer.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outer_root);
    try tmp.dir.symLink(outer_root, "safe/nest/link", .{ .is_directory = true });

    const cwd_root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(cwd_root);
    const escaped_dir = try std.fs.path.join(std.testing.allocator, &.{ cwd_root, "safe/nest/link" });
    defer std.testing.allocator.free(escaped_dir);
    const escaped_file = try std.fs.path.join(std.testing.allocator, &.{ cwd_root, "safe/nest/link/secret.txt" });
    defer std.testing.allocator.free(escaped_file);

    const sink = noop.sink();

    const rd = @import("read.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    try std.testing.expectError(error.Denied, rd.run(.{
        .id = "r-deny",
        .kind = .read,
        .args = .{
            .read = .{ .path = escaped_file },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));

    const wr = @import("write.zig").Handler.init(.{});
    try std.testing.expectError(error.Denied, wr.run(.{
        .id = "w-deny",
        .kind = .write,
        .args = .{
            .write = .{
                .path = escaped_file,
                .text = "overwrite",
            },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));

    const ed = @import("edit.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    try std.testing.expectError(error.Denied, ed.run(.{
        .id = "e-deny",
        .kind = .edit,
        .args = .{
            .edit = .{
                .path = escaped_file,
                .old = "top",
                .new = "low",
            },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));

    const ls_h = @import("ls.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    try std.testing.expectError(error.Denied, ls_h.run(.{
        .id = "l-deny",
        .kind = .ls,
        .args = .{
            .ls = .{ .path = escaped_dir },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));

    const find_h = @import("find.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    try std.testing.expectError(error.Denied, find_h.run(.{
        .id = "f-deny",
        .kind = .find,
        .args = .{
            .find = .{
                .path = escaped_dir,
                .name = "secret",
            },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));

    const grep_h = @import("grep.zig").Handler.init(.{
        .alloc = std.testing.allocator,
        .max_bytes = 1024,
    });
    try std.testing.expectError(error.Denied, grep_h.run(.{
        .id = "g-deny",
        .kind = .grep,
        .args = .{
            .grep = .{
                .path = escaped_dir,
                .pattern = "secret",
            },
        },
        .src = .system,
        .at_ms = 0,
    }, sink));
}

test "tool contract registry emits start output finish ordering" {
    const oh = OhSnap{};
    const SinkImpl = struct {
        sink: tools.Sink = undefined,
        tags: [8]std.meta.Tag(tools.Event) = undefined,
        ct: usize = 0,

        fn push(self: *@This(), ev: tools.Event) !void {
            if (self.ct >= self.tags.len) return error.OutOfMemory;
            self.tags[self.ct] = std.meta.activeTag(ev);
            self.ct += 1;
        }
    };
    const SinkBind = tools.Sink.Bind(SinkImpl, SinkImpl.push);
    var sink_impl = SinkImpl{ .sink = .{ .vt = &SinkBind.vt } };

    const Wrap = struct {
        dispatch: tools.Dispatch = .{ .vt = &Bind.vt },
        h: @import("bash.zig").Handler,

        fn run(self: *@This(), call: tools.Call, s: *tools.Sink) !tools.Result {
            return self.h.run(call, s);
        }
        const Bind = tools.Dispatch.Bind(@This(), run);
    };
    var wrap = Wrap{
        .h = @import("bash.zig").Handler.init(.{
            .alloc = std.testing.allocator,
            .max_bytes = 4096,
            .now_ms = 55,
        }),
    };

    const entries = [_]tools.Entry{
        .{
            .name = "bash",
            .kind = .bash,
            .spec = .{
                .kind = .bash,
                .desc = "bash",
                .params = &.{},
                .out = .{
                    .max_bytes = 4096,
                    .stream = true,
                },
                .timeout_ms = 1000,
                .destructive = true,
            },
            .dispatch = &wrap.dispatch,
        },
    };
    const reg = tools.Registry.init(entries[0..]);

    const call: tools.Call = .{
        .id = "call-1",
        .kind = .bash,
        .args = .{
            .bash = .{
                .cmd = "printf hi",
            },
        },
        .src = .model,
        .at_ms = 1,
    };
    const res = try reg.run("bash", call, &sink_impl.sink);
    defer wrap.h.deinitResult(res);

    try oh.snap(@src(),
        \\[]@typeInfo(core.tools.Event).@"union".tag_type.?
        \\  [0]: @typeInfo(core.tools.Event).@"union".tag_type.?
        \\    .start
        \\  [1]: @typeInfo(core.tools.Event).@"union".tag_type.?
        \\    .finish
    ).expectEqual(sink_impl.tags[0..sink_impl.ct]);
}
