//! Tool definitions, registry, and dispatch types.
const std = @import("std");
const runtime = @import("tools/runtime.zig");
pub const truncate = @import("tools/truncate.zig");
pub const shared = @import("tools/shared.zig");
pub const builtin = @import("tools/builtin.zig");
pub const read = @import("tools/read.zig");
pub const write = @import("tools/write.zig");
pub const bash = @import("tools/bash.zig");
pub const edit = @import("tools/edit.zig");
pub const grep = @import("tools/grep.zig");
pub const find = @import("tools/find.zig");
pub const ls = @import("tools/ls.zig");
pub const agent = @import("tools/agent.zig");
pub const skill = @import("tools/skill.zig");
pub const web = @import("tools/web.zig");
pub const contract_test = @import("tools/test.zig");

pub const Kind = enum {
    read,
    write,
    bash,
    edit,
    grep,
    find,
    ls,
    agent,
    web,
    ask,
    skill,
};

pub const Tool = struct {
    kind: Kind,
    desc: []const u8,
    params: []const Param,
    schema_json: ?[]const u8 = null,
    out: OutSpec,
    timeout_ms: u32,
    destructive: bool,

    pub const Param = struct {
        name: []const u8,
        ty: Type,
        required: bool,
        desc: []const u8,
    };

    pub const Type = enum {
        string,
        int,
        bool,
    };

    pub const OutSpec = struct {
        max_bytes: u32,
        stream: bool,
    };
};

pub const Spec = Tool;

pub const CancelSrc = struct {
    vt: *const Vt,

    pub const Vt = struct {
        is_canceled: *const fn (self: *CancelSrc) bool,
    };

    pub fn isCanceled(self: *CancelSrc) bool {
        return self.vt.is_canceled(self);
    }

    pub fn jsonStringify(_: CancelSrc, jw: anytype) !void {
        try jw.write(null);
    }

    pub fn Bind(comptime T: type, comptime method: fn (*T) bool) type {
        return struct {
            pub const vt = Vt{
                .is_canceled = isCanceledFn,
            };
            fn isCanceledFn(cs: *CancelSrc) bool {
                const self: *T = @fieldParentPtr("cancel_src", cs);
                return method(self);
            }
        };
    }
};

pub const Call = struct {
    id: []const u8,
    kind: Kind,
    args: Args,
    src: Source,
    at_ms: i64,
    cancel: ?*CancelSrc = null,

    pub const Source = enum {
        model,
        system,
        replay,
    };

    pub const Args = union(Kind) {
        read: ReadArgs,
        write: WriteArgs,
        bash: BashArgs,
        edit: EditArgs,
        grep: GrepArgs,
        find: FindArgs,
        ls: LsArgs,
        agent: AgentArgs,
        web: WebArgs,
        ask: AskArgs,
        skill: SkillArgs,
    };

    pub const ReadArgs = struct {
        path: []const u8,
        from_line: ?u32 = null,
        to_line: ?u32 = null,
    };

    pub const WriteArgs = struct {
        path: []const u8,
        text: []const u8,
        append: bool = false,
    };

    pub const BashArgs = struct {
        cmd: []const u8,
        cwd: ?[]const u8 = null,
        env: []const Env = &.{},
    };

    pub const EditArgs = struct {
        path: []const u8,
        old: []const u8,
        new: []const u8,
        all: bool = false,
    };

    pub const GrepArgs = struct {
        pattern: []const u8,
        path: []const u8 = ".",
        ignore_case: bool = false,
        max_results: u32 = 200,
    };

    pub const FindArgs = struct {
        name: []const u8,
        path: []const u8 = ".",
        max_results: u32 = 200,
    };

    pub const LsArgs = struct {
        path: []const u8 = ".",
        all: bool = false,
    };

    pub const AgentArgs = struct {
        agent_id: []const u8,
        prompt: []const u8,
    };

    pub const WebArgs = web.Request;

    pub const AskArgs = struct {
        questions: []const Question,

        pub const Question = struct {
            id: []const u8,
            header: []const u8 = "",
            question: []const u8,
            options: []const Option,
            allow_other: bool = true,
        };

        pub const Option = struct {
            label: []const u8,
            description: []const u8 = "",
        };
    };

    pub const SkillArgs = struct {
        name: []const u8,
        args: []const u8 = "",
    };

    pub const Env = struct {
        key: []const u8,
        val: []const u8,
    };
};

pub const Output = struct {
    call_id: []const u8,
    seq: u32,
    at_ms: i64,
    stream: Stream,
    chunk: []const u8,
    owned: bool = false,
    truncated: bool = false,

    pub const Stream = enum {
        stdout,
        stderr,
        meta,
    };
};

pub const Result = struct {
    call_id: []const u8,
    started_at_ms: i64,
    ended_at_ms: i64,
    out: []const Output,
    out_owned: bool = false,
    out_streamed: bool = false,
    final: Final,

    pub const Final = union(Tag) {
        ok: Ok,
        failed: Failed,
        cancelled: Cancelled,
        timed_out: TimedOut,
    };

    pub const Tag = enum {
        ok,
        failed,
        cancelled,
        timed_out,
    };

    pub const Ok = struct {
        code: i32 = 0,
    };

    pub const Failed = struct {
        code: ?i32 = null,
        kind: ErrKind,
        msg: []const u8,
    };

    pub const Cancelled = struct {
        reason: CancelReason,
    };

    pub const TimedOut = struct {
        limit_ms: u32,
    };

    pub const CancelReason = enum {
        user,
        shutdown,
        superseded,
    };

    pub const ErrKind = enum {
        invalid_args,
        not_found,
        denied,
        io,
        exec,
        internal,
    };
};

pub const Event = union(enum) {
    start: Start,
    output: Output,
    finish: Result,

    pub const Start = struct {
        call: Call,
        at_ms: i64,
    };
};

const rt = runtime.bind(Kind, Spec, Call, Event, Result);

pub const Sink = rt.Sink;
pub const Dispatch = rt.Dispatch;
pub const Entry = rt.Entry;
pub const Registry = rt.Registry;
pub const RegistryErr = rt.Err;

test "CancelSrc forwards isCanceled" {
    const Impl = struct {
        cancel_src: CancelSrc = .{ .vt = &CancelSrc.Bind(@This(), @This().isCanceled).vt },
        canceled: bool = false,

        fn isCanceled(self: *@This()) bool {
            return self.canceled;
        }
    };

    var impl = Impl{
        .canceled = true,
    };

    try std.testing.expect(impl.cancel_src.isCanceled());
}

test "CancelSrc stringifies as null" {
    const Impl = struct {
        cancel_src: CancelSrc = .{ .vt = &CancelSrc.Bind(@This(), @This().isCanceled).vt },
        fn isCanceled(_: *@This()) bool {
            return false;
        }
    };

    const impl = Impl{};
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, impl.cancel_src, .{});
    defer std.testing.allocator.free(json);

    try std.testing.expectEqualStrings("null", json);
}
