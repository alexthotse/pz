//! Print mode output formatting: JSON and text serialization.
const std = @import("std");
const core = @import("../../core.zig");
const audit = core.audit;

const ToolCallOut = struct {
    id: []const u8,
    name: []const u8,
    args: []const u8,
};

const ToolResultOut = struct {
    id: []const u8,
    output: []const u8,
    is_err: bool,
};

pub const Formatter = struct {
    alloc: std.mem.Allocator,
    out: std.Io.AnyWriter,
    verbose: bool = false,
    text_seen: bool = false,
    text_ended_nl: bool = false,
    thinking: std.ArrayListUnmanaged([]const u8) = .{},
    tool_calls: std.ArrayListUnmanaged(ToolCallOut) = .{},
    tool_results: std.ArrayListUnmanaged(ToolResultOut) = .{},
    errs: std.ArrayListUnmanaged([]const u8) = .{},
    usage: ?core.providers.Usage = null,
    stop: ?core.providers.StopReason = null,

    pub fn init(alloc: std.mem.Allocator, out: std.Io.AnyWriter) Formatter {
        return .{
            .alloc = alloc,
            .out = out,
        };
    }

    pub fn deinit(self: *Formatter) void {
        for (self.thinking.items) |text| self.alloc.free(text);
        self.thinking.deinit(self.alloc);

        for (self.tool_calls.items) |tc| {
            self.alloc.free(tc.id);
            self.alloc.free(tc.name);
            self.alloc.free(tc.args);
        }
        self.tool_calls.deinit(self.alloc);

        for (self.tool_results.items) |tr| {
            self.alloc.free(tr.id);
            self.alloc.free(tr.output);
        }
        self.tool_results.deinit(self.alloc);

        for (self.errs.items) |text| self.alloc.free(text);
        self.errs.deinit(self.alloc);
    }

    pub fn push(self: *Formatter, ev: core.providers.Event) !void {
        switch (ev) {
            .text => |text| try self.pushText(text),
            .thinking => |text| try self.pushThinking(text),
            .tool_call => |tc| try self.pushToolCall(tc),
            .tool_result => |tr| try self.pushToolResult(tr),
            .usage => |usage| self.pushUsage(usage),
            .stop => |stop| self.pushStop(stop.reason),
            .err => |text| try self.pushErr(text),
        }
    }

    pub fn finish(self: *Formatter) !void {
        if (!self.verbose) {
            // Errors always shown even in non-verbose mode
            for (self.errs.items) |text| {
                try self.out.writeAll("err ");
                try writeQuoted(self.out, text);
                try self.out.writeByte('\n');
            }
            if (self.text_seen and !self.text_ended_nl) {
                try self.out.writeByte('\n');
            }
            return;
        }

        self.sortMeta();
        if (!self.hasMeta()) return;

        if (self.text_seen and !self.text_ended_nl) {
            try self.out.writeByte('\n');
        }

        for (self.thinking.items) |text| {
            try self.out.writeAll("thinking ");
            try writeQuoted(self.out, text);
            try self.out.writeByte('\n');
        }

        for (self.tool_calls.items) |tc| {
            try self.out.writeAll("tool_call id=");
            try writeQuoted(self.out, tc.id);
            try self.out.writeAll(" name=");
            try writeQuoted(self.out, tc.name);
            try self.out.writeAll(" args=");
            try writeQuoted(self.out, tc.args);
            try self.out.writeByte('\n');
        }

        for (self.tool_results.items) |tr| {
            try self.out.writeAll("tool_result id=");
            try writeQuoted(self.out, tr.id);
            try self.out.writeAll(" is_err=");
            try self.out.writeAll(if (tr.is_err) "true" else "false");
            try self.out.writeAll(" out=");
            try writeQuoted(self.out, tr.output);
            try self.out.writeByte('\n');
        }

        if (self.usage) |usage| {
            try self.out.print("usage in={d} out={d} total={d}\n", .{
                usage.in_tok,
                usage.out_tok,
                usage.tot_tok,
            });
        }

        if (self.stop) |reason| {
            try self.out.writeAll("stop reason=");
            try self.out.writeAll(stopName(reason));
            try self.out.writeByte('\n');
        }

        for (self.errs.items) |text| {
            try self.out.writeAll("err ");
            try writeQuoted(self.out, text);
            try self.out.writeByte('\n');
        }
    }

    fn pushText(self: *Formatter, text: []const u8) !void {
        if (text.len == 0) return;
        self.text_seen = true;
        self.text_ended_nl = text[text.len - 1] == '\n';
        const safe = try sanitizeOutput(self.alloc, text);
        defer if (safe.ptr != text.ptr) self.alloc.free(safe);
        const redacted = try audit.redactTextAlloc(self.alloc, safe, .@"pub");
        defer self.alloc.free(redacted);
        try self.out.writeAll(redacted);
    }

    fn pushThinking(self: *Formatter, text: []const u8) !void {
        const dup = try audit.redactTextAlloc(self.alloc, text, .@"pub");
        errdefer self.alloc.free(dup);
        try self.thinking.append(self.alloc, dup);
    }

    fn pushToolCall(self: *Formatter, tc: core.providers.ToolCall) !void {
        const id = try self.alloc.dupe(u8, tc.id);
        errdefer self.alloc.free(id);

        const name = try audit.redactTextAlloc(self.alloc, tc.name, .@"pub");
        errdefer self.alloc.free(name);

        const args = try audit.redactTextAlloc(self.alloc, tc.args, .@"pub");
        errdefer self.alloc.free(args);

        try self.tool_calls.append(self.alloc, .{
            .id = id,
            .name = name,
            .args = args,
        });
    }

    fn pushToolResult(self: *Formatter, tr: core.providers.ToolResult) !void {
        const id = try self.alloc.dupe(u8, tr.id);
        errdefer self.alloc.free(id);

        const out = try audit.redactTextAlloc(self.alloc, tr.output, .@"pub");
        errdefer self.alloc.free(out);

        try self.tool_results.append(self.alloc, .{
            .id = id,
            .output = out,
            .is_err = tr.is_err,
        });
    }

    fn pushUsage(self: *Formatter, usage: core.providers.Usage) void {
        if (self.usage == null or usageLessThan(self.usage.?, usage)) {
            self.usage = usage;
        }
    }

    fn pushStop(self: *Formatter, reason: core.providers.StopReason) void {
        if (self.stop == null or self.stop.?.rank() < reason.rank()) {
            self.stop = reason;
        }
    }

    fn pushErr(self: *Formatter, text: []const u8) !void {
        const dup = try audit.redactTextAlloc(self.alloc, text, .@"pub");
        errdefer self.alloc.free(dup);
        try self.errs.append(self.alloc, dup);
    }

    fn hasMeta(self: *const Formatter) bool {
        return self.thinking.items.len > 0 or
            self.tool_calls.items.len > 0 or
            self.tool_results.items.len > 0 or
            self.usage != null or
            self.stop != null or
            self.errs.items.len > 0;
    }

    fn sortMeta(self: *Formatter) void {
        std.sort.insertion([]const u8, self.thinking.items, {}, lessText);
        std.sort.insertion(ToolCallOut, self.tool_calls.items, {}, lessToolCall);
        std.sort.insertion(ToolResultOut, self.tool_results.items, {}, lessToolResult);
        std.sort.insertion([]const u8, self.errs.items, {}, lessText);
    }

    fn lessText(_: void, a: []const u8, b: []const u8) bool {
        return std.mem.order(u8, a, b) == .lt;
    }

    fn lessToolCall(_: void, a: ToolCallOut, b: ToolCallOut) bool {
        return cmp3(a.id, b.id, a.name, b.name, a.args, b.args) == .lt;
    }

    fn lessToolResult(_: void, a: ToolResultOut, b: ToolResultOut) bool {
        const ord_id = std.mem.order(u8, a.id, b.id);
        if (ord_id != .eq) return ord_id == .lt;

        if (a.is_err != b.is_err) return !a.is_err;

        return std.mem.order(u8, a.output, b.output) == .lt;
    }
};

fn cmp3(a0: []const u8, b0: []const u8, a1: []const u8, b1: []const u8, a2: []const u8, b2: []const u8) std.math.Order {
    const ord0 = std.mem.order(u8, a0, b0);
    if (ord0 != .eq) return ord0;

    const ord1 = std.mem.order(u8, a1, b1);
    if (ord1 != .eq) return ord1;

    return std.mem.order(u8, a2, b2);
}

fn usageLessThan(curr: core.providers.Usage, next: core.providers.Usage) bool {
    if (curr.tot_tok != next.tot_tok) return curr.tot_tok < next.tot_tok;
    if (curr.out_tok != next.out_tok) return curr.out_tok < next.out_tok;
    return curr.in_tok < next.in_tok;
}

fn stopName(reason: core.providers.StopReason) []const u8 {
    return switch (reason) {
        .done => "done",
        .max_out => "max_out",
        .tool => "tool",
        .canceled => "canceled",
        .err => "err",
    };
}

fn writeQuoted(out: std.Io.AnyWriter, raw: []const u8) !void {
    try out.writeByte('"');
    for (raw) |ch| {
        switch (ch) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (ch < 0x20) {
                    try out.writeAll("\\u00");
                    try out.writeByte(hexNibble(ch >> 4));
                    try out.writeByte(hexNibble(ch & 0x0f));
                } else {
                    try out.writeByte(ch);
                }
            },
        }
    }
    try out.writeByte('"');
}

fn hexNibble(n: u8) u8 {
    return "0123456789abcdef"[n];
}

/// Strip ANSI escape sequences (CSI, OSC) and replace control bytes (except
/// \n, \r, \t) with U+FFFD for safe pipeline/stdout output.
pub fn sanitizeOutput(alloc: std.mem.Allocator, text: []const u8) ![]const u8 {
    // Quick check: no ESC and no control bytes -> return original
    var needs_work = false;
    for (text) |ch| {
        if (ch == 0x1b or (ch < 0x20 and ch != '\n' and ch != '\r' and ch != '\t') or ch == 0x7f) {
            needs_work = true;
            break;
        }
    }
    if (!needs_work) return text;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, text.len);

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == 0x1b) {
            i += 1;
            if (i >= text.len) break;
            if (text[i] == '[') {
                // CSI sequence: ESC [ ... <final byte 0x40-0x7e>
                i += 1;
                while (i < text.len) {
                    if (text[i] >= 0x40 and text[i] <= 0x7e) {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            } else if (text[i] == ']') {
                // OSC sequence: ESC ] ... ST (ESC \ or BEL)
                i += 1;
                while (i < text.len) {
                    if (text[i] == 0x07) { // BEL
                        i += 1;
                        break;
                    }
                    if (text[i] == 0x1b and i + 1 < text.len and text[i + 1] == '\\') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            } else {
                // Other ESC+char: skip both
                i += 1;
            }
        } else if (text[i] == 0x7f or (text[i] < 0x20 and text[i] != '\n' and text[i] != '\r' and text[i] != '\t')) {
            // Replace control byte with replacement char
            try out.appendSlice(alloc, "\xef\xbf\xbd"); // U+FFFD
            i += 1;
        } else {
            try out.append(alloc, text[i]);
            i += 1;
        }
    }

    return try out.toOwnedSlice(alloc);
}

fn expectFormatted(evs: []const core.providers.Event, want: []const u8) !void {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var formatter = Formatter.init(std.testing.allocator, fbs.writer().any());
    formatter.verbose = true; // tests check full diagnostic output
    defer formatter.deinit();

    for (evs) |ev| try formatter.push(ev);
    try formatter.finish();

    try std.testing.expectEqualStrings(want, fbs.getWritten());
}

test "formatter emits deterministic canonical output" {
    const evs_a = [_]core.providers.Event{
        .{ .text = "out-a" },
        .{ .thinking = "z-think" },
        .{ .tool_result = .{ .id = "call-2", .output = "res-z", .is_err = true } },
        .{ .tool_call = .{ .id = "call-2", .name = "write", .args = "{\"path\":\"b\"}" } },
        .{ .usage = .{ .in_tok = 2, .out_tok = 3, .tot_tok = 5 } },
        .{ .err = "z-err" },
        .{ .stop = .{ .reason = .done } },
        .{ .tool_call = .{ .id = "call-1", .name = "read", .args = "{\"path\":\"a\"}" } },
        .{ .thinking = "a-think" },
        .{ .tool_result = .{ .id = "call-1", .output = "res-a", .is_err = false } },
        .{ .usage = .{ .in_tok = 1, .out_tok = 1, .tot_tok = 2 } },
        .{ .err = "a-err" },
        .{ .stop = .{ .reason = .err } },
    };

    const evs_b = [_]core.providers.Event{
        .{ .err = "a-err" },
        .{ .stop = .{ .reason = .err } },
        .{ .tool_result = .{ .id = "call-1", .output = "res-a", .is_err = false } },
        .{ .thinking = "a-think" },
        .{ .tool_call = .{ .id = "call-1", .name = "read", .args = "{\"path\":\"a\"}" } },
        .{ .err = "z-err" },
        .{ .usage = .{ .in_tok = 1, .out_tok = 1, .tot_tok = 2 } },
        .{ .tool_call = .{ .id = "call-2", .name = "write", .args = "{\"path\":\"b\"}" } },
        .{ .text = "out-a" },
        .{ .stop = .{ .reason = .done } },
        .{ .tool_result = .{ .id = "call-2", .output = "res-z", .is_err = true } },
        .{ .thinking = "z-think" },
        .{ .usage = .{ .in_tok = 2, .out_tok = 3, .tot_tok = 5 } },
    };

    const want =
        "out-a\n" ++
        "thinking \"a-think\"\n" ++
        "thinking \"z-think\"\n" ++
        "tool_call id=\"call-1\" name=\"read\" args=\"{\\\"path\\\":\\\"a\\\"}\"\n" ++
        "tool_call id=\"call-2\" name=\"write\" args=\"{\\\"path\\\":\\\"b\\\"}\"\n" ++
        "tool_result id=\"call-1\" is_err=false out=\"res-a\"\n" ++
        "tool_result id=\"call-2\" is_err=true out=\"res-z\"\n" ++
        "usage in=2 out=3 total=5\n" ++
        "stop reason=err\n" ++
        "err \"a-err\"\n" ++
        "err \"z-err\"\n";

    try expectFormatted(evs_a[0..], want);
    try expectFormatted(evs_b[0..], want);
}

test "formatter preserves plain text output when metadata is absent" {
    const evs = [_]core.providers.Event{
        .{ .text = "out-" },
        .{ .text = "a" },
    };
    try expectFormatted(evs[0..], "out-a");
}

test "formatter escapes control characters in quoted fields" {
    const evs = [_]core.providers.Event{
        .{ .err = "a\tb\n\"c\"\\d\x01" },
    };

    try expectFormatted(evs[0..], "err \"a\\tb\\n\\\"c\\\"\\\\d\\u0001\"\n");
}

test "sanitizeOutput strips CSI sequences" {
    const alloc = std.testing.allocator;
    const input = "hello\x1b[31m red \x1b[0mworld";
    const result = try sanitizeOutput(alloc, input);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello red world", result);
}

test "sanitizeOutput strips OSC sequences" {
    const alloc = std.testing.allocator;
    // OSC with BEL terminator
    const input_bel = "before\x1b]0;title\x07after";
    const r1 = try sanitizeOutput(alloc, input_bel);
    defer alloc.free(r1);
    try std.testing.expectEqualStrings("beforeafter", r1);

    // OSC with ST terminator (ESC \)
    const input_st = "before\x1b]0;title\x1b\\after";
    const r2 = try sanitizeOutput(alloc, input_st);
    defer alloc.free(r2);
    try std.testing.expectEqualStrings("beforeafter", r2);
}

test "sanitizeOutput replaces control bytes with replacement char" {
    const alloc = std.testing.allocator;
    const input = "a\x01b\x7fc";
    const result = try sanitizeOutput(alloc, input);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("a\xef\xbf\xbdb\xef\xbf\xbdc", result);
}

test "sanitizeOutput preserves tabs newlines and clean text" {
    const alloc = std.testing.allocator;
    const input = "hello\tworld\nok\r\n";
    const result = try sanitizeOutput(alloc, input);
    // Should return original pointer (no alloc)
    try std.testing.expectEqual(@intFromPtr(input.ptr), @intFromPtr(result.ptr));
}

test "formatter sanitizes ANSI in text output" {
    const evs = [_]core.providers.Event{
        .{ .text = "hi\x1b[31m red\x1b[0m" },
    };
    try expectFormatted(evs[0..], "hi red");
}

test "formatter redacts secrets in text output" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var formatter = Formatter.init(std.testing.allocator, fbs.writer().any());
    defer formatter.deinit();

    try formatter.push(.{ .text = "key: sk-live-abc123" });
    try formatter.finish();

    const written = fbs.getWritten();
    // Must not contain the raw secret
    try std.testing.expect(std.mem.indexOf(u8, written, "sk-live-abc123") == null);
    // Must contain redaction tag
    try std.testing.expect(std.mem.indexOf(u8, written, "[secret:") != null);
}

test "formatter redacts secrets in verbose tool output" {
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var formatter = Formatter.init(std.testing.allocator, fbs.writer().any());
    formatter.verbose = true;
    defer formatter.deinit();

    try formatter.push(.{ .tool_call = .{ .id = "c1", .name = "bash", .args = "cat ~/.pz/auth.json" } });
    try formatter.push(.{ .tool_result = .{ .id = "c1", .output = "authorization: bearer sk-test-key", .is_err = false } });
    try formatter.finish();

    const written = fbs.getWritten();
    // Secret in tool result must be redacted
    try std.testing.expect(std.mem.indexOf(u8, written, "sk-test-key") == null);
    // Path in tool args must be redacted
    try std.testing.expect(std.mem.indexOf(u8, written, "~/.pz/auth.json") == null);
}
