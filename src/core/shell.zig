const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Sep = enum {
    start,
    @"and",
    @"or",
    seq,
    pipe,

    pub fn str(self: Sep) []const u8 {
        return switch (self) {
            .start => "",
            .@"and" => "&&",
            .@"or" => "||",
            .seq => ";",
            .pipe => "|",
        };
    }
};

pub const Token = struct {
    cmd: []const u8,
    sep: Sep,
};

pub const Error = error{
    UnterminatedQuote,
    EmptyInput,
    OutOfMemory,
};

/// Tokenize a shell command string into individual commands split on
/// &&, ||, ;, and |. Handles single/double quotes, backslash escapes,
/// backticks, and `bash -c` / `sh -c` unwrapping.
///
/// Caller owns the returned slice and all cmd strings within.
/// Use `free()` to release.
pub fn tokenize(alloc: Allocator, input: []const u8) Error![]Token {
    const trimmed = std.mem.trim(u8, input, " \t\n\r");
    if (trimmed.len == 0) return error.EmptyInput;

    var toks: std.ArrayListUnmanaged(Token) = .{};
    errdefer {
        for (toks.items) |t| alloc.free(t.cmd);
        toks.deinit(alloc);
    }

    var pos: usize = 0;
    var cur_sep: Sep = .start;

    while (pos < trimmed.len) {
        // skip whitespace between separator and command
        while (pos < trimmed.len and isWs(trimmed[pos])) pos += 1;
        if (pos >= trimmed.len) break;

        const cmd_start = pos;
        // scan forward collecting the command text, respecting quotes
        pos = try scanCmd(trimmed, pos);

        const raw = std.mem.trim(u8, trimmed[cmd_start..pos], " \t\n\r");
        if (raw.len > 0) {
            const unquoted = try unquote(alloc, raw);
            errdefer alloc.free(unquoted);
            const unwrapped = try unwrapShC(alloc, unquoted);
            if (unwrapped.ptr != unquoted.ptr) alloc.free(unquoted);
            toks.append(alloc, .{ .cmd = unwrapped, .sep = cur_sep }) catch return error.OutOfMemory;
        }

        // now check for separator
        if (pos >= trimmed.len) break;
        const sep_res = parseSep(trimmed, pos);
        cur_sep = sep_res.sep;
        pos = sep_res.next;
    }

    return toks.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

pub fn free(alloc: Allocator, tokens: []Token) void {
    for (tokens) |t| alloc.free(t.cmd);
    alloc.free(tokens);
}

// --- internals ---

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\n' or c == '\r';
}

const SepResult = struct {
    sep: Sep,
    next: usize,
};

fn parseSep(input: []const u8, pos: usize) SepResult {
    if (pos >= input.len) return .{ .sep = .start, .next = pos };
    if (pos + 1 < input.len) {
        if (input[pos] == '&' and input[pos + 1] == '&')
            return .{ .sep = .@"and", .next = pos + 2 };
        if (input[pos] == '|' and input[pos + 1] == '|')
            return .{ .sep = .@"or", .next = pos + 2 };
    }
    if (input[pos] == ';') return .{ .sep = .seq, .next = pos + 1 };
    if (input[pos] == '|') return .{ .sep = .pipe, .next = pos + 1 };
    return .{ .sep = .start, .next = pos };
}

/// Scan forward from `start` until we hit a separator (&&, ||, ;, |)
/// that is not inside quotes. Returns position of the separator (or end).
fn scanCmd(input: []const u8, start: usize) Error!usize {
    var i = start;
    while (i < input.len) {
        const c = input[i];

        // backslash escape outside quotes
        if (c == '\\' and i + 1 < input.len) {
            i += 2;
            continue;
        }

        // single quote
        if (c == '\'') {
            i += 1;
            while (i < input.len and input[i] != '\'') i += 1;
            if (i >= input.len) return error.UnterminatedQuote;
            i += 1; // skip closing '
            continue;
        }

        // double quote
        if (c == '"') {
            i += 1;
            while (i < input.len and input[i] != '"') {
                if (input[i] == '\\' and i + 1 < input.len) {
                    i += 2;
                    continue;
                }
                i += 1;
            }
            if (i >= input.len) return error.UnterminatedQuote;
            i += 1; // skip closing "
            continue;
        }

        // backtick
        if (c == '`') {
            i += 1;
            while (i < input.len and input[i] != '`') i += 1;
            if (i >= input.len) return error.UnterminatedQuote;
            i += 1;
            continue;
        }

        // check for separators
        if (c == '&' and i + 1 < input.len and input[i + 1] == '&') return i;
        if (c == '|' and i + 1 < input.len and input[i + 1] == '|') return i;
        if (c == ';') return i;
        if (c == '|') return i;

        i += 1;
    }
    return i;
}

/// Remove outer quotes and process backslash escapes.
/// Returns a newly allocated string.
fn unquote(alloc: Allocator, input: []const u8) Error![]const u8 {
    var buf: std.ArrayListUnmanaged(u8) = .{};
    errdefer buf.deinit(alloc);

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];

        if (c == '\\' and i + 1 < input.len) {
            buf.append(alloc, input[i + 1]) catch return error.OutOfMemory;
            i += 2;
            continue;
        }

        if (c == '\'') {
            i += 1; // skip opening
            while (i < input.len and input[i] != '\'') {
                buf.append(alloc, input[i]) catch return error.OutOfMemory;
                i += 1;
            }
            if (i < input.len) i += 1; // skip closing
            continue;
        }

        if (c == '"') {
            i += 1; // skip opening
            while (i < input.len and input[i] != '"') {
                if (input[i] == '\\' and i + 1 < input.len) {
                    buf.append(alloc, input[i + 1]) catch return error.OutOfMemory;
                    i += 2;
                    continue;
                }
                buf.append(alloc, input[i]) catch return error.OutOfMemory;
                i += 1;
            }
            if (i < input.len) i += 1; // skip closing
            continue;
        }

        if (c == '`') {
            i += 1;
            while (i < input.len and input[i] != '`') {
                buf.append(alloc, input[i]) catch return error.OutOfMemory;
                i += 1;
            }
            if (i < input.len) i += 1;
            continue;
        }

        buf.append(alloc, c) catch return error.OutOfMemory;
        i += 1;
    }

    return buf.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

/// Detect `bash -c "..."` or `sh -c '...'` patterns and extract inner cmd.
/// If not matched, returns the original slice (caller must not double-free).
fn unwrapShC(alloc: Allocator, input: []const u8) Error![]const u8 {
    const trimmed = std.mem.trim(u8, input, " \t");

    // Check for sh -c or bash -c prefix
    const prefixes = [_][]const u8{ "bash -c ", "sh -c " };
    for (prefixes) |pfx| {
        if (std.mem.startsWith(u8, trimmed, pfx)) {
            const rest = std.mem.trim(u8, trimmed[pfx.len..], " \t");
            if (rest.len == 0) return input;
            const dup = alloc.dupe(u8, rest) catch return error.OutOfMemory;
            return dup;
        }
    }
    return input;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const talloc = testing.allocator;

fn expectToks(input: []const u8, expected: []const struct { sep: Sep, cmd: []const u8 }) !void {
    const toks = try tokenize(talloc, input);
    defer free(talloc, toks);

    try testing.expectEqual(expected.len, toks.len);
    for (expected, toks) |exp, got| {
        try testing.expectEqual(exp.sep, got.sep);
        try testing.expectEqualStrings(exp.cmd, got.cmd);
    }
}

test "simple command" {
    try expectToks("ls -la", &.{
        .{ .sep = .start, .cmd = "ls -la" },
    });
}

test "chained and" {
    try expectToks("cd /tmp && ls", &.{
        .{ .sep = .start, .cmd = "cd /tmp" },
        .{ .sep = .@"and", .cmd = "ls" },
    });
}

test "piped" {
    try expectToks("cat foo | grep bar", &.{
        .{ .sep = .start, .cmd = "cat foo" },
        .{ .sep = .pipe, .cmd = "grep bar" },
    });
}

test "quoted preserves separators" {
    try expectToks(
        \\echo "hello && world"
    , &.{
        .{ .sep = .start, .cmd = "echo hello && world" },
    });
}

test "single quoted preserves separators" {
    try expectToks(
        \\echo 'hello || world'
    , &.{
        .{ .sep = .start, .cmd = "echo hello || world" },
    });
}

test "nested bash -c" {
    try expectToks(
        \\bash -c "echo hi && echo bye"
    , &.{
        .{ .sep = .start, .cmd = "echo hi && echo bye" },
    });
}

test "nested sh -c single quotes" {
    try expectToks(
        \\sh -c 'echo hi; echo bye'
    , &.{
        .{ .sep = .start, .cmd = "echo hi; echo bye" },
    });
}

test "mixed separators" {
    try expectToks("a; b && c || d | e", &.{
        .{ .sep = .start, .cmd = "a" },
        .{ .sep = .seq, .cmd = "b" },
        .{ .sep = .@"and", .cmd = "c" },
        .{ .sep = .@"or", .cmd = "d" },
        .{ .sep = .pipe, .cmd = "e" },
    });
}

test "empty input" {
    try testing.expectError(error.EmptyInput, tokenize(talloc, ""));
    try testing.expectError(error.EmptyInput, tokenize(talloc, "   "));
}

test "trailing separator" {
    try expectToks("ls;", &.{
        .{ .sep = .start, .cmd = "ls" },
    });
}

test "consecutive separators" {
    try expectToks("a;; b", &.{
        .{ .sep = .start, .cmd = "a" },
        .{ .sep = .seq, .cmd = "b" },
    });
}

test "backslash escape" {
    try expectToks(
        \\echo hello\;world
    , &.{
        .{ .sep = .start, .cmd = "echo hello;world" },
    });
}

test "backtick" {
    try expectToks("echo `date` && ls", &.{
        .{ .sep = .start, .cmd = "echo date" },
        .{ .sep = .@"and", .cmd = "ls" },
    });
}

test "unterminated double quote" {
    try testing.expectError(error.UnterminatedQuote, tokenize(talloc, "echo \"hello"));
}

test "unterminated single quote" {
    try testing.expectError(error.UnterminatedQuote, tokenize(talloc, "echo 'hello"));
}

test "double quote backslash escape" {
    try expectToks(
        \\echo "say \"hi\""
    , &.{
        .{ .sep = .start, .cmd = "echo say \"hi\"" },
    });
}

test "multiple pipes" {
    try expectToks("cat f | grep x | wc -l", &.{
        .{ .sep = .start, .cmd = "cat f" },
        .{ .sep = .pipe, .cmd = "grep x" },
        .{ .sep = .pipe, .cmd = "wc -l" },
    });
}

test "complex mixed" {
    try expectToks("cd /tmp && cat f | grep x; echo done || fail", &.{
        .{ .sep = .start, .cmd = "cd /tmp" },
        .{ .sep = .@"and", .cmd = "cat f" },
        .{ .sep = .pipe, .cmd = "grep x" },
        .{ .sep = .seq, .cmd = "echo done" },
        .{ .sep = .@"or", .cmd = "fail" },
    });
}

test "sep str roundtrip" {
    try testing.expectEqualStrings("&&", Sep.@"and".str());
    try testing.expectEqualStrings("||", Sep.@"or".str());
    try testing.expectEqualStrings(";", Sep.seq.str());
    try testing.expectEqualStrings("|", Sep.pipe.str());
    try testing.expectEqualStrings("", Sep.start.str());
}

test "whitespace only between seps" {
    try expectToks("a &&   b", &.{
        .{ .sep = .start, .cmd = "a" },
        .{ .sep = .@"and", .cmd = "b" },
    });
}

test "ohsnap token snapshot" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const toks = try tokenize(talloc, "cd /tmp && ls | wc");
    defer free(talloc, toks);

    const Snap = struct {
        len: usize,
        t0_cmd: []const u8,
        t1_cmd: []const u8,
        t2_cmd: []const u8,
    };

    const snap = Snap{
        .len = toks.len,
        .t0_cmd = toks[0].cmd,
        .t1_cmd = toks[1].cmd,
        .t2_cmd = toks[2].cmd,
    };

    try oh.snap(@src(),
        \\core.shell.test.ohsnap token snapshot.Snap
        \\  .len: usize = 3
        \\  .t0_cmd: []const u8
        \\    "cd /tmp"
        \\  .t1_cmd: []const u8
        \\    "ls"
        \\  .t2_cmd: []const u8
        \\    "wc"
    ).expectEqual(snap);
}

// ============================================================
// zcheck property tests
// ============================================================

test "property: tokenize never returns empty tokens" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.Id }) bool {
            const s = args.input.slice();
            const toks = tokenize(talloc, s) catch return true;
            defer free(talloc, toks);
            for (toks) |t| {
                if (t.cmd.len == 0) return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: first token always has sep=.start" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.Id }) bool {
            const s = args.input.slice();
            const toks = tokenize(talloc, s) catch return true;
            defer free(talloc, toks);
            if (toks.len == 0) return true;
            return toks[0].sep == .start;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: tokenize then join reconstructs core content" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.Id }) bool {
            const s = args.input.slice();
            const toks = tokenize(talloc, s) catch return true;
            defer free(talloc, toks);
            // Every char in every token cmd must appear in the original input
            for (toks) |t| {
                for (t.cmd) |c| {
                    if (std.mem.indexOfScalar(u8, s, c) == null) return false;
                }
            }
            return true;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: single word always produces one token" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.Id }) bool {
            const s = args.input.slice();
            // Skip if input contains separator chars, quotes, or backslashes
            for (s) |c| {
                if (c == '&' or c == '|' or c == ';' or
                    c == '\'' or c == '"' or c == '`' or c == '\\' or
                    c == ' ' or c == '\t' or c == '\n' or c == '\r') return true;
            }
            if (s.len == 0) return true;
            const toks = tokenize(talloc, s) catch return true;
            defer free(talloc, toks);
            return toks.len == 1;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: token count <= separator count + 1" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            const s = args.input.slice();
            const toks = tokenize(talloc, s) catch return true;
            defer free(talloc, toks);

            // Count unquoted separators in input
            var sep_count: usize = 0;
            var i: usize = 0;
            while (i < s.len) {
                const c = s[i];
                // skip quoted regions
                if (c == '\'') {
                    i += 1;
                    while (i < s.len and s[i] != '\'') i += 1;
                    if (i < s.len) i += 1;
                    continue;
                }
                if (c == '"') {
                    i += 1;
                    while (i < s.len and s[i] != '"') {
                        if (s[i] == '\\' and i + 1 < s.len) {
                            i += 2;
                            continue;
                        }
                        i += 1;
                    }
                    if (i < s.len) i += 1;
                    continue;
                }
                if (c == '`') {
                    i += 1;
                    while (i < s.len and s[i] != '`') i += 1;
                    if (i < s.len) i += 1;
                    continue;
                }
                if (c == '\\' and i + 1 < s.len) {
                    i += 2;
                    continue;
                }
                // count separators
                if (c == '&' and i + 1 < s.len and s[i + 1] == '&') {
                    sep_count += 1;
                    i += 2;
                    continue;
                }
                if (c == '|' and i + 1 < s.len and s[i + 1] == '|') {
                    sep_count += 1;
                    i += 2;
                    continue;
                }
                if (c == ';') {
                    sep_count += 1;
                    i += 1;
                    continue;
                }
                if (c == '|') {
                    sep_count += 1;
                    i += 1;
                    continue;
                }
                i += 1;
            }
            return toks.len <= sep_count + 1;
        }
    }.prop, .{ .iterations = 500 });
}

// ============================================================
// Edge case tests
// ============================================================

test "deeply nested quotes" {
    try expectToks(
        \\echo "it's \"fine\"" && ls
    , &.{
        .{ .sep = .start, .cmd = "echo it's \"fine\"" },
        .{ .sep = .@"and", .cmd = "ls" },
    });
}

test "only separators" {
    // Separator-only inputs: the separators are consumed but no command
    // text remains, yielding zero tokens.
    const cases = [_][]const u8{ ";", "&&", "||", "; && ||" };
    for (cases) |input| {
        const toks = try tokenize(talloc, input);
        defer free(talloc, toks);
        try testing.expectEqual(@as(usize, 0), toks.len);
    }
}

test "very long single command" {
    var buf: [1024]u8 = undefined;
    @memset(&buf, 'a');
    const toks = try tokenize(talloc, &buf);
    defer free(talloc, toks);
    try testing.expectEqual(@as(usize, 1), toks.len);
    try testing.expectEqual(Sep.start, toks[0].sep);
    try testing.expectEqual(@as(usize, 1024), toks[0].cmd.len);
}
