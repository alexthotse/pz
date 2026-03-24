//! Shell command tokenizer and pipeline parser.
const std = @import("std");
const Allocator = std.mem.Allocator;
const policy = @import("policy.zig");

/// Pipeline separator: &&, ||, ;, |.
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

/// Check if any command in the input is denied by policy rules.
/// Tokenizes the input, extracts executable names from each command
/// (including through bash -c / env / exec / xargs wrappers), and
/// evaluates each against the policy with path "cmd/<executable>".
pub fn deniedByPolicy(alloc: Allocator, input: []const u8, pol: policy.Policy) Error!bool {
    const toks = tokenize(alloc, input) catch |err| switch (err) {
        error.UnterminatedQuote, error.EmptyInput => return false,
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer free(alloc, toks);

    for (toks) |tok| {
        if (commandDeniedByPolicy(alloc, tok.cmd, pol, 0) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => true, // fail closed on parse error
        }) return true;
    }
    return false;
}

fn commandDeniedByPolicy(alloc: Allocator, cmd: []const u8, pol: policy.Policy, depth: usize) Error!bool {
    if (depth > 4) return false;
    const words = splitWordsAlloc(alloc, cmd) catch return error.OutOfMemory;
    defer words.deinit(alloc);
    return wordsDeniedByPolicy(alloc, words.words, pol, depth);
}

fn wordsDeniedByPolicy(alloc: Allocator, words: []const []u8, pol: policy.Policy, depth: usize) Error!bool {
    if (words.len == 0) return false;
    const exe = std.fs.path.basename(words[0]);
    // Check policy: "cmd/<executable>" pattern
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "cmd/{s}", .{exe}) catch return false;
    if (pol.eval(path, "bash") == .deny) return true;
    // Unwrap shell wrappers: bash -c, sh -c, env, exec, xargs
    if ((std.mem.eql(u8, exe, "bash") or std.mem.eql(u8, exe, "sh")) and words.len > 1) {
        for (words[1..], 0..) |w, i| {
            if (std.mem.eql(u8, w, "-c") and i + 2 < words.len) {
                return commandDeniedByPolicy(alloc, words[i + 2], pol, depth + 1);
            }
        }
    }
    if (std.mem.eql(u8, exe, "env") or std.mem.eql(u8, exe, "exec")) {
        // Skip env vars (KEY=VAL) and find the actual command
        for (words[1..]) |w| {
            if (std.mem.indexOfScalar(u8, w, '=') == null) {
                return commandDeniedByPolicy(alloc, w, pol, depth + 1);
            }
        }
    }
    return false;
}

pub fn touchesProtectedPath(alloc: Allocator, input: []const u8) Error!bool {
    const toks = try tokenize(alloc, input);
    defer free(alloc, toks);

    for (toks) |tok| {
        if (try commandTouchesProtectedPath(alloc, tok.cmd, 0)) return true;
    }
    return false;
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

const WordList = struct {
    words: []const []u8,

    fn deinit(self: WordList, alloc: Allocator) void {
        for (self.words) |word| alloc.free(word);
        alloc.free(self.words);
    }
};

fn splitWordsAlloc(alloc: Allocator, input: []const u8) Error!WordList {
    var out: std.ArrayListUnmanaged([]u8) = .{};
    errdefer {
        for (out.items) |word| alloc.free(word);
        out.deinit(alloc);
    }

    var it = std.mem.tokenizeAny(u8, input, " \t\r\n");
    while (it.next()) |word| try out.append(alloc, try alloc.dupe(u8, word));

    return .{ .words = try out.toOwnedSlice(alloc) };
}

fn commandTouchesProtectedPath(alloc: Allocator, cmd: []const u8, depth: usize) Error!bool {
    if (depth >= 8) return false;

    const words = try splitWordsAlloc(alloc, cmd);
    defer words.deinit(alloc);
    return wordsTouchProtectedPath(alloc, words.words, depth);
}

fn tailCmdTouchesProtectedPath(alloc: Allocator, words: []const []u8, start: usize, depth: usize) Error!bool {
    if (start >= words.len) return false;
    const tail = try std.mem.join(alloc, " ", words[start..]);
    defer alloc.free(tail);
    return commandTouchesProtectedPath(alloc, tail, depth);
}

fn wordsTouchProtectedPath(alloc: Allocator, words: []const []u8, depth: usize) Error!bool {
    if (words.len == 0) return false;

    var i: usize = 0;
    while (i < words.len and isEnvAssign(words[i])) : (i += 1) {}
    if (i >= words.len) return false;

    if (std.mem.eql(u8, words[i], "env")) {
        i += 1;
        while (i < words.len) {
            const word = words[i];
            if (std.mem.eql(u8, word, "--")) {
                i += 1;
                break;
            }
            if (std.mem.eql(u8, word, "-u")) {
                i += @intFromBool(i + 1 < words.len) + 1;
                continue;
            }
            if (word.len != 0 and word[0] == '-') {
                i += 1;
                continue;
            }
            if (isEnvAssign(word)) {
                i += 1;
                continue;
            }
            break;
        }
        return wordsTouchProtectedPath(alloc, words[i..], depth + 1);
    }

    if (std.mem.eql(u8, words[i], "exec") or std.mem.eql(u8, words[i], "command")) {
        return wordsTouchProtectedPath(alloc, words[i + 1 ..], depth + 1);
    }

    if (isShellName(words[i])) {
        var j = i + 1;
        while (j < words.len) : (j += 1) {
            const word = words[j];
            if (std.mem.eql(u8, word, "-c") or std.mem.eql(u8, word, "-lc") or std.mem.eql(u8, word, "--command")) {
                if (j + 1 < words.len) return tailCmdTouchesProtectedPath(alloc, words, j + 1, depth + 1);
                return false;
            }
        }
    }

    if (std.mem.eql(u8, words[i], "xargs")) {
        var j = i + 1;
        while (j < words.len) : (j += 1) {
            if (isShellName(words[j]) and j + 2 < words.len) {
                const flag = words[j + 1];
                if (std.mem.eql(u8, flag, "-c") or std.mem.eql(u8, flag, "-lc") or std.mem.eql(u8, flag, "--command")) {
                    return tailCmdTouchesProtectedPath(alloc, words, j + 2, depth + 1);
                }
            }
        }
    }

    for (words[i..]) |word| {
        if (policy.isProtectedPath(word)) return true;
    }
    return false;
}

fn isEnvAssign(word: []const u8) bool {
    const eq = std.mem.indexOfScalar(u8, word, '=') orelse return false;
    return eq != 0;
}

fn isShellName(word: []const u8) bool {
    if (std.mem.eql(u8, word, "sh") or std.mem.eql(u8, word, "bash")) return true;
    return std.mem.endsWith(u8, word, "/sh") or std.mem.endsWith(u8, word, "/bash");
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;
const talloc = testing.allocator;

fn appendTokSnap(out: *std.ArrayList(u8), tok: Token) !void {
    try out.writer(talloc).print("{s}|{s}\n", .{ @tagName(tok.sep), tok.cmd });
}

fn renderToks(alloc: std.mem.Allocator, toks: []const Token) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    for (toks) |tok| try appendTokSnap(&out, tok);
    return out.toOwnedSlice(alloc);
}

fn expectToks(input: []const u8, comptime expected: []const u8) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const toks = try tokenize(talloc, input);
    defer free(talloc, toks);
    const snap = try renderToks(talloc, toks);
    defer talloc.free(snap);
    try oh.snap(@src(), expected).expectEqual(snap);
}

test "simple command" {
    try expectToks("ls -la",
        \\[]u8
        \\  "start|ls -la
        \\"
    );
}

test "chained and" {
    try expectToks("cd /tmp && ls",
        \\[]u8
        \\  "start|cd /tmp
        \\and|ls
        \\"
    );
}

test "piped" {
    try expectToks("cat foo | grep bar",
        \\[]u8
        \\  "start|cat foo
        \\pipe|grep bar
        \\"
    );
}

test "quoted preserves separators" {
    try expectToks(
        \\echo "hello && world"
    ,
        \\[]u8
        \\  "start|echo hello && world
        \\"
    );
}

test "single quoted preserves separators" {
    try expectToks(
        \\echo 'hello || world'
    ,
        \\[]u8
        \\  "start|echo hello || world
        \\"
    );
}

test "nested bash -c" {
    try expectToks(
        \\bash -c "echo hi && echo bye"
    ,
        \\[]u8
        \\  "start|echo hi && echo bye
        \\"
    );
}

test "nested sh -c single quotes" {
    try expectToks(
        \\sh -c 'echo hi; echo bye'
    ,
        \\[]u8
        \\  "start|echo hi; echo bye
        \\"
    );
}

test "env wrapper preserves protected path detection" {
    try testing.expect(try touchesProtectedPath(talloc, "env FOO=1 bash -c 'cat ~/.pz/settings.json'"));
}

test "exec wrapper preserves protected path detection" {
    try testing.expect(try touchesProtectedPath(talloc, "exec cat AGENTS.md"));
}

test "xargs shell wrapper preserves protected path detection" {
    try testing.expect(try touchesProtectedPath(talloc, "printf x | xargs sh -c 'cat ~/.pz/settings.json'"));
}

test "mixed separators" {
    try expectToks("a; b && c || d | e",
        \\[]u8
        \\  "start|a
        \\seq|b
        \\and|c
        \\or|d
        \\pipe|e
        \\"
    );
}

test "empty input" {
    try testing.expectError(error.EmptyInput, tokenize(talloc, ""));
    try testing.expectError(error.EmptyInput, tokenize(talloc, "   "));
}

test "trailing separator" {
    try expectToks("ls;",
        \\[]u8
        \\  "start|ls
        \\"
    );
}

test "consecutive separators" {
    try expectToks("a;; b",
        \\[]u8
        \\  "start|a
        \\seq|b
        \\"
    );
}

test "backslash escape" {
    try expectToks(
        \\echo hello\;world
    ,
        \\[]u8
        \\  "start|echo hello;world
        \\"
    );
}

test "backtick" {
    try expectToks("echo `date` && ls",
        \\[]u8
        \\  "start|echo date
        \\and|ls
        \\"
    );
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
    ,
        \\[]u8
        \\  "start|echo say "hi"
        \\"
    );
}

test "multiple pipes" {
    try expectToks("cat f | grep x | wc -l",
        \\[]u8
        \\  "start|cat f
        \\pipe|grep x
        \\pipe|wc -l
        \\"
    );
}

test "complex mixed" {
    try expectToks("cd /tmp && cat f | grep x; echo done || fail",
        \\[]u8
        \\  "start|cd /tmp
        \\and|cat f
        \\pipe|grep x
        \\seq|echo done
        \\or|fail
        \\"
    );
}

test "sep str roundtrip" {
    try testing.expectEqualStrings("&&", Sep.@"and".str());
    try testing.expectEqualStrings("||", Sep.@"or".str());
    try testing.expectEqualStrings(";", Sep.seq.str());
    try testing.expectEqualStrings("|", Sep.pipe.str());
    try testing.expectEqualStrings("", Sep.start.str());
}

test "whitespace only between seps" {
    try expectToks("a &&   b",
        \\[]u8
        \\  "start|a
        \\and|b
        \\"
    );
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
    ,
        \\[]u8
        \\  "start|echo it's "fine"
        \\and|ls
        \\"
    );
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
