const std = @import("std");
const frame = @import("frame.zig");
const theme = @import("theme.zig");

pub const Kind = enum {
    text,
    keyword,
    string,
    comment,
    number,
    func,
    type_name,
    operator,
    punct,

    pub fn style(k: Kind, base: frame.Style) frame.Style {
        var s = base;
        switch (k) {
            .text => {},
            .keyword => {
                s.fg = theme.get().syn_keyword;
                s.bold = true;
            },
            .string => s.fg = theme.get().syn_string,
            .comment => {
                s.fg = theme.get().syn_comment;
                s.italic = true;
            },
            .number => s.fg = theme.get().syn_number,
            .func => s.fg = theme.get().syn_func,
            .type_name => s.fg = theme.get().syn_type,
            .operator => s.fg = theme.get().syn_operator,
            .punct => {
                s.fg = theme.get().syn_punct;
                s.dim = true;
            },
        }
        return s;
    }
};

pub const Token = struct {
    start: usize,
    end: usize,
    kind: Kind,
};

pub const Lang = enum {
    zig,
    python,
    bash,
    json,
    javascript,
    unknown,

    pub fn detect(hint: []const u8) Lang {
        return lang_detect_map.get(hint) orelse .unknown;
    }
};

const lang_detect_map = std.StaticStringMap(Lang).initComptime(.{
    .{ "zig", .zig },
    .{ "python", .python },
    .{ "py", .python },
    .{ "bash", .bash },
    .{ "sh", .bash },
    .{ "shell", .bash },
    .{ "zsh", .bash },
    .{ "json", .json },
    .{ "javascript", .javascript },
    .{ "js", .javascript },
    .{ "jsx", .javascript },
    .{ "ts", .javascript },
    .{ "typescript", .javascript },
    .{ "tsx", .javascript },
});

const json_lit_map = std.StaticStringMap(void).initComptime(.{
    .{ "true", {} },
    .{ "false", {} },
    .{ "null", {} },
});

pub fn tokenize(line: []const u8, lang: Lang, buf: []Token) []const Token {
    return switch (lang) {
        .zig => tokenizeLang(line, buf, .zig),
        .python => tokenizeLang(line, buf, .python),
        .bash => tokenizeLang(line, buf, .bash),
        .json => tokenizeJson(line, buf),
        .javascript => tokenizeLang(line, buf, .javascript),
        .unknown => tokenizeGeneric(line, buf),
    };
}

// --- Language configs ---

const LangCfg = struct {
    keywords: []const []const u8,
    line_comment: ?[]const u8,
    hash_comment: bool,
    has_single_quote_str: bool,
    has_types: bool, // PascalCase detection
};

fn langCfg(comptime lang: Lang) LangCfg {
    return switch (lang) {
        .zig => .{
            .keywords = &zig_kw,
            .line_comment = "//",
            .hash_comment = false,
            .has_single_quote_str = false,
            .has_types = true,
        },
        .python => .{
            .keywords = &python_kw,
            .line_comment = null,
            .hash_comment = true,
            .has_single_quote_str = true,
            .has_types = false,
        },
        .bash => .{
            .keywords = &bash_kw,
            .line_comment = null,
            .hash_comment = true,
            .has_single_quote_str = true,
            .has_types = false,
        },
        .javascript => .{
            .keywords = &js_kw,
            .line_comment = "//",
            .hash_comment = false,
            .has_single_quote_str = true,
            .has_types = false,
        },
        else => unreachable,
    };
}

const zig_kw = [_][]const u8{
    "and",      "break",     "catch",  "comptime",    "const",
    "continue", "defer",     "else",   "enum",        "errdefer",
    "error",    "false",     "fn",     "for",         "if",
    "inline",   "null",      "or",     "orelse",      "pub",
    "return",   "struct",    "switch", "test",        "true",
    "try",      "undefined", "union",  "unreachable", "var",
    "while",
};

const python_kw = [_][]const u8{
    "False",    "None",    "True",  "and",   "as",
    "assert",   "async",   "await", "break", "class",
    "continue", "def",     "del",   "elif",  "else",
    "except",   "finally", "for",   "from",  "global",
    "if",       "import",  "in",    "is",    "lambda",
    "not",      "or",      "pass",  "raise", "return",
    "try",      "while",   "with",  "yield",
};

const bash_kw = [_][]const u8{
    "case",  "do",       "done", "echo",   "elif",
    "else",  "esac",     "exit", "export", "fi",
    "for",   "function", "if",   "local",  "return",
    "set",   "source",   "then", "unset",  "until",
    "while",
};

const js_kw = [_][]const u8{
    "async",    "await", "break",    "case",       "catch",
    "class",    "const", "continue", "else",       "export",
    "extends",  "false", "finally",  "for",        "from",
    "function", "if",    "import",   "instanceof", "let",
    "new",      "null",  "return",   "switch",     "this",
    "throw",    "true",  "try",      "typeof",     "undefined",
    "var",      "while", "yield",
};

fn isKw(comptime keywords: []const []const u8, word: []const u8) bool {
    inline for (keywords) |kw| {
        if (std.mem.eql(u8, word, kw)) return true;
    }
    return false;
}

// --- Generic tokenizer (no keywords, just strings/numbers/operators) ---

fn tokenizeGeneric(line: []const u8, buf: []Token) []const Token {
    var n: usize = 0;
    var i: usize = 0;
    while (i < line.len and n < buf.len) {
        // String
        if (line[i] == '"' or line[i] == '\'') {
            const end = scanStr(line, i);
            buf[n] = .{ .start = i, .end = end, .kind = .string };
            n += 1;
            i = end;
            continue;
        }
        // Number
        if (isDigit(line[i]) and (i == 0 or !isIdentChar(line[i - 1]))) {
            const end = scanNum(line, i);
            buf[n] = .{ .start = i, .end = end, .kind = .number };
            n += 1;
            i = end;
            continue;
        }
        // Operator
        if (isOp(line[i])) {
            buf[n] = .{ .start = i, .end = i + 1, .kind = .operator };
            n += 1;
            i += 1;
            continue;
        }
        // Punct
        if (isPunct(line[i])) {
            buf[n] = .{ .start = i, .end = i + 1, .kind = .punct };
            n += 1;
            i += 1;
            continue;
        }
        // Text (identifiers / whitespace / anything else)
        const start = i;
        if (isIdentStart(line[i])) {
            i += 1;
            while (i < line.len and isIdentChar(line[i])) : (i += 1) {}
        } else {
            i += 1;
        }
        buf[n] = .{ .start = start, .end = i, .kind = .text };
        n += 1;
    }
    return buf[0..n];
}

// --- Main language tokenizer ---

fn tokenizeLang(line: []const u8, buf: []Token, comptime lang: Lang) []const Token {
    const cfg = comptime langCfg(lang);
    var n: usize = 0;
    var i: usize = 0;

    while (i < line.len and n < buf.len) {
        const tok: Token = sw: switch (line[i]) {
            '#' => {
                if (cfg.hash_comment) {
                    buf[n] = .{ .start = i, .end = line.len, .kind = .comment };
                    return buf[0 .. n + 1];
                }
                // '#' as text
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
            '/' => {
                if (cfg.line_comment) |lc| {
                    if (i + lc.len <= line.len and std.mem.eql(u8, line[i..][0..lc.len], lc)) {
                        buf[n] = .{ .start = i, .end = line.len, .kind = .comment };
                        return buf[0 .. n + 1];
                    }
                }
                // '/' as operator
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .operator };
            },
            '"', '\'' => {
                const end = scanStr(line, i);
                const start = i;
                i = end;
                break :sw .{ .start = start, .end = end, .kind = .string };
            },
            '0'...'9' => {
                if (i == 0 or !isIdentChar(line[i - 1])) {
                    const end = scanNum(line, i);
                    const start = i;
                    i = end;
                    break :sw .{ .start = start, .end = end, .kind = .number };
                }
                // Digit preceded by ident char — part of identifier, handled as text
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
            'a'...'z', 'A'...'Z', '_', '@' => {
                const start = i;
                if (line[i] == '@') i += 1;
                while (i < line.len and isIdentChar(line[i])) : (i += 1) {}
                const word = line[start..i];
                if (isKw(cfg.keywords, word)) {
                    break :sw .{ .start = start, .end = i, .kind = .keyword };
                }
                if (i < line.len and line[i] == '(') {
                    break :sw .{ .start = start, .end = i, .kind = .func };
                }
                if (cfg.has_types and isPascalCase(word)) {
                    break :sw .{ .start = start, .end = i, .kind = .type_name };
                }
                break :sw .{ .start = start, .end = i, .kind = .text };
            },
            '=', '+', '-', '*', '<', '>', '!', '&', '|', '^', '~', '%' => {
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .operator };
            },
            '(', ')', '{', '}', '[', ']', ',', ';', '.' => {
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .punct };
            },
            else => {
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
        };
        buf[n] = tok;
        n += 1;
    }
    return buf[0..n];
}

// --- JSON tokenizer ---

fn tokenizeJson(line: []const u8, buf: []Token) []const Token {
    var n: usize = 0;
    var i: usize = 0;

    while (i < line.len and n < buf.len) {
        const tok: Token = sw: switch (line[i]) {
            '"' => {
                const start = i;
                const end = scanStr(line, i);
                // Determine if this is a key (followed by ':')
                var j = end;
                while (j < line.len and (line[j] == ' ' or line[j] == '\t')) : (j += 1) {}
                const kind: Kind = if (j < line.len and line[j] == ':') .func else .string;
                i = end;
                break :sw .{ .start = start, .end = end, .kind = kind };
            },
            '-' => {
                if (i + 1 < line.len and isDigit(line[i + 1]) and
                    (i == 0 or !isIdentChar(line[i - 1])))
                {
                    const start = i;
                    const end = scanNum(line, i);
                    i = end;
                    break :sw .{ .start = start, .end = end, .kind = .number };
                }
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
            '0'...'9' => {
                if (i == 0 or !isIdentChar(line[i - 1])) {
                    const start = i;
                    const end = scanNum(line, i);
                    i = end;
                    break :sw .{ .start = start, .end = end, .kind = .number };
                }
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
            'a'...'z', 'A'...'Z', '_' => {
                const start = i;
                while (i < line.len and isIdentChar(line[i])) : (i += 1) {}
                const word = line[start..i];
                const kind: Kind = if (json_lit_map.get(word) != null) .keyword else .text;
                break :sw .{ .start = start, .end = i, .kind = kind };
            },
            '(', ')', '{', '}', '[', ']', ',', ';', '.', ':' => {
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .punct };
            },
            else => {
                i += 1;
                break :sw .{ .start = i - 1, .end = i, .kind = .text };
            },
        };
        buf[n] = tok;
        n += 1;
    }
    return buf[0..n];
}

// --- Scanner helpers ---

fn scanStr(line: []const u8, pos: usize) usize {
    const quote = line[pos];
    var i = pos + 1;
    while (i < line.len) : (i += 1) {
        if (line[i] == '\\') {
            i += 1; // skip escaped char
            continue;
        }
        if (line[i] == quote) return i + 1;
    }
    return i; // unterminated
}

fn scanNum(line: []const u8, pos: usize) usize {
    var i = pos;
    // Leading minus for JSON
    if (i < line.len and line[i] == '-') i += 1;
    // Hex/binary prefix
    if (i + 1 < line.len and line[i] == '0') {
        if (line[i + 1] == 'x' or line[i + 1] == 'X' or
            line[i + 1] == 'b' or line[i + 1] == 'B' or
            line[i + 1] == 'o' or line[i + 1] == 'O')
        {
            i += 2;
            while (i < line.len and (isHexDigit(line[i]) or line[i] == '_')) : (i += 1) {}
            return i;
        }
    }
    while (i < line.len and (isDigit(line[i]) or line[i] == '_')) : (i += 1) {}
    // Float
    if (i < line.len and line[i] == '.') {
        i += 1;
        while (i < line.len and (isDigit(line[i]) or line[i] == '_')) : (i += 1) {}
    }
    // Exponent
    if (i < line.len and (line[i] == 'e' or line[i] == 'E')) {
        i += 1;
        if (i < line.len and (line[i] == '+' or line[i] == '-')) i += 1;
        while (i < line.len and isDigit(line[i])) : (i += 1) {}
    }
    return i;
}

fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

fn isHexDigit(c: u8) bool {
    return isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}

fn isIdentChar(c: u8) bool {
    return isIdentStart(c) or isDigit(c);
}

fn isOp(c: u8) bool {
    return switch (c) {
        '=', '+', '-', '*', '/', '<', '>', '!', '&', '|', '^', '~', '%' => true,
        else => false,
    };
}

fn isPunct(c: u8) bool {
    return switch (c) {
        '(', ')', '{', '}', '[', ']', ',', ';', '.' => true,
        else => false,
    };
}

fn isPascalCase(word: []const u8) bool {
    if (word.len < 2) return false;
    // Must start with uppercase
    if (word[0] < 'A' or word[0] > 'Z') return false;
    // Must contain at least one lowercase
    for (word[1..]) |c| {
        if (c >= 'a' and c <= 'z') return true;
    }
    return false;
}

// ============================================================
// Tests
// ============================================================

const testing = std.testing;

fn writeSnapStr(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

fn tokSnapAlloc(alloc: std.mem.Allocator, line: []const u8, toks: []const Token) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);

    const w = buf.writer(alloc);
    try w.writeAll("line=");
    try writeSnapStr(w, line);
    for (toks, 0..) |tok, i| {
        try w.print("\n{d}|{s}|{d}..{d}|", .{
            i,
            @tagName(tok.kind),
            tok.start,
            tok.end,
        });
        try writeSnapStr(w, line[tok.start..tok.end]);
    }
    return buf.toOwnedSlice(alloc);
}

fn expectTokSnap(
    comptime src: std.builtin.SourceLocation,
    comptime snap: []const u8,
    line: []const u8,
    toks: []const Token,
) !void {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const actual = try tokSnapAlloc(testing.allocator, line, toks);
    defer testing.allocator.free(actual);

    try oh.snap(src, snap).expectEqual(actual);
}

test {
    _ = @import("ohsnap");
}

test "Lang.detect maps known hints" {
    try testing.expectEqual(Lang.zig, Lang.detect("zig"));
    try testing.expectEqual(Lang.python, Lang.detect("py"));
    try testing.expectEqual(Lang.python, Lang.detect("python"));
    try testing.expectEqual(Lang.bash, Lang.detect("sh"));
    try testing.expectEqual(Lang.bash, Lang.detect("bash"));
    try testing.expectEqual(Lang.bash, Lang.detect("zsh"));
    try testing.expectEqual(Lang.json, Lang.detect("json"));
    try testing.expectEqual(Lang.javascript, Lang.detect("js"));
    try testing.expectEqual(Lang.javascript, Lang.detect("javascript"));
    try testing.expectEqual(Lang.javascript, Lang.detect("ts"));
    try testing.expectEqual(Lang.unknown, Lang.detect("haskell"));
    try testing.expectEqual(Lang.unknown, Lang.detect(""));
}

test "zig: keywords highlighted" {
    var buf: [64]Token = undefined;
    const line = "const x = 1;";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="const x = 1;"
        \\0|keyword|0..5|"const"
        \\1|text|5..6|" "
        \\2|text|6..7|"x"
        \\3|text|7..8|" "
        \\4|operator|8..9|"="
        \\5|text|9..10|" "
        \\6|number|10..11|"1"
        \\7|punct|11..12|";""
    , line, toks);
}

test "zig: string literal" {
    var buf: [64]Token = undefined;
    const line = "const s = \"hello\";";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="const s = \"hello\";"
        \\0|keyword|0..5|"const"
        \\1|text|5..6|" "
        \\2|text|6..7|"s"
        \\3|text|7..8|" "
        \\4|operator|8..9|"="
        \\5|text|9..10|" "
        \\6|string|10..17|"\"hello\""
        \\7|punct|17..18|";""
    , line, toks);
}

test "zig: line comment" {
    var buf: [64]Token = undefined;
    const line = "x + 1 // add one";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="x + 1 // add one"
        \\0|text|0..1|"x"
        \\1|text|1..2|" "
        \\2|operator|2..3|"+"
        \\3|text|3..4|" "
        \\4|number|4..5|"1"
        \\5|text|5..6|" "
        \\6|comment|6..16|"// add one""
    , line, toks);
}

test "zig: number literals" {
    var buf: [64]Token = undefined;
    const line = "0xff + 42 + 3.14";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="0xff + 42 + 3.14"
        \\0|number|0..4|"0xff"
        \\1|text|4..5|" "
        \\2|operator|5..6|"+"
        \\3|text|6..7|" "
        \\4|number|7..9|"42"
        \\5|text|9..10|" "
        \\6|operator|10..11|"+"
        \\7|text|11..12|" "
        \\8|number|12..16|"3.14""
    , line, toks);
}

test "zig: function call" {
    var buf: [64]Token = undefined;
    const line = "foo(bar)";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="foo(bar)"
        \\0|func|0..3|"foo"
        \\1|punct|3..4|"("
        \\2|text|4..7|"bar"
        \\3|punct|7..8|")""
    , line, toks);
}

test "zig: PascalCase type" {
    var buf: [64]Token = undefined;
    const line = "var x: MyType = .{};";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="var x: MyType = .{};"
        \\0|keyword|0..3|"var"
        \\1|text|3..4|" "
        \\2|text|4..5|"x"
        \\3|text|5..6|":"
        \\4|text|6..7|" "
        \\5|type_name|7..13|"MyType"
        \\6|text|13..14|" "
        \\7|operator|14..15|"="
        \\8|text|15..16|" "
        \\9|punct|16..17|"."
        \\10|punct|17..18|"{"
        \\11|punct|18..19|"}"
        \\12|punct|19..20|";""
    , line, toks);
}

test "python: keywords and hash comment" {
    var buf: [64]Token = undefined;
    const line = "def foo(): # comment";
    const toks = tokenize(line, .python, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="def foo(): # comment"
        \\0|keyword|0..3|"def"
        \\1|text|3..4|" "
        \\2|func|4..7|"foo"
        \\3|punct|7..8|"("
        \\4|punct|8..9|")"
        \\5|text|9..10|":"
        \\6|text|10..11|" "
        \\7|comment|11..20|"# comment""
    , line, toks);
}

test "python: single-quote string" {
    var buf: [64]Token = undefined;
    const line = "x = 'hello'";
    const toks = tokenize(line, .python, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="x = 'hello'"
        \\0|text|0..1|"x"
        \\1|text|1..2|" "
        \\2|operator|2..3|"="
        \\3|text|3..4|" "
        \\4|string|4..11|"'hello'""
    , line, toks);
}

test "bash: keywords" {
    var buf: [64]Token = undefined;
    const line = "if [ -f file ]; then";
    const toks = tokenize(line, .bash, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="if [ -f file ]; then"
        \\0|keyword|0..2|"if"
        \\1|text|2..3|" "
        \\2|punct|3..4|"["
        \\3|text|4..5|" "
        \\4|operator|5..6|"-"
        \\5|text|6..7|"f"
        \\6|text|7..8|" "
        \\7|text|8..12|"file"
        \\8|text|12..13|" "
        \\9|punct|13..14|"]"
        \\10|punct|14..15|";"
        \\11|text|15..16|" "
        \\12|keyword|16..20|"then""
    , line, toks);
}

test "javascript: keywords and comment" {
    var buf: [64]Token = undefined;
    const line = "const x = 42; // num";
    const toks = tokenize(line, .javascript, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="const x = 42; // num"
        \\0|keyword|0..5|"const"
        \\1|text|5..6|" "
        \\2|text|6..7|"x"
        \\3|text|7..8|" "
        \\4|operator|8..9|"="
        \\5|text|9..10|" "
        \\6|number|10..12|"42"
        \\7|punct|12..13|";"
        \\8|text|13..14|" "
        \\9|comment|14..20|"// num""
    , line, toks);
}

test "json: key vs string value" {
    var buf: [64]Token = undefined;
    const line = "  \"name\": \"alice\"";
    const toks = tokenize(line, .json, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="  \"name\": \"alice\""
        \\0|text|0..1|" "
        \\1|text|1..2|" "
        \\2|func|2..8|"\"name\""
        \\3|punct|8..9|":"
        \\4|text|9..10|" "
        \\5|string|10..17|"\"alice\"""
    , line, toks);
}

test "json: boolean and null keywords" {
    var buf: [64]Token = undefined;
    const line = "true false null";
    const toks = tokenize(line, .json, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="true false null"
        \\0|keyword|0..4|"true"
        \\1|text|4..5|" "
        \\2|keyword|5..10|"false"
        \\3|text|10..11|" "
        \\4|keyword|11..15|"null""
    , line, toks);
}

test "operators and punctuation" {
    var buf: [64]Token = undefined;
    const line = "a + b(c);";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="a + b(c);"
        \\0|text|0..1|"a"
        \\1|text|1..2|" "
        \\2|operator|2..3|"+"
        \\3|text|3..4|" "
        \\4|func|4..5|"b"
        \\5|punct|5..6|"("
        \\6|text|6..7|"c"
        \\7|punct|7..8|")"
        \\8|punct|8..9|";""
    , line, toks);
}

test "escaped string characters" {
    var buf: [64]Token = undefined;
    const line = "\"he\\\"llo\"";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="\"he\\\"llo\""
        \\0|string|0..9|"\"he\\\"llo\"""
    , line, toks);
}

test "unknown lang uses generic tokenizer" {
    var buf: [64]Token = undefined;
    const line = "x = \"hi\" + 42";
    const toks = tokenize(line, .unknown, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="x = \"hi\" + 42"
        \\0|text|0..1|"x"
        \\1|text|1..2|" "
        \\2|operator|2..3|"="
        \\3|text|3..4|" "
        \\4|string|4..8|"\"hi\""
        \\5|text|8..9|" "
        \\6|operator|9..10|"+"
        \\7|text|10..11|" "
        \\8|number|11..13|"42""
    , line, toks);
}

test "zig: multi-token statement" {
    var buf: [64]Token = undefined;
    const line = "const x: MyType = foo(42); // call";
    const toks = tokenize(line, .zig, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="const x: MyType = foo(42); // call"
        \\0|keyword|0..5|"const"
        \\1|text|5..6|" "
        \\2|text|6..7|"x"
        \\3|text|7..8|":"
        \\4|text|8..9|" "
        \\5|type_name|9..15|"MyType"
        \\6|text|15..16|" "
        \\7|operator|16..17|"="
        \\8|text|17..18|" "
        \\9|func|18..21|"foo"
        \\10|punct|21..22|"("
        \\11|number|22..24|"42"
        \\12|punct|24..25|")"
        \\13|punct|25..26|";"
        \\14|text|26..27|" "
        \\15|comment|27..34|"// call""
    , line, toks);
}

test "json: multi-token object line" {
    var buf: [64]Token = undefined;
    const line = "  \"count\": 42, \"active\": true";
    const toks = tokenize(line, .json, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="  \"count\": 42, \"active\": true"
        \\0|text|0..1|" "
        \\1|text|1..2|" "
        \\2|func|2..9|"\"count\""
        \\3|punct|9..10|":"
        \\4|text|10..11|" "
        \\5|number|11..13|"42"
        \\6|punct|13..14|","
        \\7|text|14..15|" "
        \\8|func|15..23|"\"active\""
        \\9|punct|23..24|":"
        \\10|text|24..25|" "
        \\11|keyword|25..29|"true""
    , line, toks);
}

test "json: negative number and null" {
    var buf: [64]Token = undefined;
    const line = "{\"val\": -3.14, \"x\": null}";
    const toks = tokenize(line, .json, &buf);
    try expectTokSnap(@src(),
        \\[]u8
        \\  "line="{\"val\": -3.14, \"x\": null}"
        \\0|punct|0..1|"{"
        \\1|func|1..6|"\"val\""
        \\2|punct|6..7|":"
        \\3|text|7..8|" "
        \\4|number|8..13|"-3.14"
        \\5|punct|13..14|","
        \\6|text|14..15|" "
        \\7|func|15..18|"\"x\""
        \\8|punct|18..19|":"
        \\9|text|19..20|" "
        \\10|keyword|20..24|"null"
        \\11|punct|24..25|"}""
    , line, toks);
}
