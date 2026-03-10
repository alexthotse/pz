const std = @import("std");
const testing = std.testing;

pub const ver_current: u16 = 1;

pub const Effect = enum {
    allow,
    deny,
};

pub const Rule = struct {
    pattern: []const u8,
    effect: Effect,
    tool: ?[]const u8 = null,
};

pub const Policy = struct {
    rules: []const Rule,

    pub fn eval(self: Policy, path: []const u8, tool: ?[]const u8) Effect {
        return evaluate(self.rules, path, tool);
    }
};

/// Paths always denied regardless of rules.
pub const protected = [_][]const u8{
    "*.audit.log",
    "*.session",
    ".pz/config",
    ".pz/secrets",
    ".pz/auth",
};

/// Glob match: `*` matches any chars, `?` matches single char, `\` escapes.
pub fn matchGlob(pat: []const u8, txt: []const u8) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    var star_p: usize = pat.len; // invalid sentinel
    var star_t: usize = 0;

    while (ti < txt.len or pi < pat.len) {
        if (pi < pat.len) {
            const c = pat[pi];
            if (c == '*') {
                star_p = pi;
                star_t = ti;
                pi += 1;
                continue;
            }
            if (ti < txt.len) {
                if (c == '\\' and pi + 1 < pat.len) {
                    if (txt[ti] == pat[pi + 1]) {
                        pi += 2;
                        ti += 1;
                        continue;
                    }
                } else if (c == '?' or c == txt[ti]) {
                    pi += 1;
                    ti += 1;
                    continue;
                }
            }
        }
        // Backtrack to last star
        if (star_p < pat.len) {
            pi = star_p + 1;
            star_t += 1;
            ti = star_t;
            if (ti > txt.len) return false;
            continue;
        }
        return false;
    }
    return true;
}

/// Glob match on path. When pattern has `/`, matches component-by-component
/// so `*` does not cross `/` boundaries. Without `/`, matches any component.
pub fn matchPath(pat: []const u8, path: []const u8) bool {
    if (std.mem.indexOfScalar(u8, pat, '/') != null) {
        // Component-wise: split both by '/' and match segment pairs
        var pi = std.mem.splitScalar(u8, pat, '/');
        var ti = std.mem.splitScalar(u8, path, '/');
        while (true) {
            const ps = pi.next();
            const ts = ti.next();
            if (ps == null and ts == null) return true;
            if (ps == null or ts == null) return false;
            if (!matchGlob(ps.?, ts.?)) return false;
        }
    }
    // No slash in pattern: match against each path component
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (matchGlob(pat, seg)) return true;
    }
    return false;
}

/// Match env variable. Pattern `KEY_GLOB=VAL_GLOB` splits on first `=`.
/// Key-only pattern matches regardless of value.
pub fn matchEnv(pattern: []const u8, key: []const u8, val: []const u8) bool {
    if (std.mem.indexOfScalar(u8, pattern, '=')) |sep| {
        const kp = pattern[0..sep];
        const vp = pattern[sep + 1 ..];
        return matchGlob(kp, key) and matchGlob(vp, val);
    }
    return matchGlob(pattern, key);
}

/// First-match-wins. Falls through to deny if no rule matches.
/// Protected paths are always denied.
pub fn evaluate(rules: []const Rule, path: []const u8, tool: ?[]const u8) Effect {
    // Self-protection override
    for (&protected) |pp| {
        if (matchPath(pp, path)) return .deny;
    }
    for (rules) |r| {
        // Tool filter: skip rule if tool doesn't match
        if (r.tool) |rt| {
            if (tool == null) continue;
            if (!std.mem.eql(u8, rt, tool.?)) continue;
        }
        if (matchPath(r.pattern, path)) return r.effect;
    }
    return .deny;
}

/// Evaluate env key+val against rules using last-match-wins semantics.
/// Allows specific allow rules to override broad deny rules (and vice versa).
/// Default (no match): deny.
pub fn evalEnv(rules: []const Rule, key: []const u8, val: []const u8) Effect {
    var result: Effect = .deny;
    for (rules) |r| {
        if (matchEnv(r.pattern, key, val))
            result = r.effect;
    }
    return result;
}

/// Versioned policy document for JSON serialization.
pub const Doc = struct {
    version: u16 = ver_current,
    rules: []const Rule,
};

/// Parse a policy document from JSON.
/// Missing `version` defaults to 1. Unknown versions are rejected.
pub fn parseDoc(alloc: std.mem.Allocator, json: []const u8) !Doc {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const root = parsed.value;

    if (root != .object) return error.UnexpectedToken;

    const ver: u16 = blk: {
        if (root.object.get("version")) |v| {
            switch (v) {
                .integer => |i| break :blk @intCast(i),
                else => return error.UnexpectedToken,
            }
        }
        break :blk 1;
    };

    if (ver != ver_current) return error.UnsupportedPolicyVersion;

    const rules_val = root.object.get("rules") orelse return error.UnexpectedToken;
    if (rules_val != .array) return error.UnexpectedToken;

    const items = rules_val.array.items;
    const rules = try alloc.alloc(Rule, items.len);
    errdefer alloc.free(rules);

    for (items, 0..) |item, i| {
        if (item != .object) return error.UnexpectedToken;
        var rule = Rule{ .pattern = "", .effect = .allow };

        if (item.object.get("pattern")) |p| {
            if (p != .string) return error.UnexpectedToken;
            rule.pattern = try alloc.dupe(u8, p.string);
        }

        if (item.object.get("effect")) |eff| {
            if (eff != .string) return error.UnexpectedToken;
            if (std.mem.eql(u8, eff.string, "allow")) {
                rule.effect = .allow;
            } else if (std.mem.eql(u8, eff.string, "deny")) {
                rule.effect = .deny;
            } else return error.UnexpectedToken;
        }

        if (item.object.get("tool")) |t| {
            if (t != .string) return error.UnexpectedToken;
            rule.tool = try alloc.dupe(u8, t.string);
        }

        rules[i] = rule;
    }

    return .{ .version = ver, .rules = rules };
}

/// Serialize a policy document to JSON.
pub fn encodeDoc(alloc: std.mem.Allocator, doc: Doc) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    try w.writeAll("{\"version\":");
    try w.print("{d}", .{doc.version});
    try w.writeAll(",\"rules\":[");
    for (doc.rules, 0..) |rule, i| {
        if (i > 0) try w.writeByte(',');
        try w.writeAll("{\"pattern\":");
        try writeJsonStr(w, rule.pattern);
        try w.writeAll(",\"effect\":");
        try writeJsonStr(w, @tagName(rule.effect));
        if (rule.tool) |t| {
            try w.writeAll(",\"tool\":");
            try writeJsonStr(w, t);
        }
        try w.writeByte('}');
    }
    try w.writeAll("]}");
    return try buf.toOwnedSlice(alloc);
}

fn writeJsonStr(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

/// Free owned allocations from parseDoc.
pub fn deinitDoc(alloc: std.mem.Allocator, doc: Doc) void {
    for (doc.rules) |rule| {
        if (rule.pattern.len > 0) alloc.free(rule.pattern);
        if (rule.tool) |t| alloc.free(t);
    }
    alloc.free(doc.rules);
}

// ── Tests ──────────────────────────────────────────────────────────────

test "matchGlob exact" {
    try testing.expect(matchGlob("hello", "hello"));
    try testing.expect(!matchGlob("hello", "world"));
}

test "matchGlob star" {
    try testing.expect(matchGlob("*.zig", "policy.zig"));
    try testing.expect(matchGlob("foo*bar", "foobazbar"));
    try testing.expect(matchGlob("*", "anything"));
    try testing.expect(!matchGlob("*.zig", "policy.rs"));
}

test "matchGlob question" {
    try testing.expect(matchGlob("h?llo", "hello"));
    try testing.expect(matchGlob("h?llo", "hallo"));
    try testing.expect(!matchGlob("h?llo", "hllo"));
}

test "matchGlob escape" {
    try testing.expect(matchGlob("foo\\*bar", "foo*bar"));
    try testing.expect(!matchGlob("foo\\*bar", "fooxbar"));
    try testing.expect(matchGlob("a\\?b", "a?b"));
    try testing.expect(!matchGlob("a\\?b", "axb"));
}

test "matchGlob no match" {
    try testing.expect(!matchGlob("abc", "abcd"));
    try testing.expect(!matchGlob("abcd", "abc"));
}

test "matchPath dir pattern" {
    try testing.expect(matchPath("src/*.zig", "src/main.zig"));
    try testing.expect(!matchPath("src/*.zig", "lib/main.zig"));
}

test "matchPath component match" {
    try testing.expect(matchPath("*.zig", "src/core/policy.zig"));
    try testing.expect(matchPath("core", "src/core/policy.zig"));
}

test "matchPath nested" {
    try testing.expect(matchPath("src/*/policy.zig", "src/core/policy.zig"));
    try testing.expect(!matchPath("src/*/policy.zig", "src/a/b/policy.zig"));
}

test "evaluate allow" {
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .allow },
    };
    try testing.expectEqual(Effect.allow, evaluate(&rules, "main.zig", null));
}

test "evaluate deny" {
    const rules = [_]Rule{
        .{ .pattern = "*.secret", .effect = .deny },
    };
    try testing.expectEqual(Effect.deny, evaluate(&rules, "key.secret", null));
}

test "evaluate first match wins" {
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .deny },
        .{ .pattern = "*", .effect = .allow },
    };
    try testing.expectEqual(Effect.deny, evaluate(&rules, "foo.zig", null));
    // Non-zig falls to second rule
    try testing.expectEqual(Effect.allow, evaluate(&rules, "foo.txt", null));
}

test "evaluate default deny" {
    const rules = [_]Rule{};
    try testing.expectEqual(Effect.deny, evaluate(&rules, "anything", null));
}

test "evaluate tool filter" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow, .tool = "read" },
    };
    try testing.expectEqual(Effect.allow, evaluate(&rules, "f.zig", "read"));
    // Wrong tool — rule skipped, default deny
    try testing.expectEqual(Effect.deny, evaluate(&rules, "f.zig", "write"));
    // No tool — rule skipped
    try testing.expectEqual(Effect.deny, evaluate(&rules, "f.zig", null));
}

test "self-protection" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };
    try testing.expectEqual(Effect.deny, evaluate(&rules, "app.audit.log", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "data.session", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, ".pz/config", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, ".pz/secrets", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, ".pz/auth", null));
}

test "Policy struct eval" {
    const p = Policy{
        .rules = &[_]Rule{
            .{ .pattern = "*.zig", .effect = .allow },
        },
    };
    try testing.expectEqual(Effect.allow, p.eval("main.zig", null));
    try testing.expectEqual(Effect.deny, p.eval("main.rs", null));
}

test "matchEnv key-only pattern" {
    try testing.expect(matchEnv("SECRET_*", "SECRET_KEY", "x"));
    try testing.expect(!matchEnv("SECRET_*", "HOME", "/home/user"));
    try testing.expect(matchEnv("PATH", "PATH", "/usr/bin"));
    try testing.expect(matchEnv("PATH", "PATH", ""));
    try testing.expect(!matchEnv("PATH", "HOME", "/home"));
}

test "matchEnv key=value pattern" {
    try testing.expect(matchEnv("AWS_*=*AKIA*", "AWS_KEY", "myAKIAtoken"));
    try testing.expect(!matchEnv("AWS_*=*AKIA*", "AWS_KEY", "safe_value"));
    try testing.expect(!matchEnv("AWS_*=*AKIA*", "HOME", "myAKIAtoken"));
    try testing.expect(matchEnv("DB_*=prod*", "DB_HOST", "production-db"));
    try testing.expect(!matchEnv("DB_*=prod*", "DB_HOST", "dev-db"));
    try testing.expect(!matchEnv("DB_*=prod*", "CACHE_HOST", "production-db"));
}

test "evalEnv deny star then allow HOME" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .deny },
        .{ .pattern = "HOME", .effect = .allow },
    };
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "HOME", "/home/user"));
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "SECRET_KEY", "x"));
}

test "evalEnv deny star alone" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .deny },
    };
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "HOME", "/home/user"));
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "PATH", "/usr/bin"));
}

test "evalEnv allow star" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "HOME", "/home/user"));
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "SECRET", "x"));
}

test "evalEnv specific deny overrides broad allow" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
        .{ .pattern = "SECRET_KEY", .effect = .deny },
    };
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "HOME", "/home/user"));
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "SECRET_KEY", "x"));
}

test "evalEnv no rules defaults deny" {
    const rules = [_]Rule{};
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "HOME", ""));
}

test "evalEnv last match wins with multiple overrides" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .deny },
        .{ .pattern = "HOME", .effect = .allow },
        .{ .pattern = "HOME", .effect = .deny },
    };
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "HOME", "/home/user"));
}

test "evalEnv key=value pattern" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
        .{ .pattern = "AWS_*=*AKIA*", .effect = .deny },
    };
    try testing.expectEqual(Effect.deny, evalEnv(&rules, "AWS_KEY", "myAKIAtoken"));
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "AWS_KEY", "safe_value"));
    try testing.expectEqual(Effect.allow, evalEnv(&rules, "HOME", "/home/user"));
}

test "parseDoc valid v1" {
    const json = "{\"version\":1,\"rules\":[{\"pattern\":\"*.zig\",\"effect\":\"allow\"},{\"pattern\":\"*.secret\",\"effect\":\"deny\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expectEqual(@as(u16, 1), doc.version);
    try testing.expectEqual(@as(usize, 2), doc.rules.len);
    try testing.expectEqual(Effect.allow, doc.rules[0].effect);
    try testing.expectEqual(Effect.deny, doc.rules[1].effect);
}

test "parseDoc missing version defaults to v1" {
    const json = "{\"rules\":[{\"pattern\":\"*\",\"effect\":\"allow\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expectEqual(@as(u16, 1), doc.version);
    try testing.expectEqual(@as(usize, 1), doc.rules.len);
}

test "parseDoc rejects unsupported version" {
    const json = "{\"version\":99,\"rules\":[]}";
    try testing.expectError(error.UnsupportedPolicyVersion, parseDoc(testing.allocator, json));
}

test "parseDoc roundtrip" {
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .deny, .tool = "bash" },
        .{ .pattern = "*", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);

    const doc2 = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc2);

    try testing.expectEqual(@as(u16, ver_current), doc2.version);
    try testing.expectEqual(@as(usize, 2), doc2.rules.len);
    try testing.expectEqual(Effect.deny, doc2.rules[0].effect);
    try testing.expect(std.mem.eql(u8, "bash", doc2.rules[0].tool.?));
    try testing.expectEqual(Effect.allow, doc2.rules[1].effect);
    try testing.expect(doc2.rules[1].tool == null);
}

test "parseDoc with tool filter" {
    const json = "{\"version\":1,\"rules\":[{\"pattern\":\"*\",\"effect\":\"deny\",\"tool\":\"rm\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expectEqual(@as(usize, 1), doc.rules.len);
    try testing.expect(std.mem.eql(u8, "rm", doc.rules[0].tool.?));
    try testing.expectEqual(Effect.deny, doc.rules[0].effect);
}

// ── Snapshot tests (ohsnap) ────────────────────────────────────────────

fn snapEsc(alloc: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayListUnmanaged(u8) = .{};
    errdefer out.deinit(alloc);

    for (s) |c| switch (c) {
        '\\' => try out.appendSlice(alloc, "\\\\"),
        '"' => try out.appendSlice(alloc, "\\\""),
        '\n' => try out.appendSlice(alloc, "\\n"),
        '\r' => try out.appendSlice(alloc, "\\r"),
        '\t' => try out.appendSlice(alloc, "\\t"),
        else => try out.append(alloc, c),
    };

    return out.toOwnedSlice(alloc);
}

test "snapshot: evaluate with complex rule chains" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const rules = [_]Rule{
        .{ .pattern = "*.secret", .effect = .deny },
        .{ .pattern = "src/*.zig", .effect = .allow, .tool = "read" },
        .{ .pattern = "src/*.zig", .effect = .deny, .tool = "write" },
        .{ .pattern = "docs/*", .effect = .allow },
        .{ .pattern = "build/*", .effect = .deny },
        .{ .pattern = "*", .effect = .allow },
    };

    const Result = struct {
        secret_null: Effect,
        src_read: Effect,
        src_write: Effect,
        src_bash: Effect,
        docs_null: Effect,
        build_null: Effect,
        other_null: Effect,
    };

    const r = Result{
        .secret_null = evaluate(&rules, "key.secret", null),
        .src_read = evaluate(&rules, "src/main.zig", "read"),
        .src_write = evaluate(&rules, "src/main.zig", "write"),
        .src_bash = evaluate(&rules, "src/main.zig", "bash"),
        .docs_null = evaluate(&rules, "docs/README", null),
        .build_null = evaluate(&rules, "build/out.o", null),
        .other_null = evaluate(&rules, "foo.txt", null),
    };

    try oh.snap(@src(),
        \\core.policy.test.snapshot: evaluate with complex rule chains.Result
        \\  .secret_null: core.policy.Effect
        \\    .deny
        \\  .src_read: core.policy.Effect
        \\    .allow
        \\  .src_write: core.policy.Effect
        \\    .deny
        \\  .src_bash: core.policy.Effect
        \\    .allow
        \\  .docs_null: core.policy.Effect
        \\    .allow
        \\  .build_null: core.policy.Effect
        \\    .deny
        \\  .other_null: core.policy.Effect
        \\    .allow
    ).expectEqual(r);
}

test "snapshot: Doc roundtrip with special chars" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const talloc = testing.allocator;

    const rules = [_]Rule{
        .{ .pattern = "path\\with\\backslashes", .effect = .allow },
        .{ .pattern = "has\"quotes", .effect = .deny, .tool = "tab\there" },
        .{ .pattern = "new\nline", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeDoc(talloc, doc);
    defer talloc.free(json);

    const parsed = try parseDoc(talloc, json);
    defer deinitDoc(talloc, parsed);

    const Fields = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        pat1: []const u8,
        eff1: Effect,
        tool1: []const u8,
        pat2: []const u8,
        eff2: Effect,
    };

    const pat0 = try snapEsc(talloc, parsed.rules[0].pattern);
    defer talloc.free(pat0);
    const pat1 = try snapEsc(talloc, parsed.rules[1].pattern);
    defer talloc.free(pat1);
    const tool1 = try snapEsc(talloc, parsed.rules[1].tool.?);
    defer talloc.free(tool1);
    const pat2 = try snapEsc(talloc, parsed.rules[2].pattern);
    defer talloc.free(pat2);

    const f = Fields{
        .version = parsed.version,
        .n_rules = parsed.rules.len,
        .pat0 = pat0,
        .eff0 = parsed.rules[0].effect,
        .pat1 = pat1,
        .eff1 = parsed.rules[1].effect,
        .tool1 = tool1,
        .pat2 = pat2,
        .eff2 = parsed.rules[2].effect,
    };

    try oh.snap(@src(),
        \\core.policy.test.snapshot: Doc roundtrip with special chars.Fields
        \\  .version: u16 = 1
        \\  .n_rules: usize = 3
        \\  .pat0: []const u8
        \\    "path\\with\\backslashes"
        \\  .eff0: core.policy.Effect
        \\    .allow
        \\  .pat1: []const u8
        \\    "has\"quotes"
        \\  .eff1: core.policy.Effect
        \\    .deny
        \\  .tool1: []const u8
        \\    "tab\there"
        \\  .pat2: []const u8
        \\    "new\nline"
        \\  .eff2: core.policy.Effect
        \\    .allow
    ).expectEqual(f);
}

test "snapshot: protected paths denied under allow-all" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };

    const Results = struct {
        audit_log: Effect,
        session: Effect,
        pz_config: Effect,
        pz_secrets: Effect,
        pz_auth: Effect,
    };

    const r = Results{
        .audit_log = evaluate(&rules, "app.audit.log", null),
        .session = evaluate(&rules, "data.session", null),
        .pz_config = evaluate(&rules, ".pz/config", null),
        .pz_secrets = evaluate(&rules, ".pz/secrets", null),
        .pz_auth = evaluate(&rules, ".pz/auth", null),
    };

    try oh.snap(@src(),
        \\core.policy.test.snapshot: protected paths denied under allow-all.Results
        \\  .audit_log: core.policy.Effect
        \\    .deny
        \\  .session: core.policy.Effect
        \\    .deny
        \\  .pz_config: core.policy.Effect
        \\    .deny
        \\  .pz_secrets: core.policy.Effect
        \\    .deny
        \\  .pz_auth: core.policy.Effect
        \\    .deny
    ).expectEqual(r);
}

// ── Property tests (zcheck) ────────────────────────────────────────────

test "property: matchGlob star matches anything" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.String }) bool {
            return matchGlob("*", args.s.slice());
        }
    }.prop, .{ .iterations = 500 });
}

test "property: matchGlob identity (literal self-match)" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            // Id is alphanumeric-only, no glob metacharacters
            const txt = args.s.slice();
            return matchGlob(txt, txt);
        }
    }.prop, .{ .iterations = 500 });
}

test "property: evaluate empty rules always denies" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { p: zc.FilePath }) bool {
            const rules: []const Rule = &.{};
            return evaluate(rules, args.p.slice(), null) == .deny;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: evaluate allow-all allows non-protected" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            // Id generates alphanumeric strings that won't match protected
            // patterns (*.audit.log, *.session, .pz/*)
            const path = args.s.slice();
            const rules = [_]Rule{
                .{ .pattern = "*", .effect = .allow },
            };
            return evaluate(&rules, path, null) == .allow;
        }
    }.prop, .{ .iterations = 500 });
}

test "property: evalEnv last-match-wins consistency" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { k: zc.Id, v: zc.String }) bool {
            const key = args.k.slice();
            const val = args.v.slice();

            // Two rules with same pattern, opposite effects — last wins
            const allow_last = [_]Rule{
                .{ .pattern = "*", .effect = .deny },
                .{ .pattern = "*", .effect = .allow },
            };
            const deny_last = [_]Rule{
                .{ .pattern = "*", .effect = .allow },
                .{ .pattern = "*", .effect = .deny },
            };

            const r1 = evalEnv(&allow_last, key, val);
            const r2 = evalEnv(&deny_last, key, val);
            return r1 == .allow and r2 == .deny;
        }
    }.prop, .{ .iterations = 500 });
}
