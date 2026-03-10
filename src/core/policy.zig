const std = @import("std");
const testing = std.testing;

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
