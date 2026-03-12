const std = @import("std");
const signing = @import("signing.zig");
const build_options = @import("build_options");
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

pub const Lock = struct {
    cfg: bool = false,
    env: bool = false,
    cli: bool = false,
    context: bool = false,
    system_prompt: bool = false,

    pub fn merge(a: Lock, b: Lock) Lock {
        return .{
            .cfg = a.cfg or b.cfg,
            .env = a.env or b.env,
            .cli = a.cli or b.cli,
            .context = a.context or b.context,
            .system_prompt = a.system_prompt or b.system_prompt,
        };
    }
};

pub const policy_rel_path = ".pz/policy.json";

pub const ApprovalBind = union(enum) {
    version: u16,
    hash: []const u8,

    pub fn eql(a: ApprovalBind, b: ApprovalBind) bool {
        return switch (a) {
            .version => |av| switch (b) {
                .version => |bv| av == bv,
                .hash => false,
            },
            .hash => |ah| switch (b) {
                .version => false,
                .hash => |bh| std.mem.eql(u8, ah, bh),
            },
        };
    }

    pub fn dupe(self: ApprovalBind, alloc: std.mem.Allocator) !ApprovalBind {
        return switch (self) {
            .version => |v| .{ .version = v },
            .hash => |txt| .{ .hash = try alloc.dupe(u8, txt) },
        };
    }

    pub fn deinit(self: ApprovalBind, alloc: std.mem.Allocator) void {
        switch (self) {
            .version => {},
            .hash => |txt| alloc.free(txt),
        }
    }
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
    ".pz",
    "AGENTS.md",
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
    if (isProtectedPath(path)) return .deny;
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

pub fn isProtectedPath(path: []const u8) bool {
    for (&protected) |pp| {
        if (matchPath(pp, path)) return true;
    }
    return false;
}

pub fn isBlockedNetAddr(addr: std.net.Address) bool {
    return switch (addr.any.family) {
        std.posix.AF.INET => isBlockedIp4(@as(*const [4]u8, @ptrCast(&addr.in.sa.addr)).*),
        std.posix.AF.INET6 => isBlockedIp6(addr.in6.sa.addr),
        else => true,
    };
}

pub fn isBlockedIp4(ip: [4]u8) bool {
    if (ip[0] == 0) return true;
    if (ip[0] == 10) return true;
    if (ip[0] == 127) return true;
    if (ip[0] == 169 and ip[1] == 254) return true;
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) return true;
    if (ip[0] == 192 and ip[1] == 168) return true;
    if (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) return true;
    if (ip[0] == 198 and (ip[1] == 18 or ip[1] == 19)) return true;
    if (ip[0] >= 224) return true;
    return false;
}

pub fn isBlockedIp6(ip: [16]u8) bool {
    const zero = [_]u8{0} ** 16;
    if (std.mem.eql(u8, ip[0..], zero[0..])) return true;
    if (std.mem.eql(u8, ip[0..15], zero[0..15]) and ip[15] == 1) return true;
    if ((ip[0] & 0xfe) == 0xfc) return true;
    if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) return true;
    if (ip[0] == 0xff) return true;
    if (std.mem.eql(u8, ip[0..10], zero[0..10]) and ip[10] == 0xff and ip[11] == 0xff) {
        return isBlockedIp4(ip[12..16].*);
    }
    return false;
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
    lock: Lock = .{},
};

pub const SignedDoc = struct {
    doc: Doc,
    pk: signing.PublicKey,
    sig: signing.Signature,
};

pub const Resolved = struct {
    doc: Doc,
    hash_hex: [64]u8,
    has_files: bool,

    pub fn bind(self: *const Resolved) ApprovalBind {
        return .{ .hash = self.hash_hex[0..] };
    }
};

fn trustedPolicyPk() !signing.PublicKey {
    return signing.PublicKey.parseHex(build_options.policy_pk_hex);
}

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
    var init_n: usize = 0;
    errdefer {
        for (rules[0..init_n]) |rule| {
            if (rule.pattern.len > 0) alloc.free(rule.pattern);
            if (rule.tool) |t| alloc.free(t);
        }
    }

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
        init_n += 1;
    }

    var lock = Lock{};
    if (root.object.get("lock")) |lock_val| {
        if (lock_val != .object) return error.UnexpectedToken;
        if (lock_val.object.get("config")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.cfg = v.bool;
        }
        if (lock_val.object.get("env")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.env = v.bool;
        }
        if (lock_val.object.get("cli")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.cli = v.bool;
        }
        if (lock_val.object.get("context")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.context = v.bool;
        }
        if (lock_val.object.get("system_prompt")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.system_prompt = v.bool;
        }
    }

    return .{ .version = ver, .rules = rules, .lock = lock };
}

pub fn parseSignedDoc(alloc: std.mem.Allocator, json: []const u8) !SignedDoc {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.UnexpectedToken;

    const sig_obj = root.object.get("signature") orelse return error.MissingSignature;
    if (sig_obj != .object) return error.UnexpectedToken;

    const alg = sig_obj.object.get("alg") orelse return error.MissingSignature;
    if (alg != .string) return error.UnexpectedToken;
    if (!std.mem.eql(u8, alg.string, "ed25519")) return error.UnsupportedSignatureAlg;

    const key = sig_obj.object.get("key") orelse return error.MissingSignature;
    if (key != .string) return error.UnexpectedToken;
    const sig = sig_obj.object.get("sig") orelse return error.MissingSignature;
    if (sig != .string) return error.UnexpectedToken;

    const doc = try parseDoc(alloc, json);
    errdefer deinitDoc(alloc, doc);

    const payload = try encodeDoc(alloc, doc);
    defer alloc.free(payload);

    const embedded_pk = try signing.PublicKey.parseText(key.string);
    const pk = try trustedPolicyPk();
    if (!std.mem.eql(u8, embedded_pk.raw[0..], pk.raw[0..])) return error.UntrustedSigner;
    const sig_det = try signing.Signature.parseHex(sig.string);
    _ = try signing.verifyDetached(payload, sig_det, pk);

    return .{
        .doc = doc,
        .pk = pk,
        .sig = sig_det,
    };
}

/// Serialize a policy document to JSON.
pub fn encodeDoc(alloc: std.mem.Allocator, doc: Doc) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    try w.writeAll("{\"version\":");
    try w.print("{d}", .{doc.version});
    if (doc.lock.cfg or doc.lock.env or doc.lock.cli or doc.lock.context or doc.lock.system_prompt) {
        try w.writeAll(",\"lock\":{");
        var first = true;
        if (doc.lock.cfg) {
            try w.writeAll("\"config\":true");
            first = false;
        }
        if (doc.lock.env) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"env\":true");
            first = false;
        }
        if (doc.lock.cli) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"cli\":true");
            first = false;
        }
        if (doc.lock.context) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"context\":true");
            first = false;
        }
        if (doc.lock.system_prompt) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"system_prompt\":true");
        }
        try w.writeByte('}');
    }
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

pub fn encodeSignedDoc(alloc: std.mem.Allocator, doc: Doc, kp: signing.KeyPair) ![]u8 {
    const payload = try encodeDoc(alloc, doc);
    defer alloc.free(payload);

    const sig = try kp.sign(payload);
    const pk = kp.publicKey();
    const pk_hex = std.fmt.bytesToHex(pk.raw, .lower);
    const sig_hex = std.fmt.bytesToHex(sig.raw, .lower);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);
    const w = buf.writer(alloc);

    try w.writeAll(payload[0 .. payload.len - 1]);
    try w.writeAll(",\"signature\":{\"alg\":\"ed25519\",\"key\":\"");
    try w.print("{s}", .{&pk_hex});
    try w.writeAll("\",\"sig\":\"");
    try w.print("{s}", .{&sig_hex});
    try w.writeAll("\"}}");
    return try buf.toOwnedSlice(alloc);
}

pub fn hashDoc(alloc: std.mem.Allocator, doc: Doc) ![64]u8 {
    const raw = try encodeDoc(alloc, doc);
    defer alloc.free(raw);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn loadResolved(alloc: std.mem.Allocator, cwd: ?[]const u8, home: ?[]const u8) anyerror!Resolved {
    var docs: [2]?SignedDoc = .{ null, null };
    var doc_n: usize = 0;
    errdefer {
        for (docs[0..doc_n]) |maybe_doc| {
            deinitSignedDoc(alloc, maybe_doc.?);
        }
    }

    if (home) |home_path| {
        const path = try std.fs.path.join(alloc, &.{ home_path, policy_rel_path });
        defer alloc.free(path);
        if (try loadSignedDocFile(alloc, path)) |doc| {
            docs[doc_n] = doc;
            doc_n += 1;
        }
    }
    if (cwd) |cwd_path| {
        const path = try std.fs.path.join(alloc, &.{ cwd_path, policy_rel_path });
        defer alloc.free(path);
        if (try loadSignedDocFile(alloc, path)) |doc| {
            docs[doc_n] = doc;
            doc_n += 1;
        }
    }

    var total_rules: usize = 0;
    var lock = Lock{};
    for (docs[0..doc_n]) |maybe_doc| {
        const doc = maybe_doc.?;
        total_rules += doc.doc.rules.len;
        lock = lock.merge(doc.doc.lock);
    }

    const rules = try alloc.alloc(Rule, total_rules);
    var init_n: usize = 0;
    errdefer {
        for (rules[0..init_n]) |rule| {
            alloc.free(rule.pattern);
            if (rule.tool) |tool| alloc.free(tool);
        }
        alloc.free(rules);
    }

    for (docs[0..doc_n]) |maybe_doc| {
        const doc = maybe_doc.?;
        for (doc.doc.rules) |rule| {
            rules[init_n] = try dupRule(alloc, rule);
            init_n += 1;
        }
    }

    const merged = Doc{
        .version = ver_current,
        .rules = rules,
        .lock = lock,
    };
    errdefer deinitDoc(alloc, merged);

    const hash_hex = try hashDoc(alloc, merged);

    for (docs[0..doc_n]) |maybe_doc| {
        deinitSignedDoc(alloc, maybe_doc.?);
    }

    return .{
        .doc = merged,
        .hash_hex = hash_hex,
        .has_files = doc_n != 0,
    };
}

pub fn loadLock(alloc: std.mem.Allocator, cwd: ?[]const u8, home: ?[]const u8) anyerror!Lock {
    const resolved = try loadResolved(alloc, cwd, home);
    defer deinitResolved(alloc, resolved);
    return resolved.doc.lock;
}

fn loadSignedDocFile(alloc: std.mem.Allocator, path: []const u8) anyerror!?SignedDoc {
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return error.InvalidPolicy,
    };
    defer file.close();

    const raw = try file.readToEndAlloc(alloc, 256 * 1024);
    defer alloc.free(raw);

    return parseSignedDoc(alloc, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
}

fn dupRule(alloc: std.mem.Allocator, rule: Rule) !Rule {
    return .{
        .pattern = try alloc.dupe(u8, rule.pattern),
        .effect = rule.effect,
        .tool = if (rule.tool) |tool| try alloc.dupe(u8, tool) else null,
    };
}

pub fn loadApprovalBind(alloc: std.mem.Allocator, cwd: ?[]const u8, home: ?[]const u8) anyerror!ApprovalBind {
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var saw = false;

    if (home) |home_path| {
        const path = try std.fs.path.join(alloc, &.{ home_path, policy_rel_path });
        defer alloc.free(path);
        saw = try hashPolicyFile(alloc, &sha, "home", path) or saw;
    }
    if (cwd) |cwd_path| {
        const path = try std.fs.path.join(alloc, &.{ cwd_path, policy_rel_path });
        defer alloc.free(path);
        saw = try hashPolicyFile(alloc, &sha, "cwd", path) or saw;
    }
    if (!saw) return .{ .version = ver_current };

    var dig: [32]u8 = undefined;
    sha.final(&dig);
    const hex_txt = std.fmt.bytesToHex(dig, .lower);
    const hex = try alloc.dupe(u8, &hex_txt);
    return .{ .hash = hex };
}

fn hashPolicyFile(
    alloc: std.mem.Allocator,
    sha: *std.crypto.hash.sha2.Sha256,
    tag: []const u8,
    path: []const u8,
) anyerror!bool {
    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return error.InvalidPolicy,
    };
    defer file.close();

    const raw = try file.readToEndAlloc(alloc, 256 * 1024);
    defer alloc.free(raw);

    const doc = parseSignedDoc(alloc, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
    defer deinitSignedDoc(alloc, doc);

    const payload = try encodeDoc(alloc, doc.doc);
    defer alloc.free(payload);

    sha.update(tag);
    sha.update("\x00");
    sha.update(payload);
    sha.update("\x00");
    return true;
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

pub fn deinitSignedDoc(alloc: std.mem.Allocator, doc: SignedDoc) void {
    deinitDoc(alloc, doc.doc);
}

pub fn deinitResolved(alloc: std.mem.Allocator, resolved: Resolved) void {
    deinitDoc(alloc, resolved.doc);
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
    try testing.expectEqual(Effect.deny, evaluate(&rules, ".pz/settings.json", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "/tmp/.pz/sessions/abc.jsonl", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "AGENTS.md", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "/tmp/AGENTS.md", null));
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
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const json = "{\"version\":1,\"rules\":[{\"pattern\":\"*.zig\",\"effect\":\"allow\"},{\"pattern\":\"*.secret\",\"effect\":\"deny\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);

    const Snap = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        pat1: []const u8,
        eff1: Effect,
    };

    try oh.snap(@src(),
        \\core.policy.test.parseDoc valid v1.Snap
        \\  .version: u16 = 1
        \\  .n_rules: usize = 2
        \\  .pat0: []const u8
        \\    "*.zig"
        \\  .eff0: core.policy.Effect
        \\    .allow
        \\  .pat1: []const u8
        \\    "*.secret"
        \\  .eff1: core.policy.Effect
        \\    .deny
    ).expectEqual(Snap{
        .version = doc.version,
        .n_rules = doc.rules.len,
        .pat0 = doc.rules[0].pattern,
        .eff0 = doc.rules[0].effect,
        .pat1 = doc.rules[1].pattern,
        .eff1 = doc.rules[1].effect,
    });
}

test "parseDoc missing version defaults to v1" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const json = "{\"rules\":[{\"pattern\":\"*\",\"effect\":\"allow\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);

    const Snap = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
    };

    try oh.snap(@src(),
        \\core.policy.test.parseDoc missing version defaults to v1.Snap
        \\  .version: u16 = 1
        \\  .n_rules: usize = 1
        \\  .pat0: []const u8
        \\    "*"
        \\  .eff0: core.policy.Effect
        \\    .allow
    ).expectEqual(Snap{
        .version = doc.version,
        .n_rules = doc.rules.len,
        .pat0 = doc.rules[0].pattern,
        .eff0 = doc.rules[0].effect,
    });
}

test "parseDoc rejects unsupported version" {
    const json = "{\"version\":99,\"rules\":[]}";
    try testing.expectError(error.UnsupportedPolicyVersion, parseDoc(testing.allocator, json));
}

test "parseDoc roundtrip" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .deny, .tool = "bash" },
        .{ .pattern = "*", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);

    const doc2 = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc2);

    const Snap = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        tool0: []const u8,
        pat1: []const u8,
        eff1: Effect,
        tool1: []const u8,
    };

    try oh.snap(@src(),
        \\core.policy.test.parseDoc roundtrip.Snap
        \\  .version: u16 = 1
        \\  .n_rules: usize = 2
        \\  .pat0: []const u8
        \\    "*.zig"
        \\  .eff0: core.policy.Effect
        \\    .deny
        \\  .tool0: []const u8
        \\    "bash"
        \\  .pat1: []const u8
        \\    "*"
        \\  .eff1: core.policy.Effect
        \\    .allow
        \\  .tool1: []const u8
        \\    ""
    ).expectEqual(Snap{
        .version = doc2.version,
        .n_rules = doc2.rules.len,
        .pat0 = doc2.rules[0].pattern,
        .eff0 = doc2.rules[0].effect,
        .tool0 = doc2.rules[0].tool.?,
        .pat1 = doc2.rules[1].pattern,
        .eff1 = doc2.rules[1].effect,
        .tool1 = doc2.rules[1].tool orelse "",
    });
}

test "parseDoc with tool filter" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const json = "{\"version\":1,\"rules\":[{\"pattern\":\"*\",\"effect\":\"deny\",\"tool\":\"rm\"}]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);

    const Snap = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        tool0: []const u8,
    };

    try oh.snap(@src(),
        \\core.policy.test.parseDoc with tool filter.Snap
        \\  .version: u16 = 1
        \\  .n_rules: usize = 1
        \\  .pat0: []const u8
        \\    "*"
        \\  .eff0: core.policy.Effect
        \\    .deny
        \\  .tool0: []const u8
        \\    "rm"
    ).expectEqual(Snap{
        .version = doc.version,
        .n_rules = doc.rules.len,
        .pat0 = doc.rules[0].pattern,
        .eff0 = doc.rules[0].effect,
        .tool0 = doc.rules[0].tool.?,
    });
}

test "signed policy bundle verifies" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const seed = try signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const kp = try signing.KeyPair.fromSeed(seed);
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .allow },
        .{ .pattern = "*.secret", .effect = .deny, .tool = "read" },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeSignedDoc(testing.allocator, doc, kp);
    defer testing.allocator.free(json);

    const signed = try parseSignedDoc(testing.allocator, json);
    defer deinitSignedDoc(testing.allocator, signed);

    const pk_hex = std.fmt.bytesToHex(signed.pk.raw, .lower);
    const sig_hex = std.fmt.bytesToHex(signed.sig.raw, .lower);

    const Snap = struct {
        version: u16,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        pat1: []const u8,
        eff1: Effect,
        tool1: []const u8,
        pk_hex: []const u8,
        sig_hex: []const u8,
    };

    try oh.snap(@src(),
        \\core.policy.test.signed policy bundle verifies.Snap
        \\  .version: u16 = 1
        \\  .n_rules: usize = 2
        \\  .pat0: []const u8
        \\    "*.zig"
        \\  .eff0: core.policy.Effect
        \\    .allow
        \\  .pat1: []const u8
        \\    "*.secret"
        \\  .eff1: core.policy.Effect
        \\    .deny
        \\  .tool1: []const u8
        \\    "read"
        \\  .pk_hex: []const u8
        \\    "2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083"
        \\  .sig_hex: []const u8
        \\    "f12613ffcdfb4fdd333488591e9689080967f42ea950d2bc798553dae63a7d1fac31ae727640b94483e41e2ee045fb53161d285dafed2947fadd2dac380da60e"
    ).expectEqual(Snap{
        .version = signed.doc.version,
        .n_rules = signed.doc.rules.len,
        .pat0 = signed.doc.rules[0].pattern,
        .eff0 = signed.doc.rules[0].effect,
        .pat1 = signed.doc.rules[1].pattern,
        .eff1 = signed.doc.rules[1].effect,
        .tool1 = signed.doc.rules[1].tool.?,
        .pk_hex = pk_hex[0..],
        .sig_hex = sig_hex[0..],
    });
}

test "signed policy bundle rejects unsigned doc" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);

    try testing.expectError(error.MissingSignature, parseSignedDoc(testing.allocator, json));
}

test "signed policy bundle rejects tampering" {
    const seed = try signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const kp = try signing.KeyPair.fromSeed(seed);
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeSignedDoc(testing.allocator, doc, kp);
    defer testing.allocator.free(json);

    const mut = try testing.allocator.dupe(u8, json);
    defer testing.allocator.free(mut);
    const needle = "*.zig";
    const idx = std.mem.indexOf(u8, mut, needle) orelse return error.TestUnexpectedResult;
    mut[idx + 3] = 'a';

    try testing.expectError(error.SigMismatch, parseSignedDoc(testing.allocator, mut));
}

test "signed policy bundle rejects untrusted signer" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const seed = try signing.Seed.parseHex("0000000000000000000000000000000000000000000000000000000000000001");
    const kp = try signing.KeyPair.fromSeed(seed);
    const json = try encodeSignedDoc(testing.allocator, doc, kp);
    defer testing.allocator.free(json);

    try testing.expectError(error.UntrustedSigner, parseSignedDoc(testing.allocator, json));
}

fn testKeyPair() !signing.KeyPair {
    const seed = try signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    return signing.KeyPair.fromSeed(seed);
}

test "loadApprovalBind falls back to version without signed policy" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const bind = try loadApprovalBind(testing.allocator, null, null);
    defer bind.deinit(testing.allocator);

    const Snap = struct {
        kind: []const u8,
        version: u16,
        hash_hex: []const u8,
    };

    try oh.snap(@src(),
        \\core.policy.test.loadApprovalBind falls back to version without signed policy.Snap
        \\  .kind: []const u8
        \\    "version"
        \\  .version: u16 = 1
        \\  .hash_hex: []const u8
        \\    ""
    ).expectEqual(Snap{
        .kind = switch (bind) {
            .version => "version",
            .hash => "hash",
        },
        .version = switch (bind) {
            .version => |v| v,
            .hash => 0,
        },
        .hash_hex = switch (bind) {
            .version => "",
            .hash => |v| v,
        },
    });
}

test "loadApprovalBind hashes verified home and cwd policy docs" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("repo/.pz");
    const home = try tmp.dir.realpathAlloc(testing.allocator, "home");
    defer testing.allocator.free(home);
    const repo = try tmp.dir.realpathAlloc(testing.allocator, "repo");
    defer testing.allocator.free(repo);

    const kp = try testKeyPair();

    const home_rules = [_]Rule{.{ .pattern = "*.zig", .effect = .allow }};
    const repo_rules_a = [_]Rule{.{ .pattern = "*.md", .effect = .deny }};
    const home_raw = try encodeSignedDoc(testing.allocator, .{ .rules = &home_rules }, kp);
    defer testing.allocator.free(home_raw);
    const repo_raw_a = try encodeSignedDoc(testing.allocator, .{ .rules = &repo_rules_a }, kp);
    defer testing.allocator.free(repo_raw_a);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pz/policy.json", .data = home_raw });
    try tmp.dir.writeFile(.{ .sub_path = "repo/.pz/policy.json", .data = repo_raw_a });

    const bind_a = try loadApprovalBind(testing.allocator, repo, home);
    defer bind_a.deinit(testing.allocator);
    try testing.expect(bind_a == .hash);
    try testing.expectEqual(@as(usize, 64), bind_a.hash.len);

    const repo_rules_b = [_]Rule{.{ .pattern = "*.txt", .effect = .deny }};
    const repo_raw_b = try encodeSignedDoc(testing.allocator, .{ .rules = &repo_rules_b }, kp);
    defer testing.allocator.free(repo_raw_b);
    try tmp.dir.writeFile(.{ .sub_path = "repo/.pz/policy.json", .data = repo_raw_b });

    const bind_b = try loadApprovalBind(testing.allocator, repo, home);
    defer bind_b.deinit(testing.allocator);

    const Snap = struct {
        kind_a: []const u8,
        hash_a: []const u8,
        kind_b: []const u8,
        hash_b: []const u8,
        changed: bool,
    };

    try oh.snap(@src(),
        \\core.policy.test.loadApprovalBind hashes verified home and cwd policy docs.Snap
        \\  .kind_a: []const u8
        \\    "hash"
        \\  .hash_a: []const u8
        \\    "d987061230d7a458ffa2a621077af11b7454192d8fea50c9d747bac2e10c4b11"
        \\  .kind_b: []const u8
        \\    "hash"
        \\  .hash_b: []const u8
        \\    "ef03b986f298e27e9c3e1e6d05f11f63081b0db9ff9804d2c69fc495c45262dc"
        \\  .changed: bool = true
    ).expectEqual(Snap{
        .kind_a = switch (bind_a) {
            .version => "version",
            .hash => "hash",
        },
        .hash_a = switch (bind_a) {
            .version => "",
            .hash => |v| v,
        },
        .kind_b = switch (bind_b) {
            .version => "version",
            .hash => "hash",
        },
        .hash_b = switch (bind_b) {
            .version => "",
            .hash => |v| v,
        },
        .changed = !bind_a.eql(bind_b),
    });
}

test "loadResolved merges verified bundles and hashes effective doc" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("cwd/.pz");

    const kp = try testKeyPair();
    const home_raw = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{
            .{ .pattern = "runtime/cmd/*", .effect = .allow },
        },
        .lock = .{ .cfg = true },
    }, kp);
    defer testing.allocator.free(home_raw);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pz/policy.json", .data = home_raw });

    const cwd_raw = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{
            .{ .pattern = "runtime/subagent/*", .effect = .deny },
        },
        .lock = .{ .cli = true },
    }, kp);
    defer testing.allocator.free(cwd_raw);
    try tmp.dir.writeFile(.{ .sub_path = "cwd/.pz/policy.json", .data = cwd_raw });

    const home_abs = try tmp.dir.realpathAlloc(testing.allocator, "home");
    defer testing.allocator.free(home_abs);
    const cwd_abs = try tmp.dir.realpathAlloc(testing.allocator, "cwd");
    defer testing.allocator.free(cwd_abs);

    const resolved = try loadResolved(testing.allocator, cwd_abs, home_abs);
    defer deinitResolved(testing.allocator, resolved);

    const Snap = struct {
        has_files: bool,
        hash_hex: []const u8,
        n_rules: usize,
        pat0: []const u8,
        eff0: Effect,
        pat1: []const u8,
        eff1: Effect,
        lock_cfg: bool,
        lock_cli: bool,
    };

    try oh.snap(@src(),
        \\core.policy.test.loadResolved merges verified bundles and hashes effective doc.Snap
        \\  .has_files: bool = true
        \\  .hash_hex: []const u8
        \\    "d23f10456d00f7df571bf9251b5a024d8a8cffba0c30a4829ef011fe2d6df86b"
        \\  .n_rules: usize = 2
        \\  .pat0: []const u8
        \\    "runtime/cmd/*"
        \\  .eff0: core.policy.Effect
        \\    .allow
        \\  .pat1: []const u8
        \\    "runtime/subagent/*"
        \\  .eff1: core.policy.Effect
        \\    .deny
        \\  .lock_cfg: bool = true
        \\  .lock_cli: bool = true
    ).expectEqual(Snap{
        .has_files = resolved.has_files,
        .hash_hex = resolved.hash_hex[0..],
        .n_rules = resolved.doc.rules.len,
        .pat0 = resolved.doc.rules[0].pattern,
        .eff0 = resolved.doc.rules[0].effect,
        .pat1 = resolved.doc.rules[1].pattern,
        .eff1 = resolved.doc.rules[1].effect,
        .lock_cfg = resolved.doc.lock.cfg,
        .lock_cli = resolved.doc.lock.cli,
    });
}

test "loadResolved returns stable empty effective hash" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const resolved = try loadResolved(testing.allocator, null, null);
    defer deinitResolved(testing.allocator, resolved);

    const Snap = struct {
        has_files: bool,
        n_rules: usize,
        lock_cfg: bool,
        lock_env: bool,
        lock_cli: bool,
        lock_context: bool,
        lock_system_prompt: bool,
        hash_hex: []const u8,
    };

    try oh.snap(@src(),
        \\core.policy.test.loadResolved returns stable empty effective hash.Snap
        \\  .has_files: bool = false
        \\  .n_rules: usize = 0
        \\  .lock_cfg: bool = false
        \\  .lock_env: bool = false
        \\  .lock_cli: bool = false
        \\  .lock_context: bool = false
        \\  .lock_system_prompt: bool = false
        \\  .hash_hex: []const u8
        \\    "6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103"
    ).expectEqual(Snap{
        .has_files = resolved.has_files,
        .n_rules = resolved.doc.rules.len,
        .lock_cfg = resolved.doc.lock.cfg,
        .lock_env = resolved.doc.lock.env,
        .lock_cli = resolved.doc.lock.cli,
        .lock_context = resolved.doc.lock.context,
        .lock_system_prompt = resolved.doc.lock.system_prompt,
        .hash_hex = resolved.hash_hex[0..],
    });
}

const empty_eff_hash = "6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103";
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
        pz_settings: Effect,
        pz_session_file: Effect,
        agents: Effect,
    };

    const r = Results{
        .audit_log = evaluate(&rules, "app.audit.log", null),
        .session = evaluate(&rules, "data.session", null),
        .pz_settings = evaluate(&rules, ".pz/settings.json", null),
        .pz_session_file = evaluate(&rules, "/tmp/.pz/sessions/abc.jsonl", null),
        .agents = evaluate(&rules, "/tmp/AGENTS.md", null),
    };

    try oh.snap(@src(),
        \\core.policy.test.snapshot: protected paths denied under allow-all.Results
        \\  .audit_log: core.policy.Effect
        \\    .deny
        \\  .session: core.policy.Effect
        \\    .deny
        \\  .pz_settings: core.policy.Effect
        \\    .deny
        \\  .pz_session_file: core.policy.Effect
        \\    .deny
        \\  .agents: core.policy.Effect
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
    }.prop, .{ .iterations = 2000 });
}

test "property: matchGlob identity (literal self-match)" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { s: zc.Id }) bool {
            // Id is alphanumeric-only, no glob metacharacters
            const txt = args.s.slice();
            return matchGlob(txt, txt);
        }
    }.prop, .{ .iterations = 2000 });
}

test "property: evaluate empty rules always denies" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { p: zc.FilePath }) bool {
            const rules: []const Rule = &.{};
            return evaluate(rules, args.p.slice(), null) == .deny;
        }
    }.prop, .{ .iterations = 2000 });
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
    }.prop, .{ .iterations = 2000 });
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
    }.prop, .{ .iterations = 2000 });
}

test "property: hashDoc is stable for identical docs" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct {
            a: zc.Id,
            b: zc.Id,
            allow_a: bool,
            allow_b: bool,
            lock_cfg: bool,
            lock_ctx: bool,
        }) bool {
            const rules = [_]Rule{
                .{ .pattern = args.a.slice(), .effect = if (args.allow_a) .allow else .deny },
                .{ .pattern = args.b.slice(), .effect = if (args.allow_b) .allow else .deny, .tool = "bash" },
            };
            const doc: Doc = .{
                .rules = &rules,
                .lock = .{
                    .cfg = args.lock_cfg,
                    .context = args.lock_ctx,
                },
            };
            const h1 = hashDoc(testing.allocator, doc) catch return false;
            const h2 = hashDoc(testing.allocator, doc) catch return false;
            return std.mem.eql(u8, h1[0..], h2[0..]);
        }
    }.prop, .{ .iterations = 1000 });
}

test "property: empty effective hash and bind stay stable" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(_: struct { n: u8 }) bool {
            const a = loadResolved(testing.allocator, null, null) catch return false;
            defer deinitResolved(testing.allocator, a);
            const b = loadResolved(testing.allocator, null, null) catch return false;
            defer deinitResolved(testing.allocator, b);

            if (a.has_files or b.has_files) return false;
            if (!std.mem.eql(u8, a.hash_hex[0..], empty_eff_hash)) return false;
            if (!std.mem.eql(u8, b.hash_hex[0..], empty_eff_hash)) return false;
            return a.bind().eql(b.bind());
        }
    }.prop, .{ .iterations = 256 });
}

test "property: evaluate runtime tool rules honors exact tool filters" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { tool_name: zc.Id, other: zc.Id }) bool {
            const tool_name = args.tool_name.slice();
            const other = if (std.mem.eql(u8, tool_name, args.other.slice())) "other-tool" else args.other.slice();

            const path = std.fmt.allocPrint(testing.allocator, "runtime/tool/{s}", .{tool_name}) catch return false;
            defer testing.allocator.free(path);

            const rules = [_]Rule{
                .{ .pattern = path, .effect = .deny, .tool = tool_name },
                .{ .pattern = "*", .effect = .allow },
            };

            if (evaluate(&rules, path, tool_name) != .deny) return false;
            if (evaluate(&rules, path, other) != .allow) return false;
            return evaluate(&rules, "runtime/tool/other-tool", tool_name) == .allow;
        }
    }.prop, .{ .iterations = 1500 });
}

test "network policy blocks local and private ranges" {
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp4(.{ 10, 1, 2, 3 }, 443)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp4(.{ 172, 16, 1, 9 }, 443)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp4(.{ 192, 168, 4, 5 }, 443)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp4(.{ 169, 254, 2, 9 }, 443)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp6(.{0} ** 15 ++ .{1}, 443, 0, 0)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp6(.{ 0xfe, 0x80 } ++ .{0} ** 14, 443, 0, 0)));
    try testing.expect(isBlockedNetAddr(std.net.Address.initIp6(.{ 0xfc, 0 } ++ .{0} ** 14, 443, 0, 0)));
}

test "network policy allows public addresses" {
    try testing.expect(!isBlockedNetAddr(std.net.Address.initIp4(.{ 34, 117, 59, 81 }, 443)));
    try testing.expect(!isBlockedNetAddr(std.net.Address.initIp6(.{
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0,    0,
        0,    0,    0,    0,    0,    0,    0x88, 0x88,
    }, 443, 0, 0)));
}

test "ApprovalBind hash dupe preserves payload" {
    const bind = ApprovalBind{ .hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" };
    const duped = try bind.dupe(testing.allocator);
    defer duped.deinit(testing.allocator);

    try testing.expect(bind.eql(duped));
}

test "ApprovalBind version and hash are distinct" {
    const ver = ApprovalBind{ .version = 1 };
    const ver_same = ApprovalBind{ .version = 7 };

    try testing.expect(!ver.eql(.{ .hash = "1" }));
    try testing.expect(ver_same.eql(.{ .version = 7 }));
}
