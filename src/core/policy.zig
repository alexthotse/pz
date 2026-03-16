//! Policy engine: path-pattern allow/deny rules with signed locks.
const std = @import("std");
const signing = @import("signing.zig");
const build_options = @import("build_options");
const testing = std.testing;

pub const ver_current: u16 = 1;

pub const Effect = enum {
    allow,
    deny,
};

/// Session persistence policy for headless modes (print/json).
/// Headless modes default to `.off`; interactive modes (tui/rpc) to `.on`.
/// Enterprise policy can force `.off` to disable all durable writes.
pub const SessionPersist = enum {
    off,
    on,

    /// Returns the default persistence policy for a given output mode.
    /// Headless modes (print, json) disable durable session writes by
    /// default -- the caller must opt in via explicit session selection
    /// (--continue, --resume, or a session ID).
    pub fn forMode(mode: anytype) SessionPersist {
        return switch (mode) {
            .print, .json => .off,
            .tui, .rpc => .on,
        };
    }

    /// Apply enterprise policy override. If enterprise policy disables
    /// durable writes, returns `.off` regardless of the current value.
    pub fn withEnterprise(self: SessionPersist, lock: Lock) SessionPersist {
        // Enterprise config lock forces persistence off (no durable state).
        if (lock.cfg) return .off;
        return self;
    }
};

pub const Rule = struct {
    pattern: []const u8,
    effect: Effect,
    tool: ?[]const u8 = null,
    kind: ?[]const u8 = null,
};

pub const Lock = struct {
    cfg: bool = false,
    env: bool = false,
    cli: bool = false,
    context: bool = false,
    auth: bool = false,
    system_prompt: bool = false,

    pub fn merge(a: Lock, b: Lock) Lock {
        return .{
            .cfg = a.cfg or b.cfg,
            .env = a.env or b.env,
            .cli = a.cli or b.cli,
            .context = a.context or b.context,
            .auth = a.auth or b.auth,
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
                .hash => |bh| signing.ctEql(ah, bh),
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

    pub fn evalKind(self: Policy, path: []const u8, tool: ?[]const u8, kind: ?[]const u8) Effect {
        return evaluateKind(self.rules, path, tool, kind);
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
    return evaluateKind(rules, path, tool, null);
}

/// Like evaluate, but also checks the `kind` filter on rules.
pub fn evaluateKind(rules: []const Rule, path: []const u8, tool: ?[]const u8, kind: ?[]const u8) Effect {
    // Self-protection override
    if (isProtectedPath(path)) return .deny;
    for (rules) |r| {
        // Tool filter: skip rule if tool doesn't match
        if (r.tool) |rt| {
            if (tool == null) continue;
            if (!std.mem.eql(u8, rt, tool.?)) continue;
        }
        // Kind filter: skip rule if kind doesn't match
        if (r.kind) |rk| {
            if (kind == null) continue;
            if (!std.mem.eql(u8, rk, kind.?)) continue;
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

/// Egress policy for web tool: endpoint allowlists, deadlines, proxy.
pub const EgressPolicy = struct {
    rules: []const Rule = &.{},
    /// Per-request connect deadline in ms. 0 = use default (10_000).
    connect_deadline_ms: u32 = 0,
    /// Per-request total deadline in ms. 0 = use default (30_000).
    total_deadline_ms: u32 = 0,
    /// Policy-bound HTTPS proxy URL. null = direct.
    proxy_url: ?[]const u8 = null,

    pub const default_connect_ms: u32 = 10_000;
    pub const default_total_ms: u32 = 30_000;
    pub const max_connect_ms: u32 = 30_000;
    pub const max_total_ms: u32 = 120_000;

    pub fn connectMs(self: EgressPolicy) u32 {
        const raw = if (self.connect_deadline_ms == 0) default_connect_ms else self.connect_deadline_ms;
        return @min(raw, max_connect_ms);
    }

    pub fn totalMs(self: EgressPolicy) u32 {
        const raw = if (self.total_deadline_ms == 0) default_total_ms else self.total_deadline_ms;
        return @min(raw, max_total_ms);
    }

    pub fn policy(self: EgressPolicy) Policy {
        return .{ .rules = self.rules };
    }

    /// Validate that a proxy URL is well-formed and policy-allowed.
    pub fn validatedProxy(self: EgressPolicy) error{ UnsupportedScheme, MissingHost, HostDenied }!?[]const u8 {
        const url = self.proxy_url orelse return null;
        // Proxy must be http or https scheme.
        if (!startsWith(url, "http://") and !startsWith(url, "https://")) return error.UnsupportedScheme;
        // Extract host from proxy URL for policy check.
        const after_scheme = if (startsWith(url, "https://")) url[8..] else url[7..];
        const host_end = std.mem.indexOfAny(u8, after_scheme, ":/") orelse after_scheme.len;
        if (host_end == 0) return error.MissingHost;
        const host = after_scheme[0..host_end];
        // Proxy host must be allowed by egress rules.
        var path_buf: [320]u8 = undefined;
        const prefix = "runtime/web/";
        if (prefix.len + host.len > path_buf.len) return error.HostDenied;
        @memcpy(path_buf[0..prefix.len], prefix);
        for (host, 0..) |c, i| path_buf[prefix.len + i] = std.ascii.toLower(c);
        if (evaluate(self.rules, path_buf[0 .. prefix.len + host.len], "web") != .allow) {
            return error.HostDenied;
        }
        return url;
    }

    fn startsWith(hay: []const u8, needle: []const u8) bool {
        return hay.len >= needle.len and std.mem.eql(u8, hay[0..needle.len], needle);
    }
};

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
    ca_file: ?[]const u8 = null,
    lock: Lock = .{},
    /// Monotonically increasing — reject if lower than last-seen.
    generation: u64 = 0,
    /// Unix timestamp after which the policy is expired. null = no expiry.
    not_after: ?i64 = null,
    release_url: ?[]const u8 = null,
};

pub const SignedDoc = struct {
    doc: Doc,
    pk: signing.PublicKey,
    sig: signing.Signature,
};

/// Tracks last-seen policy generation for rollback detection.
/// Stored in `.pz/policy-state.json`.
pub const GenerationState = struct {
    const state_rel = ".pz/policy-state.json";

    pub fn load(alloc: std.mem.Allocator) !u64 {
        const home = std.posix.getenv("HOME") orelse return error.NoHome;
        const path = try std.fs.path.join(alloc, &.{ home, state_rel });
        defer alloc.free(path);
        const file = std.fs.openFileAbsolute(path, .{}) catch return 0;
        defer file.close();
        const raw = try file.readToEndAlloc(alloc, 4096);
        defer alloc.free(raw);
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, raw, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return 0;
        const gen_val = parsed.value.object.get("generation") orelse return 0;
        return switch (gen_val) {
            .integer => |i| if (i >= 0) @intCast(i) else 0,
            else => 0,
        };
    }

    pub fn store(alloc: std.mem.Allocator, gen: u64) !void {
        const home = std.posix.getenv("HOME") orelse return error.NoHome;
        const dir_path = try std.fs.path.join(alloc, &.{ home, ".pz" });
        defer alloc.free(dir_path);
        std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const path = try std.fs.path.join(alloc, &.{ home, state_rel });
        defer alloc.free(path);
        var buf: [64]u8 = undefined;
        const payload = std.fmt.bufPrint(&buf, "{{\"generation\":{d}}}", .{gen}) catch return error.InvalidPolicy;
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(payload);
    }

    /// Load from an explicit path (for testing without HOME).
    pub fn loadFrom(alloc: std.mem.Allocator, path: []const u8) !u64 {
        const file = std.fs.openFileAbsolute(path, .{}) catch return 0;
        defer file.close();
        const raw = try file.readToEndAlloc(alloc, 4096);
        defer alloc.free(raw);
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, raw, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return 0;
        const gen_val = parsed.value.object.get("generation") orelse return 0;
        return switch (gen_val) {
            .integer => |i| if (i >= 0) @intCast(i) else 0,
            else => 0,
        };
    }

    /// Store to an explicit path (for testing without HOME).
    pub fn storeTo(path: []const u8, gen: u64) !void {
        var buf: [64]u8 = undefined;
        const payload = std.fmt.bufPrint(&buf, "{{\"generation\":{d}}}", .{gen}) catch return error.InvalidPolicy;
        const file = try std.fs.createFileAbsolute(path, .{});
        defer file.close();
        try file.writeAll(payload);
    }
};

pub const Resolved = struct {
    doc: Doc,
    hash_hex: [64]u8,
    has_files: bool,
    locked: bool,

    pub fn bind(self: *const Resolved) ApprovalBind {
        return .{ .hash = self.hash_hex[0..] };
    }
};

fn trustedPolicyPk() !signing.PublicKey {
    return signing.PublicKey.parseHex(build_options.policy_pk_hex);
}

pub const VerifyError = error{
    InvalidPolicy,
    UntrustedSigner,
    SigMismatch,
    MissingSignature,
    OutOfMemory,
    PolicyExpired,
    GenerationRollback,
    GenerationPersistFailed,
};

/// Verify a signed policy bundle against the build-time trusted public key.
/// Checks expiry (not_after) and generation rollback against stored state.
/// Returns the parsed SignedDoc on success; caller must deinitSignedDoc.
pub fn verifySignedPolicy(alloc: std.mem.Allocator, raw: []const u8) VerifyError!SignedDoc {
    return verifySignedPolicyAt(alloc, raw, std.time.timestamp());
}

/// Like verifySignedPolicy but accepts an explicit wall-clock for testing.
pub fn verifySignedPolicyAt(alloc: std.mem.Allocator, raw: []const u8, now: i64) VerifyError!SignedDoc {
    const signed = parseSignedDoc(alloc, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MissingSignature => return error.MissingSignature,
        error.UntrustedSigner => return error.UntrustedSigner,
        error.SigMismatch => return error.SigMismatch,
        else => return error.InvalidPolicy,
    };
    errdefer deinitSignedDoc(alloc, signed);

    // Expiry check
    if (signed.doc.not_after) |deadline| {
        if (now > deadline) return error.PolicyExpired;
    }

    // Generation rollback check
    const stored_gen = GenerationState.load(alloc) catch 0;
    if (signed.doc.generation < stored_gen) return error.GenerationRollback;

    // Persist new high-water mark
    if (signed.doc.generation > stored_gen) {
        GenerationState.store(alloc, signed.doc.generation) catch return error.GenerationPersistFailed;
    }

    return signed;
}

/// Parse a policy document from JSON.
/// Missing `version` defaults to 1. Unknown versions are rejected.
pub fn parseDoc(alloc: std.mem.Allocator, json: []const u8) !Doc {
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{});
    defer parsed.deinit();
    const root = parsed.value;

    if (root != .object) return error.UnexpectedToken;

    // Reject unknown top-level keys (fail-closed)
    const known_top = std.StaticStringMap(void).initComptime(.{
        .{ "version", {} },
        .{ "rules", {} },
        .{ "ca_file", {} },
        .{ "lock", {} },
        .{ "signature", {} },
        .{ "release_url", {} },
        .{ "generation", {} },
        .{ "not_after", {} },
    });
    for (root.object.keys()) |k| {
        if (!known_top.has(k)) return error.UnknownPolicyKey;
    }

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
            if (rule.kind) |k| alloc.free(k);
        }
    }

    // Known rule keys
    const known_rule = std.StaticStringMap(void).initComptime(.{
        .{ "pattern", {} },
        .{ "effect", {} },
        .{ "tool", {} },
        .{ "kind", {} },
    });

    for (items, 0..) |item, i| {
        if (item != .object) return error.UnexpectedToken;

        // Reject unknown rule keys
        for (item.object.keys()) |k| {
            if (!known_rule.has(k)) return error.UnknownPolicyKey;
        }

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

        if (item.object.get("kind")) |k| {
            if (k != .string) return error.UnexpectedToken;
            rule.kind = try alloc.dupe(u8, k.string);
        }

        rules[i] = rule;
        init_n += 1;
    }

    var ca_file: ?[]u8 = null;
    errdefer if (ca_file) |v| alloc.free(v);
    if (root.object.get("ca_file")) |ca_val| {
        if (ca_val != .string) return error.UnexpectedToken;
        ca_file = try alloc.dupe(u8, ca_val.string);
    }

    // Known lock keys
    const known_lock = std.StaticStringMap(void).initComptime(.{
        .{ "config", {} },
        .{ "env", {} },
        .{ "cli", {} },
        .{ "context", {} },
        .{ "auth", {} },
        .{ "system_prompt", {} },
    });

    var lock = Lock{};
    if (root.object.get("lock")) |lock_val| {
        if (lock_val != .object) return error.UnexpectedToken;
        // Reject unknown lock keys
        for (lock_val.object.keys()) |k| {
            if (!known_lock.has(k)) return error.UnknownPolicyKey;
        }
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
        if (lock_val.object.get("auth")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.auth = v.bool;
        }
        if (lock_val.object.get("system_prompt")) |v| {
            if (v != .bool) return error.UnexpectedToken;
            lock.system_prompt = v.bool;
        }
    }

    var generation: u64 = 0;
    if (root.object.get("generation")) |gen_val| {
        switch (gen_val) {
            .integer => |i| {
                if (i < 0) return error.UnexpectedToken;
                generation = @intCast(i);
            },
            else => return error.UnexpectedToken,
        }
    }

    var not_after: ?i64 = null;
    if (root.object.get("not_after")) |na_val| {
        switch (na_val) {
            .integer => |i| {
                not_after = @intCast(i);
            },
            else => return error.UnexpectedToken,
        }
    }

    // Extract optional release_url for enterprise channel
    var release_url: ?[]u8 = null;
    errdefer if (release_url) |v| alloc.free(v);
    if (root.object.get("release_url")) |ru_val| {
        if (ru_val != .string) return error.UnexpectedToken;
        release_url = try alloc.dupe(u8, ru_val.string);
    }

    return .{ .version = ver, .rules = rules, .ca_file = ca_file, .lock = lock, .generation = generation, .not_after = not_after, .release_url = release_url };
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
    if (!signing.ctEql(embedded_pk.raw[0..], pk.raw[0..])) return error.UntrustedSigner;
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
    if (doc.ca_file) |ca_file| {
        try w.writeAll(",\"ca_file\":");
        try writeJsonStr(w, ca_file);
    }
    if (doc.release_url) |ru| {
        try w.writeAll(",\"release_url\":");
        try writeJsonStr(w, ru);
    }
    if (doc.lock.cfg or doc.lock.env or doc.lock.cli or doc.lock.context or doc.lock.auth or doc.lock.system_prompt) {
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
        if (doc.lock.auth) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"auth\":true");
            first = false;
        }
        if (doc.lock.system_prompt) {
            if (!first) try w.writeByte(',');
            try w.writeAll("\"system_prompt\":true");
        }
        try w.writeByte('}');
    }
    if (doc.generation != 0) {
        try w.writeAll(",\"generation\":");
        try w.print("{d}", .{doc.generation});
    }
    if (doc.not_after) |na| {
        try w.writeAll(",\"not_after\":");
        try w.print("{d}", .{na});
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
        if (rule.kind) |k| {
            try w.writeAll(",\"kind\":");
            try writeJsonStr(w, k);
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
    var ca_file: ?[]u8 = null;
    errdefer if (ca_file) |v| alloc.free(v);
    var release_url: ?[]u8 = null;
    errdefer if (release_url) |v| alloc.free(v);
    var max_gen: u64 = 0;
    var merged_na: ?i64 = null;
    for (docs[0..doc_n]) |maybe_doc| {
        const doc = maybe_doc.?;
        total_rules += doc.doc.rules.len;
        lock = lock.merge(doc.doc.lock);
        if (doc.doc.ca_file) |v| {
            if (ca_file) |curr| alloc.free(curr);
            ca_file = try alloc.dupe(u8, v);
        }
        if (doc.doc.generation > max_gen) max_gen = doc.doc.generation;
        if (doc.doc.not_after) |na| {
            merged_na = if (merged_na) |cur| @min(cur, na) else na;
        }
        if (doc.doc.release_url) |v| {
            if (release_url) |curr| alloc.free(curr);
            release_url = try alloc.dupe(u8, v);
        }
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
        .ca_file = ca_file,
        .lock = lock,
        .generation = max_gen,
        .not_after = merged_na,
        .release_url = release_url,
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
        .locked = doc_n != 0,
    };
}

pub fn loadLock(alloc: std.mem.Allocator, cwd: ?[]const u8, home: ?[]const u8) anyerror!Lock {
    const resolved = try loadResolved(alloc, cwd, home);
    defer deinitResolved(alloc, resolved);
    return resolved.doc.lock;
}

fn loadSignedDocFile(alloc: std.mem.Allocator, path: []const u8) anyerror!?SignedDoc {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidPolicy;
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
    if (!std.fs.path.isAbsolute(path)) return error.InvalidPolicy;
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
        if (rule.kind) |k| alloc.free(k);
    }
    if (doc.ca_file) |v| alloc.free(v);
    if (doc.release_url) |v| alloc.free(v);
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
    const doc = Doc{
        .version = ver_current,
        .rules = &rules,
        .ca_file = "/etc/pz/policy.pem",
    };
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
        ca_file: []const u8,
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
        \\  .ca_file: []const u8
        \\    "/etc/pz/policy.pem"
    ).expectEqual(Snap{
        .version = doc2.version,
        .n_rules = doc2.rules.len,
        .pat0 = doc2.rules[0].pattern,
        .eff0 = doc2.rules[0].effect,
        .tool0 = doc2.rules[0].tool.?,
        .pat1 = doc2.rules[1].pattern,
        .eff1 = doc2.rules[1].effect,
        .tool1 = doc2.rules[1].tool orelse "",
        .ca_file = doc2.ca_file orelse "",
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

test "verifySignedPolicy accepts valid bundle" {
    const kp = try testKeyPair();
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const json = try encodeSignedDoc(testing.allocator, .{ .rules = &rules }, kp);
    defer testing.allocator.free(json);

    const doc = try verifySignedPolicy(testing.allocator, json);
    defer deinitSignedDoc(testing.allocator, doc);

    try testing.expectEqual(@as(usize, 1), doc.doc.rules.len);
    try testing.expectEqualStrings("*", doc.doc.rules[0].pattern);
}

test "verifySignedPolicy rejects tampered bundle" {
    const kp = try testKeyPair();
    const rules = [_]Rule{.{ .pattern = "src/*", .effect = .allow }};
    const json = try encodeSignedDoc(testing.allocator, .{ .rules = &rules }, kp);
    defer testing.allocator.free(json);

    const mut = try testing.allocator.dupe(u8, json);
    defer testing.allocator.free(mut);
    const idx = std.mem.indexOf(u8, mut, "src/*") orelse return error.TestUnexpectedResult;
    mut[idx] = 'X';

    try testing.expectError(error.SigMismatch, verifySignedPolicy(testing.allocator, mut));
}

test "verifySignedPolicy rejects unsigned doc" {
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const json = try encodeDoc(testing.allocator, .{ .rules = &rules });
    defer testing.allocator.free(json);

    try testing.expectError(error.MissingSignature, verifySignedPolicy(testing.allocator, json));
}

test "loadResolved sets locked when signed policy present" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("cwd/.pz");
    const kp = try testKeyPair();
    const raw = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{.{ .pattern = "*", .effect = .allow }},
    }, kp);
    defer testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = "cwd/.pz/policy.json", .data = raw });

    const cwd = try tmp.dir.realpathAlloc(testing.allocator, "cwd");
    defer testing.allocator.free(cwd);

    const resolved = try loadResolved(testing.allocator, cwd, null);
    defer deinitResolved(testing.allocator, resolved);

    try testing.expect(resolved.locked);
    try testing.expect(resolved.has_files);
}

test "loadResolved not locked without policy files" {
    const resolved = try loadResolved(testing.allocator, null, null);
    defer deinitResolved(testing.allocator, resolved);

    try testing.expect(!resolved.locked);
    try testing.expect(!resolved.has_files);
}

test "loadResolved rejects unsigned file in lock mode" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("cwd/.pz");

    // Home has valid signed policy
    const kp = try testKeyPair();
    const signed = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{.{ .pattern = "*", .effect = .allow }},
    }, kp);
    defer testing.allocator.free(signed);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pz/policy.json", .data = signed });

    // Cwd has unsigned policy - should fail
    const unsigned = try encodeDoc(testing.allocator, .{
        .rules = &.{.{ .pattern = "*.md", .effect = .deny }},
    });
    defer testing.allocator.free(unsigned);
    try tmp.dir.writeFile(.{ .sub_path = "cwd/.pz/policy.json", .data = unsigned });

    const home = try tmp.dir.realpathAlloc(testing.allocator, "home");
    defer testing.allocator.free(home);
    const cwd = try tmp.dir.realpathAlloc(testing.allocator, "cwd");
    defer testing.allocator.free(cwd);

    try testing.expectError(error.InvalidPolicy, loadResolved(testing.allocator, cwd, home));
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
        .ca_file = "/etc/pz/home.pem",
        .lock = .{ .cfg = true },
    }, kp);
    defer testing.allocator.free(home_raw);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pz/policy.json", .data = home_raw });

    const cwd_raw = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{
            .{ .pattern = "runtime/subagent/*", .effect = .deny },
        },
        .ca_file = "/etc/pz/cwd.pem",
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
        ca_file: []const u8,
        lock_cfg: bool,
        lock_cli: bool,
    };

    try oh.snap(@src(),
        \\core.policy.test.loadResolved merges verified bundles and hashes effective doc.Snap
        \\  .has_files: bool = true
        \\  .hash_hex: []const u8
        \\    "3ca7448a886db5ed41cb6515305c862d327f6a340d45673eeecea30afd384518"
        \\  .n_rules: usize = 2
        \\  .pat0: []const u8
        \\    "runtime/cmd/*"
        \\  .eff0: core.policy.Effect
        \\    .allow
        \\  .pat1: []const u8
        \\    "runtime/subagent/*"
        \\  .eff1: core.policy.Effect
        \\    .deny
        \\  .ca_file: []const u8
        \\    "/etc/pz/cwd.pem"
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
        .ca_file = resolved.doc.ca_file orelse "",
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
        lock_auth: bool,
        lock_system_prompt: bool,
        ca_file: []const u8,
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
        \\  .lock_auth: bool = false
        \\  .lock_system_prompt: bool = false
        \\  .ca_file: []const u8
        \\    ""
        \\  .hash_hex: []const u8
        \\    "6be6bac38f2d35217ca3cd98e36322f9e8fb6638564f5a87ff660589f6302103"
    ).expectEqual(Snap{
        .has_files = resolved.has_files,
        .n_rules = resolved.doc.rules.len,
        .lock_cfg = resolved.doc.lock.cfg,
        .lock_env = resolved.doc.lock.env,
        .lock_cli = resolved.doc.lock.cli,
        .lock_context = resolved.doc.lock.context,
        .lock_auth = resolved.doc.lock.auth,
        .lock_system_prompt = resolved.doc.lock.system_prompt,
        .ca_file = resolved.doc.ca_file orelse "",
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

test "property: random byte mutations to signed policy payload fail verification" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { off: u8, val: u8 }) bool {
            const kp = testKeyPair() catch return false;
            const rules = [_]Rule{.{ .pattern = "src/*", .effect = .deny }};
            const doc: Doc = .{ .rules = &rules, .lock = .{ .cfg = true } };
            const payload = encodeDoc(testing.allocator, doc) catch return false;
            defer testing.allocator.free(payload);

            const sig = kp.sign(payload) catch return false;
            const pk = kp.publicKey();

            if (payload.len == 0) return false;
            const idx = args.off % @as(u8, @intCast(@min(payload.len, 255)));

            const mut = testing.allocator.dupe(u8, payload) catch return false;
            defer testing.allocator.free(mut);

            // Skip no-ops
            if (mut[idx] == args.val) return true;
            mut[idx] = args.val;

            // Mutated payload must fail sig verification
            _ = signing.verifyDetached(mut, sig, pk) catch return true;
            return false;
        }
    }.prop, .{ .iterations = 2000 });
}

test "signed deny cannot be weakened by unsigned allow" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath("home/.pz");
    try tmp.dir.makePath("cwd/.pz");

    // Home: signed policy with deny *
    const kp = try testKeyPair();
    const signed = try encodeSignedDoc(testing.allocator, .{
        .rules = &.{.{ .pattern = "*", .effect = .deny }},
    }, kp);
    defer testing.allocator.free(signed);
    try tmp.dir.writeFile(.{ .sub_path = "home/.pz/policy.json", .data = signed });

    // Cwd: unsigned policy with allow * — should be rejected (unsigned in signed context)
    const unsigned = try encodeDoc(testing.allocator, .{
        .rules = &.{.{ .pattern = "*", .effect = .allow }},
    });
    defer testing.allocator.free(unsigned);
    try tmp.dir.writeFile(.{ .sub_path = "cwd/.pz/policy.json", .data = unsigned });

    const home = try tmp.dir.realpathAlloc(testing.allocator, "home");
    defer testing.allocator.free(home);
    const cwd = try tmp.dir.realpathAlloc(testing.allocator, "cwd");
    defer testing.allocator.free(cwd);

    // Unsigned cwd policy fails to load alongside signed home policy
    try testing.expectError(error.InvalidPolicy, loadResolved(testing.allocator, cwd, home));

    // Even if only home is loaded, deny * still denies everything
    const resolved = try loadResolved(testing.allocator, null, home);
    defer deinitResolved(testing.allocator, resolved);

    try testing.expectEqual(Effect.deny, evaluate(resolved.doc.rules, "any/path.zig", null));
    try testing.expectEqual(Effect.deny, evaluate(resolved.doc.rules, "src/main.zig", "read"));
    try testing.expectEqual(Effect.deny, evaluate(resolved.doc.rules, "foo.txt", "write"));
}

test "EgressPolicy deadlines clamp to bounds" {
    const ep0: EgressPolicy = .{};
    try testing.expectEqual(@as(u32, 10_000), ep0.connectMs());
    try testing.expectEqual(@as(u32, 30_000), ep0.totalMs());

    const ep1: EgressPolicy = .{ .connect_deadline_ms = 50_000, .total_deadline_ms = 200_000 };
    try testing.expectEqual(@as(u32, 30_000), ep1.connectMs());
    try testing.expectEqual(@as(u32, 120_000), ep1.totalMs());

    const ep2: EgressPolicy = .{ .connect_deadline_ms = 5_000, .total_deadline_ms = 15_000 };
    try testing.expectEqual(@as(u32, 5_000), ep2.connectMs());
    try testing.expectEqual(@as(u32, 15_000), ep2.totalMs());
}

test "EgressPolicy proxy validation requires allowed host" {
    const rules = [_]Rule{
        .{ .pattern = "runtime/web/proxy.corp", .effect = .allow, .tool = "web" },
    };
    const ep: EgressPolicy = .{
        .rules = &rules,
        .proxy_url = "https://proxy.corp:8080",
    };
    const proxy = try ep.validatedProxy();
    try testing.expectEqualStrings("https://proxy.corp:8080", proxy.?);

    const ep_denied: EgressPolicy = .{
        .rules = &rules,
        .proxy_url = "https://rogue.host:8080",
    };
    try testing.expectError(error.HostDenied, ep_denied.validatedProxy());
}

test "EgressPolicy proxy rejects bad schemes" {
    const ep: EgressPolicy = .{
        .proxy_url = "socks5://proxy.corp:1080",
    };
    try testing.expectError(error.UnsupportedScheme, ep.validatedProxy());
}

test "EgressPolicy proxy null returns null" {
    const ep: EgressPolicy = .{};
    const proxy = try ep.validatedProxy();
    try testing.expect(proxy == null);
}

test "SessionPersist defaults off for headless modes" {
    const Mode = enum { tui, print, json, rpc };
    try testing.expectEqual(SessionPersist.off, SessionPersist.forMode(Mode.print));
    try testing.expectEqual(SessionPersist.off, SessionPersist.forMode(Mode.json));
    try testing.expectEqual(SessionPersist.on, SessionPersist.forMode(Mode.tui));
    try testing.expectEqual(SessionPersist.on, SessionPersist.forMode(Mode.rpc));
}

test "SessionPersist enterprise lock disables durable writes" {
    const no_lock: Lock = .{};
    const cfg_lock: Lock = .{ .cfg = true };
    // Without enterprise lock, on stays on.
    try testing.expectEqual(SessionPersist.on, SessionPersist.on.withEnterprise(no_lock));
    // Enterprise cfg lock forces off.
    try testing.expectEqual(SessionPersist.off, SessionPersist.on.withEnterprise(cfg_lock));
    // Already off stays off regardless.
    try testing.expectEqual(SessionPersist.off, SessionPersist.off.withEnterprise(no_lock));
    try testing.expectEqual(SessionPersist.off, SessionPersist.off.withEnterprise(cfg_lock));
}

test "evaluateKind denied skill is blocked" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .deny, .kind = "skill" },
        .{ .pattern = "*", .effect = .allow },
    };
    // Skill invocation blocked by kind=skill deny rule
    try testing.expectEqual(Effect.deny, evaluateKind(&rules, "any.zig", null, "skill"));
    // Non-skill invocation falls through to allow-all
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "any.zig", null, null));
    // Different kind falls through to allow-all
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "any.zig", null, "tool"));
}

test "evaluateKind allows skill by default" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .allow },
    };
    // No kind filter on rule — allows any kind including skill
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "any.zig", null, "skill"));
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "any.zig", null, null));
}

test "evaluateKind skill + tool combined filter" {
    const rules = [_]Rule{
        .{ .pattern = "*", .effect = .deny, .tool = "bash", .kind = "skill" },
        .{ .pattern = "*", .effect = .allow },
    };
    // Both tool and kind must match for the deny rule
    try testing.expectEqual(Effect.deny, evaluateKind(&rules, "f.zig", "bash", "skill"));
    // Wrong tool — deny skipped
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "f.zig", "read", "skill"));
    // Wrong kind — deny skipped
    try testing.expectEqual(Effect.allow, evaluateKind(&rules, "f.zig", "bash", null));
}

test "parseDoc rejects unknown top-level key" {
    const json = "{\"version\":1,\"rules\":[],\"bogus\":true}";
    try testing.expectError(error.UnknownPolicyKey, parseDoc(testing.allocator, json));
}

test "parseDoc rejects unknown rule key" {
    const json = "{\"version\":1,\"rules\":[{\"pattern\":\"*\",\"effect\":\"allow\",\"nope\":1}]}";
    try testing.expectError(error.UnknownPolicyKey, parseDoc(testing.allocator, json));
}

test "parseDoc rejects unknown lock key" {
    const json = "{\"version\":1,\"rules\":[],\"lock\":{\"typo\":true}}";
    try testing.expectError(error.UnknownPolicyKey, parseDoc(testing.allocator, json));
}

test "parseDoc accepts release_url" {
    const json = "{\"version\":1,\"rules\":[],\"release_url\":\"https://releases.corp/pz/latest\"}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expect(doc.release_url != null);
    try testing.expectEqualStrings("https://releases.corp/pz/latest", doc.release_url.?);
}

test "parseDoc with kind filter" {
    const json =
        \\{"version":1,"rules":[{"pattern":"*","effect":"deny","kind":"skill"}]}
    ;
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expectEqual(@as(usize, 1), doc.rules.len);
    try testing.expect(std.mem.eql(u8, "skill", doc.rules[0].kind.?));
    try testing.expectEqual(Effect.deny, doc.rules[0].effect);
}

test "encodeDoc roundtrips kind field" {
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .deny, .kind = "skill" },
    };
    const doc = Doc{ .version = ver_current, .rules = &rules };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);
    const parsed = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, parsed);
    try testing.expectEqual(@as(usize, 1), parsed.rules.len);
    try testing.expect(std.mem.eql(u8, "skill", parsed.rules[0].kind.?));
    try testing.expect(std.mem.eql(u8, "*.zig", parsed.rules[0].pattern));
    try testing.expectEqual(Effect.deny, parsed.rules[0].effect);
}

// ── Rollback resistance tests ──────────────────────────────────────────

test "parseDoc roundtrips generation and not_after" {
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const doc = Doc{ .rules = &rules, .generation = 42, .not_after = 1700000000 };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);
    const parsed = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, parsed);
    try testing.expectEqual(@as(u64, 42), parsed.generation);
    try testing.expectEqual(@as(i64, 1700000000), parsed.not_after.?);
}

test "parseDoc defaults generation 0 and not_after null" {
    const json = "{\"version\":1,\"rules\":[]}";
    const doc = try parseDoc(testing.allocator, json);
    defer deinitDoc(testing.allocator, doc);
    try testing.expectEqual(@as(u64, 0), doc.generation);
    try testing.expect(doc.not_after == null);
}

test "expired policy rejected" {
    const kp = try testKeyPair();
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const doc = Doc{ .rules = &rules, .generation = 1, .not_after = 1000 };
    const json = try encodeSignedDoc(testing.allocator, doc, kp);
    defer testing.allocator.free(json);

    // now=2000 > not_after=1000 → expired
    try testing.expectError(error.PolicyExpired, verifySignedPolicyAt(testing.allocator, json, 2000));
}

test "fresh policy accepted before expiry" {
    const kp = try testKeyPair();
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const doc = Doc{ .rules = &rules, .generation = 0, .not_after = 5000 };
    const json = try encodeSignedDoc(testing.allocator, doc, kp);
    defer testing.allocator.free(json);

    // now=3000 < not_after=5000 → accepted
    const signed = try verifySignedPolicyAt(testing.allocator, json, 3000);
    defer deinitSignedDoc(testing.allocator, signed);
    try testing.expectEqual(@as(u64, 0), signed.doc.generation);
    try testing.expectEqual(@as(i64, 5000), signed.doc.not_after.?);
}

test "generation rollback rejected via GenerationState" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a state file with generation=10
    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{ .sub_path = ".pz/policy-state.json", .data = "{\"generation\":10}" });

    const state_path = try tmp.dir.realpathAlloc(testing.allocator, ".pz/policy-state.json");
    defer testing.allocator.free(state_path);

    // Verify stored generation reads correctly
    const gen = try GenerationState.loadFrom(testing.allocator, state_path);
    try testing.expectEqual(@as(u64, 10), gen);

    // Store a higher generation, verify it persists
    try GenerationState.storeTo(state_path, 20);
    const gen2 = try GenerationState.loadFrom(testing.allocator, state_path);
    try testing.expectEqual(@as(u64, 20), gen2);
}

test "GenerationState loadFrom missing file returns 0" {
    const gen = try GenerationState.loadFrom(testing.allocator, "/tmp/nonexistent-pz-policy-state.json");
    try testing.expectEqual(@as(u64, 0), gen);
}

test "encodeDoc omits generation 0 and null not_after" {
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const doc = Doc{ .rules = &rules };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);
    // generation=0 should not appear in output
    try testing.expect(std.mem.indexOf(u8, json, "generation") == null);
    // not_after=null should not appear in output
    try testing.expect(std.mem.indexOf(u8, json, "not_after") == null);
}

test "encodeDoc includes non-zero generation and non-null not_after" {
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    const doc = Doc{ .rules = &rules, .generation = 7, .not_after = 9999 };
    const json = try encodeDoc(testing.allocator, doc);
    defer testing.allocator.free(json);
    try testing.expect(std.mem.indexOf(u8, json, "\"generation\":7") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"not_after\":9999") != null);
}

// ── Proof canaries ──────────────────────────────────────────────────

test "canary: IPv4 egress blocklist completeness (Lean Egress)" {
    // Every RFC 1918 / loopback / link-local address must be blocked.
    try testing.expect(isBlockedIp4(.{ 10, 0, 0, 1 }));
    try testing.expect(isBlockedIp4(.{ 10, 255, 255, 255 }));
    try testing.expect(isBlockedIp4(.{ 172, 16, 0, 1 }));
    try testing.expect(isBlockedIp4(.{ 172, 31, 255, 255 }));
    try testing.expect(isBlockedIp4(.{ 192, 168, 1, 1 }));
    try testing.expect(isBlockedIp4(.{ 127, 0, 0, 1 }));
    try testing.expect(isBlockedIp4(.{ 169, 254, 1, 1 }));
    // Public addresses must NOT be blocked.
    try testing.expect(!isBlockedIp4(.{ 8, 8, 8, 8 }));
    try testing.expect(!isBlockedIp4(.{ 1, 1, 1, 1 }));
    // Edge cases.
    try testing.expect(!isBlockedIp4(.{ 172, 15, 255, 255 }));
    try testing.expect(isBlockedIp4(.{ 172, 16, 0, 0 }));
    try testing.expect(!isBlockedIp4(.{ 172, 32, 0, 0 }));
}

test "canary: protected paths always deny (Lean Evaluate.protected_always_deny)" {
    const rules = [_]Rule{.{ .pattern = "*", .effect = .allow }};
    // Protected paths denied regardless of allow-all rules.
    try testing.expectEqual(Effect.deny, evaluate(&rules, ".pz/foo", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "bar.audit.log", null));
    try testing.expectEqual(Effect.deny, evaluate(&rules, "AGENTS.md", null));
    // Non-protected paths use rules.
    try testing.expectEqual(Effect.allow, evaluate(&rules, "src/main.zig", null));
}

test "canary: evaluate first-match-wins (Lean Evaluate.first_match_wins)" {
    const rules = [_]Rule{
        .{ .pattern = "*.zig", .effect = .deny },
        .{ .pattern = "*", .effect = .allow },
    };
    // First matching rule wins — deny, not allow.
    try testing.expectEqual(Effect.deny, evaluate(&rules, "foo.zig", null));
    // Non-matching first rule → second rule applies.
    try testing.expectEqual(Effect.allow, evaluate(&rules, "foo.txt", null));
}
