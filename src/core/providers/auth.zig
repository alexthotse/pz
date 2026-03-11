const std = @import("std");
const builtin = @import("builtin");
const oauth_callback = @import("oauth_callback.zig");
const audit = @import("../audit.zig");
const fs_secure = @import("../fs_secure.zig");

pub const Auth = union(enum) {
    oauth: OAuth,
    api_key: []const u8, // x-api-key
};

pub const OAuth = struct {
    access: []const u8,
    refresh: []const u8,
    expires: i64, // ms since epoch
};

pub const Result = struct {
    arena: std.heap.ArenaAllocator,
    auth: Auth,

    pub fn deinit(self: *Result) void {
        self.arena.deinit();
    }
};

const AuthEntry = struct {
    type: ?[]const u8 = null,
    access: ?[]const u8 = null,
    refresh: ?[]const u8 = null,
    expires: ?i64 = null,
    key: ?[]const u8 = null,
};

pub const Provider = enum { anthropic, openai, google };
const provider_names = [_][]const u8{ "anthropic", "openai", "google" };

pub fn providerName(p: Provider) []const u8 {
    return provider_names[@intFromEnum(p)];
}

pub const Hooks = struct {
    home_override: ?[]const u8 = null,
    get_home: *const fn (std.mem.Allocator, []const u8) anyerror![]u8 = std.process.getEnvVarOwned,
    exchange_code: *const fn (std.mem.Allocator, *const OAuthSpec, []const u8, []const u8, []const u8, []const u8) anyerror!OAuth = exchangeAuthorizationCode,
    refresh_fetch: *const fn (std.mem.Allocator, Provider, OAuth) anyerror!OAuth = fetchRefreshedOAuthForProvider,
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = std.time.milliTimestamp,
};

const OAuthTokenBody = enum {
    json_with_state,
    form_no_state,
};

const OAuthParam = struct {
    key: []const u8,
    value: []const u8,
};

const OAuthSpec = struct {
    provider: Provider,
    client_id: []const u8,
    authorize_url: []const u8,
    token_host: []const u8,
    token_path: []const u8,
    default_redirect_uri: []const u8,
    scopes: []const u8,
    local_callback_path: []const u8,
    start_action: []const u8,
    complete_action: []const u8,
    api_key_prefix: ?[]const u8 = null,
    token_body: OAuthTokenBody,
    extra_authorize: []const OAuthParam = &.{},
};

const oauth_no_expiry: i64 = std.math.maxInt(i64);
const anthropic_oauth_env = "ANTHROPIC_OAUTH_TOKEN";
const anthropic_api_key_env = "ANTHROPIC_API_KEY";
const openai_api_key_env = "OPENAI_API_KEY";

const openai_oauth_extra_authorize = [_]OAuthParam{
    .{ .key = "id_token_add_organizations", .value = "true" },
    .{ .key = "codex_cli_simplified_flow", .value = "true" },
    .{ .key = "originator", .value = "pz" },
};

const anthropic_spec = OAuthSpec{
    .provider = .anthropic,
    .client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    .authorize_url = "https://claude.ai/oauth/authorize",
    .token_host = "console.anthropic.com",
    .token_path = "/v1/oauth/token",
    .default_redirect_uri = "https://console.anthropic.com/oauth/code/callback",
    .scopes = "org:create_api_key user:profile user:inference",
    .local_callback_path = "/callback",
    .start_action = "start anthropic oauth",
    .complete_action = "complete anthropic oauth",
    .api_key_prefix = "sk-ant-",
    .token_body = .json_with_state,
    .extra_authorize = &.{.{ .key = "code", .value = "true" }},
};

const openai_spec = OAuthSpec{
    .provider = .openai,
    .client_id = "app_EMoamEEZ73f0CkXaXp7hrann",
    .authorize_url = "https://auth.openai.com/oauth/authorize",
    .token_host = "auth.openai.com",
    .token_path = "/oauth/token",
    .default_redirect_uri = "http://127.0.0.1:1455/auth/callback",
    .scopes = "openid profile email offline_access",
    .local_callback_path = "/auth/callback",
    .start_action = "start openai oauth",
    .complete_action = "complete openai oauth",
    .api_key_prefix = "sk-",
    .token_body = .form_no_state,
    .extra_authorize = openai_oauth_extra_authorize[0..],
};

fn oauthSpec(provider: Provider) ?*const OAuthSpec {
    return switch (provider) {
        .anthropic => &anthropic_spec,
        .openai => &openai_spec,
        .google => null,
    };
}

pub const OAuthLoginInfo = struct {
    callback_path: []const u8,
    start_action: []const u8,
    complete_action: []const u8,
};

pub fn oauthLoginInfo(provider: Provider) ?OAuthLoginInfo {
    const spec = oauthSpec(provider) orelse return null;
    return .{
        .callback_path = spec.local_callback_path,
        .start_action = spec.start_action,
        .complete_action = spec.complete_action,
    };
}

pub fn oauthCapable(provider: Provider) bool {
    return oauthSpec(provider) != null;
}

pub fn looksLikeApiKey(provider: Provider, key: []const u8) bool {
    const prefix = switch (provider) {
        .anthropic => anthropic_spec.api_key_prefix,
        .openai => openai_spec.api_key_prefix,
        .google => null,
    };
    if (prefix) |p| return std.mem.startsWith(u8, key, p);
    return key.len > 0;
}

pub const OAuthStart = struct {
    url: []u8,
    verifier: []u8,

    pub fn deinit(self: *OAuthStart, alloc: std.mem.Allocator) void {
        alloc.free(self.url);
        alloc.free(self.verifier);
        self.* = undefined;
    }
};

pub const OAuthCodeInput = struct {
    code: []u8,
    state: ?[]u8 = null,
    redirect_uri: ?[]u8 = null,

    pub fn deinit(self: *OAuthCodeInput, alloc: std.mem.Allocator) void {
        alloc.free(self.code);
        if (self.state) |s| alloc.free(s);
        if (self.redirect_uri) |u| alloc.free(u);
        self.* = undefined;
    }
};

const AuthFile = struct {
    anthropic: ?AuthEntry = null,
    openai: ?AuthEntry = null,
    google: ?AuthEntry = null,
};

fn findAuthFile(ar: std.mem.Allocator, home: []const u8) ![]const u8 {
    const path = try authFilePath(ar, home);
    if (std.fs.cwd().access(path, .{})) |_| return path else |_| return error.AuthNotFound;
}

fn authFilePath(ar: std.mem.Allocator, home: []const u8) ![]const u8 {
    return std.fs.path.join(ar, &.{ home, ".pz", "auth.json" });
}

/// Primary auth dir (for writes). Uses ~/.pz/ by default.
fn primaryAuthDir(ar: std.mem.Allocator, home: []const u8) ![]const u8 {
    return try std.fs.path.join(ar, &.{ home, ".pz" });
}

pub fn load(alloc: std.mem.Allocator) !Result {
    return loadForProvider(alloc, .anthropic);
}

pub fn loadForProvider(alloc: std.mem.Allocator, provider: Provider) !Result {
    return loadForProviderHome(alloc, std.process.getEnvVarOwned, provider);
}

fn loadForProviderHome(
    alloc: std.mem.Allocator,
    comptime get_home: fn (std.mem.Allocator, []const u8) anyerror![]u8,
    provider: Provider,
) !Result {
    var arena = std.heap.ArenaAllocator.init(alloc);
    errdefer arena.deinit();
    const ar = arena.allocator();

    if (authFromEnv(providerEnvAuth(ar, provider))) |auth| {
        return .{ .arena = arena, .auth = auth };
    }

    const home = get_home(ar, "HOME") catch return error.AuthNotFound;
    return .{
        .arena = arena,
        .auth = try loadFileAuthForProvider(ar, home, provider),
    };
}

const EnvAuth = struct {
    oauth: ?[]const u8 = null,
    api_key: ?[]const u8 = null,
};

fn readEnv(ar: std.mem.Allocator, key: []const u8) ?[]const u8 {
    return std.process.getEnvVarOwned(ar, key) catch null;
}

fn providerEnvAuth(ar: std.mem.Allocator, provider: Provider) EnvAuth {
    return switch (provider) {
        .anthropic => .{
            .oauth = readEnv(ar, anthropic_oauth_env),
            .api_key = readEnv(ar, anthropic_api_key_env),
        },
        .openai => .{
            .oauth = null,
            .api_key = readEnv(ar, openai_api_key_env),
        },
        .google => .{},
    };
}

fn authFromEnv(env: EnvAuth) ?Auth {
    if (env.oauth) |token| {
        if (token.len > 0) return .{ .oauth = .{
            .access = token,
            .refresh = "",
            .expires = oauth_no_expiry,
        } };
    }
    if (env.api_key) |key| {
        if (key.len > 0) return .{ .api_key = key };
    }
    return null;
}

fn loadFileAuth(alloc: std.mem.Allocator, home: []const u8) !Auth {
    return loadFileAuthForProvider(alloc, home, .anthropic);
}

fn loadFileAuthForProvider(alloc: std.mem.Allocator, home: []const u8, provider: Provider) !Auth {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const path = findAuthFile(ar, home) catch return error.AuthNotFound;
    const raw = std.fs.cwd().readFileAlloc(ar, path, 1024 * 1024) catch return error.AuthNotFound;
    const parsed = std.json.parseFromSlice(AuthFile, ar, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return error.AuthNotFound;
    const entry = switch (provider) {
        .anthropic => parsed.value.anthropic,
        .openai => parsed.value.openai,
        .google => parsed.value.google,
    } orelse return error.AuthNotFound;

    const AuthType = enum { oauth, api_key };
    const auth_map = std.StaticStringMap(AuthType).initComptime(.{
        .{ "oauth", .oauth },
        .{ "api_key", .api_key },
    });
    const typ = entry.type orelse return error.AuthNotFound;
    const resolved = auth_map.get(typ) orelse return error.AuthNotFound;
    return switch (resolved) {
        .oauth => blk: {
            const access = entry.access orelse return error.AuthNotFound;
            const refresh = entry.refresh orelse return error.AuthNotFound;
            const access_duped = try alloc.dupe(u8, access);
            errdefer alloc.free(access_duped);
            const refresh_duped = try alloc.dupe(u8, refresh);
            errdefer alloc.free(refresh_duped);
            break :blk .{ .oauth = .{
                .access = access_duped,
                .refresh = refresh_duped,
                .expires = entry.expires orelse 0,
            } };
        },
        .api_key => blk: {
            const key = entry.key orelse return error.AuthNotFound;
            break :blk .{ .api_key = try alloc.dupe(u8, key) };
        },
    };
}

pub fn beginAnthropicOAuth(alloc: std.mem.Allocator) !OAuthStart {
    return beginOAuth(alloc, .anthropic);
}

pub fn beginAnthropicOAuthWithRedirect(
    alloc: std.mem.Allocator,
    oauth_redirect_uri: []const u8,
) !OAuthStart {
    return beginOAuthWithRedirect(alloc, .anthropic, oauth_redirect_uri);
}

pub fn beginOpenAICodexOAuth(alloc: std.mem.Allocator) !OAuthStart {
    return beginOAuth(alloc, .openai);
}

pub fn beginOpenAICodexOAuthWithRedirect(
    alloc: std.mem.Allocator,
    oauth_redirect_uri: []const u8,
) !OAuthStart {
    return beginOAuthWithRedirect(alloc, .openai, oauth_redirect_uri);
}

pub fn beginOAuth(alloc: std.mem.Allocator, provider: Provider) !OAuthStart {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    return beginOAuthWithSpec(alloc, spec, spec.default_redirect_uri);
}

pub fn beginOAuthWithRedirect(
    alloc: std.mem.Allocator,
    provider: Provider,
    oauth_redirect_uri: []const u8,
) !OAuthStart {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    return beginOAuthWithSpec(alloc, spec, oauth_redirect_uri);
}

fn beginOAuthWithSpec(
    alloc: std.mem.Allocator,
    spec: *const OAuthSpec,
    oauth_redirect_uri: []const u8,
) !OAuthStart {
    const verifier = try pkceVerifier(alloc);
    errdefer alloc.free(verifier);

    const challenge = try pkceChallenge(alloc, verifier);
    defer alloc.free(challenge);

    var query = std.ArrayList(u8).empty;
    defer query.deinit(alloc);

    try appendQueryParam(alloc, &query, "response_type", "code");
    try appendQueryParam(alloc, &query, "client_id", spec.client_id);
    try appendQueryParam(alloc, &query, "redirect_uri", oauth_redirect_uri);
    try appendQueryParam(alloc, &query, "scope", spec.scopes);
    try appendQueryParam(alloc, &query, "code_challenge", challenge);
    try appendQueryParam(alloc, &query, "code_challenge_method", "S256");
    try appendQueryParam(alloc, &query, "state", verifier);
    for (spec.extra_authorize) |extra| {
        try appendQueryParam(alloc, &query, extra.key, extra.value);
    }

    const url = try std.fmt.allocPrint(alloc, "{s}?{s}", .{ spec.authorize_url, query.items });
    errdefer alloc.free(url);

    return .{
        .url = url,
        .verifier = verifier,
    };
}

pub fn completeAnthropicOAuth(alloc: std.mem.Allocator, input: []const u8) !void {
    return completeOAuth(alloc, .anthropic, input);
}

pub fn completeAnthropicOAuthFromLocalCallback(
    alloc: std.mem.Allocator,
    callback: oauth_callback.CodeState,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
) !void {
    return completeOAuthFromLocalCallback(alloc, .anthropic, callback, oauth_redirect_uri, verifier);
}

pub fn completeOpenAICodexOAuth(alloc: std.mem.Allocator, input: []const u8) !void {
    return completeOAuth(alloc, .openai, input);
}

pub fn completeOpenAICodexOAuthFromLocalCallback(
    alloc: std.mem.Allocator,
    callback: oauth_callback.CodeState,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
) !void {
    return completeOAuthFromLocalCallback(alloc, .openai, callback, oauth_redirect_uri, verifier);
}

pub fn completeOAuth(alloc: std.mem.Allocator, provider: Provider, input: []const u8) !void {
    return completeOAuthWithHooks(alloc, provider, input, .{});
}

pub fn completeOAuthWithHooks(alloc: std.mem.Allocator, provider: Provider, input: []const u8, hooks: Hooks) !void {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    try emitAuthAudit(alloc, hooks, 1, provider, "login", "oauth", .ok, .info, .{ .text = "oauth login start", .vis = .@"pub" });

    var parsed = try parseOAuthInput(alloc, input);
    defer parsed.deinit(alloc);

    const state = parsed.state orelse return error.MissingOAuthState;
    if (state.len == 0) return error.MissingOAuthState;
    const oauth_redirect_uri = parsed.redirect_uri orelse spec.default_redirect_uri;

    // Manual completion path uses state as verifier (legacy code#state support).
    const oauth = hooks.exchange_code(alloc, spec, parsed.code, state, oauth_redirect_uri, state) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    defer {
        alloc.free(oauth.access);
        alloc.free(oauth.refresh);
    }
    saveOAuthForProviderWithHooks(alloc, provider, oauth, hooks) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .ok, .notice, .{ .text = "oauth login complete", .vis = .@"pub" });
}

pub fn completeOAuthFromLocalCallback(
    alloc: std.mem.Allocator,
    provider: Provider,
    callback: oauth_callback.CodeState,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
) !void {
    return completeOAuthFromLocalCallbackWithHooks(alloc, provider, callback, oauth_redirect_uri, verifier, .{});
}

pub fn completeOAuthFromLocalCallbackWithHooks(
    alloc: std.mem.Allocator,
    provider: Provider,
    callback: oauth_callback.CodeState,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
    hooks: Hooks,
) !void {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    if (!std.mem.eql(u8, callback.state, verifier)) return error.OAuthStateMismatch;
    try emitAuthAudit(alloc, hooks, 1, provider, "login", "oauth", .ok, .info, .{ .text = "oauth login start", .vis = .@"pub" });

    const oauth = hooks.exchange_code(
        alloc,
        spec,
        callback.code,
        callback.state,
        oauth_redirect_uri,
        verifier,
    ) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    defer {
        alloc.free(oauth.access);
        alloc.free(oauth.refresh);
    }
    saveOAuthForProviderWithHooks(alloc, provider, oauth, hooks) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    try emitAuthAudit(alloc, hooks, 2, provider, "login", "oauth", .ok, .notice, .{ .text = "oauth login complete", .vis = .@"pub" });
}

pub fn parseAnthropicOAuthInput(alloc: std.mem.Allocator, input: []const u8) !OAuthCodeInput {
    return parseOAuthInput(alloc, input);
}

pub fn parseOAuthInput(alloc: std.mem.Allocator, input: []const u8) !OAuthCodeInput {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidOAuthInput;

    if (std.mem.indexOf(u8, trimmed, "code=") != null) {
        const q_start = std.mem.indexOfScalar(u8, trimmed, '?');
        const query = if (q_start) |i| blk: {
            const hash_start = std.mem.indexOfScalarPos(u8, trimmed, i + 1, '#') orelse trimmed.len;
            break :blk trimmed[i + 1 .. hash_start];
        } else trimmed;

        var parsed = try oauth_callback.parseCodeStateQuery(alloc, query);
        errdefer parsed.deinit(alloc);

        const redirect_out = if (q_start) |i| blk: {
            const redirect_source = trimmed[0..i];
            if (std.mem.startsWith(u8, redirect_source, "http://") or std.mem.startsWith(u8, redirect_source, "https://")) {
                break :blk try alloc.dupe(u8, redirect_source);
            }
            break :blk null;
        } else null;
        errdefer if (redirect_out) |u| alloc.free(u);

        return .{
            .code = parsed.code,
            .state = parsed.state,
            .redirect_uri = redirect_out,
        };
    }

    if (std.mem.indexOfScalar(u8, trimmed, '#')) |i| {
        const code_in = std.mem.trim(u8, trimmed[0..i], " \t");
        const state_in = std.mem.trim(u8, trimmed[i + 1 ..], " \t");
        if (code_in.len == 0 or state_in.len == 0) return error.InvalidOAuthInput;
        return .{
            .code = try decodeQueryValue(alloc, code_in),
            .state = try decodeQueryValue(alloc, state_in),
            .redirect_uri = null,
        };
    }

    return .{
        .code = try decodeQueryValue(alloc, trimmed),
        .state = null,
        .redirect_uri = null,
    };
}

pub fn openBrowser(alloc: std.mem.Allocator, url: []const u8) !void {
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .macos => &.{ "open", url },
        .linux => &.{ "xdg-open", url },
        .windows => &.{ "cmd", "/c", "start", "", url },
        else => return error.UnsupportedPlatform,
    };

    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = argv,
        .max_output_bytes = 1024,
    }) catch return error.BrowserOpenFailed;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    switch (result.term) {
        .Exited => |code| {
            if (code != 0) return error.BrowserOpenFailed;
        },
        else => return error.BrowserOpenFailed,
    }
}

fn pkceVerifier(alloc: std.mem.Allocator) ![]u8 {
    var raw: [32]u8 = undefined;
    std.crypto.random.bytes(&raw);
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
    const out = try alloc.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    return out;
}

fn pkceChallenge(alloc: std.mem.Allocator, verifier: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(digest.len);
    const out = try alloc.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &digest);
    return out;
}

fn encodeQueryComponentAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (raw) |c| {
        const is_unreserved =
            (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (is_unreserved) {
            try out.append(alloc, c);
            continue;
        }
        try out.append(alloc, '%');
        try out.append(alloc, hexUpper((c >> 4) & 0x0f));
        try out.append(alloc, hexUpper(c & 0x0f));
    }
    return out.toOwnedSlice(alloc);
}

fn appendQueryParam(alloc: std.mem.Allocator, out: *std.ArrayList(u8), key: []const u8, value: []const u8) !void {
    if (out.items.len > 0) try out.append(alloc, '&');
    try out.appendSlice(alloc, key);
    try out.append(alloc, '=');
    const enc = try encodeQueryComponentAlloc(alloc, value);
    defer alloc.free(enc);
    try out.appendSlice(alloc, enc);
}

fn encodeFormComponentAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    for (raw) |c| {
        const is_unreserved =
            (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_' or c == '.' or c == '~';
        if (is_unreserved) {
            try out.append(alloc, c);
            continue;
        }
        if (c == ' ') {
            try out.append(alloc, '+');
            continue;
        }
        try out.append(alloc, '%');
        try out.append(alloc, hexUpper((c >> 4) & 0x0f));
        try out.append(alloc, hexUpper(c & 0x0f));
    }
    return out.toOwnedSlice(alloc);
}

fn hexUpper(v: u8) u8 {
    return if (v < 10) ('0' + v) else ('A' + (v - 10));
}

const TokenReq = struct {
    content_type: []const u8,
    body: []const u8,
};

fn tokenReqContentType(spec: *const OAuthSpec) []const u8 {
    return switch (spec.token_body) {
        .json_with_state => "application/json",
        .form_no_state => "application/x-www-form-urlencoded",
    };
}

fn buildTokenReqBody(
    ar: std.mem.Allocator,
    spec: *const OAuthSpec,
    code: []const u8,
    state: []const u8,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
) !TokenReq {
    return switch (spec.token_body) {
        .json_with_state => blk: {
            const Body = struct {
                grant_type: []const u8,
                client_id: []const u8,
                code: []const u8,
                state: []const u8,
                redirect_uri: []const u8,
                code_verifier: []const u8,
            };
            break :blk .{
                .content_type = tokenReqContentType(spec),
                .body = try std.json.Stringify.valueAlloc(ar, Body{
                    .grant_type = "authorization_code",
                    .client_id = spec.client_id,
                    .code = code,
                    .state = state,
                    .redirect_uri = oauth_redirect_uri,
                    .code_verifier = verifier,
                }, .{}),
            };
        },
        .form_no_state => blk: {
            const code_enc = try encodeFormComponentAlloc(ar, code);
            const verifier_enc = try encodeFormComponentAlloc(ar, verifier);
            const redirect_enc = try encodeFormComponentAlloc(ar, oauth_redirect_uri);
            break :blk .{
                .content_type = tokenReqContentType(spec),
                .body = try std.fmt.allocPrint(
                    ar,
                    "grant_type=authorization_code&client_id={s}&code={s}&code_verifier={s}&redirect_uri={s}",
                    .{ spec.client_id, code_enc, verifier_enc, redirect_enc },
                ),
            };
        },
    };
}

fn buildRefreshReqBody(
    ar: std.mem.Allocator,
    spec: *const OAuthSpec,
    refresh_token: []const u8,
) !TokenReq {
    return switch (spec.token_body) {
        .json_with_state => blk: {
            const Body = struct {
                grant_type: []const u8,
                client_id: []const u8,
                refresh_token: []const u8,
            };
            break :blk .{
                .content_type = tokenReqContentType(spec),
                .body = try std.json.Stringify.valueAlloc(ar, Body{
                    .grant_type = "refresh_token",
                    .client_id = spec.client_id,
                    .refresh_token = refresh_token,
                }, .{}),
            };
        },
        .form_no_state => blk: {
            const refresh_enc = try encodeFormComponentAlloc(ar, refresh_token);
            break :blk .{
                .content_type = tokenReqContentType(spec),
                .body = try std.fmt.allocPrint(
                    ar,
                    "grant_type=refresh_token&client_id={s}&refresh_token={s}",
                    .{ spec.client_id, refresh_enc },
                ),
            };
        },
    };
}

fn parseOAuthTokenResponse(
    alloc: std.mem.Allocator,
    ar: std.mem.Allocator,
    resp_body: []const u8,
    parse_err: anyerror,
) !OAuth {
    const parsed = std.json.parseFromSlice(struct {
        access_token: []const u8,
        refresh_token: []const u8,
        expires_in: i64,
    }, ar, resp_body, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return parse_err;

    const now_ms = std.time.milliTimestamp();
    const expires = now_ms + parsed.value.expires_in * 1000 - 5 * 60 * 1000;

    const access = try alloc.dupe(u8, parsed.value.access_token);
    errdefer alloc.free(access);
    const refresh = try alloc.dupe(u8, parsed.value.refresh_token);
    errdefer alloc.free(refresh);

    return .{
        .access = access,
        .refresh = refresh,
        .expires = expires,
    };
}

fn exchangeAuthorizationCode(
    alloc: std.mem.Allocator,
    spec: *const OAuthSpec,
    code: []const u8,
    state: []const u8,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
) !OAuth {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const token_req = try buildTokenReqBody(ar, spec, code, state, oauth_redirect_uri, verifier);

    var http = std.http.Client{ .allocator = ar };
    defer http.deinit();

    const uri = std.Uri{
        .scheme = "https",
        .host = .{ .raw = spec.token_host },
        .path = .{ .raw = spec.token_path },
    };

    var send_buf: [1024]u8 = undefined;
    var req = try http.request(.POST, uri, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = token_req.content_type },
        },
        .keep_alive = false,
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = token_req.body.len };
    var bw = try req.sendBodyUnflushed(&send_buf);
    try bw.writer.writeAll(token_req.body);
    try bw.end();
    try req.connection.?.flush();

    var redir_buf: [0]u8 = .{};
    var resp = try req.receiveHead(&redir_buf);

    if (resp.head.status != .ok) return error.TokenExchangeFailed;

    var transfer_buf: [16384]u8 = undefined;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const rdr = resp.readerDecompressing(&transfer_buf, &decomp, &decomp_buf);
    const resp_body = try rdr.allocRemaining(ar, .limited(65536));

    return parseOAuthTokenResponse(alloc, ar, resp_body, error.TokenExchangeFailed);
}

fn decodeQueryValue(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const c = raw[i];
        if (c == '+') {
            try out.append(alloc, ' ');
            continue;
        }
        if (c != '%') {
            try out.append(alloc, c);
            continue;
        }
        if (i + 2 >= raw.len) return error.InvalidOAuthInput;
        const hi = fromHex(raw[i + 1]) orelse return error.InvalidOAuthInput;
        const lo = fromHex(raw[i + 2]) orelse return error.InvalidOAuthInput;
        try out.append(alloc, (hi << 4) | lo);
        i += 2;
    }
    return out.toOwnedSlice(alloc);
}

fn fromHex(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Refresh an expired OAuth token. Returns new OAuth credentials and saves to disk.
pub fn refreshOAuth(alloc: std.mem.Allocator, old: OAuth) !OAuth {
    return refreshOAuthForProvider(alloc, .anthropic, old);
}

/// Refresh an expired OAuth token for a specific provider.
pub fn refreshOAuthForProvider(alloc: std.mem.Allocator, provider: Provider, old: OAuth) !OAuth {
    return refreshOAuthForProviderWithHooks(alloc, provider, old, .{});
}

fn refreshOAuthForProviderWithHooks(alloc: std.mem.Allocator, provider: Provider, old: OAuth, hooks: Hooks) !OAuth {
    try emitAuthAudit(alloc, hooks, 1, provider, "refresh", "oauth", .ok, .info, .{ .text = "oauth refresh start", .vis = .@"pub" });
    const new_oauth = hooks.refresh_fetch(alloc, provider, old) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "refresh", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    errdefer {
        alloc.free(new_oauth.access);
        alloc.free(new_oauth.refresh);
    }
    saveOAuthForProviderWithHooks(alloc, provider, new_oauth, hooks) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "refresh", "oauth", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    try emitAuthAudit(alloc, hooks, 2, provider, "refresh", "oauth", .ok, .notice, .{ .text = "oauth refresh complete", .vis = .@"pub" });
    return new_oauth;
}

fn fetchRefreshedOAuthForProvider(alloc: std.mem.Allocator, provider: Provider, old: OAuth) !OAuth {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const req_body = try buildRefreshReqBody(ar, spec, old.refresh);

    var http = std.http.Client{ .allocator = ar };
    defer http.deinit();

    const uri = std.Uri{
        .scheme = "https",
        .host = .{ .raw = spec.token_host },
        .path = .{ .raw = spec.token_path },
    };

    var send_buf: [1024]u8 = undefined;
    var req = try http.request(.POST, uri, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = req_body.content_type },
        },
        .keep_alive = false,
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = req_body.body.len };
    var bw = try req.sendBodyUnflushed(&send_buf);
    try bw.writer.writeAll(req_body.body);
    try bw.end();
    try req.connection.?.flush();

    var redir_buf: [0]u8 = .{};
    var resp = try req.receiveHead(&redir_buf);

    if (resp.head.status != .ok) return error.RefreshFailed;

    var transfer_buf: [16384]u8 = undefined;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const rdr = resp.readerDecompressing(&transfer_buf, &decomp, &decomp_buf);
    const resp_body = try rdr.allocRemaining(ar, .limited(65536));

    const new_oauth = try parseOAuthTokenResponse(alloc, ar, resp_body, error.RefreshFailed);
    return new_oauth;
}

fn saveOAuthForProviderWithHooks(alloc: std.mem.Allocator, provider: Provider, oauth: OAuth, hooks: Hooks) !void {
    if (hooks.home_override) |home| return saveOAuthForProviderHome(alloc, home, provider, oauth);
    const home = try hooks.get_home(alloc, "HOME");
    defer alloc.free(home);
    return saveOAuthForProviderHome(alloc, home, provider, oauth);
}

fn saveOAuthForProviderHome(alloc: std.mem.Allocator, home: []const u8, provider: Provider, oauth: OAuth) !void {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const home_dup = try ar.dupe(u8, home);
    const dir_path = try primaryAuthDir(ar, home_dup);
    try fs_secure.ensureDirPath(dir_path);
    const path = try authFilePath(ar, home_dup);

    var auth_file: AuthFile = .{};
    // Load existing
    if (std.fs.cwd().readFileAlloc(ar, path, 1024 * 1024)) |raw| {
        if (std.json.parseFromSlice(AuthFile, ar, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        })) |parsed| {
            auth_file = parsed.value;
        } else |_| {}
    } else |_| {}

    const entry: AuthEntry = .{
        .type = "oauth",
        .access = oauth.access,
        .refresh = oauth.refresh,
        .expires = oauth.expires,
    };
    switch (provider) {
        .anthropic => auth_file.anthropic = entry,
        .openai => auth_file.openai = entry,
        .google => auth_file.google = entry,
    }

    const out = try std.json.Stringify.valueAlloc(ar, auth_file, .{ .whitespace = .indent_2 });
    const file = try fs_secure.createFilePath(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(out);
}

/// List providers that have credentials stored (merges all auth files).
pub fn listLoggedIn(alloc: std.mem.Allocator) ![]Provider {
    const home = std.process.getEnvVarOwned(alloc, "HOME") catch return try alloc.alloc(Provider, 0);
    defer alloc.free(home);
    return listLoggedInHome(alloc, home);
}

fn listLoggedInHome(alloc: std.mem.Allocator, home: []const u8) ![]Provider {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    var merged: AuthFile = .{};
    const path = authFilePath(ar, home) catch return try alloc.alloc(Provider, 0);
    const raw = std.fs.cwd().readFileAlloc(ar, path, 1024 * 1024) catch return try alloc.alloc(Provider, 0);
    const parsed = std.json.parseFromSlice(AuthFile, ar, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch return try alloc.alloc(Provider, 0);
    merged.anthropic = parsed.value.anthropic;
    merged.openai = parsed.value.openai;
    merged.google = parsed.value.google;

    var result = std.ArrayList(Provider).empty;
    errdefer result.deinit(alloc);
    if (merged.anthropic != null) try result.append(alloc, .anthropic);
    if (merged.openai != null) try result.append(alloc, .openai);
    if (merged.google != null) try result.append(alloc, .google);
    return try result.toOwnedSlice(alloc);
}

/// Remove credentials for a provider from all auth files.
pub fn logout(alloc: std.mem.Allocator, provider: Provider) !void {
    return logoutWithHooks(alloc, provider, .{});
}

pub fn logoutWithHooks(alloc: std.mem.Allocator, provider: Provider, hooks: Hooks) !void {
    const home = if (hooks.home_override) |path|
        try alloc.dupe(u8, path)
    else
        try hooks.get_home(alloc, "HOME");
    defer alloc.free(home);
    return logoutHomeWithHooks(alloc, home, provider, hooks);
}

fn logoutHomeWithHooks(alloc: std.mem.Allocator, home: []const u8, provider: Provider, hooks: Hooks) !void {
    try emitAuthAudit(alloc, hooks, 1, provider, "logout", "stored", .ok, .info, .{ .text = "logout start", .vis = .@"pub" });
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const home_dup = try ar.dupe(u8, home);
    const path = try authFilePath(ar, home_dup);
    const raw = std.fs.cwd().readFileAlloc(ar, path, 1024 * 1024) catch |err| {
        if (err == error.FileNotFound) {
            try emitAuthAudit(alloc, hooks, 2, provider, "logout", "stored", .ok, .notice, .{ .text = "logout noop", .vis = .@"pub" });
            return;
        }
        try emitAuthAudit(alloc, hooks, 2, provider, "logout", "stored", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    var parsed = std.json.parseFromSlice(AuthFile, ar, raw, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) catch {
        try emitAuthAudit(alloc, hooks, 2, provider, "logout", "stored", .ok, .notice, .{ .text = "logout noop", .vis = .@"pub" });
        return;
    };

    switch (provider) {
        .anthropic => parsed.value.anthropic = null,
        .openai => parsed.value.openai = null,
        .google => parsed.value.google = null,
    }

    const out = try std.json.Stringify.valueAlloc(ar, parsed.value, .{ .whitespace = .indent_2 });
    const file = try fs_secure.createFilePath(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(out);
    try emitAuthAudit(alloc, hooks, 2, provider, "logout", "stored", .ok, .notice, .{ .text = "logout complete", .vis = .@"pub" });
}

/// Save API key for a provider. Writes to primary auth dir (~/.pz/).
pub fn saveApiKey(alloc: std.mem.Allocator, provider: Provider, key: []const u8) !void {
    return saveApiKeyWithHooks(alloc, provider, key, .{});
}

pub fn saveApiKeyWithHooks(alloc: std.mem.Allocator, provider: Provider, key: []const u8, hooks: Hooks) !void {
    const home = if (hooks.home_override) |path|
        try alloc.dupe(u8, path)
    else
        try hooks.get_home(alloc, "HOME");
    defer alloc.free(home);
    return saveApiKeyHomeWithHooks(alloc, home, provider, key, hooks);
}

fn saveApiKeyHome(alloc: std.mem.Allocator, home: []const u8, provider: Provider, key: []const u8) !void {
    return saveApiKeyHomeWithHooks(alloc, home, provider, key, .{});
}

fn saveApiKeyHomeWithHooks(alloc: std.mem.Allocator, home: []const u8, provider: Provider, key: []const u8, hooks: Hooks) !void {
    try emitAuthAudit(alloc, hooks, 1, provider, "save_api_key", "api_key", .ok, .info, .{ .text = "api key save start", .vis = .@"pub" });
    saveApiKeyHomeRaw(alloc, home, provider, key) catch |err| {
        try emitAuthAudit(alloc, hooks, 2, provider, "save_api_key", "api_key", .fail, .err, .{ .text = @errorName(err), .vis = .mask });
        return err;
    };
    try emitAuthAudit(alloc, hooks, 2, provider, "save_api_key", "api_key", .ok, .notice, .{ .text = "api key save complete", .vis = .@"pub" });
}

fn saveApiKeyHomeRaw(alloc: std.mem.Allocator, home: []const u8, provider: Provider, key: []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const home_dup = try ar.dupe(u8, home);
    const dir_path = try primaryAuthDir(ar, home_dup);
    try fs_secure.ensureDirPath(dir_path);
    const path = try authFilePath(ar, home_dup);

    var auth_file: AuthFile = .{};
    // Try loading existing
    if (std.fs.cwd().readFileAlloc(ar, path, 1024 * 1024)) |raw| {
        if (std.json.parseFromSlice(AuthFile, ar, raw, .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = true,
        })) |parsed| {
            auth_file = parsed.value;
        } else |_| {}
    } else |_| {}

    const entry = AuthEntry{ .type = "api_key", .key = key };
    switch (provider) {
        .anthropic => auth_file.anthropic = entry,
        .openai => auth_file.openai = entry,
        .google => auth_file.google = entry,
    }

    const out = try std.json.Stringify.valueAlloc(ar, auth_file, .{ .whitespace = .indent_2 });
    const file = try fs_secure.createFilePath(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(out);
}

fn emitAuthAudit(
    alloc: std.mem.Allocator,
    hooks: Hooks,
    seq: u64,
    provider: Provider,
    op: []const u8,
    mech: []const u8,
    out: audit.Out,
    sev: audit.Sev,
    msg: audit.Str,
) !void {
    if (hooks.emit_audit) |emit| try emit(hooks.emit_audit_ctx.?, alloc, .{
        .ts_ms = hooks.now_ms(),
        .sid = "auth",
        .seq = seq,
        .out = out,
        .sev = sev,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .auth,
            .name = .{ .text = providerName(provider), .vis = .@"pub" },
            .op = op,
        },
        .msg = msg,
        .data = .{
            .auth = .{
                .mech = mech,
                .sub = .{ .text = providerName(provider), .vis = .@"pub" },
            },
        },
    });
}

test "saveApiKeyHome writes provider auth without process HOME" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    try saveApiKeyHome(std.testing.allocator, home, .openai, "sk-openai");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const auth = try loadFileAuthForProvider(arena.allocator(), home, .openai);
    switch (auth) {
        .api_key => |key| try std.testing.expectEqualStrings("sk-openai", key),
        else => return error.TestUnexpectedResult,
    }

    if (builtin.os.tag != .windows) {
        const st = try tmp.dir.statFile(".pz/auth.json");
        try std.testing.expectEqual(@as(std.fs.File.Mode, fs_secure.file_mode), st.mode & 0o777);
    }
}

const AuditRows = struct {
    rows: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        for (self.rows.items) |row| alloc.free(row);
        self.rows.deinit(alloc);
    }

    fn emit(ctx: *anyopaque, alloc: std.mem.Allocator, ent: audit.Entry) !void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const raw = try audit.encodeAlloc(alloc, ent);
        try self.rows.append(alloc, raw);
    }
};

test "auth audit covers api key save" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    try saveApiKeyHomeWithHooks(std.testing.allocator, home, .openai, "sk-openai", .{
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 11;
            }
        }.f,
    });

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":11,"sid":"auth","seq":1,"kind":"auth","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"openai","vis":"pub"},"op":"save_api_key"},"msg":{"text":"api key save start","vis":"pub"},"data":{"mech":"api_key","sub":{"text":"openai","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":11,"sid":"auth","seq":2,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"openai","vis":"pub"},"op":"save_api_key"},"msg":{"text":"api key save complete","vis":"pub"},"data":{"mech":"api_key","sub":{"text":"openai","vis":"pub"}},"attrs":[]}"
    ).expectEqual(joined);
}

test "auth audit covers oauth login and persistence" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    try completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=abc&state=def", .{
        .home_override = home,
        .exchange_code = struct {
            fn f(alloc: std.mem.Allocator, _: *const OAuthSpec, _: []const u8, _: []const u8, _: []const u8, _: []const u8) !OAuth {
                return .{
                    .access = try alloc.dupe(u8, "oa-access"),
                    .refresh = try alloc.dupe(u8, "oa-refresh"),
                    .expires = 123,
                };
            }
        }.f,
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 22;
            }
        }.f,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const auth = try loadFileAuthForProvider(arena.allocator(), home, .anthropic);
    try oh.snap(@src(),
        \\core.providers.auth.Auth
        \\  .oauth: core.providers.auth.OAuth
        \\    .access: []const u8
        \\      "oa-access"
        \\    .refresh: []const u8
        \\      "oa-refresh"
        \\    .expires: i64 = 123
    ).expectEqual(auth);

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":22,"sid":"auth","seq":1,"kind":"auth","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"anthropic","vis":"pub"},"op":"login"},"msg":{"text":"oauth login start","vis":"pub"},"data":{"mech":"oauth","sub":{"text":"anthropic","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":22,"sid":"auth","seq":2,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"anthropic","vis":"pub"},"op":"login"},"msg":{"text":"oauth login complete","vis":"pub"},"data":{"mech":"oauth","sub":{"text":"anthropic","vis":"pub"}},"attrs":[]}"
    ).expectEqual(joined);
}

test "auth audit covers oauth refresh and persistence" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    const got = try refreshOAuthForProviderWithHooks(std.testing.allocator, .openai, .{
        .access = "old-a",
        .refresh = "old-r",
        .expires = 1,
    }, .{
        .home_override = home,
        .refresh_fetch = struct {
            fn f(alloc: std.mem.Allocator, _: Provider, _: OAuth) !OAuth {
                return .{
                    .access = try alloc.dupe(u8, "new-a"),
                    .refresh = try alloc.dupe(u8, "new-r"),
                    .expires = 999,
                };
            }
        }.f,
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 33;
            }
        }.f,
    });
    defer {
        std.testing.allocator.free(got.access);
        std.testing.allocator.free(got.refresh);
    }

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":33,"sid":"auth","seq":1,"kind":"auth","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"openai","vis":"pub"},"op":"refresh"},"msg":{"text":"oauth refresh start","vis":"pub"},"data":{"mech":"oauth","sub":{"text":"openai","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":33,"sid":"auth","seq":2,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"openai","vis":"pub"},"op":"refresh"},"msg":{"text":"oauth refresh complete","vis":"pub"},"data":{"mech":"oauth","sub":{"text":"openai","vis":"pub"}},"attrs":[]}"
    ).expectEqual(joined);
}

test "auth audit covers logout" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);
    try saveApiKeyHome(std.testing.allocator, home, .anthropic, "sk-ant");

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    try logoutHomeWithHooks(std.testing.allocator, home, .anthropic, .{
        .emit_audit_ctx = &rows,
        .emit_audit = AuditRows.emit,
        .now_ms = struct {
            fn f() i64 {
                return 44;
            }
        }.f,
    });

    const joined = try std.mem.join(std.testing.allocator, "\n", rows.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":44,"sid":"auth","seq":1,"kind":"auth","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"anthropic","vis":"pub"},"op":"logout"},"msg":{"text":"logout start","vis":"pub"},"data":{"mech":"stored","sub":{"text":"anthropic","vis":"pub"}},"attrs":[]}
        \\{"v":1,"ts_ms":44,"sid":"auth","seq":2,"kind":"auth","sev":"notice","out":"ok","actor":{"kind":"sys"},"res":{"kind":"auth","name":{"text":"anthropic","vis":"pub"},"op":"logout"},"msg":{"text":"logout complete","vis":"pub"},"data":{"mech":"stored","sub":{"text":"anthropic","vis":"pub"}},"attrs":[]}"
    ).expectEqual(joined);
}

test "listLoggedInHome returns stored providers without leaks" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    try saveApiKeyHome(std.testing.allocator, home, .anthropic, "sk-ant");
    try saveApiKeyHome(std.testing.allocator, home, .openai, "sk-openai");

    const providers = try listLoggedInHome(std.testing.allocator, home);
    defer std.testing.allocator.free(providers);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    const w = out.writer(std.testing.allocator);
    for (providers) |provider| {
        try w.print("{s}\n", .{providerName(provider)});
    }

    try oh.snap(@src(),
        \\[]u8
        \\  "anthropic
        \\openai
        \\"
    ).expectEqual(out.items);
}

test "authFromEnv prefers oauth token over api key" {
    const auth = authFromEnv(.{
        .oauth = "sk-ant-oat-123",
        .api_key = "sk-ant-123",
    }) orelse return error.TestUnexpectedResult;
    switch (auth) {
        .oauth => |oauth| {
            try std.testing.expectEqualStrings("sk-ant-oat-123", oauth.access);
            try std.testing.expectEqualStrings("", oauth.refresh);
            try std.testing.expectEqual(@as(i64, oauth_no_expiry), oauth.expires);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "authFromEnv uses api key when oauth token is missing" {
    const auth = authFromEnv(.{
        .oauth = null,
        .api_key = "sk-ant-123",
    }) orelse return error.TestUnexpectedResult;
    switch (auth) {
        .api_key => |key| try std.testing.expectEqualStrings("sk-ant-123", key),
        else => return error.TestUnexpectedResult,
    }
}

test "loadFileAuth parses anthropic api_key entry" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{
        .sub_path = ".pz/auth.json",
        .data =
        \\{
        \\  "anthropic": {
        \\    "type": "api_key",
        \\    "key": "sk-ant-file"
        \\  }
        \\}
        ,
    });

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const auth = try loadFileAuth(arena.allocator(), home);
    switch (auth) {
        .api_key => |key| try std.testing.expectEqualStrings("sk-ant-file", key),
        else => return error.TestUnexpectedResult,
    }
}

test "loadFileAuth returns AuthNotFound when file is missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = loadFileAuth(arena.allocator(), home);
    try std.testing.expectError(error.AuthNotFound, res);
}

test "loadFileAuthForProvider parses openai oauth entry" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{
        .sub_path = ".pz/auth.json",
        .data =
        \\{
        \\  "openai": {
        \\    "type": "oauth",
        \\    "access": "oa-access",
        \\    "refresh": "oa-refresh",
        \\    "expires": 123
        \\  }
        \\}
        ,
    });

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const auth = try loadFileAuthForProvider(arena.allocator(), home, .openai);
    try oh.snap(@src(),
        \\core.providers.auth.Auth
        \\  .oauth: core.providers.auth.OAuth
        \\    .access: []const u8
        \\      "oa-access"
        \\    .refresh: []const u8
        \\      "oa-refresh"
        \\    .expires: i64 = 123
    ).expectEqual(auth);
}

test "loadFileAuthForProvider returns AuthNotFound when provider missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{
        .sub_path = ".pz/auth.json",
        .data =
        \\{
        \\  "anthropic": {
        \\    "type": "api_key",
        \\    "key": "sk-ant-file"
        \\  }
        \\}
        ,
    });

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.AuthNotFound, loadFileAuthForProvider(arena.allocator(), home, .openai));
}

test "oauth helpers expose provider capabilities and metadata" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    try std.testing.expect(oauthCapable(.anthropic));
    try std.testing.expect(oauthCapable(.openai));
    try std.testing.expect(!oauthCapable(.google));

    try std.testing.expect(looksLikeApiKey(.anthropic, "sk-ant-api03-abc"));
    try std.testing.expect(!looksLikeApiKey(.anthropic, "http://localhost/callback?code=x&state=y"));
    try std.testing.expect(looksLikeApiKey(.openai, "sk-proj-123"));
    try std.testing.expect(!looksLikeApiKey(.openai, "http://localhost/callback?code=x&state=y"));
    try std.testing.expect(looksLikeApiKey(.google, "anything"));

    const anth = oauthLoginInfo(.anthropic) orelse return error.TestUnexpectedResult;
    try oh.snap(@src(),
        \\core.providers.auth.OAuthLoginInfo
        \\  .callback_path: []const u8
        \\    "/callback"
        \\  .start_action: []const u8
        \\    "start anthropic oauth"
        \\  .complete_action: []const u8
        \\    "complete anthropic oauth"
    ).expectEqual(anth);

    const oa = oauthLoginInfo(.openai) orelse return error.TestUnexpectedResult;
    try oh.snap(@src(),
        \\core.providers.auth.OAuthLoginInfo
        \\  .callback_path: []const u8
        \\    "/auth/callback"
        \\  .start_action: []const u8
        \\    "start openai oauth"
        \\  .complete_action: []const u8
        \\    "complete openai oauth"
    ).expectEqual(oa);

    try std.testing.expect(oauthLoginInfo(.google) == null);
}

test "beginAnthropicOAuth builds authorization URL and verifier" {
    var flow = try beginAnthropicOAuth(std.testing.allocator);
    defer flow.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.startsWith(u8, flow.url, "https://claude.ai/oauth/authorize?"));
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "code_challenge=") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "state=") != null);
    try std.testing.expect(flow.verifier.len > 16);
}

test "beginAnthropicOAuthWithRedirect encodes localhost callback URI" {
    var flow = try beginAnthropicOAuthWithRedirect(std.testing.allocator, "http://127.0.0.1:54321/callback");
    defer flow.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, flow.url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback") != null);
}

test "beginOpenAICodexOAuthWithRedirect encodes callback URI and codex params" {
    var flow = try beginOpenAICodexOAuthWithRedirect(std.testing.allocator, "http://127.0.0.1:54321/auth/callback");
    defer flow.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.startsWith(u8, flow.url, "https://auth.openai.com/oauth/authorize?"));
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "client_id=app_EMoamEEZ73f0CkXaXp7hrann") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fauth%2Fcallback") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "codex_cli_simplified_flow=true") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "originator=pz") != null);
}

test "beginOAuthWithRedirect rejects unsupported provider" {
    try std.testing.expectError(
        error.UnsupportedOAuthProvider,
        beginOAuthWithRedirect(std.testing.allocator, .google, "http://127.0.0.1:1234/callback"),
    );
}

test "parseAnthropicOAuthInput supports code#state" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseAnthropicOAuthInput(std.testing.allocator, "abc123#state456");
    defer parsed.deinit(std.testing.allocator);

    try oh.snap(@src(),
        \\core.providers.auth.OAuthCodeInput
        \\  .code: []u8
        \\    "abc123"
        \\  .state: ?[]u8
        \\    "state456"
        \\  .redirect_uri: ?[]u8
        \\    null
    ).expectEqual(parsed);
}

test "parseAnthropicOAuthInput supports callback URL query params" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const input = "http://localhost:64915/callback?code=abc123&state=state%20456";
    var parsed = try parseAnthropicOAuthInput(std.testing.allocator, input);
    defer parsed.deinit(std.testing.allocator);

    try oh.snap(@src(),
        \\core.providers.auth.OAuthCodeInput
        \\  .code: []u8
        \\    "abc123"
        \\  .state: ?[]u8
        \\    "state 456"
        \\  .redirect_uri: ?[]u8
        \\    "http://localhost:64915/callback"
    ).expectEqual(parsed);
}

test "parseOAuthInput decodes escaped callback code and state" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const input = "http://127.0.0.1:1455/auth/callback?code=ab%2Bcd%2Fef&state=st%2B1%2F2";
    var parsed = try parseOAuthInput(std.testing.allocator, input);
    defer parsed.deinit(std.testing.allocator);

    try oh.snap(@src(),
        \\core.providers.auth.OAuthCodeInput
        \\  .code: []u8
        \\    "ab+cd/ef"
        \\  .state: ?[]u8
        \\    "st+1/2"
        \\  .redirect_uri: ?[]u8
        \\    "http://127.0.0.1:1455/auth/callback"
    ).expectEqual(parsed);
}

test "parseAnthropicOAuthInput supports raw query params" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseAnthropicOAuthInput(std.testing.allocator, "code=abc123&state=state%20456");
    defer parsed.deinit(std.testing.allocator);

    try oh.snap(@src(),
        \\core.providers.auth.OAuthCodeInput
        \\  .code: []u8
        \\    "abc123"
        \\  .state: ?[]u8
        \\    "state 456"
        \\  .redirect_uri: ?[]u8
        \\    null
    ).expectEqual(parsed);
}

test "parseAnthropicOAuthInput accepts code-only input" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseAnthropicOAuthInput(std.testing.allocator, "abc123");
    defer parsed.deinit(std.testing.allocator);

    try oh.snap(@src(),
        \\core.providers.auth.OAuthCodeInput
        \\  .code: []u8
        \\    "abc123"
        \\  .state: ?[]u8
        \\    null
        \\  .redirect_uri: ?[]u8
        \\    null
    ).expectEqual(parsed);
}

test "parseAnthropicOAuthInput rejects empty input" {
    try std.testing.expectError(error.InvalidOAuthInput, parseAnthropicOAuthInput(std.testing.allocator, " \t\r\n"));
}

test "completeAnthropicOAuthFromLocalCallback rejects mismatched state" {
    const code = try std.testing.allocator.dupe(u8, "c");
    defer std.testing.allocator.free(code);
    const state = try std.testing.allocator.dupe(u8, "state-a");
    defer std.testing.allocator.free(state);
    const cb = oauth_callback.CodeState{
        .code = code,
        .state = state,
    };
    try std.testing.expectError(
        error.OAuthStateMismatch,
        completeAnthropicOAuthFromLocalCallback(
            std.testing.allocator,
            cb,
            "http://127.0.0.1:1234/callback",
            "state-b",
        ),
    );
}

test "completeOpenAICodexOAuthFromLocalCallback rejects mismatched state" {
    const code = try std.testing.allocator.dupe(u8, "c");
    defer std.testing.allocator.free(code);
    const state = try std.testing.allocator.dupe(u8, "state-a");
    defer std.testing.allocator.free(state);
    const cb = oauth_callback.CodeState{
        .code = code,
        .state = state,
    };
    try std.testing.expectError(
        error.OAuthStateMismatch,
        completeOpenAICodexOAuthFromLocalCallback(
            std.testing.allocator,
            cb,
            "http://127.0.0.1:1234/auth/callback",
            "state-b",
        ),
    );
}

test "completeOAuthFromLocalCallback rejects unsupported provider" {
    const code = try std.testing.allocator.dupe(u8, "c");
    defer std.testing.allocator.free(code);
    const state = try std.testing.allocator.dupe(u8, "state-a");
    defer std.testing.allocator.free(state);
    const cb = oauth_callback.CodeState{
        .code = code,
        .state = state,
    };
    try std.testing.expectError(
        error.UnsupportedOAuthProvider,
        completeOAuthFromLocalCallback(
            std.testing.allocator,
            .google,
            cb,
            "http://127.0.0.1:1234/callback",
            "state-a",
        ),
    );
}

test "tokenReqContentType maps oauth token body types" {
    try std.testing.expectEqualStrings("application/json", tokenReqContentType(&anthropic_spec));
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", tokenReqContentType(&openai_spec));
}

test "buildRefreshReqBody uses provider-specific body shape" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const anth = try buildRefreshReqBody(ar, &anthropic_spec, "rt-1");
    try std.testing.expectEqualStrings("application/json", anth.content_type);
    try std.testing.expect(std.mem.indexOf(u8, anth.body, "\"grant_type\":\"refresh_token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, anth.body, "\"refresh_token\":\"rt-1\"") != null);

    const oa = try buildRefreshReqBody(ar, &openai_spec, "rt 2");
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", oa.content_type);
    try std.testing.expect(std.mem.indexOf(u8, oa.body, "grant_type=refresh_token") != null);
    try std.testing.expect(std.mem.indexOf(u8, oa.body, "refresh_token=rt+2") != null);
}

test "buildTokenReqBody form body escapes reserved characters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const req = try buildTokenReqBody(
        ar,
        &openai_spec,
        "ab+cd/ef",
        "unused",
        "http://127.0.0.1:1455/auth/callback?q=a+b",
        "v+1/2",
    );
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", req.content_type);
    try std.testing.expect(std.mem.indexOf(u8, req.body, "grant_type=authorization_code") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body, "code=ab%2Bcd%2Fef") != null);
    try std.testing.expect(std.mem.indexOf(u8, req.body, "code_verifier=v%2B1%2F2") != null);
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            req.body,
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback%3Fq%3Da%2Bb",
        ) != null,
    );
}

test "refreshOAuthForProvider rejects unsupported provider" {
    const old = OAuth{
        .access = "a",
        .refresh = "r",
        .expires = 0,
    };
    try std.testing.expectError(
        error.UnsupportedOAuthProvider,
        refreshOAuthForProvider(std.testing.allocator, .google, old),
    );
}
