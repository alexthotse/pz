//! OAuth protocol: begin/complete flows, PKCE, token exchange, refresh.
const std = @import("std");
const builtin = @import("builtin");
const oauth_callback = @import("oauth_callback.zig");
const audit = @import("../audit.zig");
const core_tls = @import("../tls.zig");
const url_codec = @import("../url.zig");
const auth = @import("auth.zig");
const auth_load = @import("auth_load.zig");

const Auth = auth.Auth;
const OAuth = auth.OAuth;
const Provider = auth.Provider;
const Hooks = auth.Hooks;
const OAuthStart = auth.OAuthStart;
const OAuthCodeInput = auth.OAuthCodeInput;

const OAuthTokenBody = auth.OAuthTokenBody;
const OAuthParam = auth.OAuthParam;
const OAuthSpec = auth.OAuthSpec;

const providerName = auth.providerName;
const emitAuthAudit = auth_load.emitAuthAudit;
const resolveHome = auth_load.resolveHome;
const saveOAuthForProviderWithHooks = auth_load.saveOAuthForProviderWithHooks;

// ── Spec constants ─────────────────────────────────────────────────────

const openai_oauth_extra_authorize = [_]OAuthParam{
    .{ .key = "id_token_add_organizations", .value = "true" },
    .{ .key = "codex_cli_simplified_flow", .value = "true" },
    .{ .key = "originator", .value = "pz" },
};

pub const anthropic_spec = OAuthSpec{
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

pub const openai_spec = OAuthSpec{
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

pub fn oauthSpec(provider: Provider) ?*const OAuthSpec {
    return switch (provider) {
        .anthropic => &anthropic_spec,
        .openai => &openai_spec,
        .google => null,
    };
}

// ── Public helpers ─────────────────────────────────────────────────────

pub fn oauthLoginInfo(provider: Provider) ?auth.OAuthLoginInfo {
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

// ── Begin OAuth ────────────────────────────────────────────────────────

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

    const state = try csrfToken(alloc);
    errdefer alloc.free(state);

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
    try appendQueryParam(alloc, &query, "state", state);
    for (spec.extra_authorize) |extra| {
        try appendQueryParam(alloc, &query, extra.key, extra.value);
    }

    const url = try std.fmt.allocPrint(alloc, "{s}?{s}", .{ spec.authorize_url, query.items });
    errdefer alloc.free(url);

    return .{
        .url = url,
        .state = state,
        .verifier = verifier,
    };
}

// ── Complete OAuth ─────────────────────────────────────────────────────

pub fn completeOAuth(alloc: std.mem.Allocator, provider: Provider, input: []const u8, verifier: []const u8) !void {
    return completeOAuthWithHooks(alloc, provider, input, verifier, .{});
}

pub fn completeOAuthWithHooks(alloc: std.mem.Allocator, provider: Provider, input: []const u8, verifier: []const u8, hooks: Hooks) !void {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    if (verifier.len == 0) return error.MissingOAuthVerifier;
    try emitAuthAudit(alloc, hooks, 1, provider, "login", "oauth", .ok, .info, .{ .text = "oauth login start", .vis = .@"pub" });

    var parsed = try parseOAuthInput(alloc, input);
    defer parsed.deinit(alloc);

    const state = parsed.state orelse return error.MissingOAuthState;
    if (state.len == 0) return error.MissingOAuthState;
    const oauth_redirect_uri = parsed.redirect_uri orelse spec.default_redirect_uri;

    // Verifier must be the separately-stored PKCE verifier, never derived from state.
    const oauth = hooks.exchange_code(alloc, spec, parsed.code, state, oauth_redirect_uri, verifier, hooks) catch |err| {
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
    expected_state: []const u8,
    verifier: []const u8,
) !void {
    return completeOAuthFromLocalCallbackWithHooks(alloc, provider, callback, oauth_redirect_uri, expected_state, verifier, .{});
}

pub fn completeOAuthFromLocalCallbackWithHooks(
    alloc: std.mem.Allocator,
    provider: Provider,
    callback: oauth_callback.CodeState,
    oauth_redirect_uri: []const u8,
    expected_state: []const u8,
    verifier: []const u8,
    hooks: Hooks,
) !void {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;
    if (!std.mem.eql(u8, callback.state, expected_state)) return error.OAuthStateMismatch;
    try emitAuthAudit(alloc, hooks, 1, provider, "login", "oauth", .ok, .info, .{ .text = "oauth login start", .vis = .@"pub" });

    const oauth = hooks.exchange_code(
        alloc,
        spec,
        callback.code,
        callback.state,
        oauth_redirect_uri,
        verifier,
        hooks,
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

// ── Browser launch ─────────────────────────────────────────────────────

/// Launch URL in the user's default browser.
/// Uses absolute paths to avoid PATH-resolved shellout attacks.
pub fn openBrowser(alloc: std.mem.Allocator, url: []const u8) !void {
    const argv: []const []const u8 = switch (builtin.os.tag) {
        .macos => &.{ "/usr/bin/open", url },
        .linux => blk: {
            const candidates = [_][]const u8{
                "/usr/bin/xdg-open",
                "/usr/local/bin/xdg-open",
            };
            for (candidates) |path| {
                if (std.fs.cwd().access(path, .{})) |_| {
                    break :blk @as([]const []const u8, &.{ path, url });
                } else |_| {}
            }
            return error.BrowserOpenFailed;
        },
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

// ── Refresh ────────────────────────────────────────────────────────────

/// Refresh an expired OAuth token. Returns new OAuth credentials and saves to disk.
pub fn refreshOAuth(alloc: std.mem.Allocator, old: OAuth) !OAuth {
    return refreshOAuthForProvider(alloc, .anthropic, old);
}

/// Refresh an expired OAuth token for a specific provider.
pub fn refreshOAuthForProvider(alloc: std.mem.Allocator, provider: Provider, old: OAuth) !OAuth {
    return refreshOAuthForProviderWithHooks(alloc, provider, old, .{});
}

pub fn refreshOAuthForProviderWithHooks(alloc: std.mem.Allocator, provider: Provider, old: OAuth, hooks: Hooks) !OAuth {
    try emitAuthAudit(alloc, hooks, 1, provider, "refresh", "oauth", .ok, .info, .{ .text = "oauth refresh start", .vis = .@"pub" });
    const new_oauth = hooks.refresh_fetch(alloc, provider, old, hooks) catch |err| {
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

pub fn fetchRefreshedOAuthForProvider(alloc: std.mem.Allocator, provider: Provider, old: OAuth, hooks: Hooks) !OAuth {
    const spec = oauthSpec(provider) orelse return error.UnsupportedOAuthProvider;

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const req_body = try buildRefreshReqBody(ar, spec, old.refresh);

    var http = try initHttpClient(ar, hooks.ca_file);
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

    if (req.connection) |conn| try setSocketDeadlines(conn);

    req.transfer_encoding = .{ .content_length = req_body.body.len };
    var bw = try req.sendBodyUnflushed(&send_buf);
    try bw.writer.writeAll(req_body.body);
    try bw.end();
    try req.connection.?.flush();

    var redir_buf: [0]u8 = .{};
    var resp = try req.receiveHead(&redir_buf);

    var transfer_buf: [16384]u8 = undefined;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const rdr = resp.readerDecompressing(&transfer_buf, &decomp, &decomp_buf);
    const resp_body = try rdr.allocRemaining(ar, .limited(65536));

    if (resp.head.status != .ok) {
        // Try to extract error detail from response body
        const detail = extractRefreshErr(ar, resp_body, @intFromEnum(resp.head.status));
        const redacted = audit.redactTextAlloc(ar, detail, .mask) catch detail;
        std.log.warn("oauth refresh failed: {s}", .{redacted});
        if (isInvalidGrant(resp_body)) return error.RefreshInvalidGrant;
        return error.RefreshFailed;
    }

    const new_oauth = try parseOAuthTokenResponse(alloc, ar, resp_body, error.RefreshFailed);
    return new_oauth;
}

// ── PKCE helpers ───────────────────────────────────────────────────────

fn pkceVerifier(alloc: std.mem.Allocator) ![]u8 {
    var raw: [32]u8 = undefined;
    std.crypto.random.bytes(&raw);
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
    const out = try alloc.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    return out;
}

/// Independent CSRF token for OAuth state parameter (not reusing PKCE verifier).
fn csrfToken(alloc: std.mem.Allocator) ![]u8 {
    var raw: [16]u8 = undefined;
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

// ── URL encoding helpers ───────────────────────────────────────────────

fn encodeQueryComponentAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    return url_codec.encodeComponentAlloc(alloc, raw, false);
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
    return url_codec.encodeComponentAlloc(alloc, raw, true);
}

const decodeQueryValue = url_codec.decodeQueryValue;

// ── Token request building ─────────────────────────────────────────────

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

pub fn exchangeAuthorizationCode(
    alloc: std.mem.Allocator,
    spec: *const OAuthSpec,
    code: []const u8,
    state: []const u8,
    oauth_redirect_uri: []const u8,
    verifier: []const u8,
    hooks: Hooks,
) !OAuth {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    const token_req = try buildTokenReqBody(ar, spec, code, state, oauth_redirect_uri, verifier);

    var http = try initHttpClient(ar, hooks.ca_file);
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

    if (req.connection) |conn| try setSocketDeadlines(conn);

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

// ── HTTP helpers ───────────────────────────────────────────────────────

/// Bounded deadline for auth HTTP requests (send + receive), in seconds.
const auth_http_deadline_s = 30;

pub fn initHttpClient(alloc: std.mem.Allocator, ca_file: ?[]const u8) !std.http.Client {
    var http = std.http.Client{ .allocator = alloc };
    errdefer http.deinit();
    try core_tls.applyCaFile(&http, alloc, ca_file);
    return http;
}

/// Apply SO_SNDTIMEO and SO_RCVTIMEO to the underlying socket so auth
/// HTTP requests cannot hang indefinitely.
fn setSocketDeadlines(conn: *std.http.Client.Connection) !void {
    const fd = conn.stream_writer.getStream().handle;
    const tv = std.posix.timeval{ .sec = auth_http_deadline_s, .usec = 0 };
    const tv_bytes: []const u8 = std.mem.asBytes(&tv);
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.c.SO.SNDTIMEO, tv_bytes);
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.c.SO.RCVTIMEO, tv_bytes);
}

// ── Error extraction ───────────────────────────────────────────────────

/// Extract human-readable error from refresh response body.
fn extractRefreshErr(ar: std.mem.Allocator, body: []const u8, status: u16) []const u8 {
    // Try JSON parse for "error" or "error_description" field
    if (std.json.parseFromSlice(std.json.Value, ar, body, .{ .allocate = .alloc_always })) |parsed| {
        const obj = switch (parsed.value) {
            .object => |o| o,
            else => return truncBody(body, status, ar),
        };
        // Prefer error_description, fall back to error
        if (strGet(obj, "error_description")) |desc| {
            return std.fmt.allocPrint(ar, "{d} {s}", .{ status, desc }) catch truncBody(body, status, ar);
        }
        if (strGet(obj, "error")) |err_val| {
            return std.fmt.allocPrint(ar, "{d} {s}", .{ status, err_val }) catch truncBody(body, status, ar);
        }
        return truncBody(body, status, ar);
    } else |_| {
        return truncBody(body, status, ar);
    }
}

fn strGet(map: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const val = map.get(key) orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

/// Truncate body to first 200 bytes and prepend HTTP status.
fn truncBody(body: []const u8, status: u16, ar: std.mem.Allocator) []const u8 {
    const trunc = body[0..@min(body.len, 200)];
    return std.fmt.allocPrint(ar, "{d} {s}", .{ status, trunc }) catch "refresh failed";
}

/// Check if the response body indicates an invalid_grant error.
fn isInvalidGrant(body: []const u8) bool {
    // Fast substring check — works for both JSON and form error bodies
    return std.mem.indexOf(u8, body, "invalid_grant") != null;
}

// ── Tests ──────────────────────────────────────────────────────────────

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

test "beginOAuth builds authorization URL with separate state and verifier" {
    var flow = try beginOAuth(std.testing.allocator, .anthropic);
    defer flow.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.startsWith(u8, flow.url, "https://claude.ai/oauth/authorize?"));
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "code_challenge=") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "state=") != null);
    try std.testing.expect(flow.state.len > 0);
    try std.testing.expect(flow.verifier.len > 16);
    // state and verifier are independent tokens
    try std.testing.expect(!std.mem.eql(u8, flow.state, flow.verifier));
}

test "beginOAuthWithRedirect encodes localhost callback URI" {
    var flow = try beginOAuthWithRedirect(std.testing.allocator, .anthropic, "http://127.0.0.1:54321/callback");
    defer flow.deinit(std.testing.allocator);

    try std.testing.expect(std.mem.indexOf(u8, flow.url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback") != null);
}

test "beginOAuthWithRedirect encodes callback URI and codex params" {
    var flow = try beginOAuthWithRedirect(std.testing.allocator, .openai, "http://127.0.0.1:54321/auth/callback");
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

test "parseOAuthInput supports code#state" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseOAuthInput(std.testing.allocator, "abc123#state456");
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

test "parseOAuthInput supports callback URL query params" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const input = "http://localhost:64915/callback?code=abc123&state=state%20456";
    var parsed = try parseOAuthInput(std.testing.allocator, input);
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

test "parseOAuthInput supports raw query params" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseOAuthInput(std.testing.allocator, "code=abc123&state=state%20456");
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

test "parseOAuthInput accepts code-only input" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var parsed = try parseOAuthInput(std.testing.allocator, "abc123");
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

test "parseOAuthInput rejects empty input" {
    try std.testing.expectError(error.InvalidOAuthInput, parseOAuthInput(std.testing.allocator, " \t\r\n"));
}

test "completeOAuthFromLocalCallback rejects mismatched state (anthropic)" {
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
        completeOAuthFromLocalCallback(
            std.testing.allocator,
            .anthropic,
            cb,
            "http://127.0.0.1:1234/callback",
            "state-b",
            "verifier-x",
        ),
    );
}

test "completeOAuthFromLocalCallback rejects mismatched state (openai)" {
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
        completeOAuthFromLocalCallback(
            std.testing.allocator,
            .openai,
            cb,
            "http://127.0.0.1:1234/auth/callback",
            "state-b",
            "verifier-x",
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
            "verifier-x",
        ),
    );
}

test "completeOAuthWithHooks rejects empty verifier" {
    try std.testing.expectError(
        error.MissingOAuthVerifier,
        completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=abc&state=def", "", .{}),
    );
}

test "completeOAuthWithHooks uses provided verifier not state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var got_verifier: []const u8 = "";
    const Capture = struct {
        var captured: []const u8 = "";
        fn exchange(alloc: std.mem.Allocator, _: *const OAuthSpec, _: []const u8, _: []const u8, _: []const u8, verifier: []const u8, _: Hooks) !OAuth {
            captured = verifier;
            return .{
                .access = try alloc.dupe(u8, "a"),
                .refresh = try alloc.dupe(u8, "r"),
                .expires = 1,
            };
        }
    };
    try completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=abc&state=def", "my-pkce-verifier", .{
        .home_override = home,
        .exchange_code = Capture.exchange,
    });
    got_verifier = Capture.captured;
    // The exchange must receive the explicit verifier, not the state from input.
    try std.testing.expectEqualStrings("my-pkce-verifier", got_verifier);
}

test "separate OAuth state and PKCE verifier" {
    var flow = try beginOAuth(std.testing.allocator, .anthropic);
    defer flow.deinit(std.testing.allocator);

    // state and verifier must be distinct tokens
    try std.testing.expect(!std.mem.eql(u8, flow.state, flow.verifier));
    // state is shorter (16 bytes base64 = 22 chars) vs verifier (32 bytes = 43 chars)
    try std.testing.expect(flow.state.len > 0);
    try std.testing.expect(flow.verifier.len > flow.state.len);
    // URL contains state= param
    try std.testing.expect(std.mem.indexOf(u8, flow.url, "state=") != null);
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

test "auth audit covers oauth login and persistence" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    var rows = AuditRows{};
    defer rows.deinit(std.testing.allocator);
    try completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=abc&state=def", "test-pkce-verifier", .{
        .home_override = home,
        .exchange_code = struct {
            fn f(alloc: std.mem.Allocator, _: *const OAuthSpec, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: Hooks) !OAuth {
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
    const a = try auth_load.loadFileAuthForProvider(arena.allocator(), home, .anthropic);
    try oh.snap(@src(),
        \\core.providers.auth.Auth
        \\  .oauth: core.providers.auth.OAuth
        \\    .access: []const u8
        \\      "oa-access"
        \\    .refresh: []const u8
        \\      "oa-refresh"
        \\    .expires: i64 = 123
    ).expectEqual(a);

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
            fn f(alloc: std.mem.Allocator, _: Provider, _: OAuth, _: Hooks) !OAuth {
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

test "completeOAuthWithHooks passes ca_file to exchange_code" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    try completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=abc&state=def", "test-pkce-verifier", .{
        .home_override = home,
        .ca_file = "/etc/pz/auth.pem",
        .exchange_code = struct {
            fn f(alloc: std.mem.Allocator, _: *const OAuthSpec, _: []const u8, _: []const u8, _: []const u8, _: []const u8, hooks: Hooks) !OAuth {
                try std.testing.expectEqualStrings("/etc/pz/auth.pem", hooks.ca_file orelse return error.TestUnexpectedResult);
                return .{
                    .access = try alloc.dupe(u8, "ca-a"),
                    .refresh = try alloc.dupe(u8, "ca-r"),
                    .expires = 77,
                };
            }
        }.f,
    });
}

test "refreshOAuthForProviderWithHooks passes ca_file to refresh_fetch" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    const got = try refreshOAuthForProviderWithHooks(std.testing.allocator, .openai, .{
        .access = "old-a",
        .refresh = "old-r",
        .expires = 1,
    }, .{
        .home_override = home,
        .ca_file = "/etc/pz/auth.pem",
        .refresh_fetch = struct {
            fn f(alloc: std.mem.Allocator, _: Provider, _: OAuth, hooks: Hooks) !OAuth {
                try std.testing.expectEqualStrings("/etc/pz/auth.pem", hooks.ca_file orelse return error.TestUnexpectedResult);
                return .{
                    .access = try alloc.dupe(u8, "new-a"),
                    .refresh = try alloc.dupe(u8, "new-r"),
                    .expires = 999,
                };
            }
        }.f,
    });
    defer {
        std.testing.allocator.free(got.access);
        std.testing.allocator.free(got.refresh);
    }
}

test "initHttpClient fails closed on invalid ca bundle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "bad.pem", .data = "-----BEGIN CERTIFICATE-----\nnot-base64\n" });
    const bad = try tmp.dir.realpathAlloc(std.testing.allocator, "bad.pem");
    defer std.testing.allocator.free(bad);

    if (initHttpClient(std.testing.allocator, bad)) |h| {
        var http = h;
        defer http.deinit();
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expectEqual(error.MissingEndCertificateMarker, err);
    }
}

// ── 2a: OAuth login flow tests ──────────────────────────────────────────

test "beginOAuth produces authorize URL with PKCE code_challenge" {
    for ([_]Provider{ .anthropic, .openai }) |prov| {
        var flow = try beginOAuth(std.testing.allocator, prov);
        defer flow.deinit(std.testing.allocator);

        // URL must contain code_challenge (S256)
        try std.testing.expect(std.mem.indexOf(u8, flow.url, "code_challenge=") != null);
        try std.testing.expect(std.mem.indexOf(u8, flow.url, "code_challenge_method=S256") != null);

        // Verify the code_challenge is SHA256(verifier) in base64url
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(flow.verifier, &digest, .{});
        const expected = std.base64.url_safe_no_pad.Encoder.calcSize(digest.len);
        var challenge_buf: [44]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(challenge_buf[0..expected], &digest);
        const needle = try std.fmt.allocPrint(std.testing.allocator, "code_challenge={s}", .{challenge_buf[0..expected]});
        defer std.testing.allocator.free(needle);
        try std.testing.expect(std.mem.indexOf(u8, flow.url, needle) != null);
    }
}

test "completeOAuthWithHooks with mock exchange returns valid tokens and persists" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    try completeOAuthWithHooks(std.testing.allocator, .anthropic, "code=test_code&state=test_state", "pkce-v", .{
        .home_override = home,
        .exchange_code = struct {
            fn f(alloc: std.mem.Allocator, _: *const OAuthSpec, code: []const u8, state: []const u8, _: []const u8, verifier: []const u8, _: Hooks) !OAuth {
                // Verify all params reach the exchange function
                try std.testing.expectEqualStrings("test_code", code);
                try std.testing.expectEqualStrings("test_state", state);
                try std.testing.expectEqualStrings("pkce-v", verifier);
                return .{
                    .access = try alloc.dupe(u8, "mock-access"),
                    .refresh = try alloc.dupe(u8, "mock-refresh"),
                    .expires = 5000,
                };
            }
        }.f,
    });

    // Verify auth file written to disk
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = try auth_load.loadFileAuthForProvider(arena.allocator(), home, .anthropic);
    try oh.snap(@src(),
        \\core.providers.auth.Auth
        \\  .oauth: core.providers.auth.OAuth
        \\    .access: []const u8
        \\      "mock-access"
        \\    .refresh: []const u8
        \\      "mock-refresh"
        \\    .expires: i64 = 5000
    ).expectEqual(a);
}

test "completeOAuthWithHooks rejects missing state in input" {
    try std.testing.expectError(
        error.MissingOAuthState,
        completeOAuthWithHooks(std.testing.allocator, .anthropic, "justcode", "verifier", .{
            .exchange_code = struct {
                fn f(_: std.mem.Allocator, _: *const OAuthSpec, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: Hooks) !OAuth {
                    return error.TestUnexpectedResult;
                }
            }.f,
        }),
    );
}

// ── 2b: Token refresh cycle tests ──────────────────────────────────────

test "refreshOAuthForProviderWithHooks with mock 200 returns new tokens" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    const got = try refreshOAuthForProviderWithHooks(std.testing.allocator, .anthropic, .{
        .access = "old-access",
        .refresh = "old-refresh",
        .expires = 100,
    }, .{
        .home_override = home,
        .refresh_fetch = struct {
            fn f(alloc: std.mem.Allocator, prov: Provider, old: OAuth, _: Hooks) !OAuth {
                // Verify old tokens passed correctly
                try std.testing.expectEqual(Provider.anthropic, prov);
                try std.testing.expectEqualStrings("old-refresh", old.refresh);
                return .{
                    .access = try alloc.dupe(u8, "new-access"),
                    .refresh = try alloc.dupe(u8, "new-refresh"),
                    .expires = 9999,
                };
            }
        }.f,
    });
    defer {
        std.testing.allocator.free(got.access);
        std.testing.allocator.free(got.refresh);
    }

    try oh.snap(@src(),
        \\core.providers.auth.OAuth
        \\  .access: []const u8
        \\    "new-access"
        \\  .refresh: []const u8
        \\    "new-refresh"
        \\  .expires: i64 = 9999
    ).expectEqual(got);

    // Verify updated tokens persisted to disk
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const disk_auth = try auth_load.loadFileAuthForProvider(arena.allocator(), home, .anthropic);
    try oh.snap(@src(),
        \\core.providers.auth.Auth
        \\  .oauth: core.providers.auth.OAuth
        \\    .access: []const u8
        \\      "new-access"
        \\    .refresh: []const u8
        \\      "new-refresh"
        \\    .expires: i64 = 9999
    ).expectEqual(disk_auth);
}

test "refreshOAuthForProviderWithHooks with 400 returns typed error" {
    const got = refreshOAuthForProviderWithHooks(std.testing.allocator, .anthropic, .{
        .access = "a",
        .refresh = "r",
        .expires = 0,
    }, .{
        .refresh_fetch = struct {
            fn f(_: std.mem.Allocator, _: Provider, _: OAuth, _: Hooks) !OAuth {
                return error.RefreshFailed;
            }
        }.f,
    });
    try std.testing.expectError(error.RefreshFailed, got);
}

test "refreshOAuthForProviderWithHooks propagates network error" {
    const got = refreshOAuthForProviderWithHooks(std.testing.allocator, .openai, .{
        .access = "a",
        .refresh = "r",
        .expires = 0,
    }, .{
        .refresh_fetch = struct {
            fn f(_: std.mem.Allocator, _: Provider, _: OAuth, _: Hooks) !OAuth {
                return error.ConnectionRefused;
            }
        }.f,
    });
    try std.testing.expectError(error.ConnectionRefused, got);
}

test "proactive refresh triggers when now > expires" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(home);

    const Ctx = struct {
        var called: bool = false;
        fn refresh(alloc: std.mem.Allocator, _: Provider, _: OAuth, _: Hooks) !OAuth {
            called = true;
            return .{
                .access = try alloc.dupe(u8, "refreshed-a"),
                .refresh = try alloc.dupe(u8, "refreshed-r"),
                .expires = 99999,
            };
        }
        fn now() i64 {
            return 2000; // past expires=1000
        }
    };
    Ctx.called = false;

    // Simulate what tryProactiveRefresh does: check expires, call refresh
    const old = OAuth{ .access = "a", .refresh = "r", .expires = 1000 };
    const now = Ctx.now();
    if (now >= old.expires) {
        const got = try refreshOAuthForProviderWithHooks(std.testing.allocator, .anthropic, old, .{
            .home_override = home,
            .refresh_fetch = Ctx.refresh,
            .now_ms = Ctx.now,
        });
        std.testing.allocator.free(got.access);
        std.testing.allocator.free(got.refresh);
    }
    try std.testing.expect(Ctx.called);
}

test "proactive refresh skips when token still valid" {
    const Ctx = struct {
        var called: bool = false;
        fn refresh(_: std.mem.Allocator, _: Provider, _: OAuth, _: Hooks) !OAuth {
            called = true;
            return error.TestUnexpectedResult;
        }
        fn now() i64 {
            return 500; // before expires=1000
        }
    };
    Ctx.called = false;

    const old = OAuth{ .access = "a", .refresh = "r", .expires = 1000 };
    const now = Ctx.now();
    // Same logic as tryProactiveRefresh: skip if not expired
    if (now >= old.expires) {
        const got = try refreshOAuthForProviderWithHooks(std.testing.allocator, .anthropic, old, .{
            .refresh_fetch = Ctx.refresh,
            .now_ms = Ctx.now,
        });
        std.testing.allocator.free(got.access);
        std.testing.allocator.free(got.refresh);
    }
    try std.testing.expect(!Ctx.called);
}
