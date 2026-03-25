//! Provider authentication: API key and OAuth token resolution.
//!
//! This module defines auth types and re-exports the public API from:
//!   - auth_load.zig: credential loading, file I/O, persistence
//!   - oauth_flow.zig: OAuth protocol, PKCE, token exchange, refresh
const std = @import("std");
const audit = @import("../audit.zig");
const policy = @import("../policy.zig");

// ── Submodules (pull in their tests) ───────────────────────────────────

const auth_load = @import("auth_load.zig");
const oauth_flow = @import("oauth_flow.zig");

comptime {
    _ = auth_load;
    _ = oauth_flow;
}

// ── Types ──────────────────────────────────────────────────────────────

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

pub const AuthEntry = struct {
    type: ?[]const u8 = null,
    access: ?[]const u8 = null,
    refresh: ?[]const u8 = null,
    expires: ?i64 = null,
    key: ?[]const u8 = null,
};

pub const Provider = enum { anthropic, openai, google };
pub const provider_names = [_][]const u8{ "anthropic", "openai", "google" };

pub fn providerName(p: Provider) []const u8 {
    return provider_names[@intFromEnum(p)];
}

pub const Hooks = struct {
    const Self = @This();

    home_override: ?[]const u8 = null,
    ca_file: ?[]const u8 = null,
    lock: policy.Lock = .{},
    get_home: *const fn (std.mem.Allocator, []const u8) anyerror![]u8 = std.process.getEnvVarOwned,
    exchange_code: *const fn (std.mem.Allocator, *const OAuthSpec, []const u8, []const u8, []const u8, []const u8, Self) anyerror!OAuth = oauth_flow.exchangeAuthorizationCode,
    refresh_fetch: *const fn (std.mem.Allocator, Provider, OAuth, Self) anyerror!OAuth = oauth_flow.fetchRefreshedOAuthForProvider,
    audit_emitter: ?*audit.Emitter = null,
    now_ms: *const fn () i64 = std.time.milliTimestamp,
};

pub const OAuthTokenBody = enum {
    json_with_state,
    form_no_state,
};

pub const OAuthParam = struct {
    key: []const u8,
    value: []const u8,
};

pub const OAuthSpec = struct {
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

pub const OAuthStart = struct {
    url: []u8,
    state: []u8,
    verifier: []u8,

    pub fn deinit(self: *OAuthStart, alloc: std.mem.Allocator) void {
        alloc.free(self.url);
        alloc.free(self.state);
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

pub const AuthFile = struct {
    anthropic: ?AuthEntry = null,
    openai: ?AuthEntry = null,
    google: ?AuthEntry = null,
};

pub const OAuthLoginInfo = struct {
    callback_path: []const u8,
    start_action: []const u8,
    complete_action: []const u8,
};

// ── Re-exports: auth_load ──────────────────────────────────────────────

pub const load = auth_load.load;
pub const loadForProvider = auth_load.loadForProvider;
pub const loadForProviderWithHooks = auth_load.loadForProviderWithHooks;
pub const saveApiKey = auth_load.saveApiKey;
pub const saveApiKeyWithHooks = auth_load.saveApiKeyWithHooks;
pub const listLoggedIn = auth_load.listLoggedIn;
pub const logout = auth_load.logout;
pub const logoutWithHooks = auth_load.logoutWithHooks;

// ── Re-exports: oauth_flow ─────────────────────────────────────────────

pub const oauthLoginInfo = oauth_flow.oauthLoginInfo;
pub const oauthCapable = oauth_flow.oauthCapable;
pub const looksLikeApiKey = oauth_flow.looksLikeApiKey;
pub const beginOAuth = oauth_flow.beginOAuth;
pub const beginOAuthWithRedirect = oauth_flow.beginOAuthWithRedirect;
pub const completeOAuth = oauth_flow.completeOAuth;
pub const completeOAuthWithHooks = oauth_flow.completeOAuthWithHooks;
pub const completeOAuthFromLocalCallback = oauth_flow.completeOAuthFromLocalCallback;
pub const completeOAuthFromLocalCallbackWithHooks = oauth_flow.completeOAuthFromLocalCallbackWithHooks;
pub const parseOAuthInput = oauth_flow.parseOAuthInput;
pub const openBrowser = oauth_flow.openBrowser;
pub const refreshOAuth = oauth_flow.refreshOAuth;
pub const refreshOAuthForProvider = oauth_flow.refreshOAuthForProvider;
pub const refreshOAuthForProviderWithHooks = oauth_flow.refreshOAuthForProviderWithHooks;
