//! User-facing error reports: map error codes to summaries and next steps.
const std = @import("std");

const Rule = struct {
    summary: []const u8,
    next: []const u8,
};

const rule_map = std.StaticStringMap(Rule).initComptime(.{
    .{
        "SessionDisabled", Rule{
            .summary = "session persistence is disabled",
            .next = "rerun without --no-session and ensure a writable session directory",
        },
    },
    .{
        "SessionNotFound", Rule{
            .summary = "session was not found",
            .next = "run /tree (or rpc tree) to list sessions and retry with an exact id",
        },
    },
    .{
        "AmbiguousSession", Rule{
            .summary = "session id prefix matches multiple sessions",
            .next = "use a longer id prefix or an exact session id",
        },
    },
    .{
        "InvalidSessionPath", Rule{
            .summary = "session path is invalid",
            .next = "pass a .jsonl session file path or valid session id",
        },
    },
    .{
        "FileNotFound", Rule{
            .summary = "file or directory was not found",
            .next = "verify the path exists and retry",
        },
    },
    .{
        "AccessDenied", Rule{
            .summary = "permission denied",
            .next = "grant access to the target path and retry",
        },
    },
    .{
        "ReadOnlyFileSystem", Rule{
            .summary = "target filesystem is read-only",
            .next = "choose a writable location or remount with write access",
        },
    },
    .{
        "ConnectionRefused", Rule{
            .summary = "remote endpoint refused the connection",
            .next = "check network/proxy/firewall settings and retry",
        },
    },
    .{
        "NetworkUnreachable", Rule{
            .summary = "network is unreachable",
            .next = "check internet connectivity and retry",
        },
    },
    .{
        "HostUnreachable", Rule{
            .summary = "host is unreachable",
            .next = "check DNS/network reachability and retry",
        },
    },
    .{
        "ConnectionTimedOut", Rule{
            .summary = "network request timed out",
            .next = "retry after network stabilizes",
        },
    },
    .{
        "BrowserOpenFailed", Rule{
            .summary = "failed to launch browser",
            .next = "open the printed URL manually and retry",
        },
    },
    .{
        "UnsupportedPlatform", Rule{
            .summary = "automatic browser launch is unsupported on this platform",
            .next = "open the printed URL manually and retry",
        },
    },
    .{
        "InvalidOAuthInput", Rule{
            .summary = "invalid OAuth callback payload",
            .next = "rerun /login <provider> and paste the callback URL or code#state exactly",
        },
    },
    .{
        "MissingOAuthState", Rule{
            .summary = "OAuth state/verifier is missing",
            .next = "rerun /login <provider> and paste full callback URL or code#state",
        },
    },
    .{
        "TokenExchangeFailed", Rule{
            .summary = "OAuth token exchange failed",
            .next = "rerun /login <provider> and complete authorization again",
        },
    },
    .{
        "OAuthCallbackTimeout", Rule{
            .summary = "timed out waiting for OAuth callback",
            .next = "rerun /login <provider> and complete browser authorization within the timeout",
        },
    },
    .{
        "InvalidOAuthCallbackRequest", Rule{
            .summary = "received invalid OAuth callback request",
            .next = "rerun /login <provider> and complete authorization again",
        },
    },
    .{
        "OAuthStateMismatch", Rule{
            .summary = "OAuth callback state did not match the login request",
            .next = "rerun /login <provider> and complete authorization in the same browser session",
        },
    },
    .{
        "TemporaryNameServerFailure", Rule{
            .summary = "DNS lookup failed",
            .next = "check DNS settings and retry",
        },
    },
    .{
        "UnknownArg", Rule{
            .summary = "unknown command-line argument",
            .next = "run pz --help and fix the command",
        },
    },
    .{
        "MissingPrintPrompt", Rule{
            .summary = "print mode requires a prompt",
            .next = "pass text after --print or use --prompt <text>",
        },
    },
    .{
        "MissingPromptValue", Rule{
            .summary = "missing value for --prompt",
            .next = "use --prompt <text>",
        },
    },
    .{
        "MissingSessionValue", Rule{
            .summary = "missing value for --session/--resume",
            .next = "use --session <id|path> or plain -r for latest",
        },
    },
    .{
        "MissingModeValue", Rule{
            .summary = "missing value for --mode",
            .next = "use --mode <tui|print|json|rpc>",
        },
    },
    .{
        "InvalidMode", Rule{
            .summary = "invalid mode value",
            .next = "use one of: tui, print, json, rpc",
        },
    },
    .{
        "InvalidTool", Rule{
            .summary = "invalid tools list",
            .next = "use --tools read,write,bash,edit,grep,find,ls,ask or --no-tools",
        },
    },
    .{
        "InvalidUtf8", Rule{
            .summary = "invalid UTF-8 in display text",
            .next = "check AGENTS.md, config files, and VCS history for non-UTF-8 characters",
        },
    },
    .{
        "OutOfMemory", Rule{
            .summary = "allocator ran out of memory",
            .next = "reduce context size or close other applications and retry",
        },
    },
    .{
        "TornReplayLine", Rule{
            .summary = "session file has an incomplete trailing line",
            .next = "the session was interrupted mid-write; replay will skip the torn line",
        },
    },
    .{
        "MalformedReplayLine", Rule{
            .summary = "session file contains a malformed event line",
            .next = "the session file may be corrupt; start a new session or edit the .jsonl file",
        },
    },
    .{
        "UnsupportedVersion", Rule{
            .summary = "session file uses an unsupported event version",
            .next = "upgrade pz to a version that supports this session format",
        },
    },
    .{
        "InvalidFileMode", Rule{
            .summary = "invalid mode value in config file",
            .next = "use one of: tui, print, json, rpc in your settings.json",
        },
    },
    .{
        "InvalidEnvMode", Rule{
            .summary = "invalid mode value in PZ_MODE environment variable",
            .next = "set PZ_MODE to one of: tui, print, json, rpc",
        },
    },
    .{
        "PolicyLockedConfig", Rule{
            .summary = "policy prevents config file overrides",
            .next = "remove local config files or contact the policy administrator",
        },
    },
    .{
        "PolicyLockedEnv", Rule{
            .summary = "policy prevents environment variable overrides",
            .next = "unset PZ_* environment variables or contact the policy administrator",
        },
    },
    .{
        "PolicyLockedCli", Rule{
            .summary = "policy prevents CLI flag overrides",
            .next = "remove conflicting CLI flags or contact the policy administrator",
        },
    },
    .{
        "PolicyLockedSystemPrompt", Rule{
            .summary = "policy prevents system prompt overrides",
            .next = "remove --system-prompt/--append-system-prompt or contact the policy administrator",
        },
    },
    .{
        "TerminalSetupFailed", Rule{
            .summary = "failed to enable terminal raw mode",
            .next = "ensure stdout is a terminal; use print/json mode for non-TTY environments",
        },
    },
    .{
        "Overflow", Rule{
            .summary = "context window exceeded",
            .next = "reduce prompt size or use /compact to shrink the conversation",
        },
    },
    .{
        "RefreshFailed", Rule{
            .summary = "OAuth token refresh failed",
            .next = "run /login to re-authenticate",
        },
    },
    .{
        "RefreshInvalidGrant", Rule{
            .summary = "OAuth refresh token expired or revoked",
            .next = "run /login to re-authenticate",
        },
    },
    .{
        "AuthNotFound", Rule{
            .summary = "no credentials found",
            .next = "run /login or set ANTHROPIC_API_KEY",
        },
    },
    .{
        "AuthCorrupt", Rule{
            .summary = "credentials file is corrupt",
            .next = "delete ~/.pz/auth.json and run /login",
        },
    },
    .{
        "ConnectionRefused", Rule{
            .summary = "could not connect to API server",
            .next = "check your network connection and try again",
        },
    },
    .{
        "ConnectionResetByPeer", Rule{
            .summary = "connection dropped by server",
            .next = "try again; if it persists, the API may be experiencing issues",
        },
    },
    .{
        "NetworkUnreachable", Rule{
            .summary = "network is unreachable",
            .next = "check your internet connection",
        },
    },
    .{
        "HostUnreachable", Rule{
            .summary = "API server is unreachable",
            .next = "check your internet connection and DNS",
        },
    },
    .{
        "TlsAlertHandshakeFailure", Rule{
            .summary = "TLS handshake failed",
            .next = "check if a firewall or proxy is blocking HTTPS connections",
        },
    },
    .{
        "CertificateAuthorityBundleMissing", Rule{
            .summary = "CA certificate bundle not found",
            .next = "install system CA certificates or set PZ_CA_FILE",
        },
    },
    .{
        "Canceled", Rule{
            .summary = "request was canceled",
            .next = "press Enter to send a new prompt",
        },
    },
    .{
        "TransportTransient", Rule{
            .summary = "temporary API error",
            .next = "try again; the API may be under heavy load",
        },
    },
    .{
        "UnexpectedStatus", Rule{
            .summary = "unexpected HTTP status from API",
            .next = "try again; if it persists, the API may have changed",
        },
    },
    .{
        "OutOfMemory", Rule{
            .summary = "out of memory",
            .next = "reduce conversation size with /compact or start a new session",
        },
    },
    .{
        "ProviderNotConfigured", Rule{
            .summary = "no provider configured",
            .next = "run /login or set ANTHROPIC_API_KEY to configure a provider",
        },
    },
    .{
        "MissingProviderStream", Rule{
            .summary = "no provider available",
            .next = "run /login to authenticate or set an API key",
        },
    },
    .{
        "TokenExchangeFailed", Rule{
            .summary = "OAuth authorization failed",
            .next = "try /login again; if it persists, check console.anthropic.com for account issues",
        },
    },
});

fn lookup(err: anyerror) Rule {
    const name = @errorName(err);
    return rule_map.get(name) orelse .{
        .summary = name,
        .next = "retry; if it persists, report this error with context",
    };
}

pub fn short(err: anyerror) []const u8 {
    return lookup(err).summary;
}

/// Look up a user-friendly message from a raw error name string.
/// Returns summary + actionable next step.
pub fn fromName(alloc: std.mem.Allocator, name: []const u8) ![]u8 {
    const r = rule_map.get(name) orelse return std.fmt.allocPrint(alloc, "{s}", .{name});
    return std.fmt.allocPrint(alloc, "{s} — {s}", .{ r.summary, r.next });
}

pub fn inlineMsg(alloc: std.mem.Allocator, err: anyerror) ![]u8 {
    const r = lookup(err);
    return std.fmt.allocPrint(alloc, "{s}", .{r.summary});
}

pub fn cli(alloc: std.mem.Allocator, op: []const u8, err: anyerror) ![]u8 {
    const name = @errorName(err);
    const r = lookup(err);
    return std.fmt.allocPrint(
        alloc,
        "error: {s} failed\nreason: {s}\nerror code: {s}\nnext: {s}\n",
        .{ op, r.summary, name, r.next },
    );
}

pub fn rpc(alloc: std.mem.Allocator, op: []const u8, err: anyerror) ![]u8 {
    const name = @errorName(err);
    const r = lookup(err);
    return std.fmt.allocPrint(
        alloc,
        "{s} failed: {s} (error: {s}). next: {s}",
        .{ op, r.summary, name, r.next },
    );
}

test "report maps session disabled to actionable text" {
    const msg = try cli(std.testing.allocator, "resume session", error.SessionDisabled);
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "session persistence is disabled") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "without --no-session") != null);
}

test "report falls back to error name when unknown" {
    const msg = try rpc(std.testing.allocator, "do thing", error.TestUnexpectedResult);
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "TestUnexpectedResult") != null);
}

test "report inline shows friendly summary" {
    const msg = try inlineMsg(std.testing.allocator, error.SessionDisabled);
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "session persistence is disabled") != null);
}
