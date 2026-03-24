//! Self-update: download and replace the running binary.
const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli.zig");
const core = @import("../core.zig");
const app_tls = @import("tls.zig");
const path_guard = @import("../core/tools/path_guard.zig");
const version = @import("version.zig");
const http_mock = @import("../test/http_mock.zig");
const fixtures = @import("../test/fixtures.zig");
const time_mock = @import("../test/time_mock.zig");

const ReleaseAsset = struct {
    name: []const u8,
    browser_download_url: []const u8,
};

const ReleasePayload = struct {
    tag_name: []const u8,
    assets: []ReleaseAsset = &.{},
};

const default_release_url = "https://api.github.com/repos/joelreymont/pz/releases/latest";
const release_accept = "application/vnd.github+json";
const asset_accept = "application/octet-stream";
const release_limit = 256 * 1024;
const asset_limit = 256 * 1024 * 1024;
const body_snip_limit = 220;
const any_accept = "*/*";
const sig_suffix = ".manifest";
const update_policy_path = ".pz/upgrade";
const update_policy_file = ".pz/policy.json";
const update_policy_tool = "upgrade";
const update_pk_hex = "2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083";
const dev_pk_hex = update_pk_hex;

const HeaderMode = enum {
    full,
    wgetish,
    bare,
};

const HttpDeps = struct {
    init_client: *const fn (?*anyopaque, std.mem.Allocator) anyerror!std.http.Client = initHttpClientRuntime,
    init_client_ctx: ?*anyopaque = null,
};

pub const Outcome = struct {
    ok: bool,
    msg: []u8,

    pub fn deinit(self: Outcome, alloc: std.mem.Allocator) void {
        alloc.free(self.msg);
    }
};

pub const UpdateError = error{
    InvalidCurrentVersion,
    InvalidLatestVersion,
    UnsupportedTarget,
    MissingAsset,
    ReleaseApiFailed,
    ArchiveMissingBinary,
    InvalidExecutablePath,
    MissingSignatureAsset,
    UpgradeDisabledByPolicy,
    UpdateHostDenied,
    InvalidPolicy,
    SignatureVerifyFailed,
    DowngradeBlocked,
    DefaultKeyRefused,
};

const HttpResult = union(enum) {
    ok: []u8,
    status: struct {
        code: u16,
        body: []u8,
    },

    fn deinit(self: HttpResult, alloc: std.mem.Allocator) void {
        switch (self) {
            .ok => |body| alloc.free(body),
            .status => |resp| alloc.free(resp.body),
        }
    }
};

fn initHttpClientRuntime(_: ?*anyopaque, alloc: std.mem.Allocator) !std.http.Client {
    return try app_tls.initRuntimeClient(alloc, null);
}

pub fn run(alloc: std.mem.Allocator, home: ?[]const u8) ![]u8 {
    const out = try runOutcome(alloc, home);
    return out.msg;
}

pub fn runOutcome(alloc: std.mem.Allocator, home: ?[]const u8) !Outcome {
    return runOutcomeWith(alloc, .{ .home = home });
}

pub fn runOutcomeAudited(alloc: std.mem.Allocator, hooks: AuditHooks) !Outcome {
    return runOutcomeWith(alloc, hooks);
}

pub const AuditHooks = struct {
    http_get: *const fn (std.mem.Allocator, []const u8, []const u8, usize) anyerror!HttpResult = httpGetResult,
    self_exe_path: *const fn (std.mem.Allocator) anyerror![]u8 = std.fs.selfExePathAlloc,
    install_binary: *const fn (std.mem.Allocator, []const u8, []const u8) anyerror!void = installBinary,
    check_update_allowed: *const fn (std.mem.Allocator, ?[]const u8) anyerror!void = checkUpdateAllowed,
    check_update_host: *const fn (std.mem.Allocator, []const u8, ?[]const u8) anyerror!void = checkUpdateHostAllowed,
    check_default_key: *const fn () bool = checkDefaultKeyRelease,
    resolve_release_url: *const fn (std.mem.Allocator, ?[]const u8) anyerror![]const u8 = resolveReleaseUrl,
    home: ?[]const u8 = null,
    emit_audit_ctx: ?*anyopaque = null,
    emit_audit: ?*const fn (*anyopaque, std.mem.Allocator, core.audit.Entry) anyerror!void = null,
    now_ms: *const fn () i64 = std.time.milliTimestamp,
};

const Hooks = AuditHooks;

fn runOutcomeWith(alloc: std.mem.Allocator, hooks: Hooks) !Outcome {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    // Enterprise fail-closed: reject default dev key in release builds.
    if (hooks.check_default_key()) {
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .deny,
            .err,
            .{ .text = "default key refused", .vis = .@"pub" },
            null,
            try std.fmt.allocPrint(
                alloc,
                "upgrade refused: release build uses the default dev signing key\nnext: rebuild with -Dupdate-pk-hex=<your-key> or disable upgrade via policy\n",
                .{},
            ),
        );
    }

    try emitUpdateAudit(alloc, hooks, 1, .ok, .info, .{ .text = "upgrade start", .vis = .@"pub" }, null);

    hooks.check_update_allowed(alloc, hooks.home) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .deny,
            .warn,
            .{ .text = "policy denied", .vis = .@"pub" },
            .{ .text = update_policy_path, .vis = .mask },
            try formatPolicyFailure(alloc, err),
        );
    };

    // Resolve release channel URL from policy or use default
    const release_url = hooks.resolve_release_url(ar, hooks.home) catch default_release_url;
    const release_url_is_alloc = !std.mem.eql(u8, @as([]const u8, release_url), default_release_url);
    _ = release_url_is_alloc; // arena owns it

    if (try checkUpdateUrlOrAudit(alloc, hooks, release_url, "metadata host denied")) |out| {
        return out;
    }
    const release_http = hooks.http_get(alloc, release_url, release_accept, release_limit) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "metadata fetch failed", .vis = .@"pub" },
            .{ .text = release_url, .vis = .mask },
            try formatTransportFailure(
                alloc,
                "fetch latest release metadata",
                release_url,
                err,
            ),
        );
    };
    defer release_http.deinit(alloc);

    const release_body = switch (release_http) {
        .ok => |body| body,
        .status => |resp| {
            return try auditOutcome(
                alloc,
                hooks,
                false,
                .fail,
                .err,
                .{ .text = "metadata http failed", .vis = .@"pub" },
                .{ .text = release_url, .vis = .mask },
                try formatHttpFailure(
                    alloc,
                    "fetch latest release metadata",
                    release_url,
                    resp.code,
                    resp.body,
                ),
            );
        },
    };

    const release_parsed = std.json.parseFromSlice(ReleasePayload, ar, release_body, .{
        .ignore_unknown_fields = true,
    }) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "release parse failed", .vis = .@"pub" },
            null,
            try formatParseFailure(alloc, release_body),
        );
    };
    const release = release_parsed.value;

    const current = version.parseVersion(cli.version) orelse return error.InvalidCurrentVersion;
    const latest = version.parseVersion(release.tag_name) orelse return error.InvalidLatestVersion;
    if (!latest.isNewer(current)) {
        return try auditOutcome(
            alloc,
            hooks,
            true,
            .ok,
            .info,
            .{ .text = "already up to date", .vis = .@"pub" },
            null,
            try std.fmt.allocPrint(alloc, "already up to date ({s})\n", .{cli.version}),
        );
    }

    const asset_name = targetAssetName() orelse {
        const target = try targetLabelAlloc(alloc);
        defer alloc.free(target);
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "unsupported target", .vis = .@"pub" },
            null,
            try std.fmt.allocPrint(
                alloc,
                "upgrade failed: no prebuilt binary for target {s}\nsupported targets: x86_64-linux, aarch64-linux, aarch64-macos\nmanual install: https://github.com/joelreymont/pz/releases/latest\n",
                .{target},
            ),
        );
    };
    const asset_url = findAssetUrl(release.assets, asset_name) orelse {
        const list = try assetListAlloc(alloc, release.assets);
        defer alloc.free(list);
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "release asset missing", .vis = .@"pub" },
            null,
            try std.fmt.allocPrint(
                alloc,
                "upgrade failed: release {s} does not contain asset {s}\navailable assets: {s}\nmanual install: https://github.com/joelreymont/pz/releases/latest\n",
                .{ release.tag_name, asset_name, list },
            ),
        );
    };

    if (try checkUpdateUrlOrAudit(alloc, hooks, asset_url, "archive host denied")) |out| {
        return out;
    }
    const archive_http = hooks.http_get(alloc, asset_url, asset_accept, asset_limit) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "archive download failed", .vis = .@"pub" },
            .{ .text = asset_url, .vis = .mask },
            try formatTransportFailure(alloc, "download release archive", asset_url, err),
        );
    };
    defer archive_http.deinit(alloc);

    const archive = switch (archive_http) {
        .ok => |body| body,
        .status => |resp| {
            return try auditOutcome(
                alloc,
                hooks,
                false,
                .fail,
                .err,
                .{ .text = "archive http failed", .vis = .@"pub" },
                .{ .text = asset_url, .vis = .mask },
                try formatHttpFailure(
                    alloc,
                    "download release archive",
                    asset_url,
                    resp.code,
                    resp.body,
                ),
            );
        },
    };

    const sig_name = try std.fmt.allocPrint(ar, "{s}{s}", .{ asset_name, sig_suffix });
    const sig_url = findAssetUrl(release.assets, sig_name) orelse {
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "signature asset missing", .vis = .@"pub" },
            null,
            try std.fmt.allocPrint(
                alloc,
                "upgrade failed: release {s} does not contain signature asset {s}\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
                .{ release.tag_name, sig_name },
            ),
        );
    };
    if (try checkUpdateUrlOrAudit(alloc, hooks, sig_url, "signature host denied")) |out| {
        return out;
    }
    const sig_http = hooks.http_get(alloc, sig_url, any_accept, core.signing.Manifest.max_len) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "signature download failed", .vis = .@"pub" },
            .{ .text = sig_url, .vis = .mask },
            try formatTransportFailure(alloc, "download release signature", sig_url, err),
        );
    };
    defer sig_http.deinit(alloc);
    const sig_raw = switch (sig_http) {
        .ok => |body| body,
        .status => |resp| {
            return try auditOutcome(
                alloc,
                hooks,
                false,
                .fail,
                .err,
                .{ .text = "signature http failed", .vis = .@"pub" },
                .{ .text = sig_url, .vis = .mask },
                try formatHttpFailure(
                    alloc,
                    "download release signature",
                    sig_url,
                    resp.code,
                    resp.body,
                ),
            );
        },
    };
    verifyArchiveManifest(archive, sig_raw, release.tag_name, asset_name, cli.version) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "signature verify failed", .vis = .@"pub" },
            .{ .text = asset_name, .vis = .mask },
            try formatVerifyFailure(alloc, err, asset_name),
        );
    };

    const next_bin = extractPzBinary(alloc, archive) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "archive extract failed", .vis = .@"pub" },
            .{ .text = asset_name, .vis = .mask },
            try formatExtractFailure(alloc, err, asset_name),
        );
    };
    defer alloc.free(next_bin);

    const exe_path = try hooks.self_exe_path(alloc);
    defer alloc.free(exe_path);
    hooks.install_binary(alloc, exe_path, next_bin) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .fail,
            .err,
            .{ .text = "install failed", .vis = .@"pub" },
            .{ .text = exe_path, .vis = .mask },
            try formatInstallFailure(alloc, err, exe_path),
        );
    };

    return try auditOutcome(
        alloc,
        hooks,
        true,
        .ok,
        .info,
        .{ .text = "upgrade complete", .vis = .@"pub" },
        .{ .text = exe_path, .vis = .mask },
        try std.fmt.allocPrint(
            alloc,
            "updated {s} -> {s}; verified signed archive; restart pz to use the new binary\n",
            .{ cli.version, release.tag_name },
        ),
    );
}

fn checkUpdateUrlOrAudit(alloc: std.mem.Allocator, hooks: Hooks, url: []const u8, msg: []const u8) !?Outcome {
    hooks.check_update_host(alloc, url, hooks.home) catch |err| {
        if (err == error.OutOfMemory) return err;
        return try auditOutcome(
            alloc,
            hooks,
            false,
            .deny,
            .warn,
            .{ .text = msg, .vis = .@"pub" },
            .{ .text = url, .vis = .mask },
            try formatPolicyFailure(alloc, err),
        );
    };
    return null;
}

fn auditOutcome(
    alloc: std.mem.Allocator,
    hooks: Hooks,
    ok: bool,
    out: core.audit.Outcome,
    sev: core.audit.Severity,
    msg: core.audit.Str,
    argv: ?core.audit.Str,
    user_msg: []u8,
) !Outcome {
    try emitUpdateAudit(alloc, hooks, 2, out, sev, msg, argv);
    return .{ .ok = ok, .msg = user_msg };
}

fn emitUpdateAudit(
    alloc: std.mem.Allocator,
    hooks: Hooks,
    seq: u64,
    out: core.audit.Outcome,
    sev: core.audit.Severity,
    msg: core.audit.Str,
    argv: ?core.audit.Str,
) !void {
    if (hooks.emit_audit) |emit| try emit(hooks.emit_audit_ctx.?, alloc, .{
        .ts_ms = hooks.now_ms(),
        .sid = "upgrade",
        .seq = seq,
        .outcome = out,
        .severity = sev,
        .actor = .{ .kind = .sys },
        .res = .{
            .kind = .cmd,
            .name = .{ .text = "upgrade", .vis = .@"pub" },
            .op = "run",
        },
        .msg = msg,
        .data = .{
            .tool = .{
                .name = .{ .text = "upgrade", .vis = .@"pub" },
                .call_id = "upgrade",
                .argv = argv,
            },
        },
    });
}

/// Resolve release channel URL from policy, falling back to default GitHub URL.
fn resolveReleaseUrl(alloc: std.mem.Allocator, home: ?[]const u8) ![]const u8 {
    const cwd = std.fs.cwd().realpathAlloc(alloc, ".") catch return default_release_url;
    defer alloc.free(cwd);
    return resolveFromPolicy(alloc, cwd, home);
}

fn resolveFromPolicy(alloc: std.mem.Allocator, cwd: []const u8, home: ?[]const u8) ![]const u8 {
    const resolved = core.policy.loadResolved(alloc, cwd, home) catch return default_release_url;
    defer core.policy.deinitResolved(alloc, resolved);
    if (resolved.doc.release_url) |url| {
        return alloc.dupe(u8, url);
    }
    return default_release_url;
}

fn checkUpdateAllowed(alloc: std.mem.Allocator, home: ?[]const u8) !void {
    const cwd_path = update_policy_file;
    try checkPolicyPath(alloc, cwd_path);

    const h = home orelse return;
    const home_path = try std.fs.path.join(alloc, &.{ h, update_policy_file });
    defer alloc.free(home_path);
    try checkPolicyPath(alloc, home_path);
}

fn checkPolicyPath(alloc: std.mem.Allocator, path: []const u8) !void {
    const raw = std.fs.cwd().readFileAlloc(alloc, path, 256 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
    defer alloc.free(raw);

    const doc = core.policy.parseDoc(alloc, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
    defer core.policy.deinitDoc(alloc, doc);

    if (core.policy.evaluate(doc.rules, update_policy_path, update_policy_tool) == .deny) {
        return error.UpgradeDisabledByPolicy;
    }
}

fn checkUpdateHostAllowed(alloc: std.mem.Allocator, url: []const u8, home: ?[]const u8) !void {
    try checkHostPolicyPath(alloc, update_policy_file, url);

    const h = home orelse return;
    const home_path = try std.fs.path.join(alloc, &.{ h, update_policy_file });
    defer alloc.free(home_path);
    try checkHostPolicyPath(alloc, home_path, url);
}

fn checkHostPolicyPath(alloc: std.mem.Allocator, path: []const u8, url: []const u8) !void {
    const raw = std.fs.cwd().readFileAlloc(alloc, path, 256 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
    defer alloc.free(raw);

    const doc = core.policy.parseDoc(alloc, raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidPolicy,
    };
    defer core.policy.deinitDoc(alloc, doc);

    const parsed = core.tools.web.parseUrl(url) catch return error.UpdateHostDenied;
    const pol_path = try updateHostPathAlloc(alloc, parsed.host);
    defer alloc.free(pol_path);
    if (core.policy.evaluate(doc.rules, pol_path, update_policy_tool) == .deny) {
        return error.UpdateHostDenied;
    }
}

fn updateHostPathAlloc(alloc: std.mem.Allocator, host: []const u8) ![]u8 {
    const prefix = "runtime/update/";
    const out = try alloc.alloc(u8, prefix.len + host.len);
    @memcpy(out[0..prefix.len], prefix);
    for (host, 0..) |c, i| out[prefix.len + i] = std.ascii.toLower(c);
    return out;
}

fn trustedUpdatePk() !core.signing.PublicKey {
    return core.signing.PublicKey.parseHex(update_pk_hex);
}

fn trustedUpdateRing() !core.signing.KeyRing {
    const pk = trustedUpdatePk() catch return error.SignatureVerifyFailed;
    const kid = core.signing.keyIdFromPk(pk);
    const S = struct {
        var anchor: core.signing.TrustAnchor = undefined;
    };
    S.anchor = .{ .id = kid, .pk = pk };
    return core.signing.KeyRing.fromSingle(&S.anchor);
}

fn checkDefaultKeyRelease() bool {
    if (builtin.mode == .Debug) return false;
    return isDefaultDevKey();
}

fn isDefaultDevKey() bool {
    return std.mem.eql(u8, update_pk_hex, dev_pk_hex);
}

fn verifyArchiveManifest(
    archive: []const u8,
    manifest_raw: []const u8,
    tag_name: []const u8,
    asset_name: []const u8,
    current_ver: []const u8,
) !void {
    const ring = trustedUpdateRing() catch return error.SignatureVerifyFailed;
    const m = core.signing.verifyManifestRing(
        manifest_raw,
        ring,
        archive,
        tag_name,
        asset_name,
        null,
    ) catch return error.SignatureVerifyFailed;

    core.signing.checkNotDowngrade(m.version, current_ver) catch
        return error.DowngradeBlocked;
}

fn httpGetResult(
    alloc: std.mem.Allocator,
    url: []const u8,
    accept: []const u8,
    limit: usize,
) !HttpResult {
    return try httpGetResultWith(alloc, url, accept, limit, .{});
}

fn httpGetResultWith(
    alloc: std.mem.Allocator,
    url: []const u8,
    accept: []const u8,
    limit: usize,
    deps: HttpDeps,
) !HttpResult {
    const modes = [_]HeaderMode{ .full, .wgetish, .bare };
    var i: usize = 0;
    while (i < modes.len) : (i += 1) {
        const mode = modes[i];
        var res = httpGetResultOnceWith(alloc, url, accept, limit, mode, deps) catch |err| {
            if (i + 1 < modes.len and isBadHeaderTransport(err)) continue;
            return err;
        };
        if (i + 1 < modes.len and shouldRetryForBadHeaderResponse(res)) {
            res.deinit(alloc);
            continue;
        }
        return res;
    }
    return error.AllModesExhausted;
}

fn httpGetResultOnce(
    alloc: std.mem.Allocator,
    url: []const u8,
    accept: []const u8,
    limit: usize,
    mode: HeaderMode,
) !HttpResult {
    return try httpGetResultOnceWith(alloc, url, accept, limit, mode, .{});
}

fn httpGetResultOnceWith(
    alloc: std.mem.Allocator,
    url: []const u8,
    accept: []const u8,
    limit: usize,
    mode: HeaderMode,
    deps: HttpDeps,
) !HttpResult {
    var http = try deps.init_client(deps.init_client_ctx, alloc);
    defer http.deinit();
    var proxy_arena = std.heap.ArenaAllocator.init(alloc);
    defer proxy_arena.deinit();
    try http.initDefaultProxies(proxy_arena.allocator());

    const uri = try std.Uri.parse(url);
    const ua = "pz/" ++ cli.version;
    const h_ua = std.http.Header{ .name = "User-Agent", .value = ua };
    const h_accept_full = std.http.Header{ .name = "Accept", .value = accept };
    const h_accept_any = std.http.Header{ .name = "Accept", .value = any_accept };
    const extra_headers: []const std.http.Header = switch (mode) {
        .full => &.{ h_ua, h_accept_full },
        .wgetish => &.{ h_ua, h_accept_any },
        .bare => &.{},
    };
    var req = try http.request(.GET, uri, .{
        .extra_headers = extra_headers,
        .keep_alive = false,
        .redirect_behavior = @enumFromInt(3),
    });
    defer req.deinit();

    try req.sendBodiless();

    var redir_buf: [4096]u8 = undefined;
    var resp = try req.receiveHead(&redir_buf);

    var transfer_buf: [16384]u8 = undefined;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const reader = resp.readerDecompressing(&transfer_buf, &decomp, &decomp_buf);
    const body = try reader.allocRemaining(alloc, .limited(limit));

    if (resp.head.status != .ok) {
        return .{
            .status = .{
                .code = @intFromEnum(resp.head.status),
                .body = body,
            },
        };
    }

    return .{ .ok = body };
}

fn isBadHeaderTransport(err: anyerror) bool {
    return std.mem.eql(u8, @errorName(err), "BadHeaderName");
}

fn isBadHeaderBody(body: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(body, "invalid header name") != null or
        std.ascii.indexOfIgnoreCase(body, "bad header name") != null or
        std.ascii.indexOfIgnoreCase(body, "invalid http header name") != null;
}

fn shouldRetryForBadHeaderResponse(res: HttpResult) bool {
    return switch (res) {
        .status => |st| st.code == 400 and isBadHeaderBody(st.body),
        else => false,
    };
}

fn targetLabelAlloc(alloc: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "{s}-{s}",
        .{ @tagName(builtin.target.cpu.arch), @tagName(builtin.target.os.tag) },
    );
}

fn assetListAlloc(alloc: std.mem.Allocator, assets: []const ReleaseAsset) ![]u8 {
    if (assets.len == 0) return alloc.dupe(u8, "<none>");
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    const max_items: usize = 6;
    const lim = @min(assets.len, max_items);
    for (assets[0..lim], 0..) |asset, i| {
        if (i != 0) try out.appendSlice(alloc, ", ");
        try out.appendSlice(alloc, asset.name);
    }
    if (assets.len > lim) try out.appendSlice(alloc, ", ...");
    return out.toOwnedSlice(alloc);
}

fn sanitizeSnippetAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    const lim = @min(raw.len, body_snip_limit);
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    for (raw[0..lim]) |b| {
        if (b >= 0x20 and b <= 0x7e) {
            try out.append(alloc, b);
        } else if (b == '\n' or b == '\r' or b == '\t') {
            try out.append(alloc, ' ');
        } else {
            try out.append(alloc, '.');
        }
    }
    if (out.items.len == 0) try out.appendSlice(alloc, "<empty>");
    if (raw.len > lim) try out.appendSlice(alloc, "...");
    return out.toOwnedSlice(alloc);
}

fn statusHint(status: u16) []const u8 {
    return switch (status) {
        400 => "bad request from upstream (often proxy/header rewriting).",
        401 => "GitHub rejected the request as unauthorized.",
        403 => "GitHub denied the request (possibly rate-limited or blocked).",
        404 => "Release endpoint not found.",
        429 => "GitHub rate limit exceeded. Retry later.",
        500...599 => "GitHub returned a server error. Retry shortly.",
        else => "GitHub returned an unexpected response.",
    };
}

fn indexOfIgnoreCasePos(hay: []const u8, start: usize, needle: []const u8) ?usize {
    if (start >= hay.len) return null;
    const rel = std.ascii.indexOfIgnoreCase(hay[start..], needle) orelse return null;
    return start + rel;
}

fn stripHtmlTagsCollapseAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var i: usize = 0;
    var in_tag = false;
    var pending_sp = false;
    while (i < raw.len) : (i += 1) {
        const b = raw[i];
        if (b == '<') {
            in_tag = true;
            continue;
        }
        if (b == '>') {
            in_tag = false;
            pending_sp = true;
            continue;
        }
        if (in_tag) continue;
        if (b == '\n' or b == '\r' or b == '\t' or b == ' ') {
            pending_sp = true;
            continue;
        }
        if (pending_sp and out.items.len != 0) {
            try out.append(alloc, ' ');
        }
        pending_sp = false;
        try out.append(alloc, b);
    }
    const owned = try out.toOwnedSlice(alloc);
    const trimmed = std.mem.trim(u8, owned, " ");
    if (trimmed.ptr == owned.ptr and trimmed.len == owned.len) return owned;
    const dup = try alloc.dupe(u8, trimmed);
    alloc.free(owned);
    return dup;
}

fn htmlTagTextAlloc(alloc: std.mem.Allocator, body: []const u8, tag: []const u8) !?[]u8 {
    var open_buf: [16]u8 = undefined;
    var close_buf: [20]u8 = undefined;
    const open = std.fmt.bufPrint(&open_buf, "<{s}", .{tag}) catch return null;
    const close = std.fmt.bufPrint(&close_buf, "</{s}>", .{tag}) catch return null;
    const open_idx = std.ascii.indexOfIgnoreCase(body, open) orelse return null;
    const gt_rel = std.mem.indexOfScalar(u8, body[open_idx..], '>') orelse return null;
    const val_start = open_idx + gt_rel + 1;
    const close_idx = indexOfIgnoreCasePos(body, val_start, close) orelse return null;
    if (close_idx <= val_start) return null;
    const raw = body[val_start..close_idx];
    const txt = try stripHtmlTagsCollapseAlloc(alloc, raw);
    if (txt.len == 0) {
        alloc.free(txt);
        return null;
    }
    return txt;
}

fn responseDetailAlloc(alloc: std.mem.Allocator, body: []const u8) ![]u8 {
    if (std.ascii.indexOfIgnoreCase(body, "<html") != null) {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(alloc);
        const tags = [_][]const u8{ "title", "h1", "h2", "p" };
        for (tags) |tag| {
            const part = try htmlTagTextAlloc(alloc, body, tag) orelse continue;
            defer alloc.free(part);
            if (out.items.len != 0) try out.appendSlice(alloc, " | ");
            try out.appendSlice(alloc, part);
        }
        if (out.items.len != 0) return out.toOwnedSlice(alloc);
        out.deinit(alloc);
    }
    return sanitizeSnippetAlloc(alloc, body);
}

fn formatTransportFailure(
    alloc: std.mem.Allocator,
    step: []const u8,
    url: []const u8,
    err: anyerror,
) ![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "upgrade failed: could not {s}\nreason: {s}\nurl: {s}\nnext: check network/DNS/firewall/proxy settings and retry\n",
        .{ step, @errorName(err), url },
    );
}

fn formatPolicyFailure(alloc: std.mem.Allocator, err: anyerror) ![]u8 {
    return switch (err) {
        error.UpgradeDisabledByPolicy => std.fmt.allocPrint(
            alloc,
            "upgrade blocked by policy\nnext: ask your administrator to allow tool {s} on path {s}\n",
            .{ update_policy_tool, update_policy_path },
        ),
        error.UpdateHostDenied => std.fmt.allocPrint(
            alloc,
            "upgrade blocked by policy host gate\nnext: ask your administrator to allow tool {s} on runtime/update/<host>\n",
            .{update_policy_tool},
        ),
        error.InvalidPolicy => std.fmt.allocPrint(
            alloc,
            "upgrade blocked by invalid policy\nnext: fix {s} or remove it and retry\n",
            .{update_policy_file},
        ),
        else => std.fmt.allocPrint(
            alloc,
            "upgrade blocked by policy check failure\nreason: {s}\nnext: inspect policy settings and retry\n",
            .{@errorName(err)},
        ),
    };
}

fn formatVerifyFailure(alloc: std.mem.Allocator, err: anyerror, asset_name: []const u8) ![]u8 {
    return switch (err) {
        error.SignatureVerifyFailed => std.fmt.allocPrint(
            alloc,
            "upgrade failed: signature verification failed for {s}\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
            .{asset_name},
        ),
        error.DowngradeBlocked => std.fmt.allocPrint(
            alloc,
            "upgrade failed: manifest version is not newer than running version for {s}\nnext: this may indicate a replay attack; install manually if intended\n",
            .{asset_name},
        ),
        error.DefaultKeyRefused => std.fmt.allocPrint(
            alloc,
            "upgrade refused: release build uses the default dev signing key\nnext: rebuild with -Dupdate-pk-hex=<your-key> or disable upgrade via policy\n",
            .{},
        ),
        else => std.fmt.allocPrint(
            alloc,
            "upgrade failed: could not verify {s}\nreason: {s}\nnext: inspect signing configuration and retry\n",
            .{ asset_name, @errorName(err) },
        ),
    };
}

fn formatHttpFailure(
    alloc: std.mem.Allocator,
    step: []const u8,
    url: []const u8,
    status: u16,
    body: []const u8,
) ![]u8 {
    const detail = try responseDetailAlloc(alloc, body);
    defer alloc.free(detail);
    return std.fmt.allocPrint(
        alloc,
        "upgrade failed: could not {s}\nhttp status: {d}\nreason: {s}\nurl: {s}\nresponse: {s}\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
        .{ step, status, statusHint(status), url, detail },
    );
}

fn formatParseFailure(alloc: std.mem.Allocator, body: []const u8) ![]u8 {
    const snip = try sanitizeSnippetAlloc(alloc, body);
    defer alloc.free(snip);
    return std.fmt.allocPrint(
        alloc,
        "upgrade failed: release metadata could not be parsed\nresponse: {s}\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
        .{snip},
    );
}

fn formatExtractFailure(alloc: std.mem.Allocator, err: anyerror, asset_name: []const u8) ![]u8 {
    if (err == error.ArchiveMissingBinary) {
        return std.fmt.allocPrint(
            alloc,
            "upgrade failed: downloaded archive {s} did not contain a pz binary\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
            .{asset_name},
        );
    }
    return std.fmt.allocPrint(
        alloc,
        "upgrade failed: could not unpack archive {s}\nreason: {s}\nnext: retry later or install manually from https://github.com/joelreymont/pz/releases/latest\n",
        .{ asset_name, @errorName(err) },
    );
}

fn formatInstallFailure(alloc: std.mem.Allocator, err: anyerror, exe_path: []const u8) ![]u8 {
    return switch (err) {
        error.AccessDenied => std.fmt.allocPrint(
            alloc,
            "upgrade failed: permission denied while replacing {s}\nnext: run with permissions that can write this path or reinstall manually\n",
            .{exe_path},
        ),
        else => std.fmt.allocPrint(
            alloc,
            "upgrade failed: could not replace {s}\nreason: {s}\nnext: retry or reinstall manually\n",
            .{ exe_path, @errorName(err) },
        ),
    };
}

fn targetAssetName() ?[]const u8 {
    return switch (builtin.target.os.tag) {
        .linux => switch (builtin.target.cpu.arch) {
            .x86_64 => "pz-x86_64-linux.tar.gz",
            .aarch64 => "pz-aarch64-linux.tar.gz",
            else => null,
        },
        .macos => switch (builtin.target.cpu.arch) {
            .aarch64 => "pz-aarch64-macos.tar.gz",
            else => null,
        },
        else => null,
    };
}

fn findAssetUrl(assets: []const ReleaseAsset, want_name: []const u8) ?[]const u8 {
    for (assets) |asset| {
        if (std.mem.eql(u8, asset.name, want_name)) return asset.browser_download_url;
    }
    return null;
}

fn extractPzBinary(alloc: std.mem.Allocator, archive_gz: []const u8) ![]u8 {
    var gz_reader: std.Io.Reader = .fixed(archive_gz);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decomp = std.compress.flate.Decompress.init(&gz_reader, .gzip, &window);

    var tar_buf: std.Io.Writer.Allocating = .init(alloc);
    defer tar_buf.deinit();
    _ = try decomp.reader.streamRemaining(&tar_buf.writer);
    const tar_bytes = try tar_buf.toOwnedSlice();
    defer alloc.free(tar_bytes);

    var tar_reader: std.Io.Reader = .fixed(tar_bytes);
    var file_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&tar_reader, .{
        .file_name_buffer = &file_name_buf,
        .link_name_buffer = &link_name_buf,
    });

    while (try it.next()) |file| {
        if (file.kind != .file) continue;
        if (!std.mem.eql(u8, file.name, "pz") and !std.mem.endsWith(u8, file.name, "/pz")) continue;

        var out: std.Io.Writer.Allocating = .init(alloc);
        errdefer out.deinit();
        try it.streamRemaining(file, &out.writer);
        return out.toOwnedSlice();
    }

    return error.ArchiveMissingBinary;
}

fn installBinary(alloc: std.mem.Allocator, exe_path: []const u8, binary: []const u8) !void {
    const exe_dir = std.fs.path.dirname(exe_path) orelse return error.InvalidExecutablePath;
    const exe_base = std.fs.path.basename(exe_path);

    // Unique temp name: .<base>-update-<pid>-<timestamp>.tmp
    const pid = std.c.getpid();
    const ts = @as(u64, @intCast(std.time.milliTimestamp()));
    const tmp_name = try std.fmt.allocPrint(alloc, ".{s}-update-{d}-{d}.tmp", .{ exe_base, pid, ts });
    defer alloc.free(tmp_name);
    const tmp_path = try std.fs.path.join(alloc, &.{ exe_dir, tmp_name });
    defer alloc.free(tmp_path);

    var moved = false;
    defer if (!moved) std.fs.deleteFileAbsolute(tmp_path) catch {}; // cleanup: propagation impossible

    const f = try std.fs.createFileAbsolute(tmp_path, .{ .truncate = true });
    defer f.close();

    try f.writeAll(binary);
    if (std.fs.has_executable_bit) try f.chmod(0o755);

    // fsync data+metadata before rename for crash safety.
    try f.sync();

    try std.fs.renameAbsolute(tmp_path, exe_path);
    moved = true;

    // fsync containing directory to persist the rename.
    var dir = try std.fs.openDirAbsolute(exe_dir, .{});
    defer dir.close();
    try std.posix.fsync(dir.fd);
}

fn makeTarGzAlloc(alloc: std.mem.Allocator, name: []const u8, data: []const u8) ![]u8 {
    const blk: usize = 512;
    if (name.len == 0 or name.len > 100) return error.NameTooLong;

    const data_pad = (blk - (data.len % blk)) % blk;
    const tar_len = blk + data.len + data_pad + (2 * blk);
    if (tar_len > std.math.maxInt(u16)) return error.TestUnexpectedResult;

    const tar = try alloc.alloc(u8, tar_len);
    defer alloc.free(tar);
    @memset(tar, 0);

    var hdr = tar[0..blk];
    @memcpy(hdr[0..name.len], name);
    writeOctal(hdr[100..108], 0o755);
    writeOctal(hdr[108..116], 0);
    writeOctal(hdr[116..124], 0);
    writeOctal(hdr[124..136], data.len);
    writeOctal(hdr[136..148], 0);
    @memset(hdr[148..156], ' ');
    hdr[156] = '0';
    @memcpy(hdr[257..263], "ustar\x00");
    @memcpy(hdr[263..265], "00");

    var sum: u32 = 0;
    for (hdr) |b| sum +%= b;
    writeChecksum(hdr[148..156], sum);

    const data_off = blk;
    @memcpy(tar[data_off .. data_off + data.len], data);

    const gz_len = 10 + 1 + 2 + 2 + tar_len + 8;
    const gz = try alloc.alloc(u8, gz_len);
    errdefer alloc.free(gz);

    @memcpy(gz[0..10], "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03");
    var pos: usize = 10;
    gz[pos] = 0x01;
    pos += 1;

    const len16: u16 = @intCast(tar_len);
    writeLe16(gz[pos .. pos + 2], len16);
    pos += 2;
    writeLe16(gz[pos .. pos + 2], ~len16);
    pos += 2;

    @memcpy(gz[pos .. pos + tar_len], tar);
    pos += tar_len;

    var crc = std.hash.Crc32.init();
    crc.update(tar);
    writeLe32(gz[pos .. pos + 4], crc.final());
    pos += 4;
    writeLe32(gz[pos .. pos + 4], @intCast(tar_len));
    pos += 4;

    std.debug.assert(pos == gz_len);
    return gz;
}

fn writeOctal(dst: []u8, value: usize) void {
    if (dst.len == 0) return;
    @memset(dst, '0');
    dst[dst.len - 1] = 0;

    var v = value;
    var i = dst.len - 2;
    while (true) {
        dst[i] = @as(u8, '0') + @as(u8, @intCast(v & 0x7));
        v >>= 3;
        if (v == 0 or i == 0) break;
        i -= 1;
    }
}

fn writeChecksum(dst: []u8, value: u32) void {
    @memset(dst, '0');
    var v = value;
    var i: usize = 5;
    while (true) {
        dst[i] = @as(u8, '0') + @as(u8, @intCast(v & 0x7));
        v >>= 3;
        if (v == 0 or i == 0) break;
        i -= 1;
    }
    dst[6] = 0;
    dst[7] = ' ';
}

fn writeLe16(dst: []u8, value: u16) void {
    dst[0] = @intCast(value & 0xff);
    dst[1] = @intCast((value >> 8) & 0xff);
}

fn writeLe32(dst: []u8, value: u32) void {
    dst[0] = @intCast(value & 0xff);
    dst[1] = @intCast((value >> 8) & 0xff);
    dst[2] = @intCast((value >> 16) & 0xff);
    dst[3] = @intCast((value >> 24) & 0xff);
}

test "findAssetUrl returns exact match" {
    const assets = [_]ReleaseAsset{
        .{ .name = "a.tar.gz", .browser_download_url = "https://example/a" },
        .{ .name = "b.tar.gz", .browser_download_url = "https://example/b" },
    };
    const got = findAssetUrl(&assets, "b.tar.gz") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("https://example/b", got);
}

test "findAssetUrl returns null for missing assets" {
    const assets = [_]ReleaseAsset{
        .{ .name = "a.tar.gz", .browser_download_url = "https://example/a" },
    };
    try std.testing.expect(findAssetUrl(&assets, "missing.tar.gz") == null);
}

test "targetAssetName maps supported targets only" {
    const got = targetAssetName();
    const os = builtin.target.os.tag;
    const arch = builtin.target.cpu.arch;
    const supported = (os == .linux and (arch == .x86_64 or arch == .aarch64)) or
        (os == .macos and arch == .aarch64);
    if (supported) {
        try std.testing.expect(got != null);
    } else {
        try std.testing.expect(got == null);
    }
}

test "extractPzBinary reads pz from archive root" {
    const data = "bin\n";
    const gz = try makeTarGzAlloc(std.testing.allocator, "pz", data);
    defer std.testing.allocator.free(gz);

    const got = try extractPzBinary(std.testing.allocator, gz);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(data, got);
}

test "extractPzBinary reads nested pz path" {
    const data = "nested\n";
    const gz = try makeTarGzAlloc(std.testing.allocator, "bin/pz", data);
    defer std.testing.allocator.free(gz);

    const got = try extractPzBinary(std.testing.allocator, gz);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings(data, got);
}

test "extractPzBinary errors when archive has no pz binary" {
    const gz = try makeTarGzAlloc(std.testing.allocator, "bin/other", "x");
    defer std.testing.allocator.free(gz);

    try std.testing.expectError(error.ArchiveMissingBinary, extractPzBinary(std.testing.allocator, gz));
}

test "installBinary atomically replaces executable bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "pz",
        .data = "old",
    });
    const exe_path = try tmp.dir.realpathAlloc(std.testing.allocator, "pz");
    defer std.testing.allocator.free(exe_path);

    try installBinary(std.testing.allocator, exe_path, "new-binary");

    const f = try std.fs.openFileAbsolute(exe_path, .{});
    defer f.close();
    const got = try f.readToEndAlloc(std.testing.allocator, 1024);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("new-binary", got);
}

test "installBinary rejects non-path executable" {
    try std.testing.expectError(error.InvalidExecutablePath, installBinary(std.testing.allocator, "pz", "x"));
}

test "sanitizeSnippetAlloc normalizes binary text and truncates" {
    const raw = "ok\x00\x01\nline";
    const snip = try sanitizeSnippetAlloc(std.testing.allocator, raw);
    defer std.testing.allocator.free(snip);
    try std.testing.expect(std.mem.indexOf(u8, snip, "ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, snip, "..") != null);
}

test "property: sanitizeSnippetAlloc stays printable and non-empty" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { raw: zc.String }) bool {
            const alloc = std.testing.allocator;
            const raw = args.raw.slice();
            const snip = sanitizeSnippetAlloc(alloc, raw) catch return false;
            defer alloc.free(snip);
            if (snip.len == 0) return false;
            if (snip.len > body_snip_limit + 3) return false;
            for (snip) |b| {
                if (b < 0x20 or b > 0x7e) return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 300 });
}

test "property: stripHtmlTagsCollapseAlloc unwraps simple tagged text" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: zc.Id, b: zc.Id }) bool {
            const alloc = std.testing.allocator;
            const raw = std.fmt.allocPrint(alloc, "<p>\n<b>{s}</b>\t{s}</p>", .{
                args.a.slice(),
                args.b.slice(),
            }) catch return false;
            defer alloc.free(raw);
            const got = stripHtmlTagsCollapseAlloc(alloc, raw) catch return false;
            defer alloc.free(got);
            const want = std.fmt.allocPrint(alloc, "{s} {s}", .{ args.a.slice(), args.b.slice() }) catch return false;
            defer alloc.free(want);
            return std.mem.eql(u8, want, got);
        }
    }.prop, .{ .iterations = 300 });
}

test "formatHttpFailure includes actionable fields" {
    const msg = try formatHttpFailure(
        std.testing.allocator,
        "fetch latest release metadata",
        default_release_url,
        403,
        "{\"message\":\"API rate limit exceeded\"}",
    );
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "http status: 403") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "rate-limited") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "response: ") != null);
}

test "formatHttpFailure extracts concise html error text" {
    const html =
        \\<!DOCTYPE HTML>
        \\<html><head><title>Bad Request</title></head>
        \\<body><h2>Bad Request - Invalid Header</h2>
        \\<p>HTTP Error 400. The request has an invalid header name.</p></body></html>
    ;
    const msg = try formatHttpFailure(
        std.testing.allocator,
        "download release archive",
        "https://example.invalid/archive",
        400,
        html,
    );
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "http status: 400") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "proxy/header rewriting") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "Bad Request - Invalid Header") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "invalid header name") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "<html>") == null);
}

test "formatPolicyFailure reports denied upgrade path" {
    const msg = try formatPolicyFailure(std.testing.allocator, error.UpgradeDisabledByPolicy);
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "upgrade blocked by policy") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, update_policy_tool) != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, update_policy_path) != null);
}

test "checkUpdateHostAllowed rejects host absent from policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{
        .sub_path = update_policy_file,
        .data = "{\"version\":1,\"rules\":[{\"pattern\":\".pz/upgrade\",\"effect\":\"allow\",\"tool\":\"upgrade\"}]}",
    });

    try std.testing.expectError(
        error.UpdateHostDenied,
        checkUpdateHostAllowed(std.testing.allocator, "https://api.github.com/repos/joelreymont/pz/releases/latest", null),
    );
}

test "checkUpdateHostAllowed accepts explicitly allowed host" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    try tmp.dir.makePath(".pz");
    try tmp.dir.writeFile(.{
        .sub_path = update_policy_file,
        .data =
        \\{"version":1,"rules":[
        \\  {"pattern":".pz/upgrade","effect":"allow","tool":"upgrade"},
        \\  {"pattern":"runtime/update/api.github.com","effect":"allow","tool":"upgrade"}
        \\]}
        ,
    });

    try checkUpdateHostAllowed(std.testing.allocator, "https://api.github.com/repos/joelreymont/pz/releases/latest", null);
}

const UpdateFetchSnap = struct {
    ok: bool,
    msg: []const u8,
    reqs: []const u8,
    req_ct: usize,
    fetch_ct: usize,
    all_have_ca: bool,
    all_rescan_disabled: bool,
};

const UpdateClientTap = struct {
    fetch_ct: usize = 0,
    no_ca_ct: usize = 0,
    rescan_ct: usize = 0,

    fn init(ctx: ?*anyopaque, alloc: std.mem.Allocator) !std.http.Client {
        const tap: *UpdateClientTap = @ptrCast(@alignCast(ctx.?));
        var http = try app_tls.initRuntimeClient(alloc, null);
        tap.fetch_ct += 1;
        if (http.ca_bundle.map.size == 0) tap.no_ca_ct += 1;
        if (@atomicLoad(bool, &http.next_https_rescan_certs, .acquire)) tap.rescan_ct += 1;
        return http;
    }
};

const writeTestCfg = fixtures.writeCfg;

test "update uses runtime CA bundle for metadata archive and signature fetches" {
    if (targetAssetName() == null) return;

    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_path = try app_tls.writeTestCert(tmp.dir, "ca.pem");
    defer std.testing.allocator.free(cert_path);
    try writeTestCfg(tmp, cert_path);

    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    const asset_name = targetAssetName() orelse return error.UnsupportedPlatform;
    const archive = try makeTarGzAlloc(std.testing.allocator, "bin/pz", "next-pz\n");
    defer std.testing.allocator.free(archive);
    var resps = [_]http_mock.Response{ .{}, .{}, .{}, .{}, .{}, .{} };
    var server = try http_mock.Server.initSeq(std.testing.allocator, &resps);
    defer server.deinit();

    const base_url = try server.urlAlloc(std.testing.allocator, "");
    defer std.testing.allocator.free(base_url);
    const latest_url = try server.urlAlloc(std.testing.allocator, "/release/latest");
    defer std.testing.allocator.free(latest_url);
    const archive_url = try server.urlAlloc(std.testing.allocator, "/asset/archive");
    defer std.testing.allocator.free(archive_url);
    const sig_url = try server.urlAlloc(std.testing.allocator, "/asset/archive.manifest");
    defer std.testing.allocator.free(sig_url);

    const manifest = try updateTestManifestAlloc(std.testing.allocator, archive, false, "v9.9.9", asset_name, archive_url);
    defer std.testing.allocator.free(manifest);
    const release_body = try updateReleaseBodyAlloc(std.testing.allocator, "v9.9.9", asset_name, archive_url, sig_url);
    defer std.testing.allocator.free(release_body);

    resps[0] = .{ .status = "302 Found", .headers = &.{"Location: /release/meta"} };
    resps[1] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/json"},
        .body = release_body,
    };
    resps[2] = .{ .status = "302 Found", .headers = &.{"Location: /blob/archive"} };
    resps[3] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/octet-stream"},
        .body = archive,
    };
    resps[4] = .{ .status = "307 Temporary Redirect", .headers = &.{"Location: ../blob/archive.manifest"} };
    resps[5] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: text/plain"},
        .body = manifest,
    };

    const CaHooks = struct {
        var base: []const u8 = undefined;
        var latest: []const u8 = undefined;
        var tap = UpdateClientTap{};

        fn checkHost(_: std.mem.Allocator, url: []const u8, _: ?[]const u8) !void {
            if (std.mem.eql(u8, url, default_release_url)) return;
            if (std.mem.startsWith(u8, url, base)) return;
            return error.TestUnexpectedResult;
        }

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, accept: []const u8, limit: usize) !HttpResult {
            const local_url = if (std.mem.eql(u8, url, default_release_url))
                latest
            else if (std.mem.startsWith(u8, url, base))
                url
            else
                return error.TestUnexpectedResult;
            return httpGetResultWith(alloc, local_url, accept, limit, .{
                .init_client = UpdateClientTap.init,
                .init_client_ctx = &tap,
            });
        }

        fn selfExePath(_: std.mem.Allocator) ![]u8 {
            return error.TestUnexpectedResult;
        }

        fn installBinary(_: std.mem.Allocator, _: []const u8, _: []const u8) !void {
            return error.TestUnexpectedResult;
        }
    };
    CaHooks.base = base_url;
    CaHooks.latest = latest_url;
    CaHooks.tap = .{};

    const thr = try server.spawn();
    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = CaHooks.httpGet,
        .self_exe_path = CaHooks.selfExePath,
        .install_binary = CaHooks.installBinary,
        .check_update_host = CaHooks.checkHost,
    });
    try server.join(thr);
    defer out.deinit(std.testing.allocator);

    const reqs = try joinRequestLinesAlloc(std.testing.allocator, &server);
    defer std.testing.allocator.free(reqs);

    try oh.snap(@src(),
        \\app.update.UpdateFetchSnap
        \\  .ok: bool = false
        \\  .msg: []const u8
        \\    "upgrade failed: signature verification failed for pz-aarch64-macos.tar.gz
        \\next: retry later or install manually from https://github.com/joelreymont/pz/releases/latest
        \\"
        \\  .reqs: []const u8
        \\    "GET /release/latest HTTP/1.1
        \\GET /release/meta HTTP/1.1
        \\GET /asset/archive HTTP/1.1
        \\GET /blob/archive HTTP/1.1
        \\GET /asset/archive.manifest HTTP/1.1
        \\GET /blob/archive.manifest HTTP/1.1"
        \\  .req_ct: usize = 6
        \\  .fetch_ct: usize = 3
        \\  .all_have_ca: bool = true
        \\  .all_rescan_disabled: bool = true
    ).expectEqual(UpdateFetchSnap{
        .ok = out.ok,
        .msg = out.msg,
        .reqs = reqs,
        .req_ct = server.requestCount(),
        .fetch_ct = CaHooks.tap.fetch_ct,
        .all_have_ca = CaHooks.tap.no_ca_ct == 0,
        .all_rescan_disabled = CaHooks.tap.rescan_ct == 0,
    });
}

test "update invalid runtime CA bundle fails before transport" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "bad.pem", .data = "-----BEGIN CERTIFICATE-----\nnot-base64\n" });
    const bad_path = try tmp.dir.realpathAlloc(std.testing.allocator, "bad.pem");
    defer std.testing.allocator.free(bad_path);
    try writeTestCfg(tmp, bad_path);

    var cwd = try path_guard.CwdGuard.enter(tmp.dir);
    defer cwd.deinit();

    var server = try http_mock.Server.initSeq(std.testing.allocator, &.{.{ .headers = &.{"Content-Type: application/json"}, .body = "{\"tag_name\":\"v9.9.9\",\"assets\":[]}" }});
    defer server.deinit();

    const base_url = try server.urlAlloc(std.testing.allocator, "");
    defer std.testing.allocator.free(base_url);
    const latest_url = try server.urlAlloc(std.testing.allocator, "/release/latest");
    defer std.testing.allocator.free(latest_url);

    const BadHooks = struct {
        var base: []const u8 = undefined;
        var latest: []const u8 = undefined;

        fn checkHost(_: std.mem.Allocator, url: []const u8, _: ?[]const u8) !void {
            if (std.mem.eql(u8, url, default_release_url)) return;
            if (std.mem.startsWith(u8, url, base)) return;
            return error.TestUnexpectedResult;
        }

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, accept: []const u8, limit: usize) !HttpResult {
            const local_url = if (std.mem.eql(u8, url, default_release_url))
                latest
            else if (std.mem.startsWith(u8, url, base))
                url
            else
                return error.TestUnexpectedResult;
            return httpGetResultWith(alloc, local_url, accept, limit, .{});
        }
    };
    BadHooks.base = base_url;
    BadHooks.latest = latest_url;

    const thr = try server.spawn();
    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = BadHooks.httpGet,
        .check_update_host = BadHooks.checkHost,
    });
    try server.join(thr);
    defer out.deinit(std.testing.allocator);

    const Snap = struct {
        ok: bool,
        msg: []const u8,
        req_ct: usize,
    };
    try oh.snap(@src(),
        \\app.update.test.update invalid runtime CA bundle fails before transport.Snap
        \\  .ok: bool = false
        \\  .msg: []const u8
        \\    "upgrade failed: release v9.9.9 does not contain asset pz-aarch64-macos.tar.gz
        \\available assets: <none>
        \\manual install: https://github.com/joelreymont/pz/releases/latest
        \\"
        \\  .req_ct: usize = 1
    ).expectEqual(Snap{
        .ok = out.ok,
        .msg = out.msg,
        .req_ct = server.requestCount(),
    });
}

test "update audit emits start and deny entries on policy block" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Capture = struct {
        rows: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
            for (self.rows.items) |row| alloc.free(row);
            self.rows.deinit(alloc);
        }
    };

    var cap = Capture{};
    defer cap.deinit(std.testing.allocator);

    const out = try runOutcomeWith(std.testing.allocator, .{
        .check_update_allowed = struct {
            fn f(_: std.mem.Allocator, _: ?[]const u8) !void {
                return error.UpgradeDisabledByPolicy;
            }
        }.f,
        .emit_audit_ctx = &cap,
        .emit_audit = struct {
            fn f(ctx: *anyopaque, alloc: std.mem.Allocator, ent: core.audit.Entry) !void {
                const cap_ptr: *Capture = @ptrCast(@alignCast(ctx));
                const raw = try core.audit.encodeAlloc(alloc, ent);
                try cap_ptr.rows.append(alloc, raw);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 123;
            }
        }.f,
    });
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(!out.ok);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":123,"sid":"upgrade","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"upgrade start","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":123,"sid":"upgrade","seq":2,"kind":"tool","sev":"warn","out":"deny","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"policy denied","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade","argv":{"text":"[mask:<^[0-9a-f]{16}$>]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(joined);
}

test "update audit emits start and success entries when already current" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const Capture = struct {
        rows: std.ArrayListUnmanaged([]u8) = .empty,

        fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
            for (self.rows.items) |row| alloc.free(row);
            self.rows.deinit(alloc);
        }
    };

    var cap = Capture{};
    defer cap.deinit(std.testing.allocator);

    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = struct {
            fn f(alloc: std.mem.Allocator, _: []const u8, _: []const u8, _: usize) !HttpResult {
                return .{ .ok = try alloc.dupe(u8, "{\"tag_name\":\"" ++ cli.version ++ "\",\"assets\":[]}") };
            }
        }.f,
        .emit_audit_ctx = &cap,
        .emit_audit = struct {
            fn f(ctx: *anyopaque, alloc: std.mem.Allocator, ent: core.audit.Entry) !void {
                const cap_ptr: *Capture = @ptrCast(@alignCast(ctx));
                const raw = try core.audit.encodeAlloc(alloc, ent);
                try cap_ptr.rows.append(alloc, raw);
            }
        }.f,
        .now_ms = struct {
            fn f() i64 {
                return 456;
            }
        }.f,
    });
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(out.ok);

    const joined = try std.mem.join(std.testing.allocator, "\n", cap.rows.items);
    defer std.testing.allocator.free(joined);
    try oh.snap(@src(),
        \\[]u8
        \\  "{"v":1,"ts_ms":456,"sid":"upgrade","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"upgrade start","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":456,"sid":"upgrade","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"already up to date","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade"},"attrs":[]}"
    ).expectEqual(joined);
}

test "update denies archive host before transport" {
    if (targetAssetName() == null) return;

    const out = try runOutcomeWith(std.testing.allocator, .{
        .check_update_allowed = struct {
            fn f(_: std.mem.Allocator, _: ?[]const u8) !void {}
        }.f,
        .check_update_host = struct {
            fn f(_: std.mem.Allocator, url: []const u8, _: ?[]const u8) !void {
                if (std.mem.endsWith(u8, url, ".tar.gz")) return error.UpdateHostDenied;
            }
        }.f,
        .http_get = struct {
            fn f(alloc: std.mem.Allocator, url: []const u8, _: []const u8, _: usize) !HttpResult {
                if (!std.mem.eql(u8, url, default_release_url)) return error.TestUnexpectedResult;
                const asset_name = targetAssetName() orelse return error.TestUnexpectedResult;
                const body = try std.fmt.allocPrint(
                    alloc,
                    "{{\"tag_name\":\"v9.9.9\",\"assets\":[{{\"name\":\"{s}\",\"browser_download_url\":\"https://dl.invalid/pz.tar.gz\"}},{{\"name\":\"{s}" ++ sig_suffix ++ "\",\"browser_download_url\":\"https://dl.invalid/pz.tar.gz" ++ sig_suffix ++ "\"}}]}}",
                    .{ asset_name, asset_name },
                );
                return .{ .ok = body };
            }
        }.f,
    });
    defer out.deinit(std.testing.allocator);

    try std.testing.expect(!out.ok);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "policy host gate") != null);
}

test "formatVerifyFailure reports signature rejection" {
    const msg = try formatVerifyFailure(std.testing.allocator, error.SignatureVerifyFailed, "pz.tar.gz");
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "signature verification failed") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "pz.tar.gz") != null);
}

test "isBadHeaderBody detects common bad-header responses" {
    try std.testing.expect(isBadHeaderBody("HTTP Error 400. The request has an invalid header name."));
    try std.testing.expect(isBadHeaderBody("bad header name in request"));
    try std.testing.expect(!isBadHeaderBody("rate limit exceeded"));
}

test "shouldRetryForBadHeaderResponse only retries matching 400 responses" {
    const bad = HttpResult{
        .status = .{
            .code = 400,
            .body = try std.testing.allocator.dupe(u8, "<p>invalid header name</p>"),
        },
    };
    defer bad.deinit(std.testing.allocator);
    try std.testing.expect(shouldRetryForBadHeaderResponse(bad));

    const non_400 = HttpResult{
        .status = .{
            .code = 403,
            .body = try std.testing.allocator.dupe(u8, "<p>invalid header name</p>"),
        },
    };
    defer non_400.deinit(std.testing.allocator);
    try std.testing.expect(!shouldRetryForBadHeaderResponse(non_400));

    const non_match = HttpResult{
        .status = .{
            .code = 400,
            .body = try std.testing.allocator.dupe(u8, "{\"message\":\"rate limited\"}"),
        },
    };
    defer non_match.deinit(std.testing.allocator);
    try std.testing.expect(!shouldRetryForBadHeaderResponse(non_match));
}

test "update e2e verify fail stays local and audits deterministically" {
    if (targetAssetName() == null) return;

    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const asset_name = targetAssetName() orelse return error.UnsupportedPlatform;
    const archive = try makeTarGzAlloc(std.testing.allocator, "bin/pz", "next-pz\n");
    defer std.testing.allocator.free(archive);
    var resps = [_]http_mock.Response{ .{}, .{}, .{}, .{}, .{}, .{} };
    var server = try http_mock.Server.initSeq(std.testing.allocator, &resps);
    defer server.deinit();

    const base_url = try server.urlAlloc(std.testing.allocator, "");
    defer std.testing.allocator.free(base_url);
    const latest_url = try server.urlAlloc(std.testing.allocator, "/release/latest");
    defer std.testing.allocator.free(latest_url);
    const archive_url = try server.urlAlloc(std.testing.allocator, "/asset/archive");
    defer std.testing.allocator.free(archive_url);
    const sig_url = try server.urlAlloc(std.testing.allocator, "/asset/archive.manifest");
    defer std.testing.allocator.free(sig_url);

    const manifest = try updateTestManifestAlloc(std.testing.allocator, archive, false, "v9.9.9", asset_name, archive_url);
    defer std.testing.allocator.free(manifest);
    const release_body = try updateReleaseBodyAlloc(std.testing.allocator, "v9.9.9", asset_name, archive_url, sig_url);
    defer std.testing.allocator.free(release_body);

    resps[0] = .{ .status = "302 Found", .headers = &.{"Location: /release/meta"} };
    resps[1] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/json"},
        .body = release_body,
    };
    resps[2] = .{ .status = "302 Found", .headers = &.{"Location: /blob/archive"} };
    resps[3] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/octet-stream"},
        .body = archive,
    };
    resps[4] = .{ .status = "307 Temporary Redirect", .headers = &.{"Location: ../blob/archive.manifest"} };
    resps[5] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: text/plain"},
        .body = manifest,
    };

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    const FailHooks = struct {
        var base: []const u8 = undefined;
        var latest: []const u8 = undefined;
        var clk = time_mock.FixedMs{ .now_ms = 111 };

        fn nowMs() i64 {
            return clk.nowMs();
        }

        fn checkHost(_: std.mem.Allocator, url: []const u8, _: ?[]const u8) !void {
            if (std.mem.eql(u8, url, default_release_url)) return;
            if (std.mem.startsWith(u8, url, base)) return;
            return error.TestUnexpectedResult;
        }

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, accept: []const u8, limit: usize) !HttpResult {
            const local_url = if (std.mem.eql(u8, url, default_release_url))
                latest
            else if (std.mem.startsWith(u8, url, base))
                url
            else
                return error.TestUnexpectedResult;
            return httpGetResult(alloc, local_url, accept, limit);
        }

        fn selfExePath(_: std.mem.Allocator) ![]u8 {
            return error.TestUnexpectedResult;
        }

        fn installBinary(_: std.mem.Allocator, _: []const u8, _: []const u8) !void {
            return error.TestUnexpectedResult;
        }
    };
    FailHooks.base = base_url;
    FailHooks.latest = latest_url;

    const thr = try server.spawn();
    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = FailHooks.httpGet,
        .self_exe_path = FailHooks.selfExePath,
        .install_binary = FailHooks.installBinary,
        .check_update_host = FailHooks.checkHost,
        .emit_audit_ctx = &cap,
        .emit_audit = AuditCap.emit,
        .now_ms = FailHooks.nowMs,
    });
    try server.join(thr);
    defer out.deinit(std.testing.allocator);

    const reqs = try joinRequestLinesAlloc(std.testing.allocator, &server);
    defer std.testing.allocator.free(reqs);
    const rows = try cap.joinedAlloc(std.testing.allocator);
    defer std.testing.allocator.free(rows);

    const Snap = struct {
        ok: bool,
        msg: []const u8,
        reqs: []const u8,
        rows: []const u8,
    };
    try oh.snap(@src(),
        \\app.update.test.update e2e verify fail stays local and audits deterministically.Snap
        \\  .ok: bool = false
        \\  .msg: []const u8
        \\    "upgrade failed: signature verification failed for pz-aarch64-macos.tar.gz
        \\next: retry later or install manually from https://github.com/joelreymont/pz/releases/latest
        \\"
        \\  .reqs: []const u8
        \\    "GET /release/latest HTTP/1.1
        \\GET /release/meta HTTP/1.1
        \\GET /asset/archive HTTP/1.1
        \\GET /blob/archive HTTP/1.1
        \\GET /asset/archive.manifest HTTP/1.1
        \\GET /blob/archive.manifest HTTP/1.1"
        \\  .rows: []const u8
        \\    "{"v":1,"ts_ms":111,"sid":"upgrade","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"upgrade start","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":111,"sid":"upgrade","seq":2,"kind":"tool","sev":"err","out":"fail","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"signature verify failed","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade","argv":{"text":"[mask:<^[0-9a-f]{16}$>]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(Snap{
        .ok = out.ok,
        .msg = out.msg,
        .reqs = reqs,
        .rows = rows,
    });
}

test "update e2e verify success installs via local redirects and audits deterministically" {
    if (targetAssetName() == null) return;

    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const asset_name = targetAssetName() orelse return error.UnsupportedPlatform;
    const archive = try makeTarGzAlloc(std.testing.allocator, "bin/pz", "next-pz\n");
    defer std.testing.allocator.free(archive);
    var resps = [_]http_mock.Response{ .{}, .{}, .{}, .{}, .{}, .{} };
    var server = try http_mock.Server.initSeq(std.testing.allocator, &resps);
    defer server.deinit();

    const base_url = try server.urlAlloc(std.testing.allocator, "");
    defer std.testing.allocator.free(base_url);
    const latest_url = try server.urlAlloc(std.testing.allocator, "/release/latest");
    defer std.testing.allocator.free(latest_url);
    const archive_url = try server.urlAlloc(std.testing.allocator, "/asset/archive");
    defer std.testing.allocator.free(archive_url);
    const sig_url = try server.urlAlloc(std.testing.allocator, "/asset/archive.manifest");
    defer std.testing.allocator.free(sig_url);

    const manifest = try updateTestManifestAlloc(std.testing.allocator, archive, true, "v9.9.9", asset_name, archive_url);
    defer std.testing.allocator.free(manifest);
    const release_body = try updateReleaseBodyAlloc(std.testing.allocator, "v9.9.9", asset_name, archive_url, sig_url);
    defer std.testing.allocator.free(release_body);

    resps[0] = .{ .status = "302 Found", .headers = &.{"Location: /release/meta"} };
    resps[1] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/json"},
        .body = release_body,
    };
    resps[2] = .{ .status = "302 Found", .headers = &.{"Location: /blob/archive"} };
    resps[3] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: application/octet-stream"},
        .body = archive,
    };
    resps[4] = .{ .status = "307 Temporary Redirect", .headers = &.{"Location: ../blob/archive.manifest"} };
    resps[5] = .{
        .status = "200 OK",
        .headers = &.{"Content-Type: text/plain"},
        .body = manifest,
    };

    var cap = AuditCap{};
    defer cap.deinit(std.testing.allocator);

    const SuccessHooks = struct {
        var base: []const u8 = undefined;
        var latest: []const u8 = undefined;
        var clk = time_mock.FixedMs{ .now_ms = 222 };
        var installed_path: ?[]u8 = null;
        var installed_bin: ?[]u8 = null;

        fn deinit(alloc: std.mem.Allocator) void {
            if (installed_path) |v| alloc.free(v);
            if (installed_bin) |v| alloc.free(v);
            installed_path = null;
            installed_bin = null;
        }

        fn nowMs() i64 {
            return clk.nowMs();
        }

        fn checkHost(_: std.mem.Allocator, url: []const u8, _: ?[]const u8) !void {
            if (std.mem.eql(u8, url, default_release_url)) return;
            if (std.mem.startsWith(u8, url, base)) return;
            return error.TestUnexpectedResult;
        }

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, accept: []const u8, limit: usize) !HttpResult {
            const local_url = if (std.mem.eql(u8, url, default_release_url))
                latest
            else if (std.mem.startsWith(u8, url, base))
                url
            else
                return error.TestUnexpectedResult;
            return httpGetResult(alloc, local_url, accept, limit);
        }

        fn selfExePath(alloc: std.mem.Allocator) ![]u8 {
            return alloc.dupe(u8, "/tmp/pz-self-test");
        }

        fn installBinary(alloc: std.mem.Allocator, exe_path: []const u8, binary: []const u8) !void {
            installed_path = try alloc.dupe(u8, exe_path);
            installed_bin = try alloc.dupe(u8, binary);
        }
    };
    SuccessHooks.base = base_url;
    SuccessHooks.latest = latest_url;
    SuccessHooks.deinit(std.testing.allocator);
    defer SuccessHooks.deinit(std.testing.allocator);

    const thr = try server.spawn();
    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = SuccessHooks.httpGet,
        .self_exe_path = SuccessHooks.selfExePath,
        .install_binary = SuccessHooks.installBinary,
        .check_update_host = SuccessHooks.checkHost,
        .emit_audit_ctx = &cap,
        .emit_audit = AuditCap.emit,
        .now_ms = SuccessHooks.nowMs,
    });
    try server.join(thr);
    defer out.deinit(std.testing.allocator);

    const reqs = try joinRequestLinesAlloc(std.testing.allocator, &server);
    defer std.testing.allocator.free(reqs);
    const rows = try cap.joinedAlloc(std.testing.allocator);
    defer std.testing.allocator.free(rows);

    const Snap = struct {
        ok: bool,
        msg: []const u8,
        install_path: ?[]const u8,
        install_bin: ?[]const u8,
        reqs: []const u8,
        rows: []const u8,
    };
    try oh.snap(@src(),
        \\app.update.test.update e2e verify success installs via local redirects and audits deterministically.Snap
        \\  .ok: bool = true
        \\  .msg: []const u8
        \\    "updated 0.1.8 -> v9.9.9; verified signed archive; restart pz to use the new binary
        \\"
        \\  .install_path: ?[]const u8
        \\    "/tmp/pz-self-test"
        \\  .install_bin: ?[]const u8
        \\    "next-pz
        \\"
        \\  .reqs: []const u8
        \\    "GET /release/latest HTTP/1.1
        \\GET /release/meta HTTP/1.1
        \\GET /asset/archive HTTP/1.1
        \\GET /blob/archive HTTP/1.1
        \\GET /asset/archive.manifest HTTP/1.1
        \\GET /blob/archive.manifest HTTP/1.1"
        \\  .rows: []const u8
        \\    "{"v":1,"ts_ms":222,"sid":"upgrade","seq":1,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"upgrade start","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade"},"attrs":[]}
        \\{"v":1,"ts_ms":222,"sid":"upgrade","seq":2,"kind":"tool","sev":"info","out":"ok","actor":{"kind":"sys"},"res":{"kind":"cmd","name":{"text":"upgrade","vis":"pub"},"op":"run"},"msg":{"text":"upgrade complete","vis":"pub"},"data":{"name":{"text":"upgrade","vis":"pub"},"call_id":"upgrade","argv":{"text":"[mask:<^[0-9a-f]{16}$>]","vis":"mask"}},"attrs":[]}"
    ).expectEqual(Snap{
        .ok = out.ok,
        .msg = out.msg,
        .install_path = SuccessHooks.installed_path,
        .install_bin = SuccessHooks.installed_bin,
        .reqs = reqs,
        .rows = rows,
    });
}

const AuditCap = struct {
    rows: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        for (self.rows.items) |row| alloc.free(row);
        self.rows.deinit(alloc);
    }

    fn emit(ctx: *anyopaque, alloc: std.mem.Allocator, ent: core.audit.Entry) !void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const raw = try core.audit.encodeAlloc(alloc, ent);
        try self.rows.append(alloc, raw);
    }

    fn joinedAlloc(self: *const @This(), alloc: std.mem.Allocator) ![]u8 {
        return std.mem.join(alloc, "\n", self.rows.items);
    }
};

fn updateTestManifestAlloc(
    alloc: std.mem.Allocator,
    archive: []const u8,
    valid: bool,
    ver: []const u8,
    asset: []const u8,
    url: []const u8,
) ![]u8 {
    const test_seed = try core.signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
    const kp = try core.signing.KeyPair.fromSeed(test_seed);
    const txt = try core.signing.signManifestAlloc(alloc, ver, asset, archive, url, &kp);
    if (!valid) txt[0] = if (txt[0] == 'p') 'q' else 'p';
    return txt;
}

fn updateReleaseBodyAlloc(
    alloc: std.mem.Allocator,
    tag_name: []const u8,
    asset_name: []const u8,
    asset_url: []const u8,
    sig_url: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "{{\"tag_name\":\"{s}\",\"assets\":[{{\"name\":\"{s}\",\"browser_download_url\":\"{s}\"}},{{\"name\":\"{s}" ++ sig_suffix ++ "\",\"browser_download_url\":\"{s}\"}}]}}",
        .{ tag_name, asset_name, asset_url, asset_name, sig_url },
    );
}

fn joinRequestLinesAlloc(alloc: std.mem.Allocator, server: *const http_mock.Server) ![]u8 {
    var lines = std.ArrayListUnmanaged([]const u8){};
    defer lines.deinit(alloc);
    for (0..server.requestCount()) |i| {
        const raw = server.requestAt(i);
        const line_end = std.mem.indexOf(u8, raw, "\r\n") orelse raw.len;
        try lines.append(alloc, raw[0..line_end]);
    }
    return std.mem.join(alloc, "\n", lines.items);
}

test "checkDefaultKeyRelease returns false in debug mode" {
    try std.testing.expect(!checkDefaultKeyRelease());
}

test "isDefaultDevKey detects the sentinel" {
    try std.testing.expect(isDefaultDevKey());
}

test "formatVerifyFailure reports downgrade" {
    const msg = try formatVerifyFailure(std.testing.allocator, error.DowngradeBlocked, "pz.tar.gz");
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "not newer") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "replay") != null);
}

test "formatVerifyFailure reports default key refusal" {
    const msg = try formatVerifyFailure(std.testing.allocator, error.DefaultKeyRefused, "pz.tar.gz");
    defer std.testing.allocator.free(msg);
    try std.testing.expect(std.mem.indexOf(u8, msg, "default dev signing key") != null);
}

test "update blocks when check_default_key returns true" {
    const out = try runOutcomeWith(std.testing.allocator, .{
        .check_default_key = struct {
            fn f() bool {
                return true;
            }
        }.f,
    });
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(!out.ok);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "default dev signing key") != null);
}

test "UX10: upgrade with signed manifest verification success" {
    if (targetAssetName() == null) return;

    const asset_name = targetAssetName() orelse return error.UnsupportedPlatform;
    const archive = try makeTarGzAlloc(std.testing.allocator, "bin/pz", "test-bin\n");
    defer std.testing.allocator.free(archive);
    const manifest = try updateTestManifestAlloc(std.testing.allocator, archive, true, "v9.9.9", asset_name, "http://local/archive");
    defer std.testing.allocator.free(manifest);

    var call_idx: usize = 0;
    const Ctx = struct {
        var s_archive: []const u8 = undefined;
        var s_manifest: []const u8 = undefined;
        var s_asset_name: []const u8 = undefined;

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, _: []const u8, _: usize) !HttpResult {
            if (std.mem.indexOf(u8, url, "releases/latest") != null) {
                const body = try std.fmt.allocPrint(
                    alloc,
                    "{{\"tag_name\":\"v9.9.9\",\"assets\":[{{\"name\":\"{s}\",\"browser_download_url\":\"http://local/archive\"}},{{\"name\":\"{s}" ++ sig_suffix ++ "\",\"browser_download_url\":\"http://local/archive.manifest\"}}]}}",
                    .{ s_asset_name, s_asset_name },
                );
                return .{ .ok = body };
            }
            if (std.mem.endsWith(u8, url, ".manifest")) {
                return .{ .ok = try alloc.dupe(u8, s_manifest) };
            }
            return .{ .ok = try alloc.dupe(u8, s_archive) };
        }

        fn noCheck(_: std.mem.Allocator, _: ?[]const u8) !void {}
        fn noHostCheck(_: std.mem.Allocator, _: []const u8, _: ?[]const u8) !void {}
        fn noDefaultKey() bool {
            return false;
        }
        fn install(_: std.mem.Allocator, _: []const u8, _: []const u8) !void {}
    };
    Ctx.s_archive = archive;
    Ctx.s_manifest = manifest;
    Ctx.s_asset_name = asset_name;
    _ = &call_idx;

    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = Ctx.httpGet,
        .check_update_allowed = Ctx.noCheck,
        .check_update_host = Ctx.noHostCheck,
        .check_default_key = Ctx.noDefaultKey,
        .install_binary = Ctx.install,
        .self_exe_path = struct {
            fn f(alloc: std.mem.Allocator) ![]u8 {
                return try alloc.dupe(u8, "/tmp/pz-verify-test");
            }
        }.f,
    });
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(out.ok);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "updated") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "v9.9.9") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "verified") != null);
}

test "UX10: upgrade rejects invalid signed manifest" {
    if (targetAssetName() == null) return;

    const asset_name = targetAssetName() orelse return error.UnsupportedPlatform;
    const archive = try makeTarGzAlloc(std.testing.allocator, "bin/pz", "test-bin\n");
    defer std.testing.allocator.free(archive);
    // Create an INVALID manifest (flipped first byte)
    const manifest = try updateTestManifestAlloc(std.testing.allocator, archive, false, "v9.9.9", asset_name, "http://local/archive");
    defer std.testing.allocator.free(manifest);

    const Ctx = struct {
        var s_archive: []const u8 = undefined;
        var s_manifest: []const u8 = undefined;
        var s_asset_name: []const u8 = undefined;

        fn httpGet(alloc: std.mem.Allocator, url: []const u8, _: []const u8, _: usize) !HttpResult {
            if (std.mem.indexOf(u8, url, "releases/latest") != null) {
                const body = try std.fmt.allocPrint(
                    alloc,
                    "{{\"tag_name\":\"v9.9.9\",\"assets\":[{{\"name\":\"{s}\",\"browser_download_url\":\"http://local/archive\"}},{{\"name\":\"{s}" ++ sig_suffix ++ "\",\"browser_download_url\":\"http://local/archive.manifest\"}}]}}",
                    .{ s_asset_name, s_asset_name },
                );
                return .{ .ok = body };
            }
            if (std.mem.endsWith(u8, url, ".manifest")) {
                return .{ .ok = try alloc.dupe(u8, s_manifest) };
            }
            return .{ .ok = try alloc.dupe(u8, s_archive) };
        }

        fn noCheck(_: std.mem.Allocator, _: ?[]const u8) !void {}
        fn noHostCheck(_: std.mem.Allocator, _: []const u8, _: ?[]const u8) !void {}
        fn noDefaultKey() bool {
            return false;
        }
    };
    Ctx.s_archive = archive;
    Ctx.s_manifest = manifest;
    Ctx.s_asset_name = asset_name;

    const out = try runOutcomeWith(std.testing.allocator, .{
        .http_get = Ctx.httpGet,
        .check_update_allowed = Ctx.noCheck,
        .check_update_host = Ctx.noHostCheck,
        .check_default_key = Ctx.noDefaultKey,
    });
    defer out.deinit(std.testing.allocator);
    try std.testing.expect(!out.ok);
    try std.testing.expect(std.mem.indexOf(u8, out.msg, "signature verification failed") != null);
}

test "UX10: httpGetResult follows 302 redirect and returns final body" {
    var resps = [_]http_mock.Response{
        .{
            .status = "302 Found",
            .headers = &.{"Location: /final"},
        },
        .{
            .status = "200 OK",
            .headers = &.{"Content-Type: text/plain"},
            .body = "redirect-ok",
        },
    };
    var server = try http_mock.Server.initSeq(std.testing.allocator, &resps);
    defer server.deinit();

    const url = try server.urlAlloc(std.testing.allocator, "/start");
    defer std.testing.allocator.free(url);

    const thr = try server.spawn();
    const res = try httpGetResult(std.testing.allocator, url, "text/plain", 4096);
    try server.join(thr);
    defer res.deinit(std.testing.allocator);

    // Redirect was followed: 2 requests seen
    try std.testing.expectEqual(@as(usize, 2), server.requestCount());

    // Final body returned
    switch (res) {
        .ok => |body| try std.testing.expectEqualStrings("redirect-ok", body),
        .status => return error.TestUnexpectedResult,
    }
}

test "UX10: initClient with ca_file loads bundle and disables rescan" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_path = try app_tls.writeTestCert(tmp.dir, "ca.pem");
    defer std.testing.allocator.free(cert_path);

    var http = try app_tls.initClient(std.testing.allocator, cert_path);
    defer http.deinit();

    // CA bundle loaded
    try std.testing.expect(http.ca_bundle.map.size != 0);
    // Rescan disabled (no ambient cert pickup)
    try std.testing.expect(!@atomicLoad(bool, &http.next_https_rescan_certs, .acquire));
}

test "verifyArchiveManifest rejects downgrade" {
    const kp = try core.signing.KeyPair.fromSeed(
        try core.signing.Seed.parseHex("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166"),
    );
    const archive = "downgrade-test";
    const txt = try core.signing.signManifestAlloc(
        std.testing.allocator,
        "v0.0.1",
        "pz-test.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        &kp,
    );
    defer std.testing.allocator.free(txt);

    try std.testing.expectError(
        error.DowngradeBlocked,
        verifyArchiveManifest(archive, txt, "v0.0.1", "pz-test.tar.gz", "v0.1.8"),
    );
}
