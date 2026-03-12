const std = @import("std");
const app_tls = @import("tls.zig");
const cli = @import("cli.zig");

const release_uri = std.Uri{
    .scheme = "https",
    .host = .{ .raw = "api.github.com" },
    .path = .{ .raw = "/repos/joelreymont/pz/releases/latest" },
};

/// Semver triple for comparison.
pub const Ver = struct {
    major: u16,
    minor: u16,
    patch: u16,

    pub fn isNewer(self: Ver, other: Ver) bool {
        if (self.major != other.major) return self.major > other.major;
        if (self.minor != other.minor) return self.minor > other.minor;
        return self.patch > other.patch;
    }
};

/// Parse "v1.2.3", "1.2.3", or "1.2.3-rc1" into Ver.
pub fn parseVersion(raw: []const u8) ?Ver {
    var s = raw;
    if (s.len > 0 and s[0] == 'v') s = s[1..];
    // Strip suffix after dash
    if (std.mem.indexOfScalar(u8, s, '-')) |i| s = s[0..i];
    var it = std.mem.splitScalar(u8, s, '.');
    const major = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const patch = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    return .{ .major = major, .minor = minor, .patch = patch };
}

/// Background version checker. Stack-allocatable.
pub const Check = struct {
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    result: ?[]u8 = null,
    alloc: std.mem.Allocator,
    thread: ?std.Thread = null,

    pub fn init(alloc: std.mem.Allocator) Check {
        return .{ .alloc = alloc };
    }

    pub fn spawn(self: *Check) void {
        self.thread = std.Thread.spawn(.{}, checkThread, .{self}) catch null;
    }

    pub fn poll(self: *Check) ?[]const u8 {
        if (!self.done.load(.acquire)) return null;
        return self.result;
    }

    pub fn isDone(self: *const Check) bool {
        return self.done.load(.acquire);
    }

    pub fn deinit(self: *Check) void {
        if (self.thread) |t| t.join();
        if (self.result) |r| self.alloc.free(r);
    }

    fn checkThread(self: *Check) void {
        self.result = checkLatest(self.alloc) catch null;
        self.done.store(true, .release);
    }
};

const Deps = struct {
    init_client: *const fn (?*anyopaque, std.mem.Allocator) anyerror!std.http.Client = initClientRuntime,
    init_client_ctx: ?*anyopaque = null,
    uri: std.Uri = release_uri,
    current_version: []const u8 = cli.version,
};

fn initClientRuntime(_: ?*anyopaque, alloc: std.mem.Allocator) !std.http.Client {
    return try app_tls.initRuntimeClient(alloc);
}

/// Check GitHub releases for a newer version. Returns version string if newer, null otherwise.
fn checkLatest(alloc: std.mem.Allocator) !?[]u8 {
    return try checkLatestWith(alloc, .{});
}

fn checkLatestWith(alloc: std.mem.Allocator, deps: Deps) !?[]u8 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    var http = try deps.init_client(deps.init_client_ctx, ar);
    defer http.deinit();
    try http.initDefaultProxies(ar);

    const ua = "pz/" ++ cli.version;
    var req = try http.request(.GET, deps.uri, .{
        .extra_headers = &.{
            .{ .name = "User-Agent", .value = ua },
            .{ .name = "Accept", .value = "application/vnd.github+json" },
        },
        .keep_alive = false,
    });
    defer req.deinit();

    try req.sendBodiless();

    var redir_buf: [4096]u8 = undefined;
    var resp = try req.receiveHead(&redir_buf);

    if (resp.head.status != .ok) return null;

    var transfer_buf: [16384]u8 = undefined;
    var decomp: std.http.Decompress = undefined;
    var decomp_buf: [std.compress.flate.max_window_len]u8 = undefined;
    const reader = resp.readerDecompressing(&transfer_buf, &decomp, &decomp_buf);
    const body = try reader.allocRemaining(ar, .limited(64 * 1024));

    // Parse just the tag_name field
    const tag = extractTagName(body) orelse return null;

    const current = parseVersion(deps.current_version) orelse return null;
    const latest = parseVersion(tag) orelse return null;

    if (!latest.isNewer(current)) return null;

    return try alloc.dupe(u8, tag);
}

/// Extract "tag_name":"..." from JSON without full parse.
fn extractTagName(json: []const u8) ?[]const u8 {
    const key = "\"tag_name\"";
    const pos = std.mem.indexOf(u8, json, key) orelse return null;
    const after = json[pos + key.len ..];
    // Skip whitespace and colon
    var i: usize = 0;
    while (i < after.len and (after[i] == ' ' or after[i] == ':' or after[i] == '\t' or after[i] == '\n')) : (i += 1) {}
    if (i >= after.len or after[i] != '"') return null;
    i += 1; // skip opening quote
    const start = i;
    while (i < after.len and after[i] != '"') : (i += 1) {}
    if (i >= after.len) return null;
    return after[start..i];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const http_mock = @import("../test/http_mock.zig");
const CwdGuard = @import("../core/tools/path_guard.zig").CwdGuard;

const test_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDCzCCAfOgAwIBAgIURa7/IGeeVRlDa4FwDe++jL0QdxwwDQYJKoZIhvcNAQEL
    \\BQAwFTETMBEGA1UEAwwKcHotdGVzdC1jYTAeFw0yNjAzMTIxNjE2NDRaFw0yNjAz
    \\MTMxNjE2NDRaMBUxEzARBgNVBAMMCnB6LXRlc3QtY2EwggEiMA0GCSqGSIb3DQEB
    \\AQUAA4IBDwAwggEKAoIBAQDPijTFBaC7eSjSfbDdlSperM4GjuUI4kFPjkNZeMfs
    \\QeQZtLaNRsiDmDrj4gupRt0FjaH+vpW77xinL/XCCC+h3QnbmYBAk1RjrCUDcIMS
    \\kfqZPhc7qfKsBJCK+pio5IZGSvCNDeny32zxy6mYKBUN2UMyeLOJGKUxQTR3DJ1n
    \\Z9z0DaNloQK80x/EA59BaHEaKlBOUhiGpZWzykXAWxH9DszXGX9WcneskaS9DKt4
    \\l8UYEzn/E5Lw5k+91XQJAAtiKCR69lorOJPIhe/iTsdFQ/4L75PRzaLzjPAFjFcX
    \\KMUndj4y/rpWEfVwG3eyN0HobTIydLEsaCBS3grFwWGDAgMBAAGjUzBRMB0GA1Ud
    \\DgQWBBSgqshoiKDsFd/cdjw9ISdRZl5r7zAfBgNVHSMEGDAWgBSgqshoiKDsFd/c
    \\djw9ISdRZl5r7zAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCT
    \\rRyDf+axvu0uLXpqGcJM3/xdcidqJhrFtkOAu/EufGFYr3W0QSl3lVlDpy2cvsIS
    \\FBqYEL8n31AVq5+Tfi8ORQCu6SrxuFv2lO6qit4xIRpqIwO6pfiNw6PKKkHpJheV
    \\+r0w1VpEsKKOrZQsD2m6/PkMTLrpFcjGD9EBWy23Ox+zVNVtdcYnT/FszUdHpQfs
    \\bAfNtHkWEmpZ3eBj2wXtAYlSZpwT44iLbywR+Os9jOzAEiscig2Q0SYZiO8XEQ0i
    \\/yGcMd+7viFlE60oib0k2Q4IPDnLhPm0JWXb0aWBnginT+RcjKnaEUmtuXbjG6RZ
    \\AxzSE0ZI8572sfc7EEB+
    \\-----END CERTIFICATE-----
;

const CheckSnap = struct {
    tag: []const u8,
    has_ca: bool,
    rescan_disabled: bool,
    saw_get: bool,
    saw_ua: bool,
    saw_accept: bool,
};

const ClientTap = struct {
    ca_len: usize = 0,
    rescan_disabled: bool = false,

    fn init(ctx: ?*anyopaque, alloc: std.mem.Allocator) !std.http.Client {
        const tap: *ClientTap = @ptrCast(@alignCast(ctx.?));
        var http = try app_tls.initRuntimeClient(alloc);
        tap.ca_len = http.ca_bundle.bytes.items.len;
        tap.rescan_disabled = !@atomicLoad(bool, &http.next_https_rescan_certs, .acquire);
        return http;
    }
};

fn writeCfg(tmp: std.testing.TmpDir, ca_path: []const u8) !void {
    try tmp.dir.makePath(".pz");
    const raw = try std.fmt.allocPrint(std.testing.allocator, "{{\"ca_file\":\"{s}\"}}", .{ca_path});
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = ".pz/settings.json", .data = raw });
}

fn writeCaPem(tmp: std.testing.TmpDir, name: []const u8) ![]u8 {
    try tmp.dir.writeFile(.{ .sub_path = name, .data = test_ca_pem });
    return try tmp.dir.realpathAlloc(std.testing.allocator, name);
}

fn releaseUriFor(port: u16) std.Uri {
    return .{
        .scheme = "http",
        .host = .{ .raw = "127.0.0.1" },
        .port = port,
        .path = .{ .raw = "/repos/joelreymont/pz/releases/latest" },
    };
}

test "parseVersion basic" {
    const v = parseVersion("0.1.0").?;
    try testing.expectEqual(@as(u16, 0), v.major);
    try testing.expectEqual(@as(u16, 1), v.minor);
    try testing.expectEqual(@as(u16, 0), v.patch);
}

test "parseVersion strips v prefix" {
    const v = parseVersion("v1.2.3").?;
    try testing.expectEqual(@as(u16, 1), v.major);
    try testing.expectEqual(@as(u16, 2), v.minor);
    try testing.expectEqual(@as(u16, 3), v.patch);
}

test "parseVersion strips suffix" {
    const v = parseVersion("0.1.0-rc1").?;
    try testing.expectEqual(@as(u16, 0), v.major);
    try testing.expectEqual(@as(u16, 1), v.minor);
    try testing.expectEqual(@as(u16, 0), v.patch);
}

test "parseVersion bad input" {
    try testing.expect(parseVersion("bad") == null);
    try testing.expect(parseVersion("") == null);
    try testing.expect(parseVersion("1.2") == null);
}

test "isNewer comparisons" {
    const v010 = Ver{ .major = 0, .minor = 1, .patch = 0 };
    const v020 = Ver{ .major = 0, .minor = 2, .patch = 0 };
    const v100 = Ver{ .major = 1, .minor = 0, .patch = 0 };
    const v009 = Ver{ .major = 0, .minor = 0, .patch = 9 };
    try testing.expect(v020.isNewer(v010));
    try testing.expect(!v010.isNewer(v010));
    try testing.expect(!v009.isNewer(v010));
    try testing.expect(v100.isNewer(v020));
}

test "extractTagName from json" {
    const json =
        \\{"id":123,"tag_name":"v0.2.0","name":"Release 0.2.0"}
    ;
    const tag = extractTagName(json).?;
    try testing.expectEqualStrings("v0.2.0", tag);
}

test "extractTagName missing" {
    try testing.expect(extractTagName("{}") == null);
    try testing.expect(extractTagName("{\"other\":1}") == null);
}

test "checkLatest uses runtime CA bundle for version checks" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_path = try writeCaPem(tmp, "ca.pem");
    defer std.testing.allocator.free(cert_path);
    try writeCfg(tmp, cert_path);

    var guard = try CwdGuard.enter(tmp.dir);
    defer guard.deinit();

    var server = try http_mock.Server.init(.{
        .headers = &.{"Content-Type: application/json"},
        .body = "{\"tag_name\":\"v9.9.9\"}",
    });
    defer server.deinit();

    const thr = try server.spawn();
    defer thr.join();

    var tap = ClientTap{};
    const got = try checkLatestWith(std.testing.allocator, .{
        .init_client = ClientTap.init,
        .init_client_ctx = &tap,
        .uri = releaseUriFor(server.port()),
        .current_version = "0.0.1",
    });
    defer if (got) |tag| std.testing.allocator.free(tag);

    try testing.expect(got != null);

    const req = server.request();
    const snap = CheckSnap{
        .tag = got.?,
        .has_ca = tap.ca_len != 0,
        .rescan_disabled = tap.rescan_disabled,
        .saw_get = std.mem.indexOf(u8, req, "GET /repos/joelreymont/pz/releases/latest HTTP/1.1") != null,
        .saw_ua = std.mem.indexOf(u8, req, "User-Agent: pz/" ++ cli.version) != null,
        .saw_accept = std.mem.indexOf(u8, req, "Accept: application/vnd.github+json") != null,
    };
    try oh.snap(@src(),
        \\app.version.CheckSnap
        \\  .tag: []const u8
        \\    "v9.9.9"
        \\  .has_ca: bool = true
        \\  .rescan_disabled: bool = true
        \\  .saw_get: bool = true
        \\  .saw_ua: bool = true
        \\  .saw_accept: bool = true
    ).expectEqual(snap);
}

test "checkLatest fails closed on invalid runtime CA bundle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "bad.pem", .data = "-----BEGIN CERTIFICATE-----\nnot-base64\n" });
    const bad_path = try tmp.dir.realpathAlloc(std.testing.allocator, "bad.pem");
    defer std.testing.allocator.free(bad_path);
    try writeCfg(tmp, bad_path);

    var guard = try CwdGuard.enter(tmp.dir);
    defer guard.deinit();

    try testing.expectError(error.MissingEndCertificateMarker, checkLatestWith(std.testing.allocator, .{
        .uri = releaseUriFor(1),
        .current_version = "0.0.1",
    }));
}
