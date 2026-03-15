//! Web fetch tool: HTTP requests with policy enforcement.
const std = @import("std");
const policy_mod = @import("../policy.zig");
const http_mock = @import("../../test/http_mock.zig");

pub const Method = enum {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: Method = .GET,
    url: []const u8,
    headers: []const Header = &.{},
    body: ?[]const u8 = null,
    follow_redirects: bool = true,
    max_redirects: u8 = 5,
};

pub fn hasCredentialHeaders(req: Request) bool {
    const cred_names = [_][]const u8{
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
    };
    for (req.headers) |hdr| {
        for (cred_names) |name| {
            if (std.ascii.eqlIgnoreCase(hdr.name, name)) return true;
        }
    }
    return false;
}

pub fn requiresEscalationApproval(req: Request) bool {
    if (hasCredentialHeaders(req)) return true;
    return switch (req.method) {
        .GET, .HEAD, .OPTIONS => req.body != null,
        .POST, .PUT, .PATCH, .DELETE => true,
    };
}

pub fn approvalSummaryAlloc(alloc: std.mem.Allocator, req: Request) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(alloc, "web {s} {s}", .{ @tagName(req.method), req.url });
}

pub const Response = struct {
    status: u16,
    headers: []const Header = &.{},
    body: []const u8 = "",

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        for (self.headers) |hdr| {
            if (std.ascii.eqlIgnoreCase(hdr.name, name)) return hdr.value;
        }
        return null;
    }

    pub fn location(self: Response) ?[]const u8 {
        return self.header("location");
    }

    pub fn isRedirect(self: Response) bool {
        return switch (self.status) {
            301, 302, 303, 307, 308 => self.location() != null,
            else => false,
        };
    }
};

pub const Scheme = enum {
    http,
    https,
};

pub const RedirectPolicy = struct {
    egress: policy_mod.EgressPolicy = .{},
    allow_cross_host: bool = false,
    allow_cross_port: bool = false,
    allow_https_downgrade: bool = false,
    allow_private_addrs: bool = false,
};

pub const ParseErr = std.Uri.ParseError || error{
    UnsupportedScheme,
    MissingHost,
    UserInfoNotAllowed,
    FragmentNotAllowed,
};

pub const RedirectErr = std.Uri.ResolveInPlaceError || error{
    UnsupportedScheme,
    MissingHost,
    UserInfoNotAllowed,
    FragmentNotAllowed,
    EmptyLocation,
    CrossHostRedirect,
    CrossPortRedirect,
    HttpsDowngrade,
    HostDenied,
    BlockedAddr,
    DeadlineExceeded,
    OutOfMemory,
};

pub const ResolveErr = ParseErr || error{
    HostDenied,
    BlockedAddr,
    ProxyDenied,
    DeadlineExceeded,
    ResolveFailed,
    OutOfMemory,
};

const ResolveFns = struct {
    resolve: *const fn (alloc: std.mem.Allocator, host: []const u8, port: u16) anyerror![]std.net.Address = resolveAddrsAlloc,
    free: *const fn (alloc: std.mem.Allocator, addrs: []std.net.Address) void = freeAddrsAlloc,
};

pub const ParsedUrl = struct {
    text: []const u8,
    uri: std.Uri,
    scheme: Scheme,
    host: []const u8,
    port: u16,
    path: []const u8,
    query: ?[]const u8 = null,
};

pub const OwnedUrl = struct {
    text: []u8,
    parsed: ParsedUrl,

    pub fn deinit(self: OwnedUrl, alloc: std.mem.Allocator) void {
        alloc.free(self.text);
    }
};

/// Bounded deadline for egress requests.
pub const Deadline = struct {
    start_ms: i64,
    connect_ms: u32,
    total_ms: u32,

    pub fn init(pol: policy_mod.EgressPolicy) Deadline {
        return .{
            .start_ms = milliTimestamp(),
            .connect_ms = pol.connectMs(),
            .total_ms = pol.totalMs(),
        };
    }

    pub fn connectRemaining(self: Deadline) error{DeadlineExceeded}!u32 {
        const elapsed = self.elapsedMs();
        if (elapsed >= self.total_ms) return error.DeadlineExceeded;
        const remaining_total: u32 = self.total_ms - elapsed;
        const remaining_connect = if (elapsed >= self.connect_ms) 0 else self.connect_ms - elapsed;
        if (remaining_connect == 0) return error.DeadlineExceeded;
        return @min(remaining_connect, remaining_total);
    }

    pub fn readRemaining(self: Deadline) error{DeadlineExceeded}!u32 {
        const elapsed = self.elapsedMs();
        if (elapsed >= self.total_ms) return error.DeadlineExceeded;
        return self.total_ms - elapsed;
    }

    fn elapsedMs(self: Deadline) u32 {
        const now = milliTimestamp();
        const diff = now - self.start_ms;
        if (diff < 0) return 0;
        if (diff > std.math.maxInt(u32)) return std.math.maxInt(u32);
        return @intCast(diff);
    }

    fn milliTimestamp() i64 {
        return std.time.milliTimestamp();
    }
};

pub fn parseUrl(raw: []const u8) ParseErr!ParsedUrl {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    const uri = try std.Uri.parse(text);
    return parseAbsoluteUrl(text, uri);
}

pub fn resolveRedirectAlloc(
    alloc: std.mem.Allocator,
    base: ParsedUrl,
    location_raw: []const u8,
    policy: RedirectPolicy,
) RedirectErr!OwnedUrl {
    const location = std.mem.trim(u8, location_raw, " \t\r\n");
    if (location.len == 0) return error.EmptyLocation;

    const scratch_len = location.len + compText(base.uri.path).len + location.len + 1;
    const scratch = try alloc.alloc(u8, scratch_len);
    defer alloc.free(scratch);

    @memcpy(scratch[0..location.len], location);
    var aux = scratch[0..];
    var resolved = try std.Uri.resolveInPlace(base.uri, location.len, &aux);
    resolved.fragment = null;

    try validateRedirect(base, resolved, policy);

    const text = try renderUrlAlloc(alloc, resolved);
    errdefer alloc.free(text);

    return .{
        .text = text,
        .parsed = try parseUrl(text),
    };
}

pub fn nextRedirectTargetAlloc(
    alloc: std.mem.Allocator,
    req: Request,
    res: Response,
    policy: RedirectPolicy,
) RedirectErr!?OwnedUrl {
    if (!req.follow_redirects or !res.isRedirect()) return null;
    const location = res.location() orelse return null;
    const base = try parseUrl(req.url);
    return try resolveRedirectAlloc(alloc, base, location, policy);
}

pub fn resolveConnectAddrAlloc(
    alloc: std.mem.Allocator,
    raw_url: []const u8,
    policy: RedirectPolicy,
) ResolveErr!std.net.Address {
    return resolveConnectAddrWith(alloc, try parseUrl(raw_url), policy, .{});
}

fn resolveConnectAddrWith(
    alloc: std.mem.Allocator,
    parsed: ParsedUrl,
    policy: RedirectPolicy,
    fns: ResolveFns,
) ResolveErr!std.net.Address {
    try validateEgressHost(parsed.host, policy);
    const addrs = fns.resolve(alloc, parsed.host, parsed.port) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ResolveFailed,
    };
    defer fns.free(alloc, addrs);
    if (addrs.len == 0) return error.MissingHost;

    if (!policy.allow_private_addrs) {
        for (addrs) |addr| {
            if (policy_mod.isBlockedNetAddr(addr)) return error.BlockedAddr;
        }
    }
    return addrs[0];
}

fn parseAbsoluteUrl(text: []const u8, uri: std.Uri) ParseErr!ParsedUrl {
    if (uri.user != null or uri.password != null) return error.UserInfoNotAllowed;
    if (uri.fragment != null) return error.FragmentNotAllowed;

    const scheme = try parseScheme(uri.scheme);
    const host = try parseHost(uri);

    return .{
        .text = text,
        .uri = uri,
        .scheme = scheme,
        .host = host,
        .port = uri.port orelse defaultPort(scheme),
        .path = pathText(uri),
        .query = if (uri.query) |query| compText(query) else null,
    };
}

fn validateRedirect(base: ParsedUrl, uri: std.Uri, policy: RedirectPolicy) RedirectErr!void {
    if (uri.user != null or uri.password != null) return error.UserInfoNotAllowed;

    const scheme = try parseScheme(uri.scheme);
    const host = try parseHost(uri);
    const port = uri.port orelse defaultPort(scheme);

    if (base.scheme == .https and scheme == .http and !policy.allow_https_downgrade) {
        return error.HttpsDowngrade;
    }
    if (!policy.allow_cross_host and !std.ascii.eqlIgnoreCase(base.host, host)) {
        return error.CrossHostRedirect;
    }
    if (!policy.allow_cross_port and base.port != port) {
        return error.CrossPortRedirect;
    }
    try validateEgressHost(host, policy);
}

fn validateEgressHost(host: []const u8, pol: RedirectPolicy) error{HostDenied}!void {
    var path_buf: [320]u8 = undefined;
    const prefix = "runtime/web/";
    if (prefix.len + host.len > path_buf.len) return error.HostDenied;
    @memcpy(path_buf[0..prefix.len], prefix);
    for (host, 0..) |c, i| path_buf[prefix.len + i] = std.ascii.toLower(c);
    if (pol.egress.policy().eval(path_buf[0 .. prefix.len + host.len], "web") != .allow) {
        return error.HostDenied;
    }
}

fn parseScheme(text: []const u8) error{UnsupportedScheme}!Scheme {
    if (std.ascii.eqlIgnoreCase(text, "http")) return .http;
    if (std.ascii.eqlIgnoreCase(text, "https")) return .https;
    return error.UnsupportedScheme;
}

fn parseHost(uri: std.Uri) error{MissingHost}![]const u8 {
    const host = uri.host orelse return error.MissingHost;
    const text = compText(host);
    if (text.len == 0) return error.MissingHost;
    return text;
}

fn defaultPort(scheme: Scheme) u16 {
    return switch (scheme) {
        .http => 80,
        .https => 443,
    };
}

fn compText(comp: std.Uri.Component) []const u8 {
    return switch (comp) {
        .raw => |text| text,
        .percent_encoded => |text| text,
    };
}

fn pathText(uri: std.Uri) []const u8 {
    const text = compText(uri.path);
    if (text.len == 0) return "/";
    return text;
}

fn renderUrlAlloc(alloc: std.mem.Allocator, uri: std.Uri) error{OutOfMemory}![]u8 {
    return try std.fmt.allocPrint(alloc, "{f}", .{std.Uri.fmt(&uri, .{
        .scheme = true,
        .authority = true,
        .path = true,
        .query = true,
        .fragment = false,
    })});
}

fn resolveAddrsAlloc(alloc: std.mem.Allocator, host: []const u8, port: u16) ![]std.net.Address {
    const list = try std.net.getAddressList(alloc, host, port);
    defer list.deinit();
    return try alloc.dupe(std.net.Address, list.addrs);
}

fn freeAddrsAlloc(alloc: std.mem.Allocator, addrs: []std.net.Address) void {
    alloc.free(addrs);
}

const TestAddr = struct {
    host: []const u8,
    ip: [4]u8,
};

const ChainResult = struct {
    status: u16,
    body: []u8,
    final_url: []u8,
    hops: u8,

    fn deinit(self: ChainResult, alloc: std.mem.Allocator) void {
        alloc.free(self.body);
        alloc.free(self.final_url);
    }
};

fn resolveTestAddrsAlloc(
    alloc: std.mem.Allocator,
    host: []const u8,
    port: u16,
    addrs: []const TestAddr,
) ![]std.net.Address {
    for (addrs) |item| {
        if (std.mem.eql(u8, item.host, host)) {
            const out = try alloc.alloc(std.net.Address, 1);
            out[0] = std.net.Address.initIp4(item.ip, port);
            return out;
        }
    }
    return error.UnknownHost;
}

fn fetchRedirectChainAlloc(
    alloc: std.mem.Allocator,
    req: Request,
    policy: RedirectPolicy,
    fns: ResolveFns,
) !ChainResult {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const ar = arena.allocator();

    var cur = req;
    var hops: u8 = 0;
    while (true) {
        const parsed = try parseUrl(cur.url);
        _ = try resolveConnectAddrWith(ar, parsed, policy, fns);

        const raw = try sendLocalRequestAlloc(ar, cur.method, parsed);
        const res = try parseHttpResponseAlloc(ar, raw);
        if (!cur.follow_redirects or !res.isRedirect()) {
            return .{
                .status = res.status,
                .body = try alloc.dupe(u8, res.body),
                .final_url = try alloc.dupe(u8, cur.url),
                .hops = hops,
            };
        }
        if (hops >= cur.max_redirects) return error.TooManyRedirects;

        const next = (try nextRedirectTargetAlloc(ar, cur, res, policy)) orelse {
            return error.MissingRedirectTarget;
        };
        cur.url = next.text;
        hops += 1;
    }
}

fn sendLocalRequestAlloc(
    alloc: std.mem.Allocator,
    method: Method,
    parsed: ParsedUrl,
) ![]u8 {
    var addr = try std.net.Address.parseIp("127.0.0.1", parsed.port);
    const fd = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP);
    defer (std.net.Stream{ .handle = fd }).close();
    try std.posix.connect(fd, &addr.any, addr.getOsSockLen());

    const target = if (parsed.query) |query|
        try std.fmt.allocPrint(alloc, "{s}?{s}", .{ parsed.path, query })
    else
        try alloc.dupe(u8, parsed.path);
    const host = try std.fmt.allocPrint(alloc, "{s}:{d}", .{ parsed.host, parsed.port });
    const raw_req = try std.fmt.allocPrint(
        alloc,
        "{s} {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
        .{ @tagName(method), target, host },
    );
    _ = try std.posix.write(fd, raw_req);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var buf: [1024]u8 = undefined;
    while (true) {
        const got = try std.posix.read(fd, buf[0..]);
        if (got == 0) break;
        try out.appendSlice(alloc, buf[0..got]);
    }
    return try out.toOwnedSlice(alloc);
}

fn parseHttpResponseAlloc(alloc: std.mem.Allocator, raw: []const u8) !Response {
    const head_end = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadHttpResponse;
    const head = raw[0..head_end];
    const body = raw[head_end + 4 ..];
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return error.BadHttpResponse;
    const status_line = head[0..line_end];

    var parts = std.mem.tokenizeScalar(u8, status_line, ' ');
    _ = parts.next() orelse return error.BadHttpResponse;
    const status_txt = parts.next() orelse return error.BadHttpResponse;
    const status = try std.fmt.parseInt(u16, status_txt, 10);

    var headers = std.ArrayList(Header).empty;
    errdefer headers.deinit(alloc);

    var pos = line_end + 2;
    while (pos < head.len) {
        const end = std.mem.indexOfPos(u8, head, pos, "\r\n") orelse head.len;
        const line = head[pos..end];
        if (line.len == 0) break;
        const sep = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadHttpResponse;
        try headers.append(alloc, .{
            .name = std.mem.trim(u8, line[0..sep], " \t"),
            .value = std.mem.trim(u8, line[sep + 1 ..], " \t"),
        });
        pos = end + 2;
    }

    return .{
        .status = status,
        .headers = try headers.toOwnedSlice(alloc),
        .body = body,
    };
}

fn hostName(host_port: []const u8) []const u8 {
    return host_port[0 .. std.mem.lastIndexOfScalar(u8, host_port, ':') orelse host_port.len];
}

test "parseUrl returns normalized fields for request targets" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        https: bool,
        host: []const u8,
        port: u16,
        path: []const u8,
        query: []const u8,
    };
    const url = try parseUrl(" https://EXAMPLE.test:8443/api/v1?q=ok ");

    try oh.snap(@src(),
        \\core.tools.web.test.parseUrl returns normalized fields for request targets.Snap
        \\  .https: bool = true
        \\  .host: []const u8
        \\    "EXAMPLE.test"
        \\  .port: u16 = 8443
        \\  .path: []const u8
        \\    "/api/v1"
        \\  .query: []const u8
        \\    "q=ok"
    ).expectEqual(Snap{
        .https = url.scheme == .https,
        .host = url.host,
        .port = url.port,
        .path = url.path,
        .query = url.query.?,
    });
}

test "hasCredentialHeaders detects auth-bearing headers" {
    try std.testing.expect(!hasCredentialHeaders(.{
        .url = "https://example.test/page",
    }));
    try std.testing.expect(!hasCredentialHeaders(.{
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "Accept", .value = "text/html" }},
    }));
    try std.testing.expect(hasCredentialHeaders(.{
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "Authorization", .value = "Bearer tok" }},
    }));
    try std.testing.expect(hasCredentialHeaders(.{
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "cookie", .value = "sid=abc" }},
    }));
    try std.testing.expect(hasCredentialHeaders(.{
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "X-API-KEY", .value = "secret" }},
    }));
    try std.testing.expect(hasCredentialHeaders(.{
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "Proxy-Authorization", .value = "Basic x" }},
    }));
}

test "requiresEscalationApproval escalates on credential headers" {
    try std.testing.expect(requiresEscalationApproval(.{
        .method = .GET,
        .url = "https://example.test/page",
        .headers = &.{.{ .name = "Authorization", .value = "Bearer tok" }},
    }));
}

test "requiresEscalationApproval only allows silent safe reads" {
    try std.testing.expect(!requiresEscalationApproval(.{
        .method = .GET,
        .url = "https://example.test/page",
    }));
    try std.testing.expect(!requiresEscalationApproval(.{
        .method = .HEAD,
        .url = "https://example.test/page",
    }));
    try std.testing.expect(requiresEscalationApproval(.{
        .method = .POST,
        .url = "https://example.test/form",
    }));
    try std.testing.expect(requiresEscalationApproval(.{
        .method = .GET,
        .url = "https://example.test/page",
        .body = "unexpected",
    }));
}

test "approvalSummaryAlloc includes method and url" {
    const got = try approvalSummaryAlloc(std.testing.allocator, .{
        .method = .PATCH,
        .url = "https://example.test/api",
    });
    defer std.testing.allocator.free(got);

    try std.testing.expectEqualStrings("web PATCH https://example.test/api", got);
}

test "nextRedirectTargetAlloc follows safe local redirect chain" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const req0: Request = .{
        .url = "https://svc.local/api/v1/start?x=1",
    };
    const res0: Response = .{
        .status = 302,
        .headers = &.{
            .{ .name = "Location", .value = "../next?step=1" },
        },
    };

    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.local", .effect = .allow, .tool = "web" },
    };
    const hop1 = (try nextRedirectTargetAlloc(std.testing.allocator, req0, res0, .{
        .egress = .{ .rules = &rules },
    })).?;
    defer hop1.deinit(std.testing.allocator);

    const req1: Request = .{
        .url = hop1.text,
    };
    const res1: Response = .{
        .status = 307,
        .headers = &.{
            .{ .name = "location", .value = "/done#ignored" },
        },
    };

    const hop2 = (try nextRedirectTargetAlloc(std.testing.allocator, req1, res1, .{
        .egress = .{ .rules = &rules },
    })).?;
    defer hop2.deinit(std.testing.allocator);

    const Snap = struct {
        hop0_in: []const u8,
        hop0_status: u16,
        hop0_location: []const u8,
        hop0_out: []const u8,
        hop1_in: []const u8,
        hop1_status: u16,
        hop1_location: []const u8,
        hop1_out: []const u8,
    };
    const snap = Snap{
        .hop0_in = req0.url,
        .hop0_status = res0.status,
        .hop0_location = res0.location().?,
        .hop0_out = hop1.text,
        .hop1_in = req1.url,
        .hop1_status = res1.status,
        .hop1_location = res1.location().?,
        .hop1_out = hop2.text,
    };

    try oh.snap(@src(),
        \\core.tools.web.test.nextRedirectTargetAlloc follows safe local redirect chain.Snap
        \\  .hop0_in: []const u8
        \\    "https://svc.local/api/v1/start?x=1"
        \\  .hop0_status: u16 = 302
        \\  .hop0_location: []const u8
        \\    "../next?step=1"
        \\  .hop0_out: []const u8
        \\    "https://svc.local/api/next?step=1"
        \\  .hop1_in: []const u8
        \\    "https://svc.local/api/next?step=1"
        \\  .hop1_status: u16 = 307
        \\  .hop1_location: []const u8
        \\    "/done#ignored"
        \\  .hop1_out: []const u8
        \\    "https://svc.local/done"
    ).expectEqual(snap);
}

test "resolveRedirectAlloc blocks unsafe redirects by default" {
    const base = try parseUrl("https://svc.local/api");

    try std.testing.expectError(
        error.CrossHostRedirect,
        resolveRedirectAlloc(std.testing.allocator, base, "https://evil.local/api", .{}),
    );
    try std.testing.expectError(
        error.HttpsDowngrade,
        resolveRedirectAlloc(std.testing.allocator, base, "http://svc.local/api", .{}),
    );
}

test "resolveConnectAddrAlloc blocks resolved private targets by default" {
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, _: []const u8, port: u16) ![]std.net.Address {
            const out = try alloc.alloc(std.net.Address, 2);
            out[0] = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
            out[1] = std.net.Address.initIp4(.{ 34, 117, 59, 81 }, port);
            return out;
        }

        fn free(alloc: std.mem.Allocator, addrs: []std.net.Address) void {
            alloc.free(addrs);
        }
    };

    const url = try parseUrl("https://svc.local/api");
    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.local", .effect = .allow, .tool = "web" },
    };
    try std.testing.expectError(error.BlockedAddr, resolveConnectAddrWith(
        std.testing.allocator,
        url,
        .{ .egress = .{ .rules = &rules } },
        .{ .resolve = Mock.resolve, .free = Mock.free },
    ));
}

test "resolveConnectAddrAlloc allows private targets when opted in" {
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, _: []const u8, port: u16) ![]std.net.Address {
            const out = try alloc.alloc(std.net.Address, 1);
            out[0] = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
            return out;
        }

        fn free(alloc: std.mem.Allocator, addrs: []std.net.Address) void {
            alloc.free(addrs);
        }
    };

    const url = try parseUrl("https://svc.local/api");
    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.local", .effect = .allow, .tool = "web" },
    };
    const addr = try resolveConnectAddrWith(
        std.testing.allocator,
        url,
        .{
            .egress = .{ .rules = &rules },
            .allow_private_addrs = true,
        },
        .{ .resolve = Mock.resolve, .free = Mock.free },
    );
    try std.testing.expect(std.net.Address.eql(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 443), addr));
}

test "redirect hops revalidate resolved target addresses" {
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, host: []const u8, port: u16) ![]std.net.Address {
            const out = try alloc.alloc(std.net.Address, 1);
            out[0] = if (std.mem.eql(u8, host, "svc.local"))
                std.net.Address.initIp4(.{ 34, 117, 59, 81 }, port)
            else
                std.net.Address.initIp4(.{ 10, 0, 0, 7 }, port);
            return out;
        }

        fn free(alloc: std.mem.Allocator, addrs: []std.net.Address) void {
            alloc.free(addrs);
        }
    };

    const req: Request = .{ .url = "https://svc.local/api" };
    const res: Response = .{
        .status = 302,
        .headers = &.{.{ .name = "location", .value = "https://cdn.local/final" }},
    };
    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.local", .effect = .allow, .tool = "web" },
        .{ .pattern = "runtime/web/cdn.local", .effect = .allow, .tool = "web" },
    };
    const next = (try nextRedirectTargetAlloc(std.testing.allocator, req, res, .{
        .egress = .{ .rules = &rules },
        .allow_cross_host = true,
    })).?;
    defer next.deinit(std.testing.allocator);

    try std.testing.expectError(error.BlockedAddr, resolveConnectAddrWith(
        std.testing.allocator,
        next.parsed,
        .{ .egress = .{ .rules = &rules } },
        .{ .resolve = Mock.resolve, .free = Mock.free },
    ));
}

test "resolveConnectAddrWith denies hosts not explicitly allowed" {
    const Mock = struct {
        fn resolve(_: std.mem.Allocator, _: []const u8, _: u16) ![]std.net.Address {
            return error.ShouldNotResolve;
        }

        fn free(_: std.mem.Allocator, _: []std.net.Address) void {}
    };

    const url = try parseUrl("https://svc.local/api");
    try std.testing.expectError(error.HostDenied, resolveConnectAddrWith(
        std.testing.allocator,
        url,
        .{},
        .{ .resolve = Mock.resolve, .free = Mock.free },
    ));
}

test "resolveRedirectAlloc denies cross-host targets without explicit allow" {
    const base = try parseUrl("https://svc.local/api");
    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.local", .effect = .allow, .tool = "web" },
    };

    try std.testing.expectError(
        error.HostDenied,
        resolveRedirectAlloc(std.testing.allocator, base, "https://cdn.local/final", .{
            .egress = .{ .rules = &rules },
            .allow_cross_host = true,
        }),
    );
}

test "redirect e2e allows public redirect chains over local mock sockets" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    var steps = [_]http_mock.Step{
        .{
            .resp = .{
                .status = "302 Found",
            },
        },
        .{
            .resp = .{
                .status = "200 OK",
                .headers = &.{"Content-Type: text/plain"},
                .body = "final-ok",
            },
        },
    };
    var server = try http_mock.Server.init(std.testing.allocator, steps[0..]);
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const port = server.port();
    const svc_host = try std.fmt.allocPrint(ar, "svc.test:{d}", .{port});
    const cdn_host = try std.fmt.allocPrint(ar, "cdn.test:{d}", .{port});
    const start_url = try std.fmt.allocPrint(ar, "http://{s}/start", .{svc_host});
    const next_url = try std.fmt.allocPrint(ar, "http://{s}/final", .{cdn_host});

    steps[0].expect = .{
        .target = "/start",
        .host = svc_host,
    };
    steps[0].resp.headers = &.{try std.fmt.allocPrint(ar, "Location: {s}", .{next_url})};
    steps[1].expect = .{
        .target = "/final",
        .host = cdn_host,
    };

    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.test", .effect = .allow, .tool = "web" },
        .{ .pattern = "runtime/web/cdn.test", .effect = .allow, .tool = "web" },
    };
    const addrs = [_]TestAddr{
        .{ .host = "svc.test", .ip = .{ 34, 117, 59, 81 } },
        .{ .host = "cdn.test", .ip = .{ 151, 101, 1, 69 } },
    };
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, host: []const u8, req_port: u16) ![]std.net.Address {
            return resolveTestAddrsAlloc(alloc, host, req_port, &addrs);
        }

        fn free(alloc: std.mem.Allocator, items: []std.net.Address) void {
            freeAddrsAlloc(alloc, items);
        }
    };

    const thr = try server.spawn();
    const got = try fetchRedirectChainAlloc(std.testing.allocator, .{
        .url = start_url,
    }, .{
        .egress = .{ .rules = &rules },
        .allow_cross_host = true,
    }, .{ .resolve = Mock.resolve, .free = Mock.free });
    defer got.deinit(std.testing.allocator);
    try server.join(thr);

    const final = try parseUrl(got.final_url);
    const Snap = struct {
        req0_line: []const u8,
        req0_host: []const u8,
        req1_line: []const u8,
        req1_host: []const u8,
        final_status: u16,
        final_body: []const u8,
        final_host: []const u8,
        final_path: []const u8,
        hops: u8,
    };
    const snap = Snap{
        .req0_line = http_mock.requestLine(server.request(0)).?,
        .req0_host = hostName(http_mock.header(server.request(0), "host").?),
        .req1_line = http_mock.requestLine(server.request(1)).?,
        .req1_host = hostName(http_mock.header(server.request(1), "host").?),
        .final_status = got.status,
        .final_body = got.body,
        .final_host = final.host,
        .final_path = final.path,
        .hops = got.hops,
    };
    try oh.snap(@src(),
        \\core.tools.web.test.redirect e2e allows public redirect chains over local mock sockets.Snap
        \\  .req0_line: []const u8
        \\    "GET /start HTTP/1.1"
        \\  .req0_host: []const u8
        \\    "svc.test"
        \\  .req1_line: []const u8
        \\    "GET /final HTTP/1.1"
        \\  .req1_host: []const u8
        \\    "cdn.test"
        \\  .final_status: u16 = 200
        \\  .final_body: []const u8
        \\    "final-ok"
        \\  .final_host: []const u8
        \\    "cdn.test"
        \\  .final_path: []const u8
        \\    "/final"
        \\  .hops: u8 = 1
    ).expectEqual(snap);
}

test "redirect e2e denies redirect hosts not in policy" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        ct: usize,
        line: []const u8,
    };
    var steps = [_]http_mock.Step{
        .{
            .resp = .{
                .status = "302 Found",
            },
        },
    };
    var server = try http_mock.Server.init(std.testing.allocator, steps[0..]);
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const port = server.port();
    const svc_host = try std.fmt.allocPrint(ar, "svc.test:{d}", .{port});
    const denied_host = try std.fmt.allocPrint(ar, "deny.test:{d}", .{port});
    const start_url = try std.fmt.allocPrint(ar, "http://{s}/start", .{svc_host});
    const denied_url = try std.fmt.allocPrint(ar, "http://{s}/blocked", .{denied_host});

    steps[0].expect = .{
        .target = "/start",
        .host = svc_host,
    };
    steps[0].resp.headers = &.{try std.fmt.allocPrint(ar, "Location: {s}", .{denied_url})};

    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.test", .effect = .allow, .tool = "web" },
    };
    const addrs = [_]TestAddr{
        .{ .host = "svc.test", .ip = .{ 34, 117, 59, 81 } },
        .{ .host = "deny.test", .ip = .{ 151, 101, 1, 69 } },
    };
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, host: []const u8, req_port: u16) ![]std.net.Address {
            return resolveTestAddrsAlloc(alloc, host, req_port, &addrs);
        }

        fn free(alloc: std.mem.Allocator, items: []std.net.Address) void {
            freeAddrsAlloc(alloc, items);
        }
    };

    const thr = try server.spawn();
    try std.testing.expectError(error.HostDenied, fetchRedirectChainAlloc(std.testing.allocator, .{
        .url = start_url,
    }, .{
        .egress = .{ .rules = &rules },
        .allow_cross_host = true,
    }, .{ .resolve = Mock.resolve, .free = Mock.free }));
    try server.join(thr);
    try oh.snap(@src(),
        \\core.tools.web.test.redirect e2e denies redirect hosts not in policy.Snap
        \\  .ct: usize = 1
        \\  .line: []const u8
        \\    "GET /start HTTP/1.1"
    ).expectEqual(Snap{
        .ct = server.requestCount(),
        .line = http_mock.requestLine(server.request(0)).?,
    });
}

test "redirect e2e blocks literal private redirect targets" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        ct: usize,
        host_ok: bool,
    };
    var steps = [_]http_mock.Step{
        .{
            .resp = .{
                .status = "302 Found",
            },
        },
    };
    var server = try http_mock.Server.init(std.testing.allocator, steps[0..]);
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const port = server.port();
    const svc_host = try std.fmt.allocPrint(ar, "svc.test:{d}", .{port});
    const start_url = try std.fmt.allocPrint(ar, "http://{s}/start", .{svc_host});
    const private_url = try std.fmt.allocPrint(ar, "http://127.0.0.1:{d}/private", .{port});

    steps[0].expect = .{
        .target = "/start",
        .host = svc_host,
    };
    steps[0].resp.headers = &.{try std.fmt.allocPrint(ar, "Location: {s}", .{private_url})};

    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.test", .effect = .allow, .tool = "web" },
        .{ .pattern = "runtime/web/127.0.0.1", .effect = .allow, .tool = "web" },
    };
    const addrs = [_]TestAddr{
        .{ .host = "svc.test", .ip = .{ 34, 117, 59, 81 } },
        .{ .host = "127.0.0.1", .ip = .{ 127, 0, 0, 1 } },
    };
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, host: []const u8, req_port: u16) ![]std.net.Address {
            return resolveTestAddrsAlloc(alloc, host, req_port, &addrs);
        }

        fn free(alloc: std.mem.Allocator, items: []std.net.Address) void {
            freeAddrsAlloc(alloc, items);
        }
    };

    const thr = try server.spawn();
    try std.testing.expectError(error.BlockedAddr, fetchRedirectChainAlloc(std.testing.allocator, .{
        .url = start_url,
    }, .{
        .egress = .{ .rules = &rules },
        .allow_cross_host = true,
    }, .{ .resolve = Mock.resolve, .free = Mock.free }));
    try server.join(thr);
    try oh.snap(@src(),
        \\core.tools.web.test.redirect e2e blocks literal private redirect targets.Snap
        \\  .ct: usize = 1
        \\  .host_ok: bool = true
    ).expectEqual(Snap{
        .ct = server.requestCount(),
        .host_ok = std.mem.startsWith(u8, http_mock.header(server.request(0), "host").?, "svc.test:"),
    });
}

test "redirect e2e blocks rebound redirect targets" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const Snap = struct {
        ct: usize,
        line: []const u8,
    };
    var steps = [_]http_mock.Step{
        .{
            .resp = .{
                .status = "302 Found",
            },
        },
    };
    var server = try http_mock.Server.init(std.testing.allocator, steps[0..]);
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ar = arena.allocator();

    const port = server.port();
    const svc_host = try std.fmt.allocPrint(ar, "svc.test:{d}", .{port});
    const rebound_host = try std.fmt.allocPrint(ar, "rebound.test:{d}", .{port});
    const start_url = try std.fmt.allocPrint(ar, "http://{s}/start", .{svc_host});
    const rebound_url = try std.fmt.allocPrint(ar, "http://{s}/final", .{rebound_host});

    steps[0].expect = .{
        .target = "/start",
        .host = svc_host,
    };
    steps[0].resp.headers = &.{try std.fmt.allocPrint(ar, "Location: {s}", .{rebound_url})};

    const rules = [_]policy_mod.Rule{
        .{ .pattern = "runtime/web/svc.test", .effect = .allow, .tool = "web" },
        .{ .pattern = "runtime/web/rebound.test", .effect = .allow, .tool = "web" },
    };
    const addrs = [_]TestAddr{
        .{ .host = "svc.test", .ip = .{ 34, 117, 59, 81 } },
        .{ .host = "rebound.test", .ip = .{ 10, 0, 0, 7 } },
    };
    const Mock = struct {
        fn resolve(alloc: std.mem.Allocator, host: []const u8, req_port: u16) ![]std.net.Address {
            return resolveTestAddrsAlloc(alloc, host, req_port, &addrs);
        }

        fn free(alloc: std.mem.Allocator, items: []std.net.Address) void {
            freeAddrsAlloc(alloc, items);
        }
    };

    const thr = try server.spawn();
    try std.testing.expectError(error.BlockedAddr, fetchRedirectChainAlloc(std.testing.allocator, .{
        .url = start_url,
    }, .{
        .egress = .{ .rules = &rules },
        .allow_cross_host = true,
    }, .{ .resolve = Mock.resolve, .free = Mock.free }));
    try server.join(thr);
    try oh.snap(@src(),
        \\core.tools.web.test.redirect e2e blocks rebound redirect targets.Snap
        \\  .ct: usize = 1
        \\  .line: []const u8
        \\    "GET /start HTTP/1.1"
    ).expectEqual(Snap{
        .ct = server.requestCount(),
        .line = http_mock.requestLine(server.request(0)).?,
    });
}

test "Deadline init uses policy bounds" {
    const ep: policy_mod.EgressPolicy = .{
        .connect_deadline_ms = 5_000,
        .total_deadline_ms = 20_000,
    };
    const dl = Deadline.init(ep);
    try std.testing.expectEqual(@as(u32, 5_000), dl.connect_ms);
    try std.testing.expectEqual(@as(u32, 20_000), dl.total_ms);
}

test "Deadline clamps over-max values" {
    const ep: policy_mod.EgressPolicy = .{
        .connect_deadline_ms = 999_999,
        .total_deadline_ms = 999_999,
    };
    const dl = Deadline.init(ep);
    try std.testing.expectEqual(policy_mod.EgressPolicy.max_connect_ms, dl.connect_ms);
    try std.testing.expectEqual(policy_mod.EgressPolicy.max_total_ms, dl.total_ms);
}

test "Deadline defaults match EgressPolicy defaults" {
    const dl = Deadline.init(.{});
    try std.testing.expectEqual(policy_mod.EgressPolicy.default_connect_ms, dl.connect_ms);
    try std.testing.expectEqual(policy_mod.EgressPolicy.default_total_ms, dl.total_ms);
}

test "Deadline readRemaining returns remaining total" {
    // Freshly created deadline should have nearly full total remaining.
    const dl = Deadline.init(.{ .total_deadline_ms = 60_000 });
    const rem = try dl.readRemaining();
    try std.testing.expect(rem > 59_000);
    try std.testing.expect(rem <= 60_000);
}

test "Deadline connectRemaining returns remaining connect" {
    const dl = Deadline.init(.{ .connect_deadline_ms = 10_000, .total_deadline_ms = 60_000 });
    const rem = try dl.connectRemaining();
    try std.testing.expect(rem > 9_000);
    try std.testing.expect(rem <= 10_000);
}
