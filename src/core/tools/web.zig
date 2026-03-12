const std = @import("std");
const policy_mod = @import("../policy.zig");

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

pub fn requiresEscalationApproval(req: Request) bool {
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
    egress: policy_mod.Policy = .{ .rules = &.{} },
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
    OutOfMemory,
};

pub const ResolveErr = ParseErr || error{
    HostDenied,
    BlockedAddr,
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

fn validateEgressHost(host: []const u8, policy: RedirectPolicy) error{HostDenied}!void {
    var path_buf: [320]u8 = undefined;
    const prefix = "runtime/web/";
    if (prefix.len + host.len > path_buf.len) return error.HostDenied;
    @memcpy(path_buf[0..prefix.len], prefix);
    for (host, 0..) |c, i| path_buf[prefix.len + i] = std.ascii.toLower(c);
    if (policy.egress.eval(path_buf[0 .. prefix.len + host.len], "web") != .allow) {
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

test "parseUrl returns normalized fields for request targets" {
    const url = try parseUrl(" https://EXAMPLE.test:8443/api/v1?q=ok ");

    try std.testing.expect(url.scheme == .https);
    try std.testing.expectEqualStrings("EXAMPLE.test", url.host);
    try std.testing.expectEqual(@as(u16, 8443), url.port);
    try std.testing.expectEqualStrings("/api/v1", url.path);
    try std.testing.expect(url.query != null);
    try std.testing.expectEqualStrings("q=ok", url.query.?);
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
