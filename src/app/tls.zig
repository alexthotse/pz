const std = @import("std");
const args = @import("args.zig");
const config = @import("config.zig");
const core_tls = @import("../core/tls.zig");

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

pub fn loadCaFileAlloc(alloc: std.mem.Allocator) !?[]u8 {
    const parsed = try args.parse(&.{});
    var env = try config.Env.fromProcess(alloc);
    defer env.deinit(alloc);
    var cfg = try config.discover(alloc, std.fs.cwd(), parsed, env);
    defer cfg.deinit(alloc);
    if (cfg.ca_file) |path| return try alloc.dupe(u8, path);
    return null;
}

pub fn initClient(alloc: std.mem.Allocator, ca_file: ?[]const u8) !std.http.Client {
    var http = std.http.Client{ .allocator = alloc };
    errdefer http.deinit();
    try applyCaFile(&http, alloc, ca_file);
    return http;
}

pub fn initRuntimeClient(alloc: std.mem.Allocator) !std.http.Client {
    const ca_file = try loadCaFileAlloc(alloc);
    defer if (ca_file) |path| alloc.free(path);
    return try initClient(alloc, ca_file);
}

pub fn applyCaFile(client: *std.http.Client, alloc: std.mem.Allocator, ca_file: ?[]const u8) !void {
    try core_tls.applyCaFile(client, alloc, ca_file);
}

pub fn writeTestCert(dir: std.fs.Dir, name: []const u8) ![]u8 {
    try dir.writeFile(.{ .sub_path = name, .data = test_ca_pem });
    return try dir.realpathAlloc(std.testing.allocator, name);
}

test "loadCaFileAlloc reads pz settings ca_file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_path = try writeTestCert(tmp.dir, "ca.pem");
    defer std.testing.allocator.free(cert_path);
    try tmp.dir.makePath(".pz");
    const cfg_raw = try std.fmt.allocPrint(std.testing.allocator, "{{\"ca_file\":\"{s}\"}}", .{cert_path});
    defer std.testing.allocator.free(cfg_raw);
    try tmp.dir.writeFile(.{ .sub_path = ".pz/settings.json", .data = cfg_raw });

    var guard = try @import("../core/tools/path_guard.zig").CwdGuard.enter(tmp.dir);
    defer guard.deinit();

    const got = try loadCaFileAlloc(std.testing.allocator);
    defer if (got) |path| std.testing.allocator.free(path);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings(cert_path, got.?);
}

test "initClient loads custom ca bundle and disables rescan" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cert_path = try writeTestCert(tmp.dir, "ca.pem");
    defer std.testing.allocator.free(cert_path);

    var http = try initClient(std.testing.allocator, cert_path);
    defer http.deinit();

    try std.testing.expect(http.ca_bundle.bytes.items.len != 0);
    try std.testing.expect(!@atomicLoad(bool, &http.next_https_rescan_certs, .acquire));
}

test "initClient fails closed on invalid custom ca bundle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "bad.pem", .data = "-----BEGIN CERTIFICATE-----\nnot-base64\n" });
    const bad_path = try tmp.dir.realpathAlloc(std.testing.allocator, "bad.pem");
    defer std.testing.allocator.free(bad_path);

    try std.testing.expectError(error.MissingEndCertificateMarker, initClient(std.testing.allocator, bad_path));
}

test "initClient preloads default ca bundle and disables rescan" {
    if (std.http.Client.disable_tls) return error.SkipZigTest;

    var http = try initClient(std.testing.allocator, null);
    defer http.deinit();

    try std.testing.expect(http.ca_bundle.bytes.items.len != 0);
    try std.testing.expect(!@atomicLoad(bool, &http.next_https_rescan_certs, .acquire));
}
