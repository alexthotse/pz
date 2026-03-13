const std = @import("std");
const args = @import("args.zig");
const config = @import("config.zig");
const core_tls = @import("../core/tls.zig");

const test_ca_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIDDTCCAfWgAwIBAgIUa9wBgCgyzJ8+FyfVZ2UIxqDyL+UwDQYJKoZIhvcNAQEL
    \\BQAwFTETMBEGA1UEAwwKcHotdGVzdC1jYTAgFw0yNjAzMTMxNjM3MTBaGA8yMTI2
    \\MDIxNzE2MzcxMFowFTETMBEGA1UEAwwKcHotdGVzdC1jYTCCASIwDQYJKoZIhvcN
    \\AQEBBQADggEPADCCAQoCggEBALaSWKvfyHWnkE3fVUOONQ4kpbAVO4NvYs37sdhI
    \\xyiIG27aOyUcEtc8wpEO3Yv29adrSoJ8CvRNS8gETJ6aZ6wsc1E/0Bf4/U49m2kv
    \\F7yc9TmzFEnjKxFdHbyxGb5A84c433dsyKWcO8BaUiZIjV/c7VpufdaaidcBH8uA
    \\Ak4E+ZTlfJqY8h7GJdiIsEZZR03tOgfGpHl4T6B5hmioOcPLZUpg9ABYv9zCC+lz
    \\mwWiLvNx8YmT2izRvcwFqHc/0NpnRcJVXm+bGK4Rt8qZs96utplnZFmkSPdv4Gh/
    \\qTh2rFKpYSBBPN+4FhBgqS55i/No+CBsmYU27OX+EPFabFECAwEAAaNTMFEwHQYD
    \\VR0OBBYEFOB03guA9B6hV/yKORkgbU5aZOB/MB8GA1UdIwQYMBaAFOB03guA9B6h
    \\V/yKORkgbU5aZOB/MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
    \\ABYx2oG5ES4b5i+ebNzRjp4X4xjTDo9HN3yTYyYfrTfgJ/VP7yLEB+Pc6kJua4bO
    \\nQrTOJ06zfO5te81FeW+LDr2G8uXxRnWogLhQOOaTCQTlSnztJvhsWB/6cQ6V7G+
    \\0JMi6LKVlxJhwOJvcT9kf2cdEDei8XnjN6VOF9a7Rn0+piL8TZPRhGIL8SByXs4d
    \\YHvHPaHVM6wRck/jJpDKlvUPkgLtm6FiUnVrPzY1pd1BLOc5WMhushSQbszh0ugC
    \\zWI1mb/4cPiqBmTqfosJpdqall0DvEKJhTFXXF13fF9UYL3i2ahK7kEuAYRmpvRV
    \\CYk12lwrB49yf82IqcaWrdY=
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

    try std.testing.expect(http.ca_bundle.map.size != 0);
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

    try std.testing.expect(http.ca_bundle.map.size != 0);
    try std.testing.expect(!@atomicLoad(bool, &http.next_https_rescan_certs, .acquire));
}
