//! App-level TLS config: CA bundle and certificate setup.
const std = @import("std");
const args = @import("args.zig");
const config = @import("config.zig");
const core_tls = @import("../core/tls.zig");

const fixtures = @import("../test/fixtures.zig");

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
    return fixtures.writeCert(dir, name);
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
