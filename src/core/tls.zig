const std = @import("std");

pub fn applyCaFile(client: *std.http.Client, alloc: std.mem.Allocator, ca_file: ?[]const u8) !void {
    if (std.http.Client.disable_tls) return;

    client.ca_bundle_mutex.lock();
    defer client.ca_bundle_mutex.unlock();

    if (ca_file) |path| {
        var bundle: std.crypto.Certificate.Bundle = .{};
        errdefer bundle.deinit(alloc);
        try bundle.addCertsFromFilePathAbsolute(alloc, path);

        client.ca_bundle.deinit(alloc);
        client.ca_bundle = bundle;
        bundle = .{};
    } else if (client.ca_bundle.bytes.items.len == 0) {
        try client.ca_bundle.rescan(alloc);
    }

    @atomicStore(bool, &client.next_https_rescan_certs, false, .release);
}
