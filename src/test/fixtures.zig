//! Shared test constants and helpers.

const std = @import("std");

pub const test_ca_pem =
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

/// Write test CA PEM to a dir and return the absolute path (caller frees).
pub fn writeCert(dir: std.fs.Dir, name: []const u8) ![]u8 {
    try dir.writeFile(.{ .sub_path = name, .data = test_ca_pem });
    return try dir.realpathAlloc(std.testing.allocator, name);
}

/// Write a .pz/settings.json with ca_file pointing to the given path.
pub fn writeCfg(tmp: std.testing.TmpDir, ca_path: []const u8) !void {
    try tmp.dir.makePath(".pz");
    const raw = try std.fmt.allocPrint(std.testing.allocator, "{{\"ca_file\":\"{s}\"}}", .{ca_path});
    defer std.testing.allocator.free(raw);
    try tmp.dir.writeFile(.{ .sub_path = ".pz/settings.json", .data = raw });
}
