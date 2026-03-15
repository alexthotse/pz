//! Embedded changelog.
//!
//! Release builds embed CHANGELOG.md (markdown); dev builds embed raw VCS log
//! lines (`hash description`). Both formats are handled transparently.
const std = @import("std");
const build_options = @import("build_options");

pub const log = build_options.changelog;

/// True when the embedded log is markdown (starts with `# `).
const is_md = log.len >= 2 and log[0] == '#' and log[1] == ' ';

/// Return the portion of the embedded log newer than `last_id`.
///
/// For VCS logs, `last_id` is a short commit hash matched at line start.
/// For markdown logs, `last_id` is a version string matched inside `## [ver]`.
/// Returns empty on null/empty or when already at the newest entry.
/// Returns the full log when `last_id` is not found (treat as very old build).
pub fn entriesSince(last_id: ?[]const u8) []const u8 {
    const id = last_id orelse return "";
    if (id.len == 0) return "";

    if (is_md) return mdEntriesSince(id);
    return vcsEntriesSince(id);
}

fn vcsEntriesSince(hash: []const u8) []const u8 {
    var off: usize = 0;
    while (off < log.len) {
        const eol = std.mem.indexOfScalarPos(u8, log, off, '\n') orelse log.len;
        const line = log[off..eol];
        if (line.len >= hash.len and std.mem.startsWith(u8, line, hash)) {
            return if (off == 0) "" else log[0 .. off - 1];
        }
        off = eol + 1;
    }
    return log;
}

fn mdEntriesSince(ver: []const u8) []const u8 {
    // Find `## [ver]` — everything before that heading is newer.
    var off: usize = 0;
    while (off < log.len) {
        const eol = std.mem.indexOfScalarPos(u8, log, off, '\n') orelse log.len;
        const line = log[off..eol];
        if (isMdVersion(line, ver)) {
            return if (off == 0) "" else log[0..off];
        }
        off = eol + 1;
    }
    return log;
}

/// Check if a line is `## [ver]...`
fn isMdVersion(line: []const u8, ver: []const u8) bool {
    // "## [0.1.8] - ..."
    if (!std.mem.startsWith(u8, line, "## [")) return false;
    const rest = line[4..];
    if (!std.mem.startsWith(u8, rest, ver)) return false;
    if (rest.len <= ver.len) return false;
    return rest[ver.len] == ']';
}

/// Format the embedded log for display, up to `max_entries` meaningful lines.
/// Strips markdown headings and blank lines, prefixes each line with two spaces.
/// Returns owned slice. Caller frees.
pub fn formatForDisplay(alloc: std.mem.Allocator, max_entries: usize) ![]u8 {
    return formatSlice(alloc, log, max_entries);
}

/// Format a subset of the log (raw text).
pub fn formatRaw(alloc: std.mem.Allocator, raw: []const u8, max_entries: usize) ![]u8 {
    return formatSlice(alloc, raw, max_entries);
}

fn formatSlice(alloc: std.mem.Allocator, src: []const u8, max_entries: usize) ![]u8 {
    if (src.len == 0) return try alloc.dupe(u8, "No changes.");

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var count: usize = 0;
    var off: usize = 0;
    while (off < src.len and count < max_entries) {
        const eol = std.mem.indexOfScalarPos(u8, src, off, '\n') orelse src.len;
        const line = src[off..eol];
        off = eol + 1;

        // Skip blanks and top-level markdown headings
        if (line.len == 0) continue;
        if (is_md and std.mem.startsWith(u8, line, "# ")) continue;

        if (count > 0) try out.append(alloc, '\n');
        try out.appendSlice(alloc, "  ");
        try out.appendSlice(alloc, line);
        count += 1;
    }

    if (out.items.len == 0) return try alloc.dupe(u8, "No changes.");
    return try out.toOwnedSlice(alloc);
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "entriesSince null returns empty" {
    try testing.expectEqualStrings("", entriesSince(null));
}

test "entriesSince empty id returns empty" {
    try testing.expectEqualStrings("", entriesSince(""));
}

test "entriesSince nonexistent id returns all" {
    const result = entriesSince("zzzzzzzz_no_match");
    try testing.expectEqualStrings(log, result);
}

test "formatForDisplay respects max_entries" {
    const result = try formatForDisplay(testing.allocator, 2);
    defer testing.allocator.free(result);
    var lines: usize = 1;
    for (result) |c| {
        if (c == '\n') lines += 1;
    }
    try testing.expect(lines <= 2);
}

test "formatRaw formats correctly" {
    const raw = "abc Fix thing\ndef Another fix";
    const result = try formatRaw(testing.allocator, raw, 10);
    defer testing.allocator.free(result);
    try testing.expect(std.mem.startsWith(u8, result, "  abc Fix thing"));
}

test "formatRaw empty returns no changes" {
    const result = try formatRaw(testing.allocator, "", 10);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("No changes.", result);
}

test "mdEntriesSince returns content before version" {
    const md = "## [Unreleased]\n### Added\n- Feature X\n\n## [0.2.0] - 2026-03-01\n### Fixed\n- Bug Y\n";
    // Simulate: find everything before [0.2.0]
    var off: usize = 0;
    var found: ?usize = null;
    while (off < md.len) {
        const eol = std.mem.indexOfScalarPos(u8, md, off, '\n') orelse md.len;
        const line = md[off..eol];
        if (isMdVersion(line, "0.2.0")) {
            found = off;
            break;
        }
        off = eol + 1;
    }
    try testing.expect(found != null);
    const before = md[0..found.?];
    try testing.expect(std.mem.indexOf(u8, before, "Feature X") != null);
    try testing.expect(std.mem.indexOf(u8, before, "Bug Y") == null);
}

test "isMdVersion matches exact version" {
    try testing.expect(isMdVersion("## [0.1.8] - 2026-02-23", "0.1.8"));
    try testing.expect(!isMdVersion("## [0.1.8] - 2026-02-23", "0.1.9"));
    try testing.expect(!isMdVersion("### Added", "0.1.8"));
    try testing.expect(!isMdVersion("## [0.1.80] - date", "0.1.8"));
}
