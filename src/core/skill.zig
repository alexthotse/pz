const std = @import("std");

pub const SkillMeta = struct {
    name: []const u8,
    description: []const u8,
    body: []const u8,
    disable_model_invocation: bool = false,
    user_invocable: bool = false,
};

pub const Source = enum { global, project };

pub const SkillInfo = struct {
    meta: SkillMeta,
    dir_name: []const u8,
    source: Source,
};

const max_frontmatter: usize = 4096;
const max_file: usize = 64 * 1024;

const FrontmatterResult = struct {
    meta: SkillMeta,
    body: []const u8,
};

pub fn parseFrontmatter(alloc: std.mem.Allocator, raw: []const u8) !?FrontmatterResult {
    // Strip BOM
    var content = raw;
    if (content.len >= 3 and content[0] == 0xEF and content[1] == 0xBB and content[2] == 0xBF) {
        content = content[3..];
    }

    // Must start with ---\n or ---\r\n
    const open_end = if (std.mem.startsWith(u8, content, "---\r\n"))
        @as(usize, 5)
    else if (std.mem.startsWith(u8, content, "---\n"))
        @as(usize, 4)
    else
        return null;

    // Find closing fence
    const after_open = content[open_end..];
    const close_idx = findClosingFence(after_open) orelse return null;

    const fm_block = after_open[0..close_idx];
    if (fm_block.len > max_frontmatter) return null;

    // Body starts after the closing fence line
    const fence_line_end = blk: {
        const rest = after_open[close_idx..];
        if (std.mem.startsWith(u8, rest, "---\r\n")) break :blk close_idx + 5;
        if (std.mem.startsWith(u8, rest, "---\n")) break :blk close_idx + 4;
        // fence at EOF with no trailing newline
        if (std.mem.startsWith(u8, rest, "---")) break :blk close_idx + 3;
        return null;
    };

    const body = try alloc.dupe(u8, after_open[fence_line_end..]);
    errdefer alloc.free(body);

    var name: ?[]const u8 = null;
    var desc: ?[]const u8 = null;
    var disable_model: bool = false;
    var user_inv: bool = false;

    var name_d: ?[]const u8 = null;
    errdefer if (name_d) |n| alloc.free(n);
    var desc_d: ?[]const u8 = null;
    errdefer if (desc_d) |d| alloc.free(d);

    var it = LineIter{ .buf = fm_block };
    while (it.next()) |line| {
        if (parseKV(line)) |kv| {
            const key = kv[0];
            const val = stripQuotes(kv[1]);
            if (std.mem.eql(u8, key, "name")) {
                if (name_d) |old| alloc.free(old);
                name_d = try alloc.dupe(u8, val);
                name = name_d;
            } else if (std.mem.eql(u8, key, "description")) {
                if (desc_d) |old| alloc.free(old);
                desc_d = try alloc.dupe(u8, val);
                desc = desc_d;
            } else if (std.mem.eql(u8, key, "disable_model_invocation")) {
                disable_model = std.mem.eql(u8, val, "true");
            } else if (std.mem.eql(u8, key, "user_invocable")) {
                user_inv = std.mem.eql(u8, val, "true");
            }
        }
    }

    return .{
        .meta = .{
            .name = name orelse "",
            .description = desc orelse "",
            .body = body,
            .disable_model_invocation = disable_model,
            .user_invocable = user_inv,
        },
        .body = body,
    };
}

const LineIter = struct {
    buf: []const u8,
    pos: usize = 0,

    fn next(self: *LineIter) ?[]const u8 {
        if (self.pos >= self.buf.len) return null;
        const start = self.pos;
        while (self.pos < self.buf.len and self.buf[self.pos] != '\n') : (self.pos += 1) {}
        var end = self.pos;
        if (self.pos < self.buf.len) self.pos += 1; // skip \n
        // strip \r
        if (end > start and self.buf[end - 1] == '\r') end -= 1;
        return self.buf[start..end];
    }
};

fn findClosingFence(buf: []const u8) ?usize {
    var pos: usize = 0;
    while (pos < buf.len) {
        if (std.mem.startsWith(u8, buf[pos..], "---\n") or
            std.mem.startsWith(u8, buf[pos..], "---\r\n") or
            (pos + 3 <= buf.len and std.mem.eql(u8, buf[pos..][0..3], "---") and pos + 3 == buf.len))
        {
            return pos;
        }
        // advance to next line
        while (pos < buf.len and buf[pos] != '\n') : (pos += 1) {}
        if (pos < buf.len) pos += 1;
    }
    return null;
}

fn parseKV(line: []const u8) ?[2][]const u8 {
    const colon = std.mem.indexOfScalar(u8, line, ':') orelse return null;
    const key = std.mem.trim(u8, line[0..colon], " \t");
    if (key.len == 0) return null;
    const val = std.mem.trim(u8, line[colon + 1 ..], " \t");
    return .{ key, val };
}

fn stripQuotes(val: []const u8) []const u8 {
    if (val.len >= 2 and val[0] == '\'' and val[val.len - 1] == '\'') {
        return val[1 .. val.len - 1];
    }
    return val;
}

pub fn isValidDirName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '.', '-' => {},
            else => return false,
        }
    }
    return true;
}

pub fn discoverAndRead(alloc: std.mem.Allocator) ![]SkillInfo {
    var skills = std.ArrayList(SkillInfo).empty;
    errdefer {
        for (skills.items) |s| freeSkill(alloc, s);
        skills.deinit(alloc);
    }

    // Track names for dedup (project wins)
    var seen = std.StringHashMap(usize).empty;
    defer seen.deinit(alloc);

    // Global: ~/.pi/agent/skills/*/SKILL.md
    if (std.posix.getenv("HOME")) |home| {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const skills_path = std.fmt.bufPrint(&path_buf, "{s}/.pi/agent/skills", .{home}) catch continue_label: {
            break :continue_label "";
        };
        if (skills_path.len > 0) {
            try scanDir(alloc, &skills, &seen, skills_path, .global);
        }
    }

    // Project: .pi/skills/*/SKILL.md relative to cwd
    {
        const cwd_path = std.fs.cwd().realpathAlloc(alloc, ".") catch null;
        defer if (cwd_path) |p| alloc.free(p);
        if (cwd_path) |cwd| {
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const skills_path = std.fmt.bufPrint(&path_buf, "{s}/.pi/skills", .{cwd}) catch "";
            if (skills_path.len > 0) {
                try scanDir(alloc, &skills, &seen, skills_path, .project);
            }
        }
    }

    return try skills.toOwnedSlice(alloc);
}

fn scanDir(
    alloc: std.mem.Allocator,
    skills: *std.ArrayList(SkillInfo),
    seen: *std.StringHashMap(usize),
    base_path: []const u8,
    source: Source,
) !void {
    var dir = std.fs.openDirAbsolute(base_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        if (!isValidDirName(entry.name)) continue;

        var sub = dir.openDir(entry.name, .{}) catch continue;
        defer sub.close();
        const skill_file = sub.openFile("SKILL.md", .{}) catch continue;
        defer skill_file.close();

        const content = skill_file.readToEndAlloc(alloc, max_file) catch continue;
        defer alloc.free(content);

        if (!std.unicode.utf8ValidateSlice(content)) continue;

        const parsed = (try parseFrontmatter(alloc, content)) orelse continue;
        // parsed.meta owns body/name/desc allocations

        const dir_name = try alloc.dupe(u8, entry.name);
        errdefer alloc.free(dir_name);

        const info = SkillInfo{
            .meta = parsed.meta,
            .dir_name = dir_name,
            .source = source,
        };

        if (seen.get(entry.name)) |idx| {
            // Replace: project wins over global
            freeSkill(alloc, skills.items[idx]);
            skills.items[idx] = info;
        } else {
            try seen.put(alloc, dir_name, skills.items.len);
            try skills.append(alloc, info);
        }
    }
}

fn freeSkill(alloc: std.mem.Allocator, s: SkillInfo) void {
    alloc.free(s.dir_name);
    if (s.meta.body.len > 0) alloc.free(s.meta.body);
    if (s.meta.name.len > 0) alloc.free(s.meta.name);
    if (s.meta.description.len > 0) alloc.free(s.meta.description);
}

pub fn freeSkills(alloc: std.mem.Allocator, skills: []SkillInfo) void {
    for (skills) |s| freeSkill(alloc, s);
    alloc.free(skills);
}

test "parseFrontmatter: valid" {
    const input =
        \\---
        \\name: 'my-skill'
        \\description: 'A test skill'
        \\disable_model_invocation: true
        \\user_invocable: false
        \\---
        \\Hello body
    ;
    const result = try parseFrontmatter(std.testing.allocator, input);
    defer {
        if (result) |r| {
            std.testing.allocator.free(r.meta.body);
            std.testing.allocator.free(r.meta.name);
            std.testing.allocator.free(r.meta.description);
        }
    }
    try std.testing.expect(result != null);
    const r = result.?;
    try std.testing.expectEqualStrings("my-skill", r.meta.name);
    try std.testing.expectEqualStrings("A test skill", r.meta.description);
    try std.testing.expect(r.meta.disable_model_invocation);
    try std.testing.expect(!r.meta.user_invocable);
    try std.testing.expectEqualStrings("Hello body", r.meta.body);
}

test "parseFrontmatter: missing" {
    const result = try parseFrontmatter(std.testing.allocator, "no frontmatter here");
    try std.testing.expect(result == null);
}

test "parseFrontmatter: BOM" {
    const input = "\xEF\xBB\xBF---\nname: bomtest\n---\nbody";
    const result = try parseFrontmatter(std.testing.allocator, input);
    defer {
        if (result) |r| {
            std.testing.allocator.free(r.meta.body);
            std.testing.allocator.free(r.meta.name);
        }
    }
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("bomtest", result.?.meta.name);
    try std.testing.expectEqualStrings("body", result.?.meta.body);
}

test "parseFrontmatter: CRLF" {
    const input = "---\r\nname: 'crlf'\r\ndescription: 'desc'\r\n---\r\nbody\r\n";
    const result = try parseFrontmatter(std.testing.allocator, input);
    defer {
        if (result) |r| {
            std.testing.allocator.free(r.meta.body);
            std.testing.allocator.free(r.meta.name);
            std.testing.allocator.free(r.meta.description);
        }
    }
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("crlf", result.?.meta.name);
    try std.testing.expectEqualStrings("desc", result.?.meta.description);
}

test "parseFrontmatter: no closing fence" {
    const input = "---\nname: test\nno closing fence";
    const result = try parseFrontmatter(std.testing.allocator, input);
    try std.testing.expect(result == null);
}

test "parseFrontmatter: oversized" {
    const alloc = std.testing.allocator;
    // >4KB frontmatter block
    // Build: "---\n" + 4100 x's + "\n---\nbody"
    var list = std.ArrayListUnmanaged(u8){};
    defer list.deinit(alloc);
    try list.appendSlice(alloc, "---\n");
    try list.appendNTimes(alloc, 'x', 4100);
    try list.append(alloc, '\n');
    try list.appendSlice(alloc, "---\nbody");
    const result = try parseFrontmatter(alloc, list.items);
    try std.testing.expect(result == null);
}

test "isValidDirName: valid" {
    try std.testing.expect(isValidDirName("my-skill"));
    try std.testing.expect(isValidDirName("skill_v2.0"));
    try std.testing.expect(isValidDirName("ABC123"));
    try std.testing.expect(isValidDirName("a"));
}

test "isValidDirName: invalid" {
    try std.testing.expect(!isValidDirName(""));
    try std.testing.expect(!isValidDirName("foo/bar"));
    try std.testing.expect(!isValidDirName("has space"));
    try std.testing.expect(!isValidDirName("no@special"));
}
