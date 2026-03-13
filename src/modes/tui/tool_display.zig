const std = @import("std");
const core = @import("../../core/mod.zig");

pub fn makeAlloc(a: std.mem.Allocator, name: []const u8, args: []const u8, max_bytes: usize) ![]u8 {
    const raw = try rawAlloc(a, name, args);
    defer a.free(raw);

    const redacted = try redactFlatAlloc(a, raw);
    defer a.free(redacted);

    const flat = try flattenAlloc(a, redacted);
    defer a.free(flat);

    if (flat.len <= max_bytes) return try a.dupe(u8, flat);
    if (max_bytes <= 3) return try a.dupe(u8, "...");

    const keep = max_bytes - 3;
    const out = try a.alloc(u8, max_bytes);
    @memcpy(out[0..keep], flat[0..keep]);
    @memcpy(out[keep..], "...");
    return out;
}

fn redactFlatAlloc(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);

    var i: usize = 0;
    var need_sp = false;
    while (i < raw.len) {
        while (i < raw.len and isSpace(raw[i])) : (i += 1) {}
        if (i >= raw.len) break;

        const start = i;
        while (i < raw.len and !isSpace(raw[i])) : (i += 1) {}
        const tok = raw[start..i];
        const safe = try redactTokAlloc(a, tok);
        defer a.free(safe);

        if (need_sp) try out.append(a, ' ');
        try out.appendSlice(a, safe);
        need_sp = true;
    }
    return out.toOwnedSlice(a);
}

fn redactTokAlloc(a: std.mem.Allocator, tok: []const u8) ![]u8 {
    if (tok.len >= 2) {
        const q = tok[0];
        if ((q == '\'' or q == '"') and tok[tok.len - 1] == q) {
            const inner = try core.audit.redactTextAlloc(a, tok[1 .. tok.len - 1], .@"pub");
            defer a.free(inner);
            return std.fmt.allocPrint(a, "{c}{s}{c}", .{ q, inner, q });
        }
    }
    return core.audit.redactTextAlloc(a, tok, .@"pub");
}

fn rawAlloc(a: std.mem.Allocator, name: []const u8, args: []const u8) ![]u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, a, args, .{}) catch
        return defaultAlloc(a, name);
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return defaultAlloc(a, name),
    };

    if (std.mem.eql(u8, name, "bash") or std.mem.eql(u8, name, "Bash")) {
        if (obj.get("cmd") orelse obj.get("command")) |cmd| {
            if (cmd == .string) return try a.dupe(u8, cmd.string);
        }
        return try a.dupe(u8, "<command>");
    }

    if (obj.get("path")) |path| {
        if (path == .string) return try std.fmt.allocPrint(a, "{s} {s}", .{ name, path.string });
    }
    if (obj.get("file_path")) |path| {
        if (path == .string) return try std.fmt.allocPrint(a, "{s} {s}", .{ name, path.string });
    }
    if (obj.get("url")) |url| {
        if (url == .string) return try std.fmt.allocPrint(a, "{s} {s}", .{ name, url.string });
    }
    return defaultAlloc(a, name);
}

fn defaultAlloc(a: std.mem.Allocator, name: []const u8) ![]u8 {
    if (std.mem.eql(u8, name, "bash") or std.mem.eql(u8, name, "Bash")) {
        return try a.dupe(u8, "<command>");
    }
    return try a.dupe(u8, name);
}

fn flattenAlloc(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(a);

    var last_sp = false;
    for (raw) |c| {
        const sp = c == '\n' or c == '\r' or c == '\t';
        if (sp) {
            if (!last_sp and out.items.len != 0) {
                try out.append(a, ' ');
                last_sp = true;
            }
            continue;
        }
        try out.append(a, c);
        last_sp = c == ' ';
    }
    return out.toOwnedSlice(a);
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\n' or c == '\r' or c == '\t';
}

const testing = std.testing;

test "property: flattenAlloc strips line-breaking control whitespace" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: zc.String, b: zc.String, c: zc.String }) bool {
            const alloc = testing.allocator;
            const raw = std.fmt.allocPrint(alloc, "{s}\n{s}\r\t{s}", .{
                args.a.slice(),
                args.b.slice(),
                args.c.slice(),
            }) catch return false;
            defer alloc.free(raw);
            const flat = flattenAlloc(alloc, raw) catch return false;
            defer alloc.free(flat);
            for (flat) |ch| {
                if (ch == '\n' or ch == '\r' or ch == '\t') return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 300 });
}

test "property: makeAlloc renders bounded single-line bash previews" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: zc.Id, b: zc.Id, c: zc.Id }) bool {
            const alloc = testing.allocator;
            const json = std.fmt.allocPrint(alloc, "{{\"cmd\":\"{s}\\n{s}\\t{s}\"}}", .{
                args.a.slice(),
                args.b.slice(),
                args.c.slice(),
            }) catch return false;
            defer alloc.free(json);
            const out = makeAlloc(alloc, "bash", json, 48) catch return false;
            defer alloc.free(out);
            if (out.len > 48) return false;
            for (out) |ch| {
                if (ch == '\n' or ch == '\r' or ch == '\t') return false;
            }
            return std.unicode.utf8ValidateSlice(out);
        }
    }.prop, .{ .iterations = 300 });
}
