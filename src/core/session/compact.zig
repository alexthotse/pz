//! Session compaction: summarize history to fit context window.
const std = @import("std");
const Allocator = std.mem.Allocator;
const schema = @import("schema.zig");
const reader = @import("reader.zig");
const sid_path = @import("path.zig");
const session_file = @import("session_file.zig");
const providers = @import("../providers.zig");
const prov_api = @import("../providers/api.zig");
const summary_types = @import("summary.zig");
const fs_secure = @import("../fs_secure.zig");
const shared = @import("../tools/shared.zig");
const log = std.log.scoped(.compact);

pub const checkpoint_version: u16 = 1;

pub const Checkpoint = struct {
    version: u16 = checkpoint_version,
    in_lines: u64 = 0,
    out_lines: u64 = 0,
    in_bytes: u64 = 0,
    out_bytes: u64 = 0,
    compacted_at_ms: i64 = 0,
};

pub fn run(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    compacted_at_ms: i64,
) !Checkpoint {
    const src_path = try sid_path.sidJsonlAlloc(alloc, sid);
    defer alloc.free(src_path);

    const in_file = try fs_secure.openConfined(dir, src_path, .{ .mode = .read_only });
    const in_bytes = try in_file.getEndPos();
    in_file.close();

    var rdr = try reader.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var tmp = try session_file.createSessionFile(alloc, dir, sid, ".jsonl.compact.tmp");
    defer tmp.deinit();

    var out_file = try fs_secure.createConfined(dir, tmp.path, .{
        .truncate = true,
    });
    defer out_file.close();

    var in_lines: u64 = 0;
    var out_lines: u64 = 0;
    var out_bytes: u64 = 0;
    while (try rdr.next()) |ev| {
        in_lines += 1;
        if (ev.data == .noop) continue;

        const raw = try schema.encodeAlloc(alloc, ev);
        defer alloc.free(raw);

        try out_file.writeAll(raw);
        try out_file.writeAll("\n");
        out_lines += 1;
        out_bytes += raw.len + 1;
    }
    try out_file.sync();

    try dir.rename(tmp.path, src_path);
    tmp.close();

    const ck = Checkpoint{
        .in_lines = in_lines,
        .out_lines = out_lines,
        .in_bytes = in_bytes,
        .out_bytes = out_bytes,
        .compacted_at_ms = compacted_at_ms,
    };
    try saveCheckpoint(alloc, dir, sid, ck);
    return ck;
}

pub fn loadCheckpoint(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
) !?Checkpoint {
    const path = try sid_path.sidExtAlloc(alloc, sid, ".compact.json");
    defer alloc.free(path);

    // Confined read: O_NOFOLLOW + hardlink check.
    const ck_file = fs_secure.openConfined(dir, path, .{ .mode = .read_only }) catch |read_err| switch (read_err) {
        error.FileNotFound => return null,
        else => return read_err,
    };
    defer ck_file.close();
    const raw = try ck_file.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(raw);
    if (raw.len == 0 or raw[raw.len - 1] != '\n') return error.TornCheckpoint;

    const parsed = try std.json.parseFromSlice(Checkpoint, alloc, raw, .{
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    if (parsed.value.version != checkpoint_version) return error.UnsupportedCheckpointVersion;
    return parsed.value;
}

fn saveCheckpoint(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
    ck: Checkpoint,
) !void {
    const path = try sid_path.sidExtAlloc(alloc, sid, ".compact.json");
    defer alloc.free(path);

    const raw = try std.json.Stringify.valueAlloc(alloc, ck, .{});
    defer alloc.free(raw);

    // Atomic: temp + fsync + rename.
    const with_nl = try std.fmt.allocPrint(alloc, "{s}\n", .{raw});
    defer alloc.free(with_nl);
    try fs_secure.atomicWriteAt(dir, path, with_nl);
}

fn collectSemanticJson(
    alloc: std.mem.Allocator,
    dir: std.fs.Dir,
    sid: []const u8,
) ![][]u8 {
    var rdr = try reader.ReplayReader.init(alloc, dir, sid, .{});
    defer rdr.deinit();

    var out: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (out.items) |item| alloc.free(item);
        out.deinit(alloc);
    }

    while (try rdr.next()) |ev| {
        if (ev.data == .noop) continue;
        const raw = try schema.encodeAlloc(alloc, ev);
        try out.append(alloc, raw);
    }

    return try out.toOwnedSlice(alloc);
}

fn freeJsonSlice(alloc: std.mem.Allocator, rows: [][]u8) void {
    for (rows) |row| alloc.free(row);
    alloc.free(rows);
}

pub const GeneratedSummary = struct {
    req: summary_types.SummaryReq,
    file_ops: ?[]const u8,
    event_jsons: [][]u8,
};

pub fn generateSummary(alloc: Allocator, events: []const schema.Event) !?GeneratedSummary {
    if (events.len == 0) return null;

    var jsons: std.ArrayListUnmanaged([]u8) = .empty;
    errdefer {
        for (jsons.items) |j| alloc.free(j);
        jsons.deinit(alloc);
    }

    for (events) |ev| {
        if (ev.data == .noop) continue;
        const raw = try schema.encodeAlloc(alloc, ev);
        defer alloc.free(raw);
        const wrapped = try prov_api.wrapUntrustedNamed(alloc, "session-event", @tagName(ev.data), raw);
        try jsons.append(alloc, wrapped);
    }

    if (jsons.items.len == 0) {
        jsons.deinit(alloc);
        return null;
    }

    const owned = try jsons.toOwnedSlice(alloc);
    errdefer {
        for (owned) |j| alloc.free(j);
        alloc.free(owned);
    }

    const fops = blk: {
        const raw = try formatFileOps(alloc, events);
        if (raw) |text| {
            defer alloc.free(text);
            break :blk try prov_api.wrapUntrusted(alloc, "file-ops", text);
        }
        break :blk null;
    };

    const const_jsons: []const []const u8 = @as([*]const []const u8, @ptrCast(owned.ptr))[0..owned.len];

    return .{
        .req = .{
            .events_json = const_jsons,
            .file_ops = fops,
        },
        .file_ops = fops,
        .event_jsons = owned,
    };
}

pub fn freeGeneratedSummary(alloc: Allocator, summary: GeneratedSummary) void {
    if (summary.file_ops) |fo| alloc.free(fo);
    for (summary.event_jsons) |j| alloc.free(j);
    alloc.free(summary.event_jsons);
}

pub fn escapeXml(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    var len: usize = 0;
    for (input) |c| {
        len += switch (c) {
            '&' => 5, // &amp;
            '<' => 4, // &lt;
            '>' => 4, // &gt;
            '"' => 6, // &quot;
            '\'' => 6, // &apos;
            else => 1,
        };
    }

    const buf = try alloc.alloc(u8, len);
    var i: usize = 0;
    for (input) |c| {
        switch (c) {
            '&' => {
                @memcpy(buf[i..][0..5], "&amp;");
                i += 5;
            },
            '<' => {
                @memcpy(buf[i..][0..4], "&lt;");
                i += 4;
            },
            '>' => {
                @memcpy(buf[i..][0..4], "&gt;");
                i += 4;
            },
            '"' => {
                @memcpy(buf[i..][0..6], "&quot;");
                i += 6;
            },
            '\'' => {
                @memcpy(buf[i..][0..6], "&apos;");
                i += 6;
            },
            else => {
                buf[i] = c;
                i += 1;
            },
        }
    }
    return buf;
}

// -- File operations extraction (F1) --

const FileOps = struct {
    read: []const []const u8,
    modified: []const []const u8,
};

const read_tools = [_][]const u8{ "read", "grep", "find", "ls" };
const write_tools = [_][]const u8{ "write", "edit" };

fn isToolKind(name: []const u8, comptime table: []const []const u8) bool {
    inline for (table) |t| {
        if (std.mem.eql(u8, name, t)) return true;
    }
    return false;
}

fn extractPath(alloc: std.mem.Allocator, args: []const u8) !?[]const u8 {
    const parsed = std.json.parseFromSlice(
        struct { path: ?[]const u8 = null, file_path: ?[]const u8 = null },
        alloc,
        args,
        .{ .allocate = .alloc_always },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null, // JSON parse failure
    };
    defer parsed.deinit();
    const p = parsed.value.path orelse parsed.value.file_path orelse return null;
    if (p.len == 0) return null;
    return try alloc.dupe(u8, p);
}

/// Extract read and modified file paths from tool_call events.
/// Files appearing in both read and write are placed only in modified.
fn extractFileOps(alloc: std.mem.Allocator, events: []const schema.Event) !?FileOps {
    var read_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (read_set.keys()) |k| alloc.free(k);
        read_set.deinit(alloc);
    }
    var mod_set: std.StringArrayHashMapUnmanaged(void) = .empty;
    defer {
        for (mod_set.keys()) |k| alloc.free(k);
        mod_set.deinit(alloc);
    }

    var skipped: usize = 0;
    for (events) |ev| {
        const tc = switch (ev.data) {
            .tool_call => |tc| tc,
            else => {
                skipped += 1;
                continue;
            },
        };
        const p = try extractPath(alloc, tc.args) orelse continue;
        if (isToolKind(tc.name, &write_tools)) {
            if (read_set.fetchOrderedRemove(p)) |kv| {
                alloc.free(kv.key);
            }
            const gop = try mod_set.getOrPut(alloc, p);
            if (gop.found_existing) alloc.free(p);
        } else if (isToolKind(tc.name, &read_tools)) {
            if (mod_set.contains(p)) {
                alloc.free(p);
                continue;
            }
            const gop = try read_set.getOrPut(alloc, p);
            if (gop.found_existing) alloc.free(p);
        } else {
            alloc.free(p);
        }
    }
    if (skipped > 0) log.debug("extractFileOps: skipped {d} non-tool_call events", .{skipped});

    if (read_set.count() == 0 and mod_set.count() == 0) return null;

    // Transfer ownership to caller
    const r = try alloc.dupe([]const u8, read_set.keys());
    errdefer alloc.free(r);
    read_set.clearRetainingCapacity();
    std.sort.pdq([]const u8, r, {}, lessPath);

    const m = try alloc.dupe([]const u8, mod_set.keys());
    errdefer alloc.free(m);
    mod_set.clearRetainingCapacity();
    std.sort.pdq([]const u8, m, {}, lessPath);

    return FileOps{ .read = r, .modified = m };
}

fn lessPath(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn freeFileOps(alloc: std.mem.Allocator, ops: FileOps) void {
    for (ops.read) |p| alloc.free(p);
    alloc.free(ops.read);
    for (ops.modified) |p| alloc.free(p);
    alloc.free(ops.modified);
}

// .off: summarization is mechanical; thinking tokens waste output budget
/// Format file operations as XML-style tags for compaction summaries.
/// Returns null if no file operations found.
pub fn formatFileOps(alloc: std.mem.Allocator, events: []const schema.Event) !?[]const u8 {
    const ops = try extractFileOps(alloc, events) orelse return null;
    defer freeFileOps(alloc, ops);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    if (ops.read.len > 0) {
        try buf.appendSlice(alloc, "<read-files>\n");
        for (ops.read) |p| {
            try buf.appendSlice(alloc, p);
            try buf.append(alloc, '\n');
        }
        try buf.appendSlice(alloc, "</read-files>\n");
    }
    if (ops.modified.len > 0) {
        try buf.appendSlice(alloc, "<modified-files>\n");
        for (ops.modified) |p| {
            try buf.appendSlice(alloc, p);
            try buf.append(alloc, '\n');
        }
        try buf.appendSlice(alloc, "</modified-files>\n");
    }

    return try buf.toOwnedSlice(alloc);
}

pub fn appendFileOpsFooter(
    alloc: std.mem.Allocator,
    summary: []const u8,
    events: []const schema.Event,
) ![]u8 {
    const footer = try formatFileOps(alloc, events);
    if (footer == null) return try alloc.dupe(u8, summary);
    defer alloc.free(footer.?);

    if (summary.len == 0) return try alloc.dupe(u8, footer.?);
    return try std.fmt.allocPrint(alloc, "{s}\n\n{s}", .{ summary, footer.? });
}

const summary_conv_open = "<conversation>\n";
const summary_conv_close = "\n</conversation>";
const summary_chunk_sep = "\n\n";

const SummaryCall = struct {
    req: providers.Request,
    msgs: []providers.Msg,
    prompt: []u8,
    meta: summary_types.SummaryMeta,
};

fn freeSummaryCall(alloc: std.mem.Allocator, call: SummaryCall) void {
    alloc.free(call.prompt);
    alloc.free(call.msgs[0].parts.ptr[0..3]);
    alloc.free(call.msgs);
}

fn pushTextMeta(meta: *summary_types.SummaryMeta, text: []const u8) void {
    meta.input_bytes = shared.satAdd(u64, meta.input_bytes, text.len);
    // Exact provider tokenizers vary; byte count is a deterministic upper bound.
    meta.input_tokens = shared.satAdd(u32, meta.input_tokens, text.len);
}

fn clampCount(n: usize) u32 {
    return if (n > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(n);
}

fn summaryInputMeta(events_json: []const []const u8, file_ops: ?[]const u8, budget: summary_types.SummaryBudget) summary_types.SummaryMeta {
    var meta = summary_types.SummaryMeta{
        .max_bytes = budget.max_bytes,
        .max_input_tokens = budget.max_input_tokens,
        .kept_events = clampCount(events_json.len),
        .dropped_events = 0,
    };

    pushTextMeta(&meta, prov_api.prompt_guard);
    pushTextMeta(&meta, summary_types.system_prompt);
    pushTextMeta(&meta, summary_conv_open);
    for (events_json, 0..) |ev, i| {
        if (i != 0) pushTextMeta(&meta, summary_chunk_sep);
        pushTextMeta(&meta, ev);
    }
    pushTextMeta(&meta, summary_conv_close);
    if (file_ops) |footer| {
        pushTextMeta(&meta, summary_chunk_sep);
        pushTextMeta(&meta, footer);
    }
    pushTextMeta(&meta, summary_chunk_sep);
    pushTextMeta(&meta, summary_types.prompt);
    return meta;
}

fn metaWithinBudget(meta: summary_types.SummaryMeta) bool {
    return meta.input_bytes <= meta.max_bytes and meta.input_tokens <= meta.max_input_tokens;
}

fn fitSummaryReq(req: summary_types.SummaryReq) summary_types.SummaryReq {
    var out = req;
    const full = summaryInputMeta(req.events_json, req.file_ops, req.budget);
    if (metaWithinBudget(full)) {
        out.meta = full;
        return out;
    }

    var keep_start = req.events_json.len;
    var keep_len: usize = 0;
    while (keep_start > 0) {
        const next_start = keep_start - 1;
        const meta = summaryInputMeta(req.events_json[next_start..], req.file_ops, req.budget);
        if (metaWithinBudget(meta)) {
            keep_start = next_start;
            keep_len = req.events_json.len - next_start;
            break;
        }
        keep_start = next_start;
    }

    if (keep_len == 0) {
        out.events_json = req.events_json[req.events_json.len..];
        out.meta = summary_types.SummaryMeta{
            .outcome = .over_budget,
            .input_bytes = full.input_bytes,
            .input_tokens = full.input_tokens,
            .max_bytes = req.budget.max_bytes,
            .max_input_tokens = req.budget.max_input_tokens,
            .kept_events = 0,
            .dropped_events = clampCount(req.events_json.len),
        };
        return out;
    }

    out.events_json = req.events_json[keep_start..];
    out.meta = summaryInputMeta(out.events_json, req.file_ops, req.budget);
    out.meta.outcome = .scaled;
    out.meta.kept_events = clampCount(out.events_json.len);
    out.meta.dropped_events = clampCount(req.events_json.len - out.events_json.len);
    return out;
}

fn buildSummaryPromptAlloc(
    alloc: std.mem.Allocator,
    req: summary_types.SummaryReq,
) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    try out.appendSlice(alloc, summary_conv_open);
    for (req.events_json, 0..) |ev, i| {
        if (i != 0) try out.appendSlice(alloc, summary_chunk_sep);
        try out.appendSlice(alloc, ev);
    }
    try out.appendSlice(alloc, summary_conv_close);
    if (req.file_ops) |footer| {
        try out.appendSlice(alloc, summary_chunk_sep);
        try out.appendSlice(alloc, footer);
    }
    try out.appendSlice(alloc, summary_chunk_sep);
    try out.appendSlice(alloc, summary_types.prompt);
    return try out.toOwnedSlice(alloc);
}

fn buildSummaryCall(
    alloc: std.mem.Allocator,
    model: []const u8,
    req: summary_types.SummaryReq,
) !SummaryCall {
    const fit_req = fitSummaryReq(req);
    if (fit_req.meta.outcome == .over_budget) return error.SummaryInputOverBudget;

    const prompt = try buildSummaryPromptAlloc(alloc, fit_req);
    errdefer alloc.free(prompt);

    const msgs = try alloc.alloc(providers.Msg, 2);
    errdefer alloc.free(msgs);
    const parts = try alloc.alloc(providers.Part, 3);
    errdefer alloc.free(parts);

    parts[0] = .{ .text = prov_api.prompt_guard };
    parts[1] = .{ .text = summary_types.system_prompt };
    parts[2] = .{ .text = prompt };
    msgs[0] = .{ .role = .system, .parts = parts[0..2] };
    msgs[1] = .{ .role = .user, .parts = parts[2..3] };

    return .{
        .req = .{
            .model = model,
            .msgs = msgs,
            .tools = &.{},
            .opts = .{
                .max_out = fit_req.max_tokens,
                .thinking = .off,
            },
        },
        .msgs = msgs,
        .prompt = prompt,
        .meta = fit_req.meta,
    };
}

fn collectSummaryText(alloc: std.mem.Allocator, provider: *providers.Provider, req: providers.Request) ![]u8 {
    const stream = try provider.start(req);
    defer stream.deinit();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(alloc);

    while (try stream.next()) |ev| switch (ev) {
        .text => |text| try out.appendSlice(alloc, text),
        .stop => |stop| if (stop.reason != .done) return error.SummaryFailed,
        .err => return error.SummaryFailed,
        .tool_call, .tool_result => return error.SummaryFailed,
        .thinking, .usage => {},
    };

    return try out.toOwnedSlice(alloc);
}

pub fn generateSummaryWithProvider(
    alloc: std.mem.Allocator,
    provider: *providers.Provider,
    model: []const u8,
    events: []const schema.Event,
    budget: ?summary_types.SummaryBudget,
) !?summary_types.SummaryResult {
    const generated = (try generateSummary(alloc, events)) orelse return null;
    defer freeGeneratedSummary(alloc, generated);

    var req = generated.req;
    if (budget) |cfg| req.budget = cfg;

    const call = try buildSummaryCall(alloc, model, req);
    defer freeSummaryCall(alloc, call);

    const text = try collectSummaryText(alloc, provider, call.req);
    defer alloc.free(text);

    const trimmed = std.mem.trim(u8, text, " \n\t");
    if (trimmed.len == 0) return error.SummaryFailed;

    const summary = try appendFileOpsFooter(alloc, trimmed, events);
    return .{
        .summary = summary,
        .meta = call.meta,
    };
}

test "compaction rewrites stream and preserves semantic events" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SessionSnap = struct {
        before: [][]u8,
        after: [][]u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const writer = @import("writer.zig");
    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("s1", .{
        .at_ms = 1,
        .data = .{ .prompt = .{ .text = "a" } },
    });
    try wr.append("s1", .{
        .at_ms = 2,
        .data = .{ .noop = {} },
    });
    try wr.append("s1", .{
        .at_ms = 3,
        .data = .{ .text = .{ .text = "b" } },
    });
    try wr.append("s1", .{
        .at_ms = 4,
        .data = .{ .noop = {} },
    });
    try wr.append("s1", .{
        .at_ms = 5,
        .data = .{ .stop = .{ .reason = .done } },
    });

    const before = try collectSemanticJson(std.testing.allocator, tmp.dir, "s1");
    defer freeJsonSlice(std.testing.allocator, before);

    const ck = try run(std.testing.allocator, tmp.dir, "s1", 777);
    try std.testing.expect(ck.in_bytes > ck.out_bytes);
    try oh.snap(@src(),
        \\core.session.compact.Checkpoint
        \\  .version: u16 = 1
        \\  .in_lines: u64 = 5
        \\  .out_lines: u64 = 3
        \\  .in_bytes: u64 = 252
        \\  .out_bytes: u64 = 166
        \\  .compacted_at_ms: i64 = 777
    ).expectEqual(ck);

    const after = try collectSemanticJson(std.testing.allocator, tmp.dir, "s1");
    defer freeJsonSlice(std.testing.allocator, after);

    try oh.snap(@src(),
        \\core.session.compact.test.compaction rewrites stream and preserves semantic events.SessionSnap
        \\  .before: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"a"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"text":{"text":"b"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":5,"data":{"stop":{"reason":"done"}}}"
        \\  .after: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"a"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"text":{"text":"b"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":5,"data":{"stop":{"reason":"done"}}}"
    ).expectEqual(SessionSnap{
        .before = before,
        .after = after,
    });

    const loaded = (try loadCheckpoint(std.testing.allocator, tmp.dir, "s1")) orelse {
        return error.TestUnexpectedResult;
    };
    try oh.snap(@src(),
        \\core.session.compact.Checkpoint
        \\  .version: u16 = 1
        \\  .in_lines: u64 = 5
        \\  .out_lines: u64 = 3
        \\  .in_bytes: u64 = 252
        \\  .out_bytes: u64 = 166
        \\  .compacted_at_ms: i64 = 777
    ).expectEqual(loaded);
}

test "compaction checkpoint returns null when absent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std.testing.expect((try loadCheckpoint(std.testing.allocator, tmp.dir, "missing")) == null);
}

test "compaction checkpoint rejects torn file without trailing newline" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{
        .sub_path = "s1.compact.json",
        .data = "{\"version\":1,\"in_lines\":1,\"out_lines\":1,\"in_bytes\":1,\"out_bytes\":1,\"compacted_at_ms\":1}",
    });

    try std.testing.expectError(error.TornCheckpoint, loadCheckpoint(std.testing.allocator, tmp.dir, "s1"));
}

test "escapeXml escapes mixed content" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "A<B&C");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("A&lt;B&amp;C", out);
}

test "escapeXml no escapes returns same content" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "no escapes");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("no escapes", out);
}

test "escapeXml all five special chars" {
    const alloc = std.testing.allocator;
    const out = try escapeXml(alloc, "&<>\"'");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("&amp;&lt;&gt;&quot;&apos;", out);
}

// Property: escapeXml output never contains raw special chars
test "escapeXml property: no raw specials in output" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            const s = args.input.slice();
            const out = escapeXml(std.testing.allocator, s) catch return true;
            defer std.testing.allocator.free(out);
            // Verify no raw & < > " ' remain (they must be entity-encoded)
            var i: usize = 0;
            while (i < out.len) : (i += 1) {
                const c = out[i];
                if (c == '&') {
                    // Must be start of entity: &amp; &lt; &gt; &quot; &apos;
                    if (std.mem.startsWith(u8, out[i..], "&amp;") or
                        std.mem.startsWith(u8, out[i..], "&lt;") or
                        std.mem.startsWith(u8, out[i..], "&gt;") or
                        std.mem.startsWith(u8, out[i..], "&quot;") or
                        std.mem.startsWith(u8, out[i..], "&apos;")) continue;
                    return false; // bare &
                }
                if (c == '<' or c == '>' or c == '"' or c == '\'') return false;
            }
            return true;
        }
    }.prop, .{ .iterations = 500 });
}

// Property: escapeXml output length >= input length
test "escapeXml property: output never shorter than input" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { input: zc.String }) bool {
            const s = args.input.slice();
            const out = escapeXml(std.testing.allocator, s) catch return true;
            defer std.testing.allocator.free(out);
            return out.len >= s.len;
        }
    }.prop, .{ .iterations = 500 });
}

fn mkEv(name: []const u8, args: []const u8) schema.Event {
    return .{ .at_ms = 1, .data = .{ .tool_call = .{
        .id = "c1",
        .name = name,
        .args = args,
    } } };
}

test "formatFileOps mixed read and write" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/a.zig\"}"),
        mkEv("grep", "{\"path\":\"/src/b.zig\"}"),
        mkEv("write", "{\"path\":\"/src/c.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/d.zig\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/src/a.zig
        \\/src/b.zig
        \\</read-files>
        \\<modified-files>
        \\/src/c.zig
        \\/src/d.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps read only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/x.zig\"}"),
        mkEv("find", "{\"path\":\"/y\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/x.zig
        \\/y
        \\</read-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps write only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("write", "{\"path\":\"/out.txt\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<modified-files>
        \\/out.txt
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps returns null when no file tools" {
    const evs = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
        mkEv("bash", "{\"cmd\":\"ls\"}"),
    };
    try std.testing.expect(try formatFileOps(std.testing.allocator, &evs) == null);
}

test "appendFileOpsFooter appends read and modified lists after summary" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/a.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/b.zig\"}"),
    };
    const got = try appendFileOpsFooter(std.testing.allocator, "Session summary.", &evs);
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]u8
        \\  "Session summary.
        \\
        \\<read-files>
        \\/src/a.zig
        \\</read-files>
        \\<modified-files>
        \\/src/b.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "appendFileOpsFooter leaves summary unchanged when no file tools" {
    const evs = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
        mkEv("bash", "{\"cmd\":\"ls\"}"),
    };
    const got = try appendFileOpsFooter(std.testing.allocator, "Session summary.", &evs);
    defer std.testing.allocator.free(got);
    try std.testing.expectEqualStrings("Session summary.", got);
}

test "formatFileOps deduplicates read+write to modified only" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/f.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/f.zig\"}"),
        mkEv("read", "{\"path\":\"/src/g.zig\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/src/g.zig
        \\</read-files>
        \\<modified-files>
        \\/src/f.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "formatFileOps sorts read and modified paths" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const evs = [_]schema.Event{
        mkEv("read", "{\"path\":\"/src/z.zig\"}"),
        mkEv("read", "{\"path\":\"/src/a.zig\"}"),
        mkEv("edit", "{\"path\":\"/src/m.zig\"}"),
        mkEv("write", "{\"path\":\"/src/b.zig\"}"),
    };
    const got = try formatFileOps(std.testing.allocator, &evs) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got);

    try oh.snap(@src(),
        \\[]const u8
        \\  "<read-files>
        \\/src/a.zig
        \\/src/z.zig
        \\</read-files>
        \\<modified-files>
        \\/src/b.zig
        \\/src/m.zig
        \\</modified-files>
        \\"
    ).expectEqual(got);
}

test "multi-event roundtrip preserves all event types" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SessionSnap = struct {
        before: [][]u8,
        after: [][]u8,
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const writer = @import("writer.zig");
    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "hello" } } },
        .{ .at_ms = 2, .data = .{ .text = .{ .text = "world" } } },
        .{ .at_ms = 3, .data = .{ .thinking = .{ .text = "hmm" } } },
        .{ .at_ms = 4, .data = .{ .tool_call = .{ .id = "c1", .name = "bash", .args = "{}" } } },
        .{ .at_ms = 5, .data = .{ .tool_result = .{ .id = "c1", .output = "ok" } } },
        .{ .at_ms = 6, .data = .{ .usage = .{ .in_tok = 10, .out_tok = 20, .tot_tok = 30, .cache_read = 5, .cache_write = 2 } } },
        .{ .at_ms = 7, .data = .{ .stop = .{ .reason = .done } } },
        .{ .at_ms = 8, .data = .{ .err = .{ .text = "oops" } } },
    };

    for (events) |ev| try wr.append("m1", ev);

    const before = try collectSemanticJson(std.testing.allocator, tmp.dir, "m1");
    defer freeJsonSlice(std.testing.allocator, before);

    const ck = try run(std.testing.allocator, tmp.dir, "m1", 999);

    try std.testing.expect(ck.in_bytes > 0);
    try std.testing.expect(ck.out_bytes > 0);
    try oh.snap(@src(),
        \\core.session.compact.Checkpoint
        \\  .version: u16 = 1
        \\  .in_lines: u64 = 8
        \\  .out_lines: u64 = 8
        \\  .in_bytes: u64 = 571
        \\  .out_bytes: u64 = 571
        \\  .compacted_at_ms: i64 = 999
    ).expectEqual(ck);

    const after = try collectSemanticJson(std.testing.allocator, tmp.dir, "m1");
    defer freeJsonSlice(std.testing.allocator, after);

    try oh.snap(@src(),
        \\core.session.compact.test.multi-event roundtrip preserves all event types.SessionSnap
        \\  .before: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"hello"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":2,"data":{"text":{"text":"world"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"thinking":{"text":"hmm"}}}"
        \\    [3]: []u8
        \\      "{"version":1,"at_ms":4,"data":{"tool_call":{"id":"c1","name":"bash","args":"{}"}}}"
        \\    [4]: []u8
        \\      "{"version":1,"at_ms":5,"data":{"tool_result":{"id":"c1","output":"ok","is_err":false}}}"
        \\    [5]: []u8
        \\      "{"version":1,"at_ms":6,"data":{"usage":{"in_tok":10,"out_tok":20,"tot_tok":30,"cache_read":5,"cache_write":2}}}"
        \\    [6]: []u8
        \\      "{"version":1,"at_ms":7,"data":{"stop":{"reason":"done"}}}"
        \\    [7]: []u8
        \\      "{"version":1,"at_ms":8,"data":{"err":{"text":"oops"}}}"
        \\  .after: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"hello"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":2,"data":{"text":{"text":"world"}}}"
        \\    [2]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"thinking":{"text":"hmm"}}}"
        \\    [3]: []u8
        \\      "{"version":1,"at_ms":4,"data":{"tool_call":{"id":"c1","name":"bash","args":"{}"}}}"
        \\    [4]: []u8
        \\      "{"version":1,"at_ms":5,"data":{"tool_result":{"id":"c1","output":"ok","is_err":false}}}"
        \\    [5]: []u8
        \\      "{"version":1,"at_ms":6,"data":{"usage":{"in_tok":10,"out_tok":20,"tot_tok":30,"cache_read":5,"cache_write":2}}}"
        \\    [6]: []u8
        \\      "{"version":1,"at_ms":7,"data":{"stop":{"reason":"done"}}}"
        \\    [7]: []u8
        \\      "{"version":1,"at_ms":8,"data":{"err":{"text":"oops"}}}"
    ).expectEqual(SessionSnap{
        .before = before,
        .after = after,
    });

    const TagSeq = struct { tags: [8]schema.Event.Tag };
    var tags: [8]schema.Event.Tag = undefined;
    for (after, 0..) |row, i| {
        var parsed = try schema.decodeSlice(std.testing.allocator, row);
        defer parsed.deinit();
        tags[i] = parsed.value.data;
    }
    try oh.snap(@src(),
        \\core.session.compact.test.multi-event roundtrip preserves all event types.TagSeq
        \\  .tags: [8]core.session.schema.Event.Tag
        \\    [0]: core.session.schema.Event.Tag
        \\      .prompt
        \\    [1]: core.session.schema.Event.Tag
        \\      .text
        \\    [2]: core.session.schema.Event.Tag
        \\      .thinking
        \\    [3]: core.session.schema.Event.Tag
        \\      .tool_call
        \\    [4]: core.session.schema.Event.Tag
        \\      .tool_result
        \\    [5]: core.session.schema.Event.Tag
        \\      .usage
        \\    [6]: core.session.schema.Event.Tag
        \\      .stop
        \\    [7]: core.session.schema.Event.Tag
        \\      .err
    ).expectEqual(TagSeq{ .tags = tags });
}

test "double compact is idempotent" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SessionSnap = struct {
        after1: [][]u8,
        after2: [][]u8,
    };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const writer = @import("writer.zig");
    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    try wr.append("d1", .{ .at_ms = 1, .data = .{ .prompt = .{ .text = "x" } } });
    try wr.append("d1", .{ .at_ms = 2, .data = .{ .noop = {} } });
    try wr.append("d1", .{ .at_ms = 3, .data = .{ .text = .{ .text = "y" } } });

    _ = try run(std.testing.allocator, tmp.dir, "d1", 100);

    const after1 = try collectSemanticJson(std.testing.allocator, tmp.dir, "d1");
    defer freeJsonSlice(std.testing.allocator, after1);

    const ck2 = try run(std.testing.allocator, tmp.dir, "d1", 200);

    const after2 = try collectSemanticJson(std.testing.allocator, tmp.dir, "d1");
    defer freeJsonSlice(std.testing.allocator, after2);

    try std.testing.expectEqual(ck2.in_bytes, ck2.out_bytes);
    try oh.snap(@src(),
        \\core.session.compact.Checkpoint
        \\  .version: u16 = 1
        \\  .in_lines: u64 = 2
        \\  .out_lines: u64 = 2
        \\  .in_bytes: u64 = 108
        \\  .out_bytes: u64 = 108
        \\  .compacted_at_ms: i64 = 200
    ).expectEqual(ck2);

    try oh.snap(@src(),
        \\core.session.compact.test.double compact is idempotent.SessionSnap
        \\  .after1: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"x"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"text":{"text":"y"}}}"
        \\  .after2: [][]u8
        \\    [0]: []u8
        \\      "{"version":1,"at_ms":1,"data":{"prompt":{"text":"x"}}}"
        \\    [1]: []u8
        \\      "{"version":1,"at_ms":3,"data":{"text":{"text":"y"}}}"
    ).expectEqual(SessionSnap{
        .after1 = after1,
        .after2 = after2,
    });
}

test "large event survives compaction" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const writer = @import("writer.zig");
    var wr = try writer.Writer.init(std.testing.allocator, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    const big = try std.testing.allocator.alloc(u8, 12_000);
    defer std.testing.allocator.free(big);
    @memset(big, 'A');

    try wr.append("lg", .{ .at_ms = 1, .data = .{ .text = .{ .text = big } } });

    const ck = try run(std.testing.allocator, tmp.dir, "lg", 42);
    try oh.snap(@src(),
        \\core.session.compact.Checkpoint
        \\  .version: u16 = 1
        \\  .in_lines: u64 = 1
        \\  .out_lines: u64 = 1
        \\  .in_bytes: u64 = 12052
        \\  .out_bytes: u64 = 12052
        \\  .compacted_at_ms: i64 = 42
    ).expectEqual(ck);

    const rows = try collectSemanticJson(std.testing.allocator, tmp.dir, "lg");
    defer freeJsonSlice(std.testing.allocator, rows);

    try std.testing.expectEqual(@as(usize, 1), rows.len);

    var parsed = try schema.decodeSlice(std.testing.allocator, rows[0]);
    defer parsed.deinit();

    switch (parsed.value.data) {
        .text => |t| {
            try std.testing.expectEqual(@as(usize, 12_000), t.text.len);
            try std.testing.expectEqualStrings(big, t.text);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "empty session compacts to zero lines" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try sid_path.sidJsonlAlloc(std.testing.allocator, "e1");
    defer std.testing.allocator.free(path);
    {
        var f = try tmp.dir.createFile(path, .{ .truncate = true });
        f.close();
    }

    const ck = try run(std.testing.allocator, tmp.dir, "e1", 0);
    try std.testing.expectEqual(@as(u64, 0), ck.in_lines);
    try std.testing.expectEqual(@as(u64, 0), ck.out_lines);
    try std.testing.expectEqual(@as(u64, 0), ck.in_bytes);
    try std.testing.expectEqual(@as(u64, 0), ck.out_bytes);
}

test "generateSummary with tool_call events produces file_ops" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SummarySnap = struct {
        file_ops: ?[]const u8,
        event_jsons: []const []const u8,
        req_event_jsons: []const []const u8,
    };
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
        .{ .at_ms = 2, .data = .{ .tool_call = .{
            .id = "c1",
            .name = "write",
            .args = "{\"path\":\"/src/foo.zig\"}",
        } } },
        .{ .at_ms = 3, .data = .{ .tool_result = .{
            .id = "c1",
            .output = "ok",
        } } },
    };

    const summary = (try generateSummary(alloc, &events)) orelse return error.TestUnexpectedResult;
    defer freeGeneratedSummary(alloc, summary);

    try oh.snap(@src(),
        \\core.session.compact.test.generateSummary with tool_call events produces file_ops.SummarySnap
        \\  .file_ops: ?[]const u8
        \\    "<untrusted-input kind="file-ops">
        \\<modified-files>
        \\/src/foo.zig
        \\</modified-files>
        \\
        \\</untrusted-input>"
        \\  .event_jsons: []const []const u8
        \\    [0]: []const u8
        \\      "<untrusted-input kind="session-event" name="text">
        \\{"version":1,"at_ms":1,"data":{"text":{"text":"hello"}}}
        \\</untrusted-input>"
        \\    [1]: []const u8
        \\      "<untrusted-input kind="session-event" name="tool_call">
        \\{"version":1,"at_ms":2,"data":{"tool_call":{"id":"c1","name":"write","args":"{\"path\":\"/src/foo.zig\"}"}}}
        \\</untrusted-input>"
        \\    [2]: []const u8
        \\      "<untrusted-input kind="session-event" name="tool_result">
        \\{"version":1,"at_ms":3,"data":{"tool_result":{"id":"c1","output":"ok","is_err":false}}}
        \\</untrusted-input>"
        \\  .req_event_jsons: []const []const u8
        \\    [0]: []const u8
        \\      "<untrusted-input kind="session-event" name="text">
        \\{"version":1,"at_ms":1,"data":{"text":{"text":"hello"}}}
        \\</untrusted-input>"
        \\    [1]: []const u8
        \\      "<untrusted-input kind="session-event" name="tool_call">
        \\{"version":1,"at_ms":2,"data":{"tool_call":{"id":"c1","name":"write","args":"{\"path\":\"/src/foo.zig\"}"}}}
        \\</untrusted-input>"
        \\    [2]: []const u8
        \\      "<untrusted-input kind="session-event" name="tool_result">
        \\{"version":1,"at_ms":3,"data":{"tool_result":{"id":"c1","output":"ok","is_err":false}}}
        \\</untrusted-input>"
    ).expectEqual(SummarySnap{
        .file_ops = summary.file_ops,
        .event_jsons = summary.event_jsons,
        .req_event_jsons = summary.req.events_json,
    });
}

test "generateSummary with text-only events has null file_ops" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const SummarySnap = struct {
        file_ops: ?[]const u8,
        event_jsons: []const []const u8,
    };
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "just text" } } },
        .{ .at_ms = 2, .data = .{ .prompt = .{ .text = "a prompt" } } },
    };

    const summary = (try generateSummary(alloc, &events)) orelse return error.TestUnexpectedResult;
    defer freeGeneratedSummary(alloc, summary);

    try oh.snap(@src(),
        \\core.session.compact.test.generateSummary with text-only events has null file_ops.SummarySnap
        \\  .file_ops: ?[]const u8
        \\    null
        \\  .event_jsons: []const []const u8
        \\    [0]: []const u8
        \\      "<untrusted-input kind="session-event" name="text">
        \\{"version":1,"at_ms":1,"data":{"text":{"text":"just text"}}}
        \\</untrusted-input>"
        \\    [1]: []const u8
        \\      "<untrusted-input kind="session-event" name="prompt">
        \\{"version":1,"at_ms":2,"data":{"prompt":{"text":"a prompt"}}}
        \\</untrusted-input>"
    ).expectEqual(SummarySnap{
        .file_ops = summary.file_ops,
        .event_jsons = summary.event_jsons,
    });
}

test "generateSummary with empty events returns null" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{};
    try std.testing.expect((try generateSummary(alloc, &events)) == null);
}

test "generateSummary skips noop events" {
    const alloc = std.testing.allocator;
    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .noop = {} } },
        .{ .at_ms = 2, .data = .{ .noop = {} } },
    };
    try std.testing.expect((try generateSummary(alloc, &events)) == null);
}

test "generateSummaryWithProvider enforces thinking off and returns summary metadata" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};

    const TestProvider = struct {
        provider: providers.Provider = .{ .vt = &providers.Provider.Bind(@This(), @This().start).vt },
        const StreamCtx = struct {
            stream: providers.Stream = .{ .vt = &providers.Stream.Bind(@This(), @This().next, @This().deinit).vt },
            alloc: std.mem.Allocator,
            idx: usize = 0,

            fn next(self: *StreamCtx) !?providers.Event {
                const out = switch (self.idx) {
                    0 => providers.Event{ .text = "## Goal\nShip it." },
                    1 => providers.Event{ .stop = .{ .reason = .done } },
                    else => null,
                };
                self.idx += 1;
                return out;
            }

            fn deinit(self: *StreamCtx) void {
                self.alloc.destroy(self);
            }
        };

        fn start(self: *@This(), req: providers.Request) !*providers.Stream {
            _ = self;
            try std.testing.expect(req.opts.thinking == .off);
            try std.testing.expectEqual(@as(?u32, 1024), req.opts.max_out);
            try std.testing.expectEqual(@as(usize, 2), req.msgs.len);
            try std.testing.expectEqual(@as(usize, 2), req.msgs[0].parts.len);
            try std.testing.expect(std.mem.indexOf(u8, req.msgs[1].parts[0].text, "<conversation>") != null);
            try std.testing.expect(std.mem.indexOf(u8, req.msgs[1].parts[0].text, "<untrusted-input kind=\"file-ops\">") != null);
            try std.testing.expect(std.mem.indexOf(u8, req.msgs[1].parts[0].text, summary_types.prompt) != null);

            const ctx = try std.testing.allocator.create(StreamCtx);
            ctx.* = .{ .alloc = std.testing.allocator };
            return &ctx.stream;
        }
    };

    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
        .{ .at_ms = 2, .data = .{ .tool_call = .{
            .id = "c1",
            .name = "write",
            .args = "{\"path\":\"/src/foo.zig\"}",
        } } },
    };
    var provider = TestProvider{};
    const got = (try generateSummaryWithProvider(std.testing.allocator, &provider.provider, "m", &events, null)) orelse return error.TestUnexpectedResult;
    defer std.testing.allocator.free(got.summary);
    const meta_snap = try std.fmt.allocPrint(
        std.testing.allocator,
        "outcome={s} input={d}/{d} limit={d}/{d} kept={d} dropped={d}",
        .{
            @tagName(got.meta.outcome),
            got.meta.input_bytes,
            got.meta.input_tokens,
            got.meta.max_bytes,
            got.meta.max_input_tokens,
            got.meta.kept_events,
            got.meta.dropped_events,
        },
    );
    defer std.testing.allocator.free(meta_snap);

    try oh.snap(@src(),
        \\[]const u8
        \\  "## Goal
        \\Ship it.
        \\
        \\<modified-files>
        \\/src/foo.zig
        \\</modified-files>
        \\"
    ).expectEqual(got.summary);
    try oh.snap(@src(),
        \\[]u8
        \\  "outcome=fit input=1315/1315 limit=65536/65536 kept=2 dropped=0"
    ).expectEqual(meta_snap);
}

test "buildSummaryCall scales oversized compaction input deterministically" {
    const OhSnap = @import("ohsnap");
    const oh = OhSnap{};
    const alloc = std.testing.allocator;

    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "old context that should be dropped first" } } },
        .{ .at_ms = 2, .data = .{ .text = .{ .text = "middle context that should also be dropped" } } },
        .{ .at_ms = 3, .data = .{ .text = .{ .text = "latest context that must survive compaction" } } },
    };

    const generated = (try generateSummary(alloc, &events)) orelse return error.TestUnexpectedResult;
    defer freeGeneratedSummary(alloc, generated);

    const one_ev = summaryInputMeta(generated.req.events_json[2..], generated.req.file_ops, .{
        .max_bytes = std.math.maxInt(u64),
        .max_input_tokens = std.math.maxInt(u32),
    });

    var req = generated.req;
    req.budget = .{
        .max_bytes = one_ev.input_bytes,
        .max_input_tokens = one_ev.input_tokens,
    };

    const call_a = try buildSummaryCall(alloc, "m", req);
    defer freeSummaryCall(alloc, call_a);
    const call_b = try buildSummaryCall(alloc, "m", req);
    defer freeSummaryCall(alloc, call_b);

    try std.testing.expectEqualStrings(call_a.prompt, call_b.prompt);

    const prompt_snap = try std.fmt.allocPrint(
        alloc,
        "old={any} middle={any} latest={any}",
        .{
            std.mem.indexOf(u8, call_a.prompt, "old context") != null,
            std.mem.indexOf(u8, call_a.prompt, "middle context") != null,
            std.mem.indexOf(u8, call_a.prompt, "latest context") != null,
        },
    );
    defer alloc.free(prompt_snap);
    const meta_snap = try std.fmt.allocPrint(
        alloc,
        "outcome={s} input={d}/{d} limit={d}/{d} kept={d} dropped={d}",
        .{
            @tagName(call_a.meta.outcome),
            call_a.meta.input_bytes,
            call_a.meta.input_tokens,
            call_a.meta.max_bytes,
            call_a.meta.max_input_tokens,
            call_a.meta.kept_events,
            call_a.meta.dropped_events,
        },
    );
    defer alloc.free(meta_snap);

    try oh.snap(@src(),
        \\[]u8
        \\  "outcome=scaled input=1065/1065 limit=1065/1065 kept=1 dropped=2"
    ).expectEqual(meta_snap);
    try oh.snap(@src(),
        \\[]u8
        \\  "old=false middle=false latest=true"
    ).expectEqual(prompt_snap);
}

test "generateSummaryWithProvider stops before provider when input cannot fit budget" {
    const alloc = std.testing.allocator;

    const NeverCalledProvider = struct {
        provider: providers.Provider = .{ .vt = &providers.Provider.Bind(@This(), @This().start).vt },

        fn start(self: *@This(), _: providers.Request) !*providers.Stream {
            _ = self;
            return error.TestUnexpectedResult;
        }
    };

    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "single event that cannot fit" } } },
    };

    var provider = NeverCalledProvider{};
    try std.testing.expectError(error.SummaryInputOverBudget, generateSummaryWithProvider(
        alloc,
        &provider.provider,
        "m",
        &events,
        .{ .max_bytes = 32, .max_input_tokens = 32 },
    ));
}

test "generateSummaryWithProvider returns provider error" {
    const FailingProvider = struct {
        provider: providers.Provider = .{ .vt = &providers.Provider.Bind(@This(), @This().start).vt },

        fn start(self: *@This(), _: providers.Request) !*providers.Stream {
            _ = self;
            return error.TransportFatal;
        }
    };

    const events = [_]schema.Event{
        .{ .at_ms = 1, .data = .{ .text = .{ .text = "hello" } } },
    };
    var provider = FailingProvider{};
    try std.testing.expectError(error.TransportFatal, generateSummaryWithProvider(
        std.testing.allocator,
        &provider.provider,
        "m",
        &events,
        null,
    ));
}

test "P0-1 regression: compaction run has no leaks across multi-event stream" {
    // Exercises the compaction read-encode-write loop with many events of
    // varied types. std.testing.allocator (GPA) detects any leaks or UAF.
    const writer = @import("writer.zig");
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var wr = try writer.Writer.init(alloc, tmp.dir, .{
        .flush = .{ .always = {} },
    });

    // Write a mix of event types including noops that compaction strips.
    const event_count = 20;
    var i: usize = 0;
    while (i < event_count) : (i += 1) {
        const ms: i64 = @intCast(i + 1);
        const ev: schema.Event = switch (i % 5) {
            0 => .{ .at_ms = ms, .data = .{ .text = .{ .text = "text" } } },
            1 => .{ .at_ms = ms, .data = .{ .noop = {} } },
            2 => .{ .at_ms = ms, .data = .{ .prompt = .{ .text = "prompt" } } },
            3 => .{ .at_ms = ms, .data = .{ .err = .{ .text = "oops" } } },
            4 => .{ .at_ms = ms, .data = .{ .stop = .{ .reason = .done } } },
            else => unreachable,
        };
        try wr.append("leak", ev);
    }

    const ck = try run(alloc, tmp.dir, "leak", 999);
    // 20 events, 4 noops stripped => 16 output lines
    try std.testing.expectEqual(@as(u64, event_count), ck.in_lines);
    try std.testing.expectEqual(@as(u64, 16), ck.out_lines);

    // Verify the compacted file is still readable without leaks.
    var rdr = try reader.ReplayReader.init(alloc, tmp.dir, "leak", .{});
    defer rdr.deinit();
    var read_count: u64 = 0;
    while (try rdr.next()) |ev| {
        const raw = try schema.encodeAlloc(alloc, ev);
        defer alloc.free(raw);
        try std.testing.expect(raw.len > 0);
        read_count += 1;
    }
    try std.testing.expectEqual(ck.out_lines, read_count);
}
