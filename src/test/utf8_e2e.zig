//! T5d: End-to-end test proving invalid UTF-8 in tool output survives
//! through provider request → session persist → export.
const std = @import("std");
const testing = std.testing;
const schema = @import("../core/session/schema.zig");
const writer_mod = @import("../core/session/writer.zig");
const reader_mod = @import("../core/session/reader.zig");
const export_mod = @import("../core/session/export.zig");
const utf8_case = @import("utf8_case.zig");

test "T5d invalid UTF-8 in tool output survives persist and export" {
    const alloc = testing.allocator;

    // 1. Build event with raw invalid UTF-8 in tool_result output —
    //    simulates a provider returning binary garbage in a tool result.
    const ev = schema.Event{
        .at_ms = 1,
        .data = .{
            .tool_result = .{
                .id = "call-bad",
                .output = utf8_case.bad_tool_out[0..],
                .is_err = false,
            },
        },
    };

    // 2. Persist via writer (encodes with UTF-8 sanitization).
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var w = try writer_mod.Writer.init(alloc, tmp.dir, .{});
    try w.append("utf8-e2e", ev);

    // 3. Read back via ReplayReader (session persist → decode).
    var rdr = try reader_mod.ReplayReader.init(alloc, tmp.dir, "utf8-e2e", .{});
    defer rdr.deinit();

    const read_ev = (try rdr.next()) orelse return error.TestUnexpectedResult;
    // The persisted output must be the lossy-sanitized version.
    try testing.expectEqualStrings(utf8_case.lossy_tool_out, read_ev.data.tool_result.output);

    // 4. Export to markdown — proves the full pipeline doesn't crash
    //    and the sanitized text appears in the export.
    const md_path = try export_mod.toMarkdown(alloc, tmp.dir, "utf8-e2e", null);
    defer alloc.free(md_path);

    const md_file = try tmp.dir.openFile(md_path, .{});
    defer md_file.close();
    const md = try md_file.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(md);

    // Exported markdown must contain the lossy-sanitized output.
    try testing.expect(std.mem.indexOf(u8, md, utf8_case.lossy_tool_out) != null);
    // Must NOT contain any raw 0xff byte.
    try testing.expect(std.mem.indexOfScalar(u8, md, 0xff) == null);
}
