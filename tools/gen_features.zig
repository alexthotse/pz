const std = @import("std");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const spec_path = "SPEC.md";
    const out_dir = "src/features";

    const spec_file = std.fs.cwd().openFile(spec_path, .{}) catch |err| {
        std.debug.print("Failed to open {s}: {}\n", .{ spec_path, err });
        return err;
    };
    defer spec_file.close();

    var dir = std.fs.cwd().openDir(out_dir, .{}) catch |err| blk: {
        if (err == error.FileNotFound) {
            try std.fs.cwd().makeDir(out_dir);
            break :blk try std.fs.cwd().openDir(out_dir, .{});
        } else {
            return err;
        }
    };
    defer dir.close();

    const content = try spec_file.readToEndAlloc(alloc, 1024 * 1024);
    var lines = std.mem.splitScalar(u8, content, '\n');

    var in_tasks = false;
    var index_file_content: std.ArrayList(u8) = .empty;
    defer index_file_content.deinit(alloc);

    try index_file_content.appendSlice(alloc, "const std = @import(\"std\");\n\n");

    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "## §T TASKS")) {
            in_tasks = true;
            continue;
        }
        if (in_tasks and std.mem.startsWith(u8, line, "## ")) {
            break;
        }
        if (!in_tasks) continue;

        // T1|x|port AWAY_SUMMARY: idle sum REPL|-
        if (!std.mem.startsWith(u8, line, "T")) continue;

        var parts = std.mem.splitScalar(u8, line, '|');
        _ = parts.next(); // id
        _ = parts.next(); // status
        const task_part = parts.next() orelse continue;

        // port AWAY_SUMMARY: idle sum REPL
        if (!std.mem.startsWith(u8, task_part, "port ")) continue;
        const task_desc = task_part[5..]; // "AWAY_SUMMARY: idle sum REPL"

        var colon_parts = std.mem.splitScalar(u8, task_desc, ':');
        const raw_feature_name = colon_parts.next() orelse continue;
        const desc = std.mem.trim(u8, colon_parts.next() orelse "", " ");

        // generate snake_case name
        var snake_name: std.ArrayList(u8) = .empty;
        defer snake_name.deinit(alloc);

        var struct_name: std.ArrayList(u8) = .empty;
        defer struct_name.deinit(alloc);

        var capitalize_next = true;

        for (raw_feature_name) |c| {
            if (c == '_') {
                try snake_name.append(alloc, '_');
                capitalize_next = true;
            } else {
                try snake_name.append(alloc, std.ascii.toLower(c));
                if (capitalize_next) {
                    try struct_name.append(alloc, c);
                    capitalize_next = false;
                } else {
                    try struct_name.append(alloc, std.ascii.toLower(c));
                }
            }
        }

        const feature_filename = try std.fmt.allocPrint(alloc, "{s}.zig", .{snake_name.items});
        
        var out_file = try dir.createFile(feature_filename, .{});
        defer out_file.close();

        const out_content = try std.fmt.allocPrint(alloc,
            \\const std = @import("std");
            \\
            \\/// {s}
            \\pub const {s} = struct {{
            \\    allocator: std.mem.Allocator,
            \\    enabled: bool,
            \\
            \\    pub fn init(allocator: std.mem.Allocator) !{s} {{
            \\        return {s}{{
            \\            .allocator = allocator,
            \\            .enabled = false,
            \\        }};
            \\    }}
            \\
            \\    pub fn deinit(self: *{s}) void {{
            \\        _ = self;
            \\    }}
            \\
            \\    pub fn enable(self: *{s}) void {{
            \\        self.enabled = true;
            \\    }}
            \\
            \\    pub fn process(self: *{s}) !void {{
            \\        if (!self.enabled) return;
            \\        // Core logic for {s}
            \\    }}
            \\}};
            \\
            \\test "{s} lifecycle" {{
            \\    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            \\    defer arena.deinit();
            \\
            \\    var feature = try {s}.init(arena.allocator());
            \\    defer feature.deinit();
            \\
            \\    try std.testing.expect(!feature.enabled);
            \\    feature.enable();
            \\    try std.testing.expect(feature.enabled);
            \\    try feature.process();
            \\}}
            \\
        , .{ desc, struct_name.items, struct_name.items, struct_name.items, struct_name.items, struct_name.items, struct_name.items, raw_feature_name, raw_feature_name, struct_name.items });

        try out_file.writeAll(out_content);
        
        try index_file_content.writer(alloc).print("pub const {s} = @import(\"{s}\").{s};\n", .{struct_name.items, feature_filename, struct_name.items});
    }

    var index_file = try dir.createFile("index.zig", .{});
    defer index_file.close();
    try index_file.writeAll(index_file_content.items);

    std.debug.print("Successfully generated all feature modules in {s}\n", .{out_dir});
}
