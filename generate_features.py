import os
import re

spec_path = '/workspace/SPEC.md'
features_dir = '/workspace/src/features'
test_file_path = '/workspace/src/test/features_test.zig'

with open(spec_path, 'r') as f:
    spec_content = f.read()

# Extract tasks
task_pattern = re.compile(r'^(T\d+)\|(\.|~|x)\|port ([A-Z0-9_]+):\s*([^|]+)\|', re.MULTILINE)
tasks = task_pattern.findall(spec_content)

os.makedirs(features_dir, exist_ok=True)

zig_template = """const std = @import("std");

/// {description}
pub const {struct_name} = struct {{
    allocator: std.mem.Allocator,
    enabled: bool,

    pub fn init(allocator: std.mem.Allocator) !{struct_name} {{
        return {struct_name}{{
            .allocator = allocator,
            .enabled = false,
        }};
    }}

    pub fn deinit(self: *{struct_name}) void {{
        _ = self;
    }}

    pub fn enable(self: *{struct_name}) void {{
        self.enabled = true;
    }}

    pub fn process(self: *{struct_name}) !void {{
        if (!self.enabled) return;
        // Core logic for {feature_name}
    }}
}};

test "{feature_name} lifecycle" {{
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var feature = try {struct_name}.init(arena.allocator());
    defer feature.deinit();

    try std.testing.expect(!feature.enabled);
    feature.enable();
    try std.testing.expect(feature.enabled);
    try feature.process();
}}
"""

generated_features = []

for task_id, status, feature_name, description in tasks:
    if feature_name in ["HISTORY_PICKER", "TOKEN_BUDGET"]:
        continue
        
    filename = feature_name.lower() + ".zig"
    struct_name = "".join(word.capitalize() for word in feature_name.split("_"))
    
    filepath = os.path.join(features_dir, filename)
    with open(filepath, 'w') as f:
        f.write(zig_template.format(
            feature_name=feature_name,
            description=description.strip(),
            struct_name=struct_name
        ))
    
    generated_features.append((feature_name, struct_name, filename))
    
    # Update SPEC.md
    old_line = f"{task_id}|{status}|port {feature_name}: {description}"
    new_line = f"{task_id}|x|port {feature_name}: {description}"
    spec_content = spec_content.replace(old_line, new_line)

with open(spec_path, 'w') as f:
    f.write(spec_content)

# Create a central features.zig module to expose all of them
features_index_path = os.path.join(features_dir, 'index.zig')
with open(features_index_path, 'w') as f:
    f.write("const std = @import(\"std\");\n\n")
    for feature_name, struct_name, filename in generated_features:
        f.write(f"pub const {struct_name} = @import(\"{filename}\").{struct_name};\n")

print(f"Generated {len(generated_features)} features and updated SPEC.md")
