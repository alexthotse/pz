const baseline = @import("perf/baseline.zig");
const fuzz = @import("perf/fuzz.zig");

test "perf module tests" {
    _ = baseline;
    _ = fuzz;
}
