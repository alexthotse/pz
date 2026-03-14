const mode = @import("../mode.zig");
const run_impl = @import("run.zig");
pub const errors = @import("errors.zig");

pub fn run(run_ctx: mode.Ctx) !errors.Result {
    return run_impl.exec(run_ctx);
}
