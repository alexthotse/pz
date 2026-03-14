//! Print mode: non-interactive streaming output.
const mode = @import("mode.zig");
const run_impl = @import("print/run.zig");
pub const errors = @import("print/errors.zig");

pub fn run(run_ctx: mode.Ctx) !errors.Result {
    return run_impl.exec(run_ctx);
}
