//! Output modes: TUI, print, JSON, RPC.
pub const mode = @import("modes/mode.zig");
pub const Ctx = mode.Ctx;
pub const tui = @import("modes/tui.zig");
pub const print = @import("modes/print.zig");
