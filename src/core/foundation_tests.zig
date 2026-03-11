pub const core = struct {
    pub const audit = @import("audit.zig");
    pub const syslog = @import("syslog.zig");
};

test "foundation module tests" {
    _ = core.audit;
    _ = core.syslog;
}
