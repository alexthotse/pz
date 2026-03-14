//! Shared test buffer writer for TUI snapshot tests.
//! Satisfies the `anytype` writer interface used by Renderer.render() and Ui.draw().

pub const TestBuf = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) TestBuf {
        return .{ .buf = buf };
    }

    pub fn clear(self: *TestBuf) void {
        self.len = 0;
    }

    pub fn writeAll(self: *TestBuf, bytes: []const u8) !void {
        if (self.len + bytes.len > self.buf.len) return error.NoSpaceLeft;
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn view(self: *const TestBuf) []const u8 {
        return self.buf[0..self.len];
    }
};
