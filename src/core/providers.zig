//! Provider layer: LLM API clients, auth, streaming, retry.
pub const retry = @import("providers/retry.zig");
pub const types = @import("providers/types.zig");
pub const stream_parse = @import("providers/stream_parse.zig");
pub const client = @import("providers/client.zig");
pub const proc_transport = @import("providers/proc_transport.zig");
pub const auth = @import("providers/auth.zig");
pub const oauth_callback = @import("providers/oauth_callback.zig");
pub const http_client = @import("providers/http_client.zig");
pub const anthropic = @import("providers/anthropic.zig");
pub const openai = @import("providers/openai.zig");
pub const models = @import("providers/models.zig");

const c = @import("providers/api.zig");

pub const Role = c.Role;
pub const Request = c.Request;
pub const Msg = c.Msg;
pub const Part = c.Part;
pub const Tool = c.Tool;
pub const ToolCall = c.ToolCall;
pub const ToolResult = c.ToolResult;
pub const Opts = c.Opts;
pub const Event = c.Event;
pub const Usage = c.Usage;
pub const Stop = c.Stop;
pub const StopReason = c.StopReason;
pub const Provider = c.Provider;
pub const Stream = c.Stream;
pub const Aborter = c.Aborter;
pub const AbortSlot = c.AbortSlot;
pub const CancelPoll = c.CancelPoll;
