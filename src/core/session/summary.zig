//! Summary types: request, budget, metadata, result, and prompt constants.

pub const SummaryReq = struct {
    events_json: []const []const u8,
    file_ops: ?[]const u8 = null,
    max_tokens: u32 = 1024,
    budget: SummaryBudget = .{},
    meta: SummaryMeta = .{},
};

pub const SummaryBudget = struct {
    max_bytes: u64 = 64 * 1024,
    max_input_tokens: u32 = 64 * 1024,
};

pub const SummaryOutcome = enum {
    fit,
    scaled,
    over_budget,
};

pub const SummaryMeta = struct {
    outcome: SummaryOutcome = .fit,
    input_bytes: u64 = 0,
    input_tokens: u32 = 0,
    max_bytes: u64 = 64 * 1024,
    max_input_tokens: u32 = 64 * 1024,
    kept_events: u32 = 0,
    dropped_events: u32 = 0,
};

pub const SummaryResult = struct {
    summary: []const u8,
    meta: SummaryMeta = .{},
};

pub const system_prompt =
    "You are a context summarization assistant. " ++
    "Read the conversation and output only the structured summary.";

pub const prompt =
    "The messages above are a conversation to summarize. " ++
    "Create a structured checkpoint another LLM can use to continue the work.\n\n" ++
    "Use this exact format:\n\n" ++
    "## Goal\n" ++
    "[What the user is trying to accomplish]\n\n" ++
    "## Constraints & Preferences\n" ++
    "- [Constraint or (none)]\n\n" ++
    "## Progress\n" ++
    "### Done\n" ++
    "- [x] [Completed work]\n\n" ++
    "### In Progress\n" ++
    "- [ ] [Current work]\n\n" ++
    "### Blocked\n" ++
    "- [Current blockers or (none)]\n\n" ++
    "## Key Decisions\n" ++
    "- **[Decision]**: [Rationale]\n\n" ++
    "## Next Steps\n" ++
    "1. [Ordered next step]\n\n" ++
    "## Critical Context\n" ++
    "- [Exact paths, symbols, errors, or (none)]\n\n" ++
    "Keep each section concise. Preserve exact file paths, function names, and error messages.";
