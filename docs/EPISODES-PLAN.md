# pz Thread & Episode Architecture

Draft design for thread weaving and episodic memory in pz.
See `docs/EPISODES.md` for background (Slate's approach).

## Problem

pz's current compaction (`compact.zig`) runs mid-conversation, losing context unpredictably. Subagents are fire-and-forget — they return a response string and discard their full trace. There is no mechanism for:

- Structured result handoff between sub-tasks
- Natural compaction at task boundaries
- Composing context across independent work streams
- The orchestrator referencing prior sub-task results by name

## Core Primitive: Thread

A **Thread** is a named, resumable sub-conversation with its own session, tool access, and provider. When a thread completes an action, its trajectory is compressed into an **Episode** — a structured summary that the orchestrator (or other threads) can reference.

```
Orchestrator (main loop)
  ├── thread:analyze  → Episode{files_read, conclusions}
  ├── thread:impl     → Episode{files_changed, build_status}
  │     └── (received episode from thread:analyze as input)
  └── thread:test     → Episode{test_results, failures}
        └── (received episodes from thread:analyze + thread:impl)
```

### Thread vs. Subagent

| Property | Current subagent | Thread |
|---|---|---|
| Identity | Anonymous | Named, addressable |
| Result | Response string | Structured Episode |
| Context | Fully isolated | Episode composition |
| Lifetime | Single-shot | Resumable across actions |
| Compaction | N/A (discarded) | Natural at completion boundary |
| Parallelism | Independent | Orchestrator-coordinated |

## Data Model

### Thread

```zig
pub const Thread = struct {
    id: ThreadId,           // unique, auto-generated
    name: []const u8,       // user-visible label
    session_id: []const u8, // own JSONL session
    state: State,
    parent: ?ThreadId,      // orchestrator thread
    input_eps: []EpisodeRef, // episodes fed as context

    pub const State = enum {
        idle,     // waiting for orchestrator dispatch
        running,  // executing an action
        done,     // action complete, episode ready
        failed,   // action errored
    };
};
```

### Episode

```zig
pub const Episode = struct {
    thread_id: ThreadId,
    thread_name: []const u8,
    goal: []const u8,        // what the thread was asked to do
    outcome: Outcome,
    files_read: [][]const u8,
    files_changed: [][]const u8,
    key_findings: [][]const u8,  // model-generated bullet points
    tool_summary: []ToolSummary, // compressed tool call trace
    token_usage: Usage,
    elapsed_ms: i64,

    pub const Outcome = enum {
        success,
        partial,
        failed,
    };

    pub const ToolSummary = struct {
        tool: []const u8,   // "bash", "edit", etc.
        target: []const u8, // file path or command
        result: []const u8, // truncated output
    };
};
```

### EpisodeRef

```zig
pub const EpisodeRef = struct {
    thread_name: []const u8,
    episode: *const Episode,
};
```

## Session Storage

Each thread gets its own session file:

```
.pz/sessions/
  <main-sid>.jsonl           # orchestrator
  <main-sid>.t.analyze.jsonl # thread:analyze
  <main-sid>.t.impl.jsonl    # thread:impl
  <main-sid>.t.test.jsonl    # thread:test
```

Episodes are serialized as session events (new `Event.Data` variant):

```zig
pub const Data = union(Tag) {
    // ... existing variants ...
    episode: Episode,        // thread completion summary
    thread_start: ThreadStart, // thread dispatch record
};
```

## Orchestrator Protocol

### Dispatch

The orchestrator dispatches a thread via a new tool or ModeEv:

```
thread:spawn {
    name: "analyze",
    goal: "Read src/core/loop.zig and identify all error paths",
    input_episodes: ["prior-thread-name"],  // optional
    tools: ["read", "grep", "find"],        // tool mask
    model: "sonnet",                        // optional override
}
```

### Completion

When a thread finishes, the loop:

1. Generates the Episode (model-assisted compression of the thread's trace)
2. Persists the Episode to the orchestrator's session
3. Injects the Episode into the orchestrator's context as a structured message
4. Marks the thread as `done`

### Resumption

Threads can be resumed for follow-up actions. The thread retains its full session history. A new action appends to the same session file and produces a new Episode.

### Parallel Dispatch

Multiple threads can run concurrently. The orchestrator blocks until all dispatched threads complete, then receives all Episodes at once:

```
thread:spawn { name: "a", goal: "..." }
thread:spawn { name: "b", goal: "..." }
thread:join ["a", "b"]  // blocks, returns both episodes
```

## Episode Generation

When a thread completes, its full trajectory is compressed:

1. Collect all session events from the thread's session
2. Extract file operations (reads, writes, edits) from tool calls
3. Call `generateSummary` (existing `compact.zig` infra) with the thread's events
4. Model produces structured Episode fields: goal, outcome, key_findings
5. Tool trace is mechanically compressed: tool name + target + truncated output

This reuses the existing `GeneratedSummary` / `SummaryReq` infrastructure in `compact.zig` / `contract.zig`.

## Integration Points

### loop.zig

New `ModeEv` variants:

```zig
pub const ModeEv = union(enum) {
    // ... existing ...
    thread_start: ThreadStart,
    thread_episode: Episode,
};
```

The main loop gains a thread dispatch path: when a tool call requests `thread:spawn`, the loop creates a new Thread, runs it (possibly in a separate OS thread or sequentially), and on completion injects the Episode.

### runtime.zig

Thread management: track active threads, their sessions, coordinate parallel dispatch. The TUI shows thread status in the footer.

### compact.zig

Episode generation reuses `generateSummary`. The key difference: compaction no longer runs mid-conversation on the orchestrator. Instead, each thread's trace is naturally bounded and compressed at completion.

The orchestrator's context grows only by Episodes (small, structured) rather than raw tool traces.

### Provider contract

New `SummaryReq` variant or reuse existing one for episode generation. The model is asked to produce structured Episode fields given the raw thread trace.

## Context Flow

```
Orchestrator context:
  [system prompt]
  [user message]
  [Episode: thread:analyze — read 5 files, found 3 error paths, ...]
  [Episode: thread:impl — changed 2 files, build passes, ...]
  [assistant response]
  [Episode: thread:test — 12/12 tests pass, ...]
  [assistant response]
```

Each Episode is a compact, structured message — not a wall of tool call traces. The orchestrator sees *what happened* without *how it happened*.

## Compaction Strategy

With threads, the orchestrator's context grows much more slowly:

| Without threads | With threads |
|---|---|
| 50 tool calls × ~2KB each = 100KB | 5 episodes × ~1KB each = 5KB |
| Compaction needed every ~20 turns | Compaction rarely needed |
| Lossy, unpredictable | Structured, deterministic |

When the orchestrator's context does eventually need compaction, episodes provide natural summary units that survive compression far better than raw traces.

## Implementation Phases

### Phase 1: Sequential threads, manual episode

- `Thread` struct + `Episode` struct in `core/thread.zig`
- Thread session files via existing `SessionFile`
- Episode generation via `generateSummary`
- `thread:spawn` as a new tool in the registry
- Sequential execution only (orchestrator blocks)
- Episode injected as structured assistant message

### Phase 2: Parallel threads

- Concurrent thread execution (OS threads or async)
- `thread:join` for batch completion
- TUI thread status display

### Phase 3: Thread resumption + episode composition

- Resume threads by name for follow-up actions
- Pass episodes as input context to new threads
- Episode-to-episode references

### Phase 4: Cross-model threads

- Per-thread model override
- Episode boundary as clean model handoff point

## Design Gaps

### Episode generation is underspecified

Episode generation is the make-or-break surface and gets one paragraph. "Reuse `generateSummary`" is insufficient — EPISODES.md itself notes compaction is "largely unsolved." The quality of `key_findings` (model-generated free text) determines whether episodes are useful or just smaller garbage.

Needs its own design section covering:
- Prompt structure for episode compression (what instructions produce reliable structured output)
- Eval criteria: how to measure whether an episode retains the information the orchestrator needs
- When episode generation isn't worth the cost (short threads where raw result < compression overhead)
- Failure mode: what happens when the compression model hallucinates or drops critical details

### Thread resumption breaks the compaction story

A resumed thread retains full session history. Over multiple resumptions, the thread's own context grows unbounded — the same problem as the main loop today. The design assumes threads are short-lived but then adds resumption without addressing intra-thread compaction.

Options: (a) cap thread lifetime and force a new thread with the prior episode as input, (b) compact within the thread using its own episodes, (c) accept bounded growth with a hard token ceiling.

### Parallel execution has no design

Phase 2 says "concurrent thread execution (OS threads or async)" — that's the entire design for the feature that delivers the main value. Sequential threads (Phase 1) are just subagents with a nicer result format.

Needs:
- Scheduling: FIFO queue? Priority? Dependency-ordered?
- Backpressure: max concurrent threads, queuing when at capacity
- File coordination: two threads editing the same file = corruption. File ownership must be enforced in the Thread struct, not by convention.
- OS thread pool sizing vs. async dispatch tradeoffs

### No failure semantics

- If `thread:analyze` fails, does `thread:impl` still launch?
- `thread:join` blocks forever if a thread hangs — no timeout, no watchdog, no token budget
- Partial-failure on join: does the orchestrator receive episodes from completed threads while one is still failing?
- Error propagation: should dependent threads auto-cancel when a dependency fails?

### No resource limits

Each thread is a full model conversation. 5 parallel threads = 5x API cost. Needs:
- Per-thread token budget (input + output ceiling)
- Total session budget across all threads
- Cost-aware dispatch (don't spawn a thread if budget is nearly exhausted)
- Token accounting surfaced to TUI and episode metadata

## Resolved Decisions

These were listed as open questions but have clear answers:

1. **Thread depth**: Depth-1 only. Slate uses depth-1; unbounded recursion needs guards that add complexity without proven value. Threads cannot spawn sub-threads.
2. **Thread tool mask**: Threads get an explicit tool list at spawn time. Write/edit tools require file ownership declared in the Thread struct. Read-only threads inherit full read access.
3. **Thread naming**: Names must be unique within a session. The Thread struct enforces this at creation. Resumed threads keep their original name.
4. **Failure episodes**: Failed threads produce episodes with `outcome: .failed`, including the error message and last N tool calls. The orchestrator always gets an episode — never a hang.
5. **Episode format**: Hybrid — mechanical fields (`files_read`, `files_changed`, `tool_summary`) are extracted deterministically; `key_findings` is model-generated. Structured fields are authoritative; `key_findings` is advisory.
6. **Cost tracking**: Per-thread `token_usage` in Episode struct (already present). Orchestrator aggregates across all threads for session total.

## Remaining Open Questions

1. **TUI rendering**: How to show thread progress without cluttering the main transcript? Dedicated footer panel vs. inline status markers.
2. **Episode injection format**: System message vs. structured tool result vs. dedicated message role for episodes in the orchestrator context.
