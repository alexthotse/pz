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

### Phase 1: Sequential threads

Prerequisites (verified viable, ~200-300 lines):
- `ProviderFactory`: create fresh Provider instance per thread (reuse cached auth, separate HTTP client). NOT full thread-safety — just aliasing prevention.
- `BufferSink` or `NullSink`: thread events go to a separate ModeSink. Only the episode summary is pushed to the parent's mode sink.
- Per-thread `Writer` instance (separate `pending` counter). Same directory, different sid.
- Thread `Opts.abort_slot = null` (or separate slot). Prevents clobbering parent's abort slot.
- Thread `Opts.compactor = null`. Thread sessions are bounded (one action), no compaction needed.
- Depth guard: `thread:spawn` handler checks depth counter in Opts, refuses if > 0.
- Tool mask intersection: `thread_mask = requested & parent_mask`.
- `ToolAuth` + `Approver` inherited from parent Opts (mandatory, fail-closed).

Implementation:
- `Thread` struct + `Episode` struct in `core/thread.zig`
- Episode generation: reuse `start()` with episode-specific system prompt requesting JSON conforming to Episode schema. Collect full stream text. `std.json.parseFromSlice` into `EpisodeResult`. On parse failure, produce mechanical-only episode (`outcome: .failed`, empty `key_findings`, `tool_summary` from session data).
- `thread:spawn` as new tool kind (NOT agent tool reuse — in-process, not RPC). Bump `entries`/`selected` arrays to `[12]`, add `mask_thread` + `mask_thread_join` bits, extend `activeEntries`/`maskForName`/`rebuildEntries`.
- Sequential execution: recursive `loop.run` from within `runTool`, Opts by value with field overrides
- Thread session files via `SessionFile` with validated naming (`<sid>.t.<name>.jsonl`, name: `[a-z0-9-]`, max 32 chars)
- Session selector filtering: `fileSid`/`latestSidAlloc`/`fromIdOrPrefix` exclude `.t.` files
- Episode storage: transient struct — created at thread completion, serialized to text envelope (`[EPISODE:name] {json}`), injected as `Part.text`, then freed. No stable arena needed for Phase 1. Phase 3 deserializes from session text.
- Session event storage: do NOT add new `Event.Data` variants. Store episodes as `tool_result` events with convention (tool name `__episode__`, tool id `__thread_start__`). Existing readers pass these through to `Hist` via the `tool_result` arm. Forward-compatible with old binaries.

### Phase 1.5: Runtime isolation (prerequisite for Phase 2)

- File ownership enforcement: `owned_paths` on Runtime, checked at dispatch layer before write/edit
- CwdGuard elimination: file tools use `openat`/Dir-relative operations instead of `chdir`
- Provider thread-safety: mutex or per-thread instances via factory
- Session writer locking or per-thread store instances
- Per-thread `CmdCache` (or mutex-protected shared cache)
- Per-thread `AbortSlot` with thread-selection for cancel
- `ToolAuth.noop` and `Approver.noop` sentinels (fail-closed default, non-optional fields)

### Phase 2: Parallel threads

- Concurrent thread execution (OS threads)
- Scheduling: dependency-ordered dispatch
- Backpressure: max concurrent threads, queuing when at capacity
- `thread:join` with `timeout_ms`, partial-join semantics
- Per-thread resource limits: `max_tokens` ceiling, pre-dispatch budget check
- TUI thread status display
- Print/JSON modes: sequential-only restriction or per-thread output buffering

### Phase 3: Episode composition

- Pass episodes as input context to new threads (value-copied, not pointer)
- Episode-to-episode references
- No thread resumption — follow-up spawns new thread with prior episode as input

### Phase 4: Cross-model threads

- Per-thread model override via ProviderFactory
- Episode boundary as clean model handoff point

## Review Findings (Round 1 — baseline R1-314a)

Adversarial review by 6 agents. 8 Critical, 11 Major, 3 Minor accepted.

### Critical: GeneratedSummary produces wrong shape (F1)

`generateSummary` → `GeneratedSummary { req: SummaryReq, file_ops, event_jsons }` → provider returns `SummaryResult { summary: []const u8 }` — a single markdown blob. Episode needs `goal`, `outcome` (enum), `key_findings` ([][]const u8), `tool_summary` ([]ToolSummary). Zero overlap. "Reuse generateSummary" is architecturally false.

**Required**: New prompt requesting JSON-structured output. New parser for Episode fields. New `EpisodeReq`/`EpisodeResult` types in provider contract. The existing summary infra is not reusable for episodes.

### Critical: loop.run is monolithic and non-reentrant (F2)

`Opts` takes single provider, store, mode sink. `loop.run` is blocking with no yield point. Thread dispatch from within `runTool` means recursive `loop.run` (Phase 1) or OS threads sharing non-thread-safe state (Phase 2). Neither works without restructuring.

**Required**: Either (a) `ThreadContext` wrapping `Opts` with per-thread overrides, or (b) refactor `loop.run` to accept thread dispatch as an async operation. Design this before implementation.

### Critical: No file ownership enforcement (F3)

Plan says "Write/edit tools require file ownership declared in Thread struct." No such concept exists. `edit.Handler.run`, `write.Handler.run` execute unconditionally against any path passing `path_guard`. No hook for ownership checks.

**Required**: Ownership check at dispatch layer (`builtin.Runtime` or `loop.runTool`). `owned_paths: ?[]const []const u8` on Runtime or Call context. Prerequisite for Phase 2.

### Critical: Tool mask privilege escalation (F4)

`builtin.Runtime.init` does `opts.tool_mask & mask_all` — clamps to known tools, not to parent's mask. Model-generated `thread:spawn { tools: ["bash","write","agent"] }` succeeds even if orchestrator is restricted to `["read","grep"]`.

**Required**: `thread_mask = requested_mask & parent_mask` enforced before thread Runtime creation.

### Critical: Providers not thread-safe (F5)

`anthropic.Client` and `openai.Client` own a `std.http.Client` (not thread-safe) and mutable `auth` state. One provider instance per Runtime. Parallel threads sharing a provider = data race.

**Required**: Per-thread provider instance via factory function. Current `init` reads auth from disk (expensive) — needs caching strategy.

### Critical: CwdGuard is process-global (F6)

`CwdGuard` holds a global `std.Thread.Mutex`, calls `dir.setAsCwd()`. CWD is per-process. Parallel threads with file tools deadlock or serialize all file operations.

**Required**: File tools need `openat`/`Dir`-relative operations instead of `chdir`. Prerequisite for Phase 2.

### Critical: Session writer races (F7)

`Writer.append` opens file, seeks to end, writes, closes — no lock. Shared `pending` counter is a race. Even with per-thread session files, sharing one `Writer` instance races on `pending`.

**Required**: Per-thread `Writer` instances or per-thread `Store` instances.

### Critical: Parallel execution has no design (F8)

Phase 2 = main value proposition. Current design: one bullet point. Needs: scheduling, backpressure, max concurrency, file coordination, provider factory, CWD elimination, per-thread stores/writers/runtimes.

**Required**: Add "Phase 1.5: Runtime isolation prerequisites" covering F3-F7 before parallel dispatch.

### Major: Event.Data variant blast radius (F9)

Adding `episode` + `thread_start` to `Data` union breaks 7+ exhaustive switches across schema.zig (`dupeData`, `freeData`, `sanitizeData`), export.zig, 6 property tests. Episode's nested slices (`[][]const u8`, `[]ToolSummary`) make deep-copy/free significantly more complex than existing variants. Session format versioning (v1) unaddressed — old binaries can't read new sessions.

### Major: ModeEv variant blast radius (F10)

New `thread_start`/`thread_episode` variants break `JsonSink` (exhaustive switch). All 4 modes need thread-aware rendering. Print/JSON modes currently drop unknown variants silently.

### Major: Agent infra is inter-process, threads are in-process (F11)

`agent.zig` uses process-level RPC (Frame/Msg/Hello/policy_hash). `tools/agent.zig` returns `ChildProc.RunRes` (text). Threads need shared allocator, session file multiplexing, provider queuing. Zero reuse. Plan should explicitly state `thread:spawn` is a new tool kind, not a variant of agent.

### Major: EpisodeRef raw pointer UAF (F12)

`EpisodeRef { episode: *const Episode }`. If owning arena is freed, all refs dangle. Same class as P0-1 (compaction arena dangle). Episodes need value-copy or indices into a stable episode store.

### Major: Session naming pollution (F13)

`<sid>.t.<name>.jsonl` — `latestSidAlloc` picks thread file as "latest". `fromIdOrPrefix("sid")` returns AmbiguousSession. Thread names need validation (alphanum + hyphen, max 32 chars). Session listing needs filter excluding `.t.` files.

### Major: Thread resumption unbounded context (F14)

Resumed threads retain full session history, growing unbounded. Decision: cap thread lifetime. Force new thread with prior episode as input. Aligns with Slate's "one action per thread" (EPISODES.md:89).

### Major: No pre-dispatch resource limits (F15)

Post-hoc `token_usage` in Episode is accounting, not budgeting. Add `max_tokens` to `thread:spawn`, total session budget, pre-dispatch budget check refusing spawn when exhausted.

### Major: No timeout on thread:join (F16)

Add `timeout_ms` to `thread:join`. Define partial-join: return completed episodes, mark incomplete threads as timed out with `outcome: .failed`.

### Major: In-process threads bypass policy (F17)

RPC enforces `policy_hash` in Hello handshake. In-process threads skip this entirely. `ToolAuth` and `Approver` are optional in `Opts` — a thread constructing its own `Opts` could omit them.

**Required**: `ToolAuth` and `Approver` mandatory for thread Opts. Fail-closed default.

### Major: Runtime shared mutable state (F18)

`tools.builtin.Runtime` owns `skill_cache` (no sync) and dispatch pointers bound to `self`. Per-thread tool mask needs per-thread Runtime instance.

### Major: Print/JSON modes thread-unaware (F19)

`runPrint` and `runJson` write to single unsynchronized writer. ModeEv thread variants fall through to `else => {}`. Print mode may reasonably restrict to sequential threads.

### Minor: P21b competing design (F20)

P21b (multi-agent UX) designs separate result format with visible outcome states. Needs reconciliation: episodes replace P21b or build on top of it.

### Minor: Episode prompt injection (F21)

`key_findings` is model-generated free text injected into orchestrator context. A compromised thread could inject adversarial content mimicking system messages. Episodes need a distinct message envelope or role.

### Minor: CmdCache/AbortSlot not thread-safe (F22)

`CmdCache` uses unsynchronized `ArrayHashMap`. `AbortSlot` stores single `?Aborter`. Per-thread instances or mutex required. Cancel needs thread-selection mechanism.

### Round 2 Findings (baseline R2-314b)

**Major: Provider stream aliasing in sequential mode (F23)** — Recursive `loop.run` reuses same HTTP client. Inner `provider.start()` mutates connection pool while outer stream is paused. Need separate Provider instance per thread even sequentially.

**Major: AbortSlot clobbering (F24)** — Inner `loop.run` overwrites parent's abort slot (loop.zig:670). After thread completes, abort slot is null. Cancel breaks for remainder of outer turn.

**Major: Mode sink reentrancy (F25)** — Thread events (provider/session/tool) push to same ModeSink as orchestrator. TUI/print/JSON cannot distinguish thread events. Need BufferSink for threads.

**Major: Shared Writer pending counter (F26)** — Same Writer instance, different sids. Thread appends perturb orchestrator's flush accounting. Per-thread Writer required.

**Major: validateSid allows dots (F27)** — Decision #3 states `[a-z0-9-]` validation but `validateSid` only rejects `/`, `\`, NUL. Need new `validateThreadName` function.

**Major: ToolAuth fail-open (F28)** — Decision #9 says "mandatory" but `Opts.tool_auth` is `?Optional = null`, skip when null (loop.zig:1064). Changing to non-optional breaks all test callers (~4+ sites).

**Major: Depth-1 unenforced (F29)** — Mask architecture is bitwise, no "orchestrator-only" concept. Thread can spawn sub-threads via tool mask. Need depth counter in Opts.

### Round 3 Findings (baseline R3-314c)

**Critical: Episode generation contract undesigned (F30)** — Phase 1 says "EpisodeReq/EpisodeResult" but specifies nothing: no JSON schema, no streaming-to-JSON collection, no parse failure handling. Fixed: reuse `start()` with episode prompt, collect text, `std.json.parseFromSlice`, mechanical-only fallback on parse failure.

**Critical: Q3 forward-compat factually wrong (F31)** — `MalformedReplayLine` is fatal in all callers (loop.run, compact, export use `try`). Adding `Event.Data` variants breaks old binaries. Fixed: store episodes as `tool_result` events with reserved tool names. No new variants.

**High: Tool registry array bump (F32)** — `entries`/`selected` are `[10]`. Adding `thread:spawn`+`thread:join` needs `[12]`, new mask bits, new entries in `activeEntries`/`maskForName`/`rebuildEntries`.

**High: Episode arena contradiction (F33)** — Plan said "value-copied into stable arena" but Decision #11 uses text serialization. Fixed: Episode struct is transient — created, serialized to text, freed. No stable arena for Phase 1.

## Resolved Decisions

1. **Thread depth**: Depth-1 only. Enforced by depth counter in Opts — `thread:spawn` handler refuses if depth > 0. Tool mask alone cannot prevent this (mask is bitwise, no concept of "orchestrator-only" tools).
2. **Thread tool mask**: `thread_mask = requested & parent_mask` at spawn time. Trivially implementable. File ownership (Phase 1.5) is a separate, unresolved design question.
3. **Thread naming**: Unique within session. Validated by NEW `validateThreadName` function (separate from `validateSid`): `[a-z0-9-]`, max 32 chars. `fileSid`/`latestSidAlloc`/`fromIdOrPrefix` must filter out `.t.` files.
4. **Failure episodes**: Failed threads always produce episodes with `outcome: .failed`. If episode generation itself fails (corrupt session, provider error), produce mechanical-only episode from whatever session data is recoverable.
5. **Episode format**: Hybrid — mechanical fields extracted deterministically, `key_findings` model-generated and advisory.
6. **Cost tracking**: Per-thread `token_usage` in Episode. Pre-dispatch budget check. Per-thread `max_tokens` ceiling.
7. **Thread resumption**: No resumption. One action per thread. Follow-up spawns new thread with prior episode as input (value-copied).
8. **thread:spawn**: New tool kind (not agent tool reuse). In-process recursive `loop.run` with Opts field overrides.
9. **Policy enforcement**: Thread inherits parent's `ToolAuth` + `Approver`. Current fields are `?Optional = null` (fail-open). Fix: define `ToolAuth.noop`/`Approver.noop` sentinels, make fields non-optional, update all callers.
10. **Phase 1 sequential viability**: Confirmed. Does NOT require F5 (provider thread-safety), F6 (CwdGuard), F7 (session writer races). Requires 6 targeted Opts overrides: ProviderFactory, BufferSink, per-thread Writer, abort_slot=null, compactor=null, depth guard.
11. **Episode injection**: Serialize to text with structured envelope (e.g., `[EPISODE:name] {...}`) in `Part.text`. Lower blast radius than new `Part.episode` variant for Phase 1.

## Resolved Open Questions (from R2 evidence)

- **Phase ordering (Q4)**: Phase 1 proceeds without Phase 1.5. Phase 1.5 is prerequisite for Phase 2 only.
- **Mode thread policy (Q5)**: Non-TUI modes restrict to sequential threads. Print/JSON receive episode events via the parent ModeSink only (thread events go to BufferSink).
- **Session schema versioning (Q3)**: `MalformedReplayLine` is FATAL in all callers (`loop.run`, `compact.zig`, `export.zig` — all use `try rdr.next()`). Forward compat does NOT work. Solution: do not add new `Event.Data` variants. Store episodes as `tool_result` events with reserved tool names (`__episode__`, `__thread_start__`). Old binaries treat them as normal tool results — no parse failure, no schema break.

## Remaining Open Questions

1. **TUI rendering**: Dedicated footer panel vs. inline status markers for thread progress.
2. **File ownership design** (Phase 1.5): Where stored (`Runtime.owned_paths`?), where checked (per-handler or generic pre-dispatch), how paths normalized for matching.
