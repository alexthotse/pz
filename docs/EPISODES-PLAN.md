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

A **Thread** is a named, single-action sub-conversation with its own session, tool access, and provider. When a thread completes its action, its trajectory is compressed into an **Episode** — a structured summary that the orchestrator (or other threads) can reference. Threads are not resumable — follow-up work spawns a new thread with the prior episode as input (see Decision #7).

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
| Lifetime | Single-shot | Single-action, not resumable |
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
    input_eps: []const []const u8, // thread names whose episodes are deserialized from session text (Phase 3)

    pub const State = enum {
        pending,  // created, not yet started
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

Episode values are transient — created at thread completion, serialized to text envelope (`[EPISODE:name] {json}`), then freed. Phase 3 episode composition deserializes from session text by thread name. No raw pointers to episodes (avoids UAF — see F12).

## Session Storage

Each thread gets its own session file:

```
.pz/sessions/
  <main-sid>.jsonl           # orchestrator
  <main-sid>.t.analyze.jsonl # thread:analyze
  <main-sid>.t.impl.jsonl    # thread:impl
  <main-sid>.t.test.jsonl    # thread:test
```

Episodes are stored as new `Event.Data` variants (`episode: Episode`, `thread_start: ThreadStart`). Hard cutover — old binaries cannot read sessions with episodes. No compatibility shims, no migration.

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

### No Resumption

Threads are single-action. Follow-up work spawns a new thread with the prior episode deserialized from session text as input context (Phase 3). See Decision #7.

### Parallel Dispatch (Phase 2)

Multiple threads can run concurrently. The orchestrator blocks until all dispatched threads complete, then receives all Episodes at once:

```
thread:spawn { name: "a", goal: "..." }
thread:spawn { name: "b", goal: "..." }
thread:join ["a", "b"]  // blocks, returns both episodes
```

## Episode Generation

When a thread completes, its trajectory is compressed into an Episode:

1. Collect all session events from the thread's session file
2. Extract mechanical fields deterministically: `files_read`, `files_changed` from tool calls, `tool_summary` (tool name + target + truncated output), `token_usage`, `elapsed_ms`
3. Call `start()` with an episode-specific system prompt requesting JSON conforming to the Episode schema. The prompt includes the thread's session events as context.
4. Collect full stream text. Strip markdown code fences if present.
5. `std.json.parseFromSlice` into `EpisodeResult` to get `goal`, `outcome`, `key_findings`
6. On parse failure, produce mechanical-only episode: `outcome: .failed`, empty `key_findings`, mechanical fields from step 2

Does NOT reuse `generateSummary` / `SummaryReq` — different output shape (see F1, F30).

## Integration Points

### loop.zig

Phase 1: no new `ModeEv` variants. Thread events go to a `BufferSink`; only the episode text envelope reaches the parent ModeSink as a `Part.text` injection. Phase 2 may add `ModeEv` variants for TUI thread status display.

The event loop gains a thread dispatch state: `thread:spawn` registers a new provider stream fd. The orchestrator's state machine yields until the thread's state machine reaches `done`, then injects the episode.

### runtime.zig

Thread management: track active threads, their sessions, coordinate dispatch. TUI shows thread status in the footer (Phase 2).

### compact.zig

Episode generation does NOT reuse `generateSummary` (different output shape — see F1). New episode-specific prompt via `start()`, requesting JSON conforming to Episode schema. Mechanical fallback on parse failure.

The orchestrator's context grows only by episode text envelopes (small, structured) rather than raw tool traces.

### Provider contract

No new `SummaryReq` variant. Episode generation reuses `start()` with an episode-specific system prompt. The model produces structured JSON; the harness parses it into an Episode struct.

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

## Assumption

This plan assumes **P10 (Zero-latency cancel)** is already implemented. The main loop is an async event loop driven by `poll`/`kqueue` fds. Tool calls are fd-registered state machines, not blocking calls. Provider streams are pollfds. `CwdGuard` is eliminated — file tools use `openat`/Dir-relative operations.

## Implementation Phases

### Phase 1: Sequential threads

Thread dispatch is a state machine transition in the event loop. The orchestrator's turn pauses while the thread's turn runs on its own provider stream fd. Sequential = one thread at a time, orchestrator waits.

Per-thread isolation:
- `ProviderFactory`: fresh Provider instance per thread (separate HTTP connection, reuse cached auth)
- `BufferSink`: thread events go to a separate ModeSink. Only the episode summary is pushed to the parent's mode sink.
- Per-thread `Writer` instance (separate session file, separate flush counter)
- Per-thread `AbortSlot` (cancel targets the active thread's fd)
- Per-thread `CmdCache` (approval state does not leak between thread and orchestrator)
- No compaction for threads (bounded single-action lifetime)
- Depth guard: thread state machine refuses `thread:spawn` if depth > 0
- Tool mask: `thread_mask = requested & parent_mask`
- `ToolAuth` + `Approver` inherited from parent (mandatory, fail-closed via `ToolAuth.noop` sentinel)

Implementation:
- `Thread` struct + `Episode` struct in `core/thread.zig`
- Episode generation: `start()` with episode-specific system prompt requesting JSON conforming to Episode schema. Collect full stream text. Strip markdown code fences (`\`\`\`json ... \`\`\``) before parsing — models routinely wrap JSON in fences. `std.json.parseFromSlice` into `EpisodeResult`. On parse failure, produce mechanical-only episode (`outcome: .failed`, empty `key_findings`, `tool_summary` from session data).
- `thread:spawn` as new tool kind (NOT agent tool reuse — in-process, not RPC). Bump `entries`/`selected` arrays to `[11]`, add `mask_thread` bit, extend `activeEntries`/`maskForName`/`rebuildEntries`. `thread:join` is Phase 2 (bump to `[12]` then).
- Thread session files via `SessionFile` with validated naming (`<sid>.t.<name>.jsonl`, name: `[a-z0-9-]`, max 32 chars)
- Session selector filtering: `fileSid`/`latestSidAlloc`/`fromIdOrPrefix` exclude `.t.` files
- Episode injection: transient struct serialized to text envelope (`[EPISODE:name] {json}`), injected as `Part.text` with role `.user`, then freed.
- Session persistence: new `Event.Data` variants (`episode: Episode`, `thread_start: ThreadStart`). Hard cutover — no forward compat. Update all exhaustive switches (`dupeData`, `freeData`, `sanitizeData`, `export.zig`, property tests). Deep-copy/free for Episode's nested slices.

### Phase 2: Parallel threads

Multiple thread provider streams registered as concurrent pollfds in the event loop. Orchestrator continues processing its own events while threads run.

- Thread dispatch via event loop fd registration
- Scheduling: dependency-ordered dispatch
- Backpressure: max concurrent pollfds, queuing when at capacity
- `thread:join` with `timeout_ms`, partial-join semantics (return completed episodes, mark timed-out threads as `.failed`)
- Per-thread resource limits: `max_tokens` ceiling, pre-dispatch budget check
- TUI thread status display
- Print/JSON modes: sequential-only restriction or per-thread output buffering

### Phase 3: Episode composition

- Pass episodes as input context to new threads (deserialized from session text)
- Episode-to-episode references
- No thread resumption — follow-up spawns new thread with prior episode as input

### Phase 4: Cross-model threads

- Per-thread model override via ProviderFactory
- Episode boundary as clean model handoff point

## Review Findings

**Note**: This plan now assumes P10 (async event loop) is complete. The following findings from Rounds 1-2 are **superseded by P10** and retained only for historical context: F2 (loop.run non-reentrant), F5 (provider thread-safety), F6 (CwdGuard), F7 (session writer races), F23 (provider stream aliasing), F24 (AbortSlot clobbering), F25 (mode sink reentrancy), F26 (shared Writer pending counter). These problems do not exist in a P10 world.

### Round 1 (baseline R1-314a)

6 agents. 8 Critical, 11 Major, 3 Minor accepted.

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

**Required**: Phase 2 design. [Superseded: P10 resolves F5-F7; F3 (file ownership) deferred to Phase 2 per F40. No Phase 1.5 — P10 is the prerequisite.]

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

**Critical: Q3 forward-compat factually wrong (F31)** — `MalformedReplayLine` is fatal in all callers (loop.run, compact, export use `try`). Adding `Event.Data` variants breaks old binaries. Fixed: store episodes as `prompt` events with text envelope.

**High: Tool registry array bump (F32)** — `entries`/`selected` are `[10]`. Adding `thread:spawn`+`thread:join` needs `[12]`, new mask bits, new entries in `activeEntries`/`maskForName`/`rebuildEntries`.

**High: Episode arena contradiction (F33)** — Plan said "value-copied into stable arena" but Decision #11 uses text serialization. Fixed: Episode struct is transient — created, serialized to text, freed. No stable arena for Phase 1.

### Round 4 Findings (baseline R4-314d)

**Critical: tool_result convention broken (F34)** — `ToolResult` has no `name` field (only `id`, `out`, `is_err`). Can't encode episode identity via tool name. Fixed: abandoned `tool_result` approach entirely.

**Critical: Orphaned tool_result rejected by API (F35)** — Standalone `tool_result` without matching `tool_call` is rejected by Anthropic API (400 error). Session replay after episode storage would fail. Fixed: use `prompt` events instead.

**High: Storage/injection contradiction (F36)** — Line 250 said text envelope in `Part.text`, line 251 said `tool_result` events. Two representations = non-deterministic replay. Fixed: single representation — `prompt` event with text envelope.

**Major: P10 dependency undeclared (F37)** — Entire plan now assumes P10 is complete. Thread dispatch is a state machine transition, not recursive loop.run.

### Round 5 (baseline R5-314e)

**Critical: Decision #8 contradicted P10 assumption (F38)** — Said "recursive loop.run" but plan assumes async event loop. Fixed: Decision #8 rewritten as state machine transition.

**High: Episode replay phantom user turn (F39)** — `prompt` events replay as user messages. Model treats episode JSON as user input. Fixed: Decision #10 specifies `[EPISODE:` prefix detection and context wrapping on replay.

**High: File ownership misplaced in Phase 1 (F40)** — Phase 1 listed file ownership but 3 other locations said Phase 2. Fixed: removed from Phase 1. Sequential threads don't need it.

**High: thread:join unusable in Phase 1 (F41)** — Phase 1 is sequential; spawn blocks until complete. Registering join wastes a tool slot. Fixed: Decision #12 — bump to [11] for Phase 1, add join in Phase 2.

**High: Episode generation budget unaccounted (F42)** — Thread at token ceiling can't generate episode. Fixed: Decision #6 reserves fixed budget for episode generation, subtracted before action.

**High: Decision #10 referenced stale findings (F43)** — F5/F6/F7 said "not required for Phase 1" but P10 assumption means they're already resolved. Fixed: Resolved Q4 updated.

## Resolved Decisions

1. **Thread depth**: Depth-1 only. Enforced by depth counter in thread state — `thread:spawn` handler refuses if depth > 0.
2. **Thread tool mask**: `thread_mask = requested & parent_mask` at spawn time.
3. **Thread naming**: Unique within session. Validated by `validateThreadName`: `[a-z0-9-]`, max 32 chars. `fileSid`/`latestSidAlloc`/`fromIdOrPrefix` filter out `.t.` files.
4. **Failure episodes**: Failed threads always produce episodes with `outcome: .failed`. Episode generation failure produces mechanical-only episode. If budget exhausted after action, use mechanical-only (no provider call for episode).
5. **Episode format**: Hybrid — mechanical fields extracted deterministically, `key_findings` model-generated and advisory.
6. **Cost tracking**: Per-thread `token_usage` in Episode. Pre-dispatch budget check. Per-thread `max_tokens` ceiling. Reserve fixed token budget for episode generation (subtracted from `max_tokens` before action starts).
7. **Thread resumption**: No resumption. One action per thread. Follow-up spawns new thread with prior episode as input.
8. **thread:spawn**: New tool kind. State machine transition in the event loop — registers a new provider stream fd, orchestrator's state machine yields until thread's state machine reaches `done`. NOT recursive `loop.run` (P10 eliminates the blocking loop pattern).
9. **Policy enforcement**: Thread inherits parent's `ToolAuth` + `Approver`. Define `ToolAuth.noop`/`Approver.noop` sentinels (fail-closed), make fields non-optional.
10. **Episode injection**: New `Part.episode` variant in provider contract. Episodes are structured messages with a dedicated role/part type — not serialized as text in `Part.text`. Requires updating all provider encoders (Anthropic, OpenAI) to handle the new variant.
11. **Session schema**: New `Event.Data` variants (`episode`, `thread_start`). Hard cutover — old binaries cannot read new sessions. No compat shims, no migration, no fallback. This is consistent with pz's core constraint: hard cutovers only.
12. **Phase 1 tool registry**: Bump to `[11]` for `thread:spawn` only. `thread:join` is Phase 2 — not registered until parallel threads are implemented.

## Resolved Open Questions

- **Phase ordering (Q4)**: P10 is assumed complete. Phase 1 builds directly on the async event loop. F5 (provider safety), F6 (CwdGuard), F7 (writer races) are resolved by P10 — not deferred. Phase 2 adds parallel fd multiplexing on top.
- **Mode thread policy (Q5)**: Non-TUI modes restrict to sequential threads. Print/JSON receive episode events via the parent ModeSink only (thread events go to BufferSink).
- **Session schema versioning (Q3)**: New `Event.Data` variants. Hard cutover. No compat shims.

## Remaining Open Questions

1. **TUI rendering**: Dedicated footer panel vs. inline status markers for thread progress.
2. **File ownership design** (Phase 2): Where stored (`Runtime.owned_paths`?), where checked (per-handler or generic pre-dispatch), how paths normalized. Not needed for Phase 1 (sequential, no concurrent file access).
