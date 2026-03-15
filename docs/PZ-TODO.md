# PZ-TODO: Built-in Task Management

Replaces external `dots` CLI and subsumes `PLAN.md` as the executable work-tracking layer.
`PLAN.md` remains as the strategic overview; tasks are the actionable decomposition.
Add as `SK8` in PLAN.md Phase 6.

## Goals

1. Model can propose task updates via tool call; user confirms via approval gate or manages directly via `/todo`.
2. Tasks persist as markdown files in `.pz/tasks/` for durability and implementation detail.
3. All modes (TUI, print, JSON, RPC) handle todo events. TUI gets inline transcript blocks + `/todo` overlay.
4. No external dependencies — all logic lives in pz.

## Prior Art

### Codex (OpenAI)
- Protocol: `UpdatePlanArgs { explanation: Option<String>, plan: Vec<PlanItemArg> }` where `PlanItemArg { step: String, status: StepStatus }` and `StepStatus = Pending | InProgress | Completed`.
- Model calls `update_plan` tool with full plan state each time (replace, not patch).
- CLI rendering: `✓` green (completed), `→` cyan (in-progress), `•` dim (pending).
- TUI rendering: `✔` + `crossed_out().dim()` (completed), `□` cyan bold (in-progress), `□` dim (pending).
- Plan updates appear as `HistoryCell` blocks in chat transcript with `"Updated Plan"` header.

### dots (joelreymont/dots)
- Zig CLI, markdown frontmatter files in `.dots/`, archive subdir for closed items.
- Frontmatter: `title`, `status` (open/active/closed), `priority`, `issue-type`, `created-at`, `closed-at`, `close-reason`.
- Body: free-form markdown (description, files, acceptance criteria).
- Features: parent-child hierarchy, blocking dependencies, slug-based IDs with hex suffix, search, tree view.
- Commands: `add`, `ls`, `on` (activate), `off` (complete), `rm`, `show`, `tree`, `find`, `ready` (unblocked).

## Design

### Storage: `.pz/tasks/`

```
.pz/tasks/
  fix-uaf-3a7b1e2f.md   # open task
  add-grep-c1f29d0a.md   # open task
  archive/                # completed tasks moved here
    setup-ci-8e4d5f7b.md
```

No config file. IDs are slug + random hex (no sequence numbers).
`TaskStore.open()` calls `makePath(".pz/tasks/archive")` to create the directory tree on first use.

Each task file uses line-oriented frontmatter (NOT YAML) + markdown body:

```markdown
---
id: fix-uaf-3a7b1e2f
title: Fix UAF in compaction
status: open
priority: 1
parent:
blocks:
created: 2026-03-15T10:00:00+01:00
closed:
---

Do: prove/refute ReplayReader arena-dangle in multi-event compaction.
Files: `src/core/session/compact.zig`, `src/core/session/reader.zig`
Accept: allocator regression proves no dangling event data across next() calls.
```

### Frontmatter Format

NOT YAML. Minimal line-oriented `key: value` format:
- Delimited by `---` lines (start and end)
- One field per line: `key: value`
- First `: ` (colon-space) is the delimiter; value is everything after
- Empty value = null (e.g., `parent:`, `closed:`)
- Arrays: comma-separated inline (e.g., `blocks: id1, id2`) or empty for `[]`
- No multiline values, no nested objects, no quoting, no anchors
- Body cannot contain `---` on a line by itself (serializer escapes to `\-\-\-`)

### Status Model

```
open → active → done
         ↓
       blocked   (computed: has unresolved `blocks` dependency)
```

Three stored states: `open`, `active`, `done`.
`blocked` is computed at display time from dependency graph (same as dots).
No `cancelled` — delete the file instead.

### ID Generation

`{slug}-{hex8}` where slug is kebab-case from title (max 20 chars), hex8 is 4 random bytes hex-encoded (8 hex chars).
Example: `fix-uaf-3a7b1e2f`, `add-grep-tool-c1f29d0a`.

**Slug sanitization (security-critical):**
- Characters restricted to `[a-z0-9-]` only; all others stripped
- Leading dots and path separators (`/`, `\`) forbidden
- Final filename validated as single path component (no `/`, `\`, `.`, `..`)
- On collision (file exists), retry with new random bytes (max 3 retries, then error)

**Short-ID resolution:** unique prefix match. Ambiguous prefix (matches >1 task) returns error listing all matches.

### Task File Format

Fields:
| Field     | Type       | Required | Description |
|-----------|------------|----------|-------------|
| `id`      | string     | yes      | Unique slug-hex ID |
| `title`   | string     | yes      | Short description (< 80 chars) |
| `status`  | enum       | yes      | `open`, `active`, `done` |
| `priority`| int 0-9    | yes      | 0 = highest, default 2 |
| `parent`  | string?    | no       | Parent task ID for hierarchy |
| `blocks`  | []string   | no       | IDs this task blocks (dependency) |
| `created` | ISO 8601   | yes      | Creation timestamp |
| `closed`  | ISO 8601?  | no       | Completion timestamp |

Body: free-form markdown, max 4KB. Implementation notes, file references, acceptance criteria.
The body is the replacement for dots descriptions AND plan item detail.

**Body sanitization:** body cannot contain frontmatter delimiters (`---` on its own line).
The serializer escapes these on write; the parser un-escapes on read.

### Module: `src/core/tasks/`

```
src/core/tasks/
  mod.zig       # public API: TaskStore, Task, Status, re-exports
  store.zig     # disk I/O, CRUD, resolve, archive, dependency graph
  format.zig    # frontmatter parse/serialize
```

No separate `resolve.zig` — resolution and dependency logic live in `store.zig`.

#### `Task` struct

```zig
pub const Status = enum { open, active, done };

pub const Task = struct {
    id: []const u8,
    title: []const u8,
    status: Status,
    priority: u4,           // 0-9
    parent: ?[]const u8,
    blocks: []const []const u8,
    created: []const u8,    // ISO 8601
    closed: ?[]const u8,
    body: []const u8,       // markdown after frontmatter, max 4KB
};
```

#### `TaskStore` API

```zig
pub const TaskStore = struct {
    dir: fs.Dir,            // .pz/tasks/
    alloc: Allocator,

    /// Opens .pz/tasks/, creating directory tree if needed.
    pub fn open(alloc: Allocator) !TaskStore;
    pub fn close(self: *TaskStore) void;

    // CRUD
    pub fn create(self: *TaskStore, title: []const u8, opts: CreateOpts) !Task;
    pub fn get(self: *TaskStore, id: []const u8) !?Task;
    pub fn list(self: *TaskStore, filter: ?Status) ![]Task;
    pub fn delete(self: *TaskStore, id: []const u8) !void;

    // Status transitions (enforce state machine)
    pub fn activate(self: *TaskStore, id: []const u8) !void;   // open → active
    pub fn complete(self: *TaskStore, id: []const u8) !void;    // active → done, archive
    pub fn reopen(self: *TaskStore, id: []const u8) !void;      // done → open, unarchive

    // Queries (always read from disk, no caching)
    pub fn resolve(self: *TaskStore, short_id: []const u8) ![]const u8;
    pub fn ready(self: *TaskStore) ![]Task;     // unblocked open tasks
    pub fn tree(self: *TaskStore, root: ?[]const u8) ![]TreeNode;
};
```

No `update(Patch)` — status changes go through named transition methods.
No `sync()` — incremental updates only, never bulk replace.
All query methods read from disk on every call (no in-memory cache). This is correct for small task counts and avoids stale-state bugs with concurrent access.

### Security

#### Policy bypass

The todo tool writes to `.pz/tasks/` which is inside the protected `.pz/` directory.
This is an intentional, scoped bypass of `path_guard`:
- The `TaskStore` does NOT go through `path_guard.createFile()`.
- Instead, it writes only within `.pz/tasks/` via its own `fs.Dir` handle.
- The slug sanitizer prevents path traversal out of this directory.
- This bypass is acceptable because: (a) the write target is narrowly scoped, (b) content is validated, (c) the tool is gated by the approval system.

#### Approval gate

The `todo` tool MUST be marked `destructive = true` for `update` and `add` actions.
`read` is non-destructive. The tool handler checks the action and sets the destructive flag accordingly.
This ensures the user sees and approves all model-initiated task mutations.

#### Content validation

- Title: max 80 chars, slug-safe subset validated
- Body: max 4KB, frontmatter delimiters escaped
- Status: closed enum, no arbitrary values
- IDs from model: validated via `resolve()` which only matches existing files

#### Tool mask inheritance

`mask_todo` is NOT included in `mask_all`. It is a separate opt-in flag.
The main agent gets `mask_all | mask_todo`. Child agents spawned via the `agent` tool do NOT inherit `mask_todo` — they cannot modify task state.
Background agents (read-only by policy) cannot mutate tasks.

### Model Tool: `todo`

Added to `builtin.zig`:
- `mask_todo: u16 = 1 << 10` (new bit, not in `mask_all`)
- Bump `entries: [11]tools.Entry` and `selected: [11]tools.Entry` (from `[10]`)
- Add `mask_todo` check in `activeEntries()`
- Add `"todo"` to `maskForName` static map
- Add 11th entry in `rebuildEntries()`
- Uses `schema_json` (raw JSON schema), same pattern as `ask` tool

#### Type changes in `src/core/tools.zig`

```zig
// Add to Kind enum (line ~18):
pub const Kind = enum { read, write, bash, edit, grep, find, ls, agent, web, ask, skill, todo };

// Add TodoArgs struct:
pub const TodoArgs = struct {
    action: enum { read, update, add },
    tasks: ?[]const TaskItem,
    note: ?[]const u8,

    pub const TaskItem = struct {
        id: ?[]const u8,
        title: ?[]const u8,
        status: ?[]const u8,
        priority: ?i64,
        parent: ?[]const u8,
        body: ?[]const u8,
    };
};

// Add to Call.Args union (line ~107):
pub const Args = union(Kind) {
    // ... existing variants ...
    todo: TodoArgs,
};
```

**Every exhaustive switch on `Kind` or `Args` must be updated.** Audit: `loop.zig`, `runtime.zig`, session serialization, test infrastructure.

Tool schema sent to the model (via `schema_json`):

```json
{
  "name": "todo",
  "description": "View or update the task list. Use 'read' to see current tasks, 'update' to modify task statuses, 'add' to create new tasks.",
  "parameters": {
    "action": { "type": "string", "enum": ["read", "update", "add"], "required": true },
    "tasks": {
      "type": "array",
      "description": "For 'update': [{id, status}]. For 'add': [{title, priority?, parent?, body?}].",
      "items": {
        "type": "object",
        "properties": {
          "id": { "type": "string" },
          "title": { "type": "string" },
          "status": { "type": "string", "enum": ["open", "active", "done"] },
          "priority": { "type": "integer" },
          "parent": { "type": "string" },
          "body": { "type": "string" }
        }
      }
    },
    "note": { "type": "string", "description": "Optional explanation of what changed and why" }
  }
}
```

**action=read**: Returns task list as markdown table (titles + status only, NOT bodies). Bodies are only in the files.
**action=update**: Patches task statuses. Incremental, not replace-all. Each item processed independently — one bad ID does not abort the batch. Result shows per-item success/failure.
**action=add**: Creates new tasks with validated title/body. Model cannot set `id` (auto-generated).

Tool result returned to model: updated task list summary (titles + status, no bodies).

### Tool Handler: `src/core/tools/todo.zig`

Follows existing handler pattern: `fn runTodo(self: *Runtime, call: tools.Call, sink: tools.Sink) Err!tools.Result`.

```zig
pub fn runTodo(self: *Runtime, call: tools.Call, sink: tools.Sink) Err!tools.Result {
    const args = call.args.todo;
    var store = try TaskStore.open(self.alloc);
    defer store.close();

    switch (args.action) {
        .read => {
            const tasks = try store.list(null);
            return .{ .output = formatSummary(self.alloc, tasks) };
        },
        .update => {
            var results = std.ArrayList(u8).init(self.alloc);
            for (args.tasks orelse &.{}) |item| {
                // Process each independently; collect errors per-item
                const id = store.resolve(item.id orelse continue) catch |e| {
                    try results.appendSlice(errMsg(e, item.id));
                    continue;
                };
                const status = parseStatus(item.status) catch continue;
                switch (status) {
                    .active => store.activate(id) catch |e| { /* collect */ continue; },
                    .done => store.complete(id) catch |e| { /* collect */ continue; },
                    .open => store.reopen(id) catch |e| { /* collect */ continue; },
                }
            }
            const tasks = try store.list(null);
            // Emit ModeEv for TUI rendering (see Event Plumbing)
            self.pushModeEv(.{ .todo_update = .{
                .note = args.note,
                .tasks = toSnapshots(tasks),
            }});
            return .{ .output = formatSummary(self.alloc, tasks) };
        },
        .add => {
            for (args.tasks orelse &.{}) |item| {
                _ = try store.create(item.title orelse continue, .{
                    .priority = item.priority,
                    .parent = item.parent,
                    .body = item.body,
                });
            }
            const tasks = try store.list(null);
            self.pushModeEv(.{ .todo_update = .{
                .note = args.note,
                .tasks = toSnapshots(tasks),
            }});
            return .{ .output = formatSummary(self.alloc, tasks) };
        },
    }
}
```

Note: `store.list()` called once per action, result reused for both event emission and tool result.

### User Command: `/todo`

Registered as a built-in slash command in `runtime.zig`, NOT in skill.zig:
- Add `.todo` to `Cmd` enum at `runtime.zig:~4251`
- Add `"todo"` to `cmd_map` StaticStringMap at `runtime.zig:~4252`
- Add `.todo` case in the dispatch switch at `runtime.zig:~4298`
- Add `{ .name = "todo", .desc = "Manage tasks" }` to `cmds` array in `cmdpicker.zig:~16`

```
/todo              — show task list (overlay)
/todo add "title"  — create task interactively
/todo on <id>      — activate task
/todo off <id>     — complete task
/todo rm <id>      — delete task
/todo tree         — show hierarchy
```

`/todo` with no args opens the overlay. Subcommands execute immediately and re-render.
`/todo` mutations go through the same `TaskStore` path as the model tool. All mutations are serialized through the event loop (single-threaded owner) to avoid concurrent write races.

### TUI Rendering

#### Inline Transcript Block

When a `todo_update` ModeEv fires, a block is pushed to the transcript:

```
• Updated Tasks
  └ ✔ ̶F̶i̶x̶ ̶U̶A̶F̶ ̶i̶n̶ ̶c̶o̶m̶p̶a̶c̶t̶i̶o̶n̶          (strikethrough + dim)
  └ □ Add grep tool                   (cyan bold = active)
  └ □ Write session export            (dim = pending)
```

Rendering rules (matching Codex's TUI style):
| Status   | Marker | Text Style |
|----------|--------|------------|
| `done`   | `✔`    | `crossed_out` + `dim` |
| `active` | `□`    | `cyan` + `bold` |
| `open`   | `□`    | `dim` |

Implementation in `src/modes/tui/transcript.zig`: add `.todo_update` to the `Kind` enum (at line ~19, alongside `text, user, thinking, tool, err, meta, image`). The block holds a `TodoSnapshot` slice and optional note.

#### `/todo` Overlay

Add `.todo` to `overlay.Kind` enum (at line ~11, alongside `model, session, settings, fork, login, logout, queue`).

The todo overlay needs structured row data (id, title, status, priority, blocked), unlike the generic `Overlay` which uses `items: []const []const u8`. Either:
- (a) Create a separate `TodoOverlay` struct with custom rendering, or
- (b) Extend `Overlay` to support a custom row renderer.

Option (a) is cleaner. Shows:
- All tasks grouped by parent (tree view), max depth 3
- Status markers with color
- Priority column
- Blocked indicator
- Scrollable, dismissible with ESC

### Event Plumbing

New variant in `ModeEv` union at `src/core/loop.zig:~23`:

```zig
pub const ModeEv = union(enum) {
    replay: ...,
    session: ...,
    provider: ...,
    tool: ...,
    session_write_err: ...,
    todo_update: TodoUpdate,   // NEW
};

pub const TodoUpdate = struct {
    note: ?[]const u8,
    tasks: []const TaskSnapshot,
};

pub const TaskSnapshot = struct {
    id: []const u8,
    title: []const u8,
    status: tasks.Status,
    priority: u4,
};
```

**All four mode sinks must handle `.todo_update` explicitly (no `else =>` fallthrough):**

| Sink | File:line | Handling |
|------|-----------|----------|
| `TuiSink.push` | `runtime.zig:~452` | Push `TodoUpdateCell` to transcript; refresh overlay if open |
| `PrintSink.push` | `runtime.zig:~422` | Print text summary: `✓`/`→`/`•` markers (same as Codex CLI) |
| `JsonSink.push` | `runtime.zig:~1536` | Emit `{"type":"todo_update","note":...,"tasks":[...]}` |
| `LiveTurnSink.push` | `runtime.zig:~1348` | Ignore (live turn does not render meta events) |

**RPC mode** (if/when added): forward as structured JSON, same as `JsonSink`.

Additionally, `tools.Event` union (`tools.zig:~272`) may need a `.todo_update` variant if the event flows through the tool sink path. Alternative: emit directly via `self.pushModeEv()` from the tool handler (as shown in the handler code above), bypassing `tools.Event` entirely. This is acceptable because the todo tool's output IS the tool result; the `ModeEv` is a side-channel notification for rendering.

### Session Replay

Todo tool calls are persisted in session JSONL like any other tool call (`tool_call` + `tool_result` events).
On session replay, the stored result is used — the tool is NOT re-executed.
The `ModeEv.todo_update` side-channel does NOT fire during replay, so replayed sessions will not show inline todo blocks in the transcript. This is acceptable because:
- Task state is authoritative on disk (`.pz/tasks/`), not in the session
- The model can call `todo(action=read)` to get current state on resume

### Context Injection

The model needs to know about existing tasks at session start and after mutations.

**Injection point:** Add a task summary part in `buildReqMsgs` (`loop.zig:~865`) as an additional system message part, incrementing `sys_part_ct`. This keeps it separate from the cached system prompt (avoids invalidating prompt cache on every task change).

**Format:** Compact markdown, titles and status only (never bodies — bodies are untrusted model-written content, per P27 prompt injection concerns):

```markdown
## Current Tasks
- [active] fix-uaf-3a7b: Fix UAF in compaction
- [open] add-grep-c1f2: Add grep tool
- [done] setup-ci-8e4d: Setup CI pipeline
```

**Refresh:** Regenerated on every turn (cheap — reads disk, formats ~100 bytes per task). Stale context from user `/todo` commands is automatically refreshed on the next model turn.

**Token budget:** Cap at 50 tasks in the summary. If >50, show only `active` and `open` tasks (skip `done`).

### Concurrency

All task mutations (from model tool AND `/todo` commands) are serialized through the runtime event loop. The `/todo` handler runs on the main thread; the model tool handler runs on the tool dispatch thread. Both go through `TaskStore.open()` which opens the directory — no in-memory state to race on.

File-level atomicity for `complete()` (the only operation that moves files):
1. Write updated frontmatter to temp file in `.pz/tasks/`
2. Rename temp to `archive/{id}.md` (atomic on same filesystem)
3. Delete original

If step 3 fails, the archive copy is canonical.

### Migration from dots

One-time CLI subcommand: `pz todo import` (add to `Cmd` enum and dispatch in `runtime.zig`, plus `args.zig` for CLI parsing).

1. Scan `.dots/` for markdown files with frontmatter.
2. Parse each into a `Task` (map dots status: `open`→`open`, `active`→`active`, `closed`→`done`).
3. **Validate imported content:** apply same sanitization as `TaskStore.create()` — size limits on body, slug validation on IDs, frontmatter delimiter escaping. Imported content is untrusted.
4. Write to `.pz/tasks/`.
5. Preserve parent-child relationships and blocking dependencies.
6. Skip malformed files with a warning; map unknown statuses to `open`.

After migration, `.dots/` can be removed. No backward compatibility layer.

### Migration from PLAN.md

Manual. `PLAN.md` remains as strategic overview. User or agent creates tasks from plan items via `/todo add` or the model's `todo` tool. Plan items reference task IDs:

```markdown
### P0-1: UAF in compaction
Task: `fix-uaf-3a7b` — done ✔
```

### Relationship to PLAN.md

- `PLAN.md` = what and why (phases, goals, acceptance criteria, strategic ordering)
- `.pz/tasks/` = who, when, how far (status, priority, implementation notes, blocking deps)
- Plan items may reference task IDs; tasks may reference plan item labels in their body
- Neither generates the other — they are maintained independently

## Implementation Order

1. **`src/core/tasks/format.zig`** — frontmatter parser/serializer
   - Deps: none
   - Tests: zcheck roundtrip property (`parse(serialize(task)) == task`), ohsnap for parse output, edge cases (special chars in title, empty body, max body size)

2. **`src/core/tasks/store.zig`** — disk I/O (create, read, list, archive, resolve, dependency graph)
   - Deps: step 1
   - Tests: ohsnap for list output, temp dir tests for CRUD, collision retry, ambiguous short-ID error, slug sanitization (path traversal attempts)

3. **`src/core/tasks/mod.zig`** — public API surface, re-exports
   - Deps: steps 1-2

4. **`src/core/tools.zig` + `src/core/tools/builtin.zig`** — add `todo` to `Kind` enum, `TodoArgs` to `Call.Args`, `mask_todo`, bump arrays to `[11]`, `schema_json`, `maskForName`, `rebuildEntries`, `activeEntries`
   - Deps: step 3
   - Tests: registry test (tool count = 11), mask round-trip
   - **Audit all exhaustive switches on `Kind`/`Args`** across codebase

5. **`src/core/tools/todo.zig`** — tool handler matching `(self: *Runtime, call: tools.Call, sink: tools.Sink) -> Result` pattern
   - Deps: steps 3-4
   - Tests: ohsnap for tool results, mock TaskStore via temp dir, per-item error collection, destructive flag behavior

6. **Event plumbing** — `TodoUpdate` in `ModeEv` (`loop.zig`), explicit handling in all 4 sinks (`runtime.zig`: TuiSink, PrintSink, JsonSink, LiveTurnSink)
   - Deps: step 5
   - Tests: ohsnap for print/json output format

7. **`src/modes/tui/transcript.zig`** — add `.todo_update` to `Kind` enum, `TodoUpdateBlock` rendering
   - Deps: step 6
   - Tests: ohsnap for rendered cells

8. **`src/modes/tui/overlay.zig`** — add `.todo` to `overlay.Kind`, `TodoOverlay` struct
   - Deps: step 7
   - Tests: ohsnap for rendered frame

9. **`/todo` slash command** — `Cmd` enum + `cmd_map` + dispatch in `runtime.zig`, entry in `cmdpicker.zig`
   - Deps: steps 7-8
   - Tests: integration test with mock harness

10. **Context injection** — task summary part in `buildReqMsgs` (`loop.zig`), titles+status only, 50-task cap
    - Deps: step 3 (only needs TaskStore)
    - Tests: ohsnap for injected prompt content, verify bodies are never included

11. **`pz todo import`** — dots migration CLI subcommand in `args.zig` + `runtime.zig`
    - Deps: step 3
    - Tests: ohsnap for migrated output, malformed input handling

## File Inventory

New files:
- `docs/PZ-TODO.md` (this document)
- `src/core/tasks/mod.zig`
- `src/core/tasks/store.zig`
- `src/core/tasks/format.zig`
- `src/core/tools/todo.zig`

Modified files:
- `src/core/tools.zig` — add `.todo` to `Kind`, `TodoArgs` struct, `todo: TodoArgs` in `Args` union
- `src/core/tools/builtin.zig` — `mask_todo = 1 << 10`, bump `[10]` → `[11]`, `mask_all` unchanged (todo is opt-in), `schema_json`, `maskForName`, `rebuildEntries`, `activeEntries`
- `src/core/loop.zig` — `todo_update: TodoUpdate` in `ModeEv`, `TodoUpdate`/`TaskSnapshot` structs
- `src/app/runtime.zig` — all 4 sink `.todo_update` arms, `Cmd.todo` + `cmd_map` + dispatch, `pz todo import` subcommand, context injection
- `src/modes/tui/transcript.zig` — `.todo_update` in `Kind` enum, todo block rendering
- `src/modes/tui/overlay.zig` — `.todo` in `overlay.Kind`, `TodoOverlay` struct
- `src/modes/tui/cmdpicker.zig` — add `/todo` entry to `cmds` array
- `src/app/args.zig` — `pz todo import` CLI subcommand parsing
- `PLAN.md` — add SK8 item in Phase 6
