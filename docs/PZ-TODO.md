# PZ-TODO: Built-in Task Management

Replaces external `dots` CLI. Tasks are the executable work-tracking layer.
Add as `SK8` in the plan file.

## Goals

1. Model proposes task updates via tool call; approval gate on mutations; user manages directly via `/todo`.
2. Tasks persist as markdown in `.pz/tasks/` for durability and implementation detail.
3. All modes (TUI, print, JSON, RPC) handle todo events. TUI gets inline transcript blocks + `/todo` overlay.
4. No external dependencies — all logic lives in pz.

## Prior Art

### Codex (OpenAI)
- Model calls `update_plan` tool with full plan state each time (replace, not patch).
- CLI rendering: `✓` green, `→` cyan, `•` dim. TUI: `✔` strikethrough+dim, `□` cyan bold, `□` dim.
- Plan updates as `HistoryCell` blocks in chat transcript.

### dots (joelreymont/dots)
- Zig CLI, markdown frontmatter files in `.dots/`, archive subdir for closed items.
- Features: parent-child hierarchy, blocking deps, slug-based IDs, search, tree view.
- Commands: `add`, `ls`, `on`, `off`, `rm`, `show`, `tree`, `find`, `ready`.

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

Three stored states: `open`, `active`, `done`.
`blocked` is computed at display time from dependency graph (same as dots).
No `cancelled` — delete the file instead.

### ID Generation

`{slug}-{hex8}` where slug is kebab-case from title (max 20 chars), hex8 is 4 random bytes hex-encoded (8 hex chars).

**Slug sanitization (security-critical):**
- Characters restricted to `[a-z0-9-]` only; all others stripped
- Leading dots and path separators (`/`, `\`) forbidden
- Final filename validated as single path component (no `/`, `\`, `.`, `..`)
- On collision (file exists), retry with new random bytes (max 3 retries, then error)

**Short-ID resolution:** unique prefix match. Ambiguous prefix (matches >1 task) returns error listing all matches.

### Task File Format

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
All query methods read from disk on every call (no in-memory cache). Correct for small task counts and avoids stale-state bugs.

### Security

#### Policy bypass

The todo tool writes to `.pz/tasks/` inside the protected `.pz/` directory.
Intentional, scoped bypass of `path_guard`:
- `TaskStore` does NOT go through `path_guard.createFile()`
- Writes only within `.pz/tasks/` via its own `fs.Dir` handle
- Slug sanitizer prevents path traversal out of this directory
- Acceptable because: (a) narrowly scoped, (b) content validated, (c) gated by approval

#### Approval gate

The `todo` tool is marked `destructive = true` on the `tools.Tool` entry (static flag). This means `read` actions also trigger the approval gate. This is the correct tradeoff: the `destructive` flag is set at entry construction time in `rebuildEntries()` and cannot vary per-call. Marking non-destructive would leave mutations ungated.

After the first approval, the approval cache suppresses subsequent prompts for the session.

#### Content validation

- Title: max 80 chars, slug-safe subset validated
- Body: max 4KB, frontmatter delimiters escaped
- Status: closed enum, no arbitrary values
- Priority from model: `?i64` in `TodoArgs`, clamped to `u4` (0-9) before storage
- IDs from model: validated via `resolve()` which only matches existing files
- Model cannot delete tasks — deletion is user-only via `/todo rm`

#### Tool mask inheritance

`mask_todo` IS included in `mask_all` (so `init()` at `builtin.zig:173` does not strip it via `opts.tool_mask & mask_all`). Child agent inheritance is controlled at spawn time: the `agent` tool explicitly strips `mask_todo` from the child's mask. Background agents (read-only by policy) cannot mutate tasks because the approval gate blocks them.

### Model Tool: `todo`

Added to `builtin.zig`:
- `mask_todo: u16 = 1 << 10` — included in `mask_all`
- Bump `entries: [11]tools.Entry` and `selected: [11]tools.Entry` (from `[10]`)
- Also bump `PolicyToolRegistry` arrays in `runtime.zig:~251`: `ctxs: [11]` and `entries: [11]`
- Add `mask_todo` check in `activeEntries()` (and update fast-path: `mask_all` equality still works since `mask_todo` is in `mask_all`)
- Add `"todo"` to `maskForName` static map
- Add 11th entry in `rebuildEntries()`
- Uses `schema_json` (raw JSON schema), same pattern as `ask` tool
- `destructive = true` on the entry spec
- Note: `web` has a `Kind` variant but no builtin entry; array size `[11]` counts registered entries, not `Kind` variants (12 with `todo`)

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
        priority: ?i64,       // clamped to u4(0-9) by handler
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

**Every exhaustive switch on `Kind` or `Args` must be updated.** Known sites:
- `loop.zig:~1173` (`noteApproval` — needs_approval)
- `loop.zig:~1197` (`approvalSummaryAlloc`)
- `loop.zig:~1256` (`parseCallArgs`)
- `runtime.zig:~209` (`toolPolicyPath`)
- `runtime.zig:~342` (`toolAuditInfo`)
- `runtime.zig:~1671` (`auditResKind`)
- `runtime.zig:~1680` (`auditResOp`)
- Plus any switches in session serialization and test infrastructure. Grep for `switch.*Kind` and `switch.*Args` across codebase.

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

**action=read**: Returns task list as markdown table (titles + status only, NOT bodies).
**action=update**: Patches task statuses. Each item processed independently — one bad ID does not abort the batch. Result shows per-item success/failure.
**action=add**: Creates new tasks with validated title/body. Model cannot set `id` (auto-generated).

### Tool Handler: `src/core/tools/todo.zig`

The handler runs inside `builtin.Runtime` which has NO access to `ModeEv` or mode sinks. Therefore the handler does NOT emit `ModeEv` events. Instead, `app/runtime.zig` emits the `ModeEv.todo_update` event post-tool-result when it detects a completed `todo` tool call. This follows the principle that tool handlers return results, and the runtime routes events.

Handler signature matches existing pattern:

```zig
pub fn runTodo(self: *@This(), call: tools.Call, writer: tools.Sink) !tools.Result {
    const args = call.args.todo;
    var store = try TaskStore.open(self.alloc);
    defer store.close();

    switch (args.action) {
        .read => {
            const tasks = try store.list(null);
            return .{ .output = formatSummary(self.alloc, tasks) };
        },
        .update => {
            var errs = std.ArrayList(u8).init(self.alloc);
            for (args.tasks orelse &.{}) |item| {
                const raw_id = item.id orelse {
                    try errs.appendSlice("error: missing id for update item\n");
                    continue;
                };
                const id = store.resolve(raw_id) catch |e| {
                    try appendErr(&errs, "resolve", raw_id, e);
                    continue;
                };
                const status = parseStatus(item.status) catch |e| {
                    try appendErr(&errs, "status", raw_id, e);
                    continue;
                };
                switch (status) {
                    .active => store.activate(id) catch |e| {
                        try appendErr(&errs, "activate", raw_id, e);
                    },
                    .done => store.complete(id) catch |e| {
                        try appendErr(&errs, "complete", raw_id, e);
                    },
                    .open => store.reopen(id) catch |e| {
                        try appendErr(&errs, "reopen", raw_id, e);
                    },
                }
            }
            const tasks = try store.list(null);
            var out = formatSummary(self.alloc, tasks);
            if (errs.items.len > 0) out = try appendErrors(self.alloc, out, errs.items);
            return .{ .output = out };
        },
        .add => {
            for (args.tasks orelse &.{}) |item| {
                const title = item.title orelse continue;
                const prio: ?u4 = if (item.priority) |p|
                    std.math.cast(u4, std.math.clamp(p, 0, 9))
                else null;
                _ = try store.create(title, .{
                    .priority = prio,
                    .parent = item.parent,
                    .body = item.body,
                });
            }
            const tasks = try store.list(null);
            return .{ .output = formatSummary(self.alloc, tasks) };
        },
    }
}
```

**Post-tool-result event emission** (in `app/runtime.zig`, tool result handling path):
After a `todo` tool call completes, the runtime checks `call.kind == .todo` and, if the action was `update` or `add`, reads the current task state and pushes `ModeEv.todo_update` to the mode sink. This keeps the tool handler pure (no sink coupling) and matches how other post-tool side effects are handled.

### User Command: `/todo`

Registered as a built-in slash command in `runtime.zig`, NOT in skill.zig:
- Add `.todo` to `Cmd` enum at `runtime.zig:~4251`
- Add `"todo"` to `cmd_map` StaticStringMap at `runtime.zig:~4252`
- Add `.todo` case in the dispatch switch at `runtime.zig:~4298`
- Add `{ .name = "todo", .desc = "Manage tasks" }` to `cmds` array in `cmdpicker.zig:~16` (maintain alphabetical sort — insert between `"tree"` and `"upgrade"`)

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

| Status   | Marker | Text Style |
|----------|--------|------------|
| `done`   | `✔`    | `crossed_out` + `dim` |
| `active` | `□`    | `cyan` + `bold` |
| `open`   | `□`    | `dim` |

Implementation in `src/modes/tui/transcript.zig`: add `.todo_update` to the `Kind` enum (at line ~19, alongside `text, user, thinking, tool, err, meta, image`). Block holds `TaskSnapshot` slice + optional note.

#### `/todo` Overlay

Add `.todo` to `overlay.Kind` enum (at line ~11). Audit all `overlay.Kind` switches for exhaustiveness.

Create a separate `TodoOverlay` struct (not the generic `Overlay`, which only supports `[]const []const u8` rows). Shows:
- Tasks grouped by parent (tree view), max depth 3
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

**All four mode sinks must handle `.todo_update` explicitly.** Three of the four sinks (`PrintSink`, `TuiSink`, `LiveTurnSink`) currently use `else => {}`. As part of Step 6, convert these to exhaustive switches (or add explicit `.todo_update` arms before the `else`):

| Sink | File:line | Handling |
|------|-----------|----------|
| `TuiSink.push` | `runtime.zig:~452` | Push `TodoUpdateBlock` to transcript; refresh overlay if open |
| `PrintSink.push` | `runtime.zig:~422` | Print text: `✓`/`→`/`•` markers per task |
| `JsonSink.push` | `runtime.zig:~1536` | Emit `{"type":"todo_update","note":...,"tasks":[...]}` (already exhaustive — will get compile error if missing) |
| `LiveTurnSink.push` | `runtime.zig:~1348` | Ignore (add explicit `.todo_update => {}` arm) |

**RPC mode** (if/when added): forward as structured JSON, same as `JsonSink`.

The todo handler does NOT emit `ModeEv` — the runtime does post-tool-result (see Tool Handler section). No changes needed to `tools.Event` union.

### Session Replay

Todo tool calls are persisted in session JSONL like any other tool call.
On replay, the stored result is used — the tool is NOT re-executed.
The `ModeEv.todo_update` side-channel does NOT fire during replay. Task state is authoritative on disk, not in the session. Model can call `todo(action=read)` to get current state on resume.

### Context Injection

**Injection point:** Add a task summary as the LAST system message part in `buildReqMsgs` (`loop.zig:~865`), incrementing `sys_part_ct` from its current computed value. Ordering: `[pz_identity, system_prompt, task_summary]`. Task summary is last so changes to it do not invalidate the cached prefix (pz_identity + system_prompt).

Note: `sys_part_ct` is currently `1 + (if system_prompt != null then 1 else 0)`. Must change to `1 + (if system_prompt != null then 1 else 0) + (if task_summary != null then 1 else 0)`. The parts array allocation at `live_len + sys_part_ct` must account for this. If `TaskStore.open()` fails (no `.pz/` directory), skip the task summary part gracefully — do not fail the request build.

**Format:** Compact markdown, titles and status only (never bodies — bodies are untrusted model-written content, per P27 prompt injection concerns):

```markdown
## Current Tasks
- [active] fix-uaf-3a7b: Fix UAF in compaction
- [open] add-grep-c1f2: Add grep tool
- [done] setup-ci-8e4d: Setup CI pipeline
```

**Refresh:** Regenerated on every turn (cheap — reads disk, formats ~100 bytes per task).
**Token budget:** Cap at 50 tasks. If >50, show only `active` and `open` (skip `done`).

### Concurrency

**Single-writer model.** Only the orchestrator (main session model + user `/todo`) mutates tasks. Subagents are workers — they do work and report results; the orchestrator evaluates and checks tasks off. Subagents do NOT get `mask_todo` (already stripped at spawn).

This eliminates all contention: one writer, many readers. No locking needed.

File-level atomicity for `complete()`:
1. Write updated frontmatter to temp file in `.pz/tasks/`
2. Rename temp to `archive/{id}.md` (atomic on same filesystem)
3. Delete original. If step 3 fails, archive copy is canonical.

### Review Integration

Task files ARE plan items. The review-plan skill takes a path — file or directory:
- File: reviews that file as a plan (existing behavior)
- Directory: globs `*.md`, reviews each file as a plan item

Each review agent gets a subset of task files — natural parallelism. Findings reference task IDs directly. Orchestrator applies via `todo(action=update)`.

No aggregation, temp files, or special review commands needed. One-line change in the review skill prompt to accept directory paths.

### Migration from dots

One-time CLI subcommand: `pz todo import` (add to `Cmd` enum and dispatch in `runtime.zig`, plus `args.zig` for CLI parsing).

1. Scan `.dots/` for markdown files with frontmatter.
2. Parse each into `Task` (map: `open`→`open`, `active`→`active`, `closed`→`done`; unknown→`open`).
3. **Validate imported content:** same sanitization as `TaskStore.create()` — size limits on body, slug validation on IDs, frontmatter escaping. Imported content is untrusted. Skip malformed files with warning.
4. Write to `.pz/tasks/`, preserving parent-child and blocking deps.

After migration, `.dots/` can be removed. No backward compatibility.

## Implementation Order

1. **`src/core/tasks/format.zig`** — frontmatter parser/serializer
   - Deps: none
   - Tests: zcheck roundtrip property (`parse(serialize(task)) == task`), ohsnap for parse output, edge cases (special chars in title, empty body, max body size, `---` in body)

2. **`src/core/tasks/store.zig`** — disk I/O (create, read, list, archive, resolve, dependency graph)
   - Deps: step 1
   - Tests: ohsnap for list output, temp dir CRUD, collision retry, ambiguous short-ID error, slug sanitization (path traversal attempts), priority clamping

3. **`src/core/tasks/mod.zig`** — public API surface, re-exports
   - Deps: steps 1-2

4. **`src/core/tools.zig` + `src/core/tools/builtin.zig`** — add `.todo` to `Kind`, `TodoArgs` to `Args`, `mask_todo` (in `mask_all`), bump `[10]`→`[11]`, `schema_json`, `maskForName`, `rebuildEntries`, `activeEntries`, `destructive=true`
   - Also: bump `PolicyToolRegistry` arrays in `runtime.zig:~251` from `[10]` to `[11]`
   - Deps: step 3
   - Tests: registry test (tool count = 11), mask round-trip
   - **Grep `switch.*Kind` and `switch.*Args`** — update all 7+ exhaustive switch sites

5. **`src/core/tools/todo.zig`** — tool handler `(self, Call, Sink) -> !Result` pattern
   - Deps: steps 3-4
   - Tests: ohsnap for tool results, temp dir TaskStore, per-item error collection, priority clamping

6. **Event plumbing** — `TodoUpdate` in `ModeEv` (`loop.zig`), post-tool-result emission in `runtime.zig`, explicit `.todo_update` arms in all 4 sinks
   - Deps: step 5
   - Tests: ohsnap for print/json output format

7. **`src/modes/tui/transcript.zig`** — add `.todo_update` to `Kind` enum, `TodoUpdateBlock` rendering
   - Deps: step 6
   - Tests: ohsnap for rendered cells

8. **`src/modes/tui/overlay.zig`** — add `.todo` to `overlay.Kind`, `TodoOverlay` struct, audit Kind switches
   - Deps: step 7
   - Tests: ohsnap for rendered frame

9. **`/todo` slash command** — `Cmd.todo` + `cmd_map` + dispatch in `runtime.zig`, entry in `cmdpicker.zig` (sorted)
   - Deps: steps 7-8
   - Tests: integration test with mock harness

10. **Context injection** — task summary as last system part in `buildReqMsgs`, `sys_part_ct` arithmetic, graceful fallback if no `.pz/`
    - Deps: step 3
    - Tests: ohsnap for injected content, verify bodies never included, verify TaskStore failure doesn't break request

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
- `src/core/tools.zig` — `.todo` in `Kind`, `TodoArgs`, `todo: TodoArgs` in `Args`
- `src/core/tools/builtin.zig` — `mask_todo = 1 << 10` in `mask_all`, `[10]`→`[11]`, `schema_json`, `maskForName`, `rebuildEntries`, `activeEntries`, `destructive=true`
- `src/core/loop.zig` — `todo_update: TodoUpdate` in `ModeEv`, structs, all exhaustive `Kind`/`Args` switches
- `src/app/runtime.zig` — `PolicyToolRegistry` `[10]`→`[11]`, all 4 sink `.todo_update` arms, post-tool-result `ModeEv` emission, `Cmd.todo` + `cmd_map` + dispatch, `pz todo import`, all exhaustive `Kind`/`Args` switches
- `src/modes/tui/transcript.zig` — `.todo_update` in `Kind` enum, block rendering
- `src/modes/tui/overlay.zig` — `.todo` in `overlay.Kind`, `TodoOverlay` struct
- `src/modes/tui/cmdpicker.zig` — `/todo` entry in `cmds` (sorted)
- `src/app/args.zig` — `pz todo import` CLI subcommand parsing

## Design Decisions

- **Multi-file storage**: one file per task. Subagents read their assigned task file for context; orchestrator writes. No contention.
- **Single-writer concurrency**: orchestrator only. Subagents report results, don't manage state.
- **Review via directory**: review-plan skill generalized to accept a directory. Task files are self-contained plan items.
