# PZ-TODO: Built-in Task Management

Replaces external `dots` CLI. A task list is a single markdown file.
Add as `SK8` in the plan.

## Goals

1. Model proposes task updates via tool call; approval gate on mutations; user manages directly via `/todo`.
2. Tasks persist in a single markdown file (default: `.pz/tasks.md`).
3. All modes (TUI, print, JSON, RPC) handle todo events. TUI gets inline transcript blocks + `/todo` overlay.
4. No external dependencies — all logic lives in pz.

## Prior Art

### Codex (OpenAI)
- Model calls `update_plan` tool with full plan state each time (replace, not patch).
- CLI: `✓` green, `→` cyan, `•` dim. TUI: `✔` strikethrough+dim, `□` cyan bold, `□` dim.

### dots (joelreymont/dots)
- Zig CLI, one markdown file per task in `.dots/`, archive subdir for closed.
- Features: parent-child hierarchy, blocking deps, slug-based IDs, search, tree view.

---

## Storage

### Single file: `.pz/tasks.md`

One file holds all tasks. Each task is a `## ` section:

```markdown
## Fix UAF in compaction
id: fix-uaf-3a7b | status: active | priority: 1 | created: 2026-03-15

Do: prove/refute ReplayReader arena-dangle in multi-event compaction.
Files: `src/core/session/compact.zig`, `src/core/session/reader.zig`
Accept: allocator regression proves no dangling event data across next() calls.

## Add grep tool
id: add-grep-c1f2 | status: open | priority: 2 | created: 2026-03-15

Add grep tool with ripgrep backend.

## Setup CI pipeline
id: setup-ci-8e4d | status: done | priority: 2 | created: 2026-03-14 | closed: 2026-03-15

Configure GitHub Actions for CI.
```

The file IS the plan. The review skill reads it directly.
Any file in this format works — `todo(file="./sprint-3.md")`, `/todo --file ./sprint-3.md`.

### Section format

```
## {title}
id: {id} | status: {status} | priority: {N} | created: {ISO} [| closed: {ISO}] [| parent: {id}] [| blocks: {id}, {id}]

{body — free-form markdown, max 4KB per task}
```

- **Line 1** (`## `): title, max 80 chars.
- **Line 2** (metadata): pipe-delimited `key: value`. Parsed by splitting on ` | ` then first `: ` only.
- **Lines 3+**: body. Free-form markdown.
- Sections separated by blank lines.
- **Section boundary rule**: a `## ` line is a section start ONLY if the next non-empty line contains `id:`. This prevents `## ` in body text from being misparse as a new task.

### Metadata fields

| Field     | Type       | Required | Description |
|-----------|------------|----------|-------------|
| `id`      | string     | yes      | Unique slug-hex ID |
| `status`  | enum       | yes      | `open`, `active`, `done` |
| `priority`| int 0-9    | yes      | 0 = highest, default 2 |
| `created` | ISO 8601   | yes      | Creation timestamp |
| `closed`  | ISO 8601   | no       | Completion timestamp |
| `parent`  | string     | no       | Parent task ID |
| `blocks`  | string csv | no       | IDs this task blocks |

Title comes from the `## ` heading. Values must NOT contain ` | ` (enforced on write, error on parse).

### Status model

Three stored states: `open`, `active`, `done`.
`blocked` computed from dependency graph at display time.
No `cancelled` — remove the section.

### ID generation

`{slug}-{hex8}`: kebab-case from title (max 20 chars) + 4 random bytes hex-encoded.
Slug chars: `[a-z0-9-]` only. All other chars stripped. No leading dots or path separators.
Short-ID resolution: unique prefix match across all tasks in file. Ambiguous → error listing matches.
Collision: retry with new random (max 3).

---

## Module: `src/core/tasks/`

```
src/core/tasks/
  mod.zig       # TaskList, Task, Status, re-exports
  parse.zig     # parse task file → []Task
  render.zig    # []Task → markdown
```

### `Task` struct

```zig
pub const Status = enum { open, active, done };

pub const Task = struct {
    id: []const u8,
    title: []const u8,
    status: Status,
    priority: u4,
    parent: ?[]const u8,
    blocks: []const []const u8,
    created: []const u8,
    closed: ?[]const u8,
    body: []const u8,
};
```

### `TaskList` API

```zig
pub const TaskList = struct {
    alloc: Allocator,
    tasks: []Task,
    path: []const u8,

    /// Load task file. Creates if missing. Default: ".pz/tasks.md".
    pub fn open(alloc: Allocator, path: []const u8) !TaskList;
    pub fn deinit(self: *TaskList) void;

    // Mutations (each calls flush — atomic rewrite)
    pub fn add(self: *TaskList, title: []const u8, opts: AddOpts) !*Task;
    pub fn remove(self: *TaskList, id: []const u8) !void;
    pub fn activate(self: *TaskList, id: []const u8) !void;
    pub fn complete(self: *TaskList, id: []const u8) !void;
    pub fn reopen(self: *TaskList, id: []const u8) !void;

    // Lifecycle
    pub fn clear(self: *TaskList) !usize;   // remove done tasks (skip if parent of non-done; cyclic done groups ARE clearable), return count
    pub fn reset(self: *TaskList) !void;     // remove all tasks (writes backup to .pz/tasks.md.bak first)

    // Queries — returned slices are borrowed from TaskList, invalid after deinit()
    pub fn get(self: *TaskList, id: []const u8) ?*Task;
    pub fn resolve(self: *TaskList, short_id: []const u8) !*Task;  // min 4 chars
    pub fn filter(self: *TaskList, status: ?Status) []Task;
    pub fn ready(self: *TaskList) []Task;
    pub fn isBlocked(self: *TaskList, id: []const u8) bool;

    // Persistence
    fn flush(self: *TaskList) !void;  // atomic: write {path}.tmp, stat-check mtime, rename
};
```

Short-lived: open, mutate, close. Always reads fresh from disk.

---

## Security

### Policy bypass

Default `.pz/tasks.md` is inside protected `.pz/`. Protection comes from policy rules (not path_guard). `toolPolicyPath` for `.todo` returns `"runtime/tool/todo"` (synthetic — like `ask`/`web`). The handler bypasses policy's `.pz/` self-protection by writing directly, acceptable because: (a) narrowly scoped to one file, (b) content validated, (c) gated by approval.

Non-default files: handler MUST call `path_guard` AND `isProtectedPath()` to validate the path BEFORE `TaskList.open()`. Both must pass. Reject any `file` path ending in `.bak` (prevents reading backup files from `/todo reset`).

### Approval gate

`destructive = true` on `tools.Tool` entry (static). All actions including `read` trigger approval on first use. Cache suppresses repeats.

### Content validation

- Title: max 80 chars, must not contain `\n`, `\r`, ` | `, `#`, or `</` (prevents metadata/section/XML injection)
- Body: max 4KB per task, lines matching `^## ` escaped on write (`\## `), unescaped on read
- Status: closed enum
- Priority: `?i64` clamped to `u4` (0-9)
- IDs: validated via `resolve()`, minimum 4 chars to prevent overly broad prefix matches
- Note: max 256 bytes
- Model cannot delete tasks — user-only via `/todo rm`
- Max 200 tasks per file. `add()` errors when exceeded.

### Tool mask

`mask_todo` in `mask_all`. Child agents get it stripped at spawn — orchestrator-only writes. Note: the agent tool is currently unimplemented (`agent.zig` returns "unavailable"). The mask stripping must be added when the agent tool is wired up. `AgentArgs` will need a `tool_mask` field or the spawn protocol must carry the mask. Blocked on agent tool implementation — mark as dependency.

---

## Model Tool: `todo`

### Registration in `builtin.zig`

- `mask_todo: u16 = 1 << 10` in `mask_all`
- Bump `entries`/`selected` `[10]` → `[11]`
- Bump `PolicyToolRegistry` in `runtime.zig` (`PolicyToolRegistry` struct): `ctxs`/`entries` `[10]` → `[11]`
- Add to `activeEntries()`, `maskForName`, `rebuildEntries()`
- `schema_json` pattern (like `ask`)
- `destructive = true`
- Note: `web` has Kind variant but no entry; `[11]` = registered entries

### Type changes in `tools.zig`

```zig
pub const Kind = enum { read, write, bash, edit, grep, find, ls, agent, web, ask, skill, todo };

pub const TodoArgs = struct {
    action: enum { read, update, add },
    file: ?[]const u8,         // default: ".pz/tasks.md"
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

pub const Args = union(Kind) {
    // ... existing ...
    todo: TodoArgs,
};
```

**Exhaustive switch sites** (add `.todo` arm). Use function/type names as anchors — line numbers are approximate:
- `loop.zig` `noteApproval` fn
- `loop.zig` `approvalSummaryAlloc` fn — **RUNTIME CRASH** if missed: `else => unreachable`. Must add `.todo` arm: `"todo {action} {file}"`.
- `runtime.zig` `approvalSummaryFromKeyAlloc` fn — has `else =>` that produces wrong output. Must add `.todo` arm.
- `loop.zig` `parseCallArgs` fn — must handle `TodoArgs` nested `[]const TaskItem` JSON deserialization
- `runtime.zig` `toolPolicyPath` fn — return `"runtime/tool/todo"` (synthetic)
- `runtime.zig` `toolAuditInfo` fn — `.todo => .{ .res_kind = .cfg, .op = @tagName(action), .target = file, .argv = "todo" }`
- `runtime.zig` `auditResKind` fn
- `runtime.zig` `auditResOp` fn
- Plus session serialization (`session/schema.zig`), test infra (`test/tool_snap.zig`), and any others. Grep `switch.*Kind` and `switch.*Args` for full list (expect 11+).
- Distinguish: exhaustive switches (compile error if missed — safe) vs `else => unreachable` (runtime crash — dangerous) vs `else => {}` (silent skip).

### Tool schema (`schema_json`)

```json
{
  "name": "todo",
  "description": "Manage a task list. 'read' to see tasks, 'update' to change statuses, 'add' to create.",
  "parameters": {
    "action": { "type": "string", "enum": ["read", "update", "add"], "required": true },
    "file": { "type": "string", "description": "Task file (default: .pz/tasks.md)" },
    "tasks": {
      "type": "array",
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
    "note": { "type": "string", "description": "Explanation of what changed" }
  }
}
```

**action=read**: titles + status (no bodies). Warn if empty tasks array on update.
**action=update**: patch statuses, per-item errors.
**action=add**: create tasks, model cannot set `id`.

---

## Tool Handler: `src/core/tools/todo.zig`

Runs in `builtin.Runtime` — NO access to `ModeEv`. Returns `tools.Result` (with `call_id`, timestamps, `out` slice, `final`). Reference `runAsk` in `builtin.zig` for the correct pattern — the pseudocode below is simplified.

`app/runtime.zig` emits `ModeEv.todo_update` post-tool-result. This is a **new pattern** — no existing post-tool ModeEv emission exists. Add the check in the tool-result handling path (after `execTool` returns in `loop.zig`), not in the handler.

**PrintSink note:** `PrintSink.push()` delegates to `Formatter.push()` which only knows `providers.Event`. The `.todo_update` arm must be handled BEFORE the formatter delegation, directly in `PrintSink.push()`.

Handler pseudocode (simplified — actual must construct full `tools.Result`):

```
runTodo(self, call, sink):
  args = call.args.todo
  file = args.file orelse ".pz/tasks.md"
  if file != default: validate via path_guard + isProtectedPath
  list = TaskList.open(alloc, file)
  defer list.deinit()

  switch args.action:
    .read => return result(formatSummary(list.tasks))
    .update =>
      items = args.tasks orelse return result("error: no tasks for update")
      errs = []
      for items: resolve id, parse status, call activate/complete/reopen
        collect per-item errors (missing id, bad status, transition failure)
      return result(formatSummary(list.tasks) + errs)
    .add =>
      for items: validate title (error if missing, not skip), clamp priority, add
      return result(formatSummary(list.tasks) + errs)
```

---

## `/todo` Command

Built-in slash command in `runtime.zig`:
- `.todo` in `Cmd` enum
- `"todo"` in `cmd_map` StaticStringMap
- `.todo` case in dispatch switch
- `{ .name = "todo", .desc = "Manage tasks" }` in `cmdpicker.zig` (list is not perfectly sorted — `bg` at end breaks order. Append `todo` after `tree`)

```
/todo                        — show task list (overlay)
/todo --file ./sprint-3.md   — different task file
/todo add "title"            — create task
/todo on <id>                — activate
/todo off <id>               — complete
/todo rm <id>                — delete section
/todo tree                   — hierarchy view
/todo clear                  — remove done tasks (skips parents of non-done)
/todo reset                  — empty file (writes .bak first)
```

No auto-deletion when all done. Done tasks stay as context until `/todo clear` or `/todo reset`.

---

## TUI Rendering

### Inline transcript block

On `ModeEv.todo_update`:

```
• Updated Tasks
  └ ✔ ̶F̶i̶x̶ ̶U̶A̶F̶          (strikethrough + dim)
  └ □ Add grep tool   (cyan bold)
  └ □ Write export    (dim)
```

| Status | Marker | Style |
|--------|--------|-------|
| `done` | `✔` | `crossed_out` + `dim` |
| `active` | `□` | `cyan` + `bold` |
| `open` | `□` | `dim` |

Add `.todo_update` to transcript `Kind` enum in `transcript.zig`.

### `/todo` overlay

Add `.todo` to `overlay.Kind` enum in `overlay.zig`. Separate `TodoOverlay` struct. Tree view (max depth 3), status markers, priority, blocked indicator. Scrollable, ESC dismisses.

---

## Event Plumbing

New `ModeEv` variant in `loop.zig` (`ModeEv` union):

```zig
pub const ModeEv = union(enum) {
    // ... existing ...
    todo_update: TodoUpdate,
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

All 4 sinks need explicit `.todo_update` arm (3 use `else => {}`):

| Sink | Handling |
|------|----------|
| `TuiSink` | Push block to transcript; refresh overlay |
| `PrintSink` | Print `✓`/`→`/`•` per task |
| `JsonSink` | `{"type":"todo_update",...}` (already exhaustive) |
| `LiveTurnSink` | `.todo_update => {}` |

Handler does NOT emit ModeEv — runtime does post-tool-result.

---

## Session, Context, Concurrency

**Session replay:** stored result used, tool not re-executed. `ModeEv` doesn't fire on replay. Task state authoritative in file.

**Context injection:** task summary as LAST system part in `buildReqMsgs` (`loop.zig` `buildReqMsgs` fn). Order: `[pz_identity, system_prompt, task_summary]`. `sys_part_ct` adds `+ (task_summary ? 1 : 0)`. The `loop.zig` `Opts` struct needs a `task_file` field to thread the path. If `TaskList.open()` fails with file-not-found, omit (no tasks yet). If other error, log warning to mode sink (not silent skip). Format: titles + status only, wrapped with `wrapUntrustedNamed(alloc, "task-list", summary)` to prevent cross-session prompt injection. Cap 50 tasks; >50 filter done first, then cap by priority.

**Concurrency:** single-writer. Orchestrator only. Subagents work and report; orchestrator checks off. `mask_todo` stripped from child agents. File atomicity via write-tmp-rename (tmp in same dir as target). All `/todo` commands and model tool calls serialized through event loop. Tool calls within a single model turn are dispatched sequentially by the agent loop — no concurrent `todo` execution possible.

**Concurrent modification detection:** `flush()` stats the file at open time (mtime + size) and re-stats before rename. If changed externally between open and flush, return error instead of silently overwriting.

---

## Migration from dots

CLI subcommand `pz todo import`:

1. Scan `.dots/` for frontmatter markdown files
2. Map status: `open`→`open`, `active`→`active`, `closed`→`done`, unknown→`open`
3. Validate: same sanitization as `TaskList.add()`. Skip malformed with warning.
4. Append as sections to `.pz/tasks.md`, preserving parent/blocks

## Review Integration

The task file IS a plan. Point the review-plan skill at `.pz/tasks.md` (or any task-format file). All 6 review agents read the same file — they partition by concern (security, completeness, feasibility), not by task. No aggregation needed.

---

## Implementation Order

1. **`src/core/tasks/parse.zig`** — parse `## ` sections → `[]Task` (two-line lookahead: `## ` + `id:`)
   - Deps: none
   - Tests: zcheck roundtrip (`render(parse(f)) == f`), ohsnap parse output, edge cases (`## ` in body, pipe in value, empty file, malformed metadata)

2. **`src/core/tasks/render.zig`** — `[]Task` → markdown sections
   - Deps: step 1
   - Tests: ohsnap output, roundtrip with parse

3. **`src/core/tasks/mod.zig`** — `TaskList` API, clear/reset
   - Deps: steps 1-2
   - Tests: temp file CRUD, ID collision retry, short-ID ambiguity, slug sanitization, priority clamp, clear skips parents, reset writes backup

4. **`tools.zig` + `builtin.zig`** — `.todo` Kind, `TodoArgs`, `mask_todo` in `mask_all`, `[11]`, `schema_json`, `destructive=true`
   - Also: `PolicyToolRegistry` `[11]` in `runtime.zig`
   - Deps: step 3
   - Tests: registry (count=11), mask roundtrip, ohsnap `parseCallArgs(.todo, ...)` with read/update/add payloads (null tasks, empty array, missing optionals), ohsnap `approvalSummaryAlloc(.todo, ...)`, `maskForName("todo") == mask_todo`, `activeEntries` with mask_todo set/unset
   - Grep all exhaustive `Kind`/`Args` switches (11+)

5. **`todo.zig`** — handler `(self, Call, Sink) -> !Result`, path_guard for non-default files
   - Deps: steps 3-4
   - Tests: ohsnap results, per-item errors, priority clamp, empty update error
   - Note: parsed `TodoArgs` fields are arena-scoped (`parse_arena`). Handler must copy any data it needs to outlive the arena. Follow `runAsk` pattern.

6. **Event plumbing** — `ModeEv.todo_update`, post-tool emission, 4 sink arms
   - Deps: step 5
   - Tests: ohsnap print/json output

7. **`transcript.zig`** — `.todo_update` Kind, block rendering
   - Deps: step 6
   - Tests: ohsnap cells

8. **`overlay.zig`** — `.todo` Kind, `TodoOverlay`
   - Deps: step 7
   - Tests: ohsnap frame

9. **`/todo` command** — `Cmd.todo`, `cmd_map`, dispatch, `cmdpicker`
   - Deps: steps 7-8
   - Tests: integration

10. **Context injection** — `buildReqMsgs`, `sys_part_ct`, warn on failure
    - Deps: step 3
    - Tests: ohsnap content, no bodies, failure logs warning

11. **`pz todo import`** — dots migration. Requires subcommand concept in `cli.zig` (not trivial — `args.zig` does not exist, current parser has no subcommands)
    - Deps: step 3
    - Tests: ohsnap migrated output, malformed input

---

## File Inventory

New:
- `src/core/tasks/mod.zig`
- `src/core/tasks/parse.zig`
- `src/core/tasks/render.zig`
- `src/core/tools/todo.zig`

Modified:
- `src/core/tools.zig` — `.todo` Kind, `TodoArgs`, `Args`
- `src/core/tools/builtin.zig` — `mask_todo`, `[11]`, `schema_json`, `destructive=true`
- `src/core/loop.zig` — `ModeEv.todo_update`, `Opts.task_file`, post-tool emission, exhaustive switches incl `approvalSummaryAlloc`
- `src/core.zig` — barrel import: `pub const tasks = @import("core/tasks/mod.zig")`
- `src/app/runtime.zig` — `PolicyToolRegistry[11]`, 4 sinks (PrintSink needs pre-Formatter arm), post-tool ModeEv emission, `Cmd.todo`, `toolPolicyPath` synthetic, `toolAuditInfo`
- `src/app/cli.zig` — `pz todo import` subcommand dispatch (needs subcommand concept — `args.zig` exists but has no subcommand infra)
- `src/core/session/schema.zig` — verify session deserialization handles new `.todo` Kind variant
- `src/test/tool_snap.zig` — test infra may have Kind switches
- `src/modes/tui/transcript.zig` — `.todo_update` Kind
- `src/modes/tui/overlay.zig` — `.todo` Kind, `TodoOverlay`
- `src/modes/tui/cmdpicker.zig` — `/todo` entry
- `lean/PzProofs/Mask.lean` — `mask_all := 0x7FF` (was `0x3FF`), re-verify theorems

## Design Decisions

- **Single file.** All tasks in `.pz/tasks.md`. One read, one write, review skill works directly.
- **Any file.** `TaskList.open(alloc, path)` works on any task-format markdown.
- **Single writer.** Orchestrator only. Subagents work and report; orchestrator checks off.
- **Task file IS a plan.** Same format, same review skill. No separate plan concept.
- **No auto-cleanup.** Done tasks stay until `/todo clear` or `/todo reset`.
- **Section boundary = `## ` + `id:` on next line.** Prevents body `## ` from breaking parser.
- **Metadata split: first `: ` only.** Values with `: ` are safe. Values with ` | ` are forbidden.
- **`clear` skips parents.** Done tasks with non-done children preserved. Cyclic done groups ARE clearable.
- **Parent cycle rejection.** `add()` rejects parent if it would create a cycle.
- **`.bak` files rejected.** `file` param cannot end in `.bak` — prevents reading reset backups.
- **Title strips `</`.** Prevents `</untrusted-input>` breakout in `wrapUntrustedNamed` body. Note: the body-escape gap in `wrapUntrustedNamed` is a pre-existing codebase vulnerability (affects context.zig, loop.zig, compact.zig). Todo mitigates via title sanitization; a codebase-wide fix to escape `</` in the body is tracked separately.
- **`reset` writes backup.** `.pz/tasks.md.bak` before emptying.
- **Context injection warns on failure.** Not silent skip — logs to mode sink. File-not-found is OK (no tasks yet).
- **Context wrapped untrusted.** `wrapUntrustedNamed("task-list", ...)` prevents cross-session prompt injection.
- **Tmp file in same dir.** `{path}.tmp` ensures same-filesystem rename.
- **Concurrent mod detection.** `flush()` checks mtime before rename.
- **Title sanitization.** Rejects `\n`, `\r`, ` | `, `#` — prevents metadata/section injection.
- **Body escaping.** Lines matching `^## ` escaped on write to prevent section forgery.
- **Max 200 tasks.** `add()` errors when exceeded.
- **toolPolicyPath returns synthetic.** `"runtime/tool/todo"` — bypasses `.pz/` self-protection for default file only.
- **Handler constructs full `tools.Result`.** Reference `runAsk` pattern — not the simplified `.output` form.
- **Post-tool ModeEv is a new pattern.** No existing precedent — add in `loop.zig` after `execTool`.
- **PrintSink pre-Formatter.** `.todo_update` handled before `Formatter.push()` delegation.
- **Lean proofs updated.** `mask_all` changes from `0x3FF` to `0x7FF`.
- **u16 mask: 5 bits remaining.** Bit 10 = todo. Future tools may need `u32` migration.
- **Deletion via update+clear.** Known social engineering risk. Approval gate shows status changes. Document as accepted tradeoff.
- **Agent mask stripping.** Blocked on agent tool implementation — tracked as dependency.

### Malformed file handling

- Section with no metadata line: skip with warning
- Unknown metadata keys: ignore
- Duplicate metadata keys: first wins
- Title >80 chars on read: accept (enforce only on add)
- Body >4KB on read: accept (enforce only on add)
- Content before first `## `: ignored (preamble)
- `## ` in body without valid `id:` on next line: treated as body text
