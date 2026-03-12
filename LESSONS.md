# Lessons Learned

Hard-won patterns and anti-patterns from building pz. **Update this file at the end of every session** with new discoveries.

---

## Session Notes (2026-03-11)

### Worked Well
- Before `jj workspace add`, move root to a fresh empty child; creating workspaces from a non-empty working-copy commit can base the new workspace on the parent commit instead of the intended integrated head.
- For cross-feature audit proof, keep the E2E harness under `src/test/`, feed it a mixed row set from real hook emitters where public (`auth`, `bg`) plus manual control fixtures where hooks stay private, and verify the sealed syslog bodies round-trip exactly through both UDP and TCP mocks.
- For signed runtime-policy checks, map slash/tool/subagent actions onto a synthetic namespace like `runtime/...`; it stays outside policy self-protection and gives stable paths for hashable authority decisions.
- Landing worker results with `jj restore --from <commit> <file>` kept dot merges exact and avoided stale workspace side-data.
- Replacing `git` shell-outs in `build.zig` with `jj log` made test runs work inside `jj workspace` siblings without fake `.git` hacks.
- For seeded `pbt` self-tests, snapshot the actual fixed-seed success stream and shrunk witness from the harness instead of guessing expected bytes.
- For borrowed replay/session events, add an owned path (`nextDup`/`dupe`) instead of relying on callers to remember arena lifetime rules.
- For DNS/network guards, keep address classification in one shared helper and compare `std.net.Address` values with `std.net.Address.eql`, not struct equality.
- For TUI `ask`, keep the tool thread on a waitable handoff and let the main loop answer through its existing `tui_input.Reader`; pausing the ESC watcher only while the main loop owns stdin preserves single-reader semantics and avoids editor/ask interleaving.
- Gate every bash entrypoint through one shared protected-command scanner; otherwise direct `!cmd` and tool `bash` drift and one becomes the bypass.
- For RFC 5424 UDP truncation, parse through the structured-data boundary and append truncation metadata there; trimming raw bytes blindly risks invalid frames and would miss the `sendRaw` audit path.
- Pulling the ad hoc blocked-stream provider out of the loop test and into `src/test/provider_mock.zig` made the cancel regression cheaper to reuse and gave `T7b` a real local provider harness instead of copy-pasted test scaffolding.
- A tiny one-shot local HTTP server under `src/test/http_mock.zig` is enough to unblock update/share/redirect testing; land the harness before trying to write higher-level E2E around it.
- Contract helpers added under `src/core/providers/contract.zig` are not automatically visible through `src/core/providers/mod.zig`; owned callers should import the contract directly unless the module surface is intentionally widened.
- When a test frees a companion `parts` buffer by deriving its size from `msgs.len`, any change that allows multi-part system messages must update that free path too or the debug allocator will catch a mismatched free/leak.
- Approval caches for privileged tool calls need the full raw arg payload plus session/location/policy binding; anything narrower silently broadens the grant surface.
- For shipped audit E2E, capture multiple collector frames, extract the syslog body back out, and verify the sealed chain from the collected payloads; that proves transport + redaction together instead of only unit-encoding them.
- For runtime control audit, route slash commands, RPC commands, and overlay selections through one shared helper with its own sequence counter; otherwise one UI path will bypass privileged audit again.
- For DLP-style text redaction, keep path/secret markers in shared lists and property-test both positive markers and plain-id negatives; otherwise detector growth turns into unreviewable `or` chains.
- For approval-cache properties, generate alternate session/hash strings inside the property so the invariant never collapses onto an accidental equal input.

### Did Not Work
- Assuming `execWithIo` exercises the live TUI loop was wrong. `runTui` gates overflow-retry and other live-turn behavior behind `isatty(STDIN_FILENO)`, so fixed-buffer tests only cover the non-TTY prompt path unless stdin/tty are injectable.
- Using synthetic policy paths under `.pz/runtime/...` for runtime actions was wrong because policy self-protection denies any `.pz` path before rule evaluation.
- Letting a worker validate in a workspace whose build still shells out to `git` created false failures. Fix the build once instead of faking `.git` per workspace.
- For raw string snapshots, writing only the body text is wrong. `ohsnap` expects the full typed shape like `[]u8` plus the value line.
- Escaping JSON quotes inside raw multiline `ohsnap` snapshots is wrong. After `\\`, the quotes are literal snapshot content.
- Putting `<!update>` anywhere but the first snapshot line does not work; `ohsnap` will keep failing instead of rewriting the snapshot.
- Using `<!update>` inside tests that temporarily `chdir` with `CwdGuard` is wrong. `ohsnap` resolves the module root from the current working directory, so rewrite mode can fail with `FileNotFound`; patch the snapshot text by hand in those tests.
- Exposing Zig stdlib private error sets (for example `std.net.GetAddressListError`) from repo APIs is a dead end. Map them at the boundary.
- Treating `std.net.Stream.writer` like the old zero-arg API caused wasted compile/debug churn. In Zig 0.15 it requires a caller-supplied buffer; direct `std.posix.write` is often simpler in tiny test servers.
- Leaving temporary `std.debug.print` probes in inherited code polluted targeted test runs and risks shipping noise. Strip them before final validation, not after.

## Session Notes (2026-03-10)

### Worked Well
- Keep a repo-local `docs/zig.md` copied from `~/.agents/docs/zig.md` and point `AGENTS.md` at it so every agent works from the same Zig 0.15 rules inside the repo.
- Enforce `ohsnap` for struct/multi-field assertions and `joelreymont/zcheck` for property tests in the task definition before parallel work starts; that prevents workers from drifting into field-by-field test rewrites.
- For parallel dot execution, assign one `jj workspace` per agent, give each worker explicit file ownership, and merge their work back only after the tracks stabilize. Reuse and close the live agent pool instead of over-spawning threads.
- Keep routine Zig API knowledge in `docs/zig.md` so normal work does not require spelunking Zig std/source.

### Did Not Work
- Leaving Zig rules only in `~/.agents/docs/zig.md` made the repo instructions incomplete. Do not rely on off-repo paths when the project expects durable, shared guidance.
- Spawning fresh subagents without first reclaiming finished threads hit the agent limit and stalled review rounds. Reuse or close agents before launching more.
- Looking at Zig std/source for normal API recall wasted time. Default to `docs/zig.md` and only read source when truly blocked.

## Session Notes (2026-02-22)

### Worked Well
- Running pi and pz in parallel tmux sessions (100x50) with `tmux capture-pane -p -S -500` gives exact terminal output for side-by-side parity comparison. Captures must happen while TUI is running since pz uses alternate screen buffer.
- Formatting tool calls as `$ cmd args` (parsing JSON args to extract command/path) matches pi's display and is much more readable than raw `[tool name#id]` format.
- Collapsing long tool output with `... (N earlier lines, ctrl+o to expand)` keeps the transcript compact without losing information.
- Suppressing usage/stop protocol events from transcript (handling them only in panels/status bar) eliminates visual noise that pi doesn't show.
- Using `pushAnsi()` with span-based coloring for tool results preserves ANSI colors from tool output (e.g., colored grep results) while keeping the frame-buffer rendering clean.
- Adding `eofReader()` test helper (returns 0 bytes = EOF) replaced all `null` input readers in runtime tests, preventing them from blocking on real stdin in non-TTY mode.

### Did Not Work
- Passing `null` for input reader in runtime tests caused real stdin reads in non-TTY mode, hanging tests indefinitely. Always use an explicit EOF reader.
- Early `return` after processing `-p` prompt caused pz to exit immediately after the first response instead of staying in TUI mode like pi. The prompt path must fall through to the input loop.
- Using `frame.Color.eql` directly on `vscreen.Color` types in fixture tests caused type mismatch. Must use VScreen's own `expectFg`/`expectBg` methods.
- Variable name `count` in `pushToolResult` shadowed `Transcript.count()` method. Zig treats method names as field access, so local variables must not shadow struct method names.
- Zig 0.15's `std.Io.AnyReader` (DeprecatedReader) is a flat struct with `context: *const anyopaque` and `readFn`, not a vtable-based interface. Constructing it requires `.{ .context = undefined, .readFn = &S.read }`.

## Architecture & Design

### TUI parity approach
Compare against pi by running both with identical prompts and capturing terminal output. Track specific gaps (status bar fields, startup sections, transcript formatting) as discrete tasks. Fix the most visually impactful differences first.

### Transcript block kinds control visibility
The `Kind` enum (text, thinking, tool, err, meta) determines per-block filtering via `show_tools` and `show_thinking` flags. Tool display and thinking display are independent toggles. Thinking defaults to visible (matching pi), toggled with ctrl+t.

### Status bar accumulates across turns
Usage stats (in/out tokens, cache R/W, cost) come from provider usage events and accumulate in `Panels.usage`. The status bar renders these on each frame.

### Cost calculation uses integer micents
Cost is tracked in micents (1/100000 of a dollar) to avoid floating point. Rates are stored in cents/MTok. Formula: `tokens * rate_cents / 1000`. Model tier detected by substring match ("opus", "haiku", default sonnet). Displayed as `$N.NNN`.

### Prompt caching needs minimum token count
Anthropic requires ~1024 tokens in a cached block before it actually caches. Short system prompts won't trigger caching. `cache_control: {"type": "ephemeral"}` is set on the last system text block. R/W tokens show in status bar when >0.

### OAuth = subscription
Auth type from `~/.pi/agent/auth.json` determines subscription status. OAuth users get `(sub)` indicator in status bar. API key users don't. Detected via `Client.isSub()` and passed through `runTui()` as bool.

### Skills discovery is simple glob
`~/.claude/skills/*/SKILL.md` — iterate dirs, check file exists, sort for stable display. Shown in `[Skills]` startup section matching pi.

### jj bookmark for branch display
Pi shows git branch in footer, but jj repos have detached HEAD. Use `jj log --no-graph -r @ -T bookmarks` to get the jj bookmark name. Strip trailing `*` (dirty indicator). Fall back to git branch, then `detached`.

### TurnCtx eliminates parameter sprawl
`runTuiTurn` had 12+ params passed from 7 call sites. Replaced with `TurnCtx` struct holding stable loop state (alloc, provider, store, tools_rt ptr, mode, max_turns). Per-turn variables (sid, prompt, model, opts) passed via `TurnOpts`. Store `*tools.builtin.Runtime` (pointer) not `tools.Registry` (value) so `/tools` changes are visible.

### Overlay composites on frame buffer
Model selector overlay renders directly onto the frame buffer after normal TUI content, before `rnd.render()`. Key interception happens before `ui.onKey()` — when overlay is open, up/down/enter/esc are handled by overlay, not editor. Box-drawing chars (┌┐└┘│─) make clean borders.

### ESC cancellation needs raw mode + dedicated thread
Detecting ESC during streaming requires a dedicated InputWatcher thread (mirrors pi's CancellableLoader + AbortController pattern). The thread uses `poll()` with 100ms timeout + `read()` on stdin, setting an atomic bool when ESC (0x1b) is received. Critical: raw mode (`enableRaw`) MUST be set before starting the thread — in canonical mode, `poll()` POLLIN only fires on complete lines, so bare ESC never triggers it. The `enableRaw` call was moved before the `-p` prompt path for this reason. Non-blocking approaches (`fcntl O_NONBLOCK`, inline `pollCancel` in push callback) failed on macOS due to Zig's `read()` wrapper returning `WouldBlock` even when `std.c.read()` returns 0.
