# Agent Rules

## Mission

Build `pz`: a Zig CLI harness with TUI. Do not optimize for compatibility with pi.

## Core Constraints

- Correctness over speed.
- Use hard cutovers only: no legacy support, compatibility shims, or fallback paths.
- No silent fallbacks.
- Root-cause fixes only.
- Keep names short and clear.
- Keep hot paths allocation-aware.

## Read Window Rule

- Use `rg -n` to find the anchor first.
- Default file reads to a 20-line window around the anchor.
- If that is insufficient, double the window: 40, then 80, then 160.
- Only start wider when it is obvious up front that 20 lines cannot contain the relevant construct.

## Trace Rule

- Emit terse commentary traces during active work so the user can see progress.
- Include a trace before substantial reads, edits, test runs, merges, and agent launches.
- Keep traces factual and short.

## Source Control

Use `jj`, not `git`.

- New change: `jj new`
- Describe change: `jj describe -m "<imperative message>"`
- Sync: `jj git fetch` / `jj git push`

## Parallel Work (Required)

For multi-agent work, use separate `jj` workspaces.

Default shape:

1. Keep `1` local lane for integration, rebases, merges, flakes, and shared-surface debugging.
2. Launch only `2-3` worker lanes by default.
3. Expand past `3` workers only if the next dots are truly disjoint in files and dependencies.

1. Create workspaces under `.jj-ws/` (see jj skill for commands).
2. Assign file ownership per workspace.
3. Do not edit files owned by another workspace.
4. Reconcile by rebasing/squashing after each track stabilizes.

## File Ownership Rule

If a file is touched by another active agent, stop and reassign before editing.
Do not launch overlapping dots in parallel just because they look “small”.
If dots overlap in runtime/provider/session/core surfaces, serialize them unless a prior dot closes the dependency.

## Commit Rule

Only include files changed by the current agent/task. No broad staging.

## Agent Reporting Rule

Agents must report what they CHANGED (files, lines, insertions/deletions), not claim things were "already done." If no changes needed, explain why with file:line evidence. Never declare victory without a diff.

## Testing Rule

Run `timeout 60 zig build test 2>&1 | tail -5` ONCE. Never loop, retry, or run multiple grep variations.
A useful test proves behavior the compiler cannot — error paths, edge cases, integration contracts, security boundaries. Skip tests that verify comptime-guaranteed behavior, constants, or type correctness.
Run relevant tests before and after each fix or feature.
Every bug fix must add or strengthen a test.
Use `ohsnap` snapshots for struct/multi-field outputs and serialized payload checks.
Use `std.testing.expectEqual` only for scalar primitives.
Use `joelreymont/zcheck` for property tests and add fuzz/property coverage where the surface warrants it.

## Zig Rules

See `docs/zig.md` (mirrored from `~/.agents/docs/zig.md`).

## Formal Verification

- TLA+ spec for thread dispatch: `docs/tla/ThreadDispatch.tla`
- Run with `/tla` skill after changing thread dispatch, file ownership, or join/cancel logic
- Lean 4 proofs planned for policy enforcement and signing (see dot)

## Plan Rule

Track execution against `PLAN.md`.
When a plan item is complete, update status in commit message and notes.

## Lessons Rule

Read `LESSONS.md` at the start of work.
Update `LESSONS.md` at the end of the session with new do-more and do-not-do lessons.

## Release Rule

For release work, import and follow `.claude/skills/release/SKILL.md` in addition to this file.
Release prep must include a `CHANGELOG.md` entry for the new version before tagging.
