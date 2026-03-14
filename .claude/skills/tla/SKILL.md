---
name: tla
description: 'Run TLA+ model checker on thread dispatch spec. Triggers: "run tla", "check tla", "model check", "verify threads", "tla+", "check dispatch".'
user_invocable: true
---

# TLA+ Model Check

Run TLC on `docs/tla/ThreadDispatch.tla` to verify thread dispatch invariants.

## When to Run

- After modifying thread dispatch, file ownership, join/cancel, or budget logic in EPISODES-PLAN.md
- After changing Thread/Episode data model
- After modifying any resolved decision that affects concurrency

## Command

```bash
/opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC \
  -cp ~/tools/tla2tools.jar tlc2.TLC \
  docs/tla/ThreadDispatch.tla \
  -config docs/tla/ThreadDispatch.cfg \
  -workers auto
```

Run from project root. Expected: ~3-4M states, <3 minutes, exit code 0.

## Interpreting Results

- **No errors, exit 0**: all invariants and temporal properties hold.
- **Deadlock reached**: a state has no successor. Check if it's a valid terminal state (orch_state="done", round=MaxRounds) or a real bug.
- **Invariant violated**: TLC prints the violating state trace. Read the trace to find which property broke and in which state transition.
- **Temporal property violated**: liveness failure — a thread never completes, join never terminates, or cancel never propagates. The counterexample trace shows the lasso (cycle).

## Updating the Spec

When the episodes plan changes:
1. Update `ThreadDispatch.tla` to match new design decisions
2. Run TLC to verify
3. If state space explodes (>10M states or >5 min), reduce constants in `.cfg` (fewer threads/files/rounds) — the properties are symmetry-invariant

## Verified Properties

Safety (invariants):
- `FileOwnershipDisjoint`: no two concurrent threads share files
- `BudgetNonNegative`: no thread overspends
- `GlobalBudgetNonNegative`: total budget never negative
- `ToolMaskValid`: no privilege escalation
- `DepthOneEnforced`: no sub-thread spawning
- `FileLocksConsistent`: locks match ownership
- `EpisodesFromCompleted`: episodes only from done/failed threads
- `JoinCompleteness`: orchestrator done only after all episodes collected

Liveness (temporal):
- `ThreadProgress`: running threads eventually complete
- `JoinTermination`: join always terminates
- `CancelResponsiveness`: aborted threads eventually fail
