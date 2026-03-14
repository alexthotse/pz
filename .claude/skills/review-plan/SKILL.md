---
name: review-plan
description: 'Adversarial plan review. Triggers: "review plan", "critique plan", "stress test plan". Launches parallel agents to break the plan, iterates until clean.'
user_invocable: true
---

# Review Plan (Adversarial)

## Non-Negotiable

Parallel agents are mandatory. Manual single-agent review is not acceptable.
Plan-only critique is FORBIDDEN — agents must re-read code and verify plan against implementation.

## Workflow

### Step 0: Re-ground

Restate: user goal, constraints, success conditions.
Re-read implementation code for each planned area (+ one adjacent caller/callee per area).

### Step 1: Write/Update Plan Draft

`PLAN.md` items must have: number, file paths + line ranges, acceptance criteria, risk notes, effort estimate, dependency/order, goal mapping.

### Step 2: Adversarial Rounds

**Frozen baseline rule:** Freeze `baseline_id` per round. All agents in a round share the same baseline. Do not edit `PLAN.md` while agents are running.

**Full-round barrier:** Wait for ALL agents to finish before patching `PLAN.md`. Aggregate, then update once.

**Surface partition:** Assign each agent a disjoint code surface. Track coverage map per round.

**Agent output contract:** Exhaust assigned surface. Return ALL material findings (not just the first). Dedupe against existing `PLAN.md`. Cite the missing/insufficient plan item. If clean: `No new Critical/Major findings.`

**Round 1 — Broad attack (6 agents via Agent tool):**
1. **plan-critic**: Completeness, dependencies, estimates — what goals have NO coverage?
2. **edge-case-hunter**: Feasibility — which items will fail in practice?
3. **reviewer**: Assumptions, regressions, maintainability risks
4. **scout**: Blind spots — files/paths NEVER mentioned in plan
5. **code-auditor**: Security — trust boundaries, privilege escalation, data-exfil, audit gaps, policy bypasses
6. **destructor**: Gap between spec and implementation. Sees ONLY the plan/spec and the code — never the implementation discussion or prior agent context. Catches: stubs, TODOs, silent skips, simplified implementations that don't match spec, error paths that quietly do nothing, hardcoded values that should be configurable. Fresh context is the point — shared blind spots with the implementer are what this agent exists to break.

Each agent prompt must include: `baseline_id`, prior findings, assigned surface, explicit code files/line ranges to inspect.

**Round 2+:** Target weakest areas from prior round. Each round must:
- Cover at least one file/path NOT covered in any prior round
- Focus on what was MISSED
- Attempt to DISPROVE fixes from prior rounds
- Include `code-auditor` when touching policy, auth, sandboxing, tool execution, secrets

### Step 3: Triage

Severity:
- **Critical**: security boundary, policy bypass, privilege escalation, data loss
- **Major**: correctness bug, broken dependency, missing test coverage, misleading plan item
- **Minor**: clarity, naming, estimate, optional test
- **Nit**: style only — reject unless hiding real impact

Only Critical and Major are material.

Findings table: ID, Severity, Source agent, Evidence (file:line), Decision (accept/reject/defer), Goal impact.

### Step 4: Update PLAN.md

For accepted findings: revise text, adjust criteria, add dependencies, add follow-up items.
For rejected findings: short false-positive note with reason.

### Step 5: Iterate Until Clean

Loop Steps 2-4. **No iteration cap.**

- Each round covers new territory (different files, callers, failure scenarios)
- Stop ONLY after 2 consecutive rounds produce zero new accepted Critical/Major findings
- After 4+ rounds with persistent findings, surface root cause pattern and ask user

**Forbidden:**
- Patching PLAN.md before full round finishes
- Counting stale findings from old baseline
- Stopping after first clean round
- Sending agents to validate known issues instead of attacking unknowns
- Capping iterations

### Step 6: Final Output

1. Agent launch record (scope, baseline_id, per round)
2. Iteration log (round count, findings per round, convergence)
3. Code-grounding evidence (files/lines inspected)
4. Final findings table (all rounds, all decisions)
5. Goal-to-plan coverage matrix
6. PLAN.md changes summary
7. Open risks/unknowns (explicit; if none, say "None")

## Done When

- 2 consecutive rounds: zero new Critical/Major
- All accepted Critical/Major incorporated and re-validated
- Remaining accepted findings are Minor only (tracked as backlog)
- Every plan item has acceptance criteria
- Dependencies are explicit and conflict-free
- Every user goal mapped to plan coverage or explicit gap
