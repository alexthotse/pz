# Episodes Context Management Benchmark

Measure whether episodes actually solve the context degradation problem.

## Core Question

Does the orchestrator make better decisions when receiving structured episode summaries vs raw tool traces? Does it complete longer tasks without losing context?

## Methodology

### A/B Comparison

Run identical multi-step tasks under two conditions:
- **Control (no episodes)**: single-agent, all tool traces in context, current compaction
- **Treatment (episodes)**: orchestrator + threads, episode summaries replace tool traces

Same model, same task, same tools. Measure the difference.

### Task Suite

Tasks must be long enough to stress context management. Minimum 30 tool calls per task. Three categories:

**T1: Multi-file refactor** (~50-100 tool calls)
- Rename a type across 10+ files
- Requires reading each file, understanding usage, editing consistently
- Success metric: all references updated, builds clean, tests pass
- Failure mode without episodes: forgets which files were already updated, re-reads files, inconsistent edits

**T2: Bug investigation** (~30-60 tool calls)
- Given a failing test, find root cause across 5+ files
- Requires reading test, tracing call chain, identifying the bug, fixing it
- Success metric: correct root cause identified, fix applied, test passes
- Failure mode without episodes: loses track of investigation findings, revisits dead ends

**T3: Feature implementation** (~80-150 tool calls)
- Add a new tool to pz (e.g., a `web` tool handler)
- Requires reading existing tool patterns, writing handler, tests, wiring into registry
- Success metric: tool works, tests pass, matches existing patterns
- Failure mode without episodes: forgets patterns from earlier reads, inconsistent with codebase conventions

**T4: Code review** (~40-80 tool calls)
- Review a large diff (500+ lines across 10+ files)
- Requires reading each changed file, understanding context, finding issues
- Success metric: all real issues found, no false positives
- Failure mode without episodes: forgets earlier findings, repeats analysis, misses cross-file issues

### Metrics

#### Primary (success/failure)

| Metric | How measured | Target |
|---|---|---|
| Task completion rate | Binary: did the task succeed? | Episodes > Control |
| Correctness | Manual review of output quality | Episodes >= Control |
| First-try success | Completed without backtracking/retry | Episodes > Control |

#### Secondary (efficiency)

| Metric | How measured | Target |
|---|---|---|
| Total tokens (in+out) | Sum across all API calls | Episodes < Control (despite episode generation cost) |
| Context size at turn N | Input token count at each turn | Episodes grows slower |
| Compaction count | Number of mid-conversation compactions triggered | Episodes: 0-1, Control: 3+ |
| Tool call count | Total tool invocations | Episodes <= Control (less re-reading) |
| Wall time | End-to-end task duration | Episodes <= Control |
| API calls | Number of provider round-trips | Episodes <= Control |

#### Context Quality (the core measurement)

| Metric | How measured | Target |
|---|---|---|
| Context compression ratio | (total tool trace bytes) / (total episode bytes) | > 10:1 |
| Information retention | Key findings from threads present in orchestrator context? | > 90% |
| Hallucination rate | Orchestrator claims something an episode doesn't support? | < 5% |
| Re-read rate | Files read more than once across threads | Episodes < Control |
| Context at task end | Tokens in final API request | Episodes < Control by 5x+ |

### Episode Quality Measurement

For each episode generated, evaluate:

1. **Mechanical accuracy**: Do `files_read`, `files_changed`, `tool_summary` match the actual thread trace? (Automated: diff against session events)
2. **Key findings relevance**: Do the model-generated `key_findings` capture what the orchestrator needs? (Manual review + automated: does the orchestrator reference the findings?)
3. **Outcome correctness**: Does `outcome` (success/partial/failed) match reality? (Automated: compare against thread's actual result)
4. **Compression loss**: What information was lost? (Manual: compare episode to full trace, flag critical omissions)

### Test Infrastructure

```
pz bench episodes [--task T1|T2|T3|T4|all] [--runs N] [--model sonnet|opus]
```

Each run:
1. Set up a clean worktree (jj workspace) with a known starting state
2. Run the task under Control (no episodes, single agent)
3. Reset worktree to same starting state
4. Run the same task under Treatment (episodes enabled)
5. Collect all metrics
6. Compare

Output: JSON report with all metrics, per-run and aggregated.

### Statistical Requirements

- Minimum 5 runs per task per condition (LLM outputs are stochastic)
- Report mean, median, and p25/p75 for each metric
- Use same random seed where possible (API temperature=0)
- Same model version for both conditions

## Implementation

### Phase 1: Manual benchmark (before episodes implementation)

Record baseline metrics for the Control condition on T1-T4. This establishes what "current compaction" looks like:
- How many tokens at turn 30, 50, 80?
- How many compactions fire?
- Where does the agent lose context?
- What files get re-read unnecessarily?

Run: `pz --session-stats` to capture per-turn token counts (needs implementation if not present).

### Phase 2: Episode benchmark (after episodes Phase 1)

Run Treatment condition on T1-T4. Compare against Phase 1 baselines.

### Phase 3: Regression gate

Add to CI: a simplified version of T1 (rename a type across 3 files) that runs both conditions and asserts:
- Treatment completes in <= Control tokens
- Treatment triggers 0 compactions
- Treatment context at final turn is < 50% of Control

This prevents regressions in episode quality as the system evolves.

## Expected Results

Based on the EPISODES-PLAN.md analysis (100KB raw traces → 5KB episodes):

| Metric | Control (predicted) | Treatment (predicted) |
|---|---|---|
| Context at turn 50 | ~200K tokens | ~40K tokens |
| Compactions | 3-5 | 0-1 |
| Total tokens (T1) | ~500K | ~350K (episode gen adds cost, but less re-reading saves more) |
| Task completion (T3) | ~60% (context degradation at turn 80+) | ~90% |
| Re-read rate | 40%+ of files read twice | <10% |

The critical prediction: **Treatment enables tasks that Control cannot complete** due to context degradation past turn 80.

## Open Questions

1. **Episode generation cost**: How many tokens does a single episode generation call use? If it's 2K tokens per thread, and a task uses 10 threads, that's 20K tokens of overhead. Is the context savings worth it?
2. **Episode quality variance**: How often does the model produce bad key_findings? Does the mechanical-only fallback fire frequently?
3. **Cross-model episodes**: Does an opus orchestrator understand sonnet-generated episodes? (Phase 4 of episodes plan)
4. **Diminishing returns**: At what task complexity does the episode advantage plateau? Is there a task so long that even episodes can't prevent context degradation?
