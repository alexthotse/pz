# Thread Weaving and Episodic Memory for Agents

Source: <https://randomlabs.ai/blog/slate>

## Background

Building agents that generalize requires solving three compounding problems: long-horizon task execution, the balance between strategic and tactical reasoning, and working memory management. Each is tractable in isolation but they compound.

### Long-Horizon Tasks

Long-horizon tasks are path-dependent — the required actions depend on each other, and the minimum number of steps exceeds what a minimal harness (limited tool-calling loop with no planning or memory infrastructure) can do.

The agent requires: adequate working memory so the model attends to the right context at the right time, a balance of strategic and tactical execution, and the ability to integrate new information without losing the overall goal.

### Working Memory

Models cannot attend uniformly across their context window. Usable capacity degrades as length grows. The usable portion is "working memory." Dex Horthy coined "Dumb Zone" for the region where retrieval quality drops.

### Strategy vs. Tactics

Strategy is open-ended planning based on knowledge that guides the system towards the goal. Tactics are learned, local action sequences that take steps towards the goal.

Software engineering spans the full spectrum: remembering a bash command is a tactic; designing a backwards-compatible schema is strategic.

When a model plans step by step, it first retrieves knowledge and strategizes, then uses tactics to execute. Most AGENTS.md rules are actually tactical (e.g. "never run db commands").

> "Knowledge overhang": knowledge the model has access to theoretically but can't access tactically without scaffolding like "think step by step" or planning in files.

## Prior Approaches

No existing approach solves all problems simultaneously. Each accepts a tradeoff.

### Compaction

Compaction compresses context to stay within working memory. It is largely unsolved. Main issue: not deterministically lossy — important information is unpredictably lost.

Examples in the wild:
- Claude Code compaction (notoriously bad)
- The Ralph Wiggum loop (Geoffrey Huntley)
- Amp handoffs (requires user guidance)

### Subagents

Subagents isolate context to avoid filling the main window. Naive implementations fail to transfer information across context boundaries — all they return is a response message.

### Markdown Planning

Plans help maintain coherence across compactions and isolated subagent contexts. But plans go stale. Making execution structure mandatory (task trees, gated steps) solves early-stopping but constrains expressivity.

Failure modes:
1. Model isn't good enough to plan well
2. Model isn't good enough to follow the plan
3. Model forgets it has free will and over-decomposes

### RLM and Recursive Decomposition

RLM gives the model a Python REPL with recursive ability. Task structure emerges naturally. But unbounded recursion needs guards against over-decomposition, and the lack of synchronization between stack levels is problematic — the main model can't adapt to failures encountered during isolated execution.

Key insight: stack-based isolation works well for research (decomposing retrieval tasks on immutable data) but not for implementation tasks where the environment changes.

### Devin / Manus / Altera / Claude Code

All follow a pattern: strategize at a high level, delegate to a lower-level subagent, compress the lower-level context, return to the higher level for synchronization.

Prone to the same failures as rigid task decomposition. Synchronous subagents are reliable but slow. Asynchronous subagents introduce reconciliation problems.

Claude Code and Codex delegate to subagents via prompts; subagents respond when done. This introduces synchronization problems because the parent is isolated from the child context and relies on message passing.

> "We think single-threaded agents have not been solved fully. As an industry, we do not need to move on to teams just yet."

## Slate's Approach: Thread Weaving and Episodes

Problems to solve:
1. **Compaction**: compress trajectory while retaining key information
2. **Strategic coherence**: strategize and stay aligned throughout the task
3. **Expressivity**: interfaces that allow complex behaviors
4. **Task decomposition**: break down tasks while maintaining flexibility
5. **Synchronization**: coordinate work across isolated execution contexts

One architectural primitive solves all: the **thread**. Frequent, bounded synchronization between an orchestrator thread and worker threads gives a usable balance of speed, latency, and intelligence.

### Threads

One central orchestration agent delegates actions to worker threads using a highly expressive interface (tool, CLI, or DSL). A worker thread executes the action and returns to the main orchestrator.

**Not subagents.** Key differences:

- Each thread executes **one action**, then pauses and hands control back
- Threads are **general workers** serving the system's current intent, not purpose-specific subagents
- Threads **accumulate context** as a persistent reusable store for that work stream
- Instead of message passing, every thread action generates a compressed representation of its step history: an **episode**

### Episodes

The steps a thread takes while completing an action constitute an episode. This gives tractable **episodic memory** in LLMs.

Episodic memory is the compressed representation of a completed episode: only important results are retained, not the full tactical trace. Threads don't do back-and-forth message passing. They execute, and the episode is returned.

**The built-in completion boundary is what makes compaction natural.** Compaction happens at thread completion, not arbitrarily mid-conversation.

Episodes can be used as direct inputs to other threads. A thread can be initialized with a prior thread's episode — inheriting useful conclusions and work history without inheriting full context. This **composability** distinguishes it from naive subagents that only pass back a single response string.

### Thread Weaving

The orchestrator uses threads **by reference**, giving it semantics for complex context routing. The result is a system that decomposes tasks implicitly and adaptively:

- Not forced to commit to a static plan upfront
- Forced to externalize decomposition in useful units of work that can be compressed and referenced later
- Frequent synchronization means the orchestrator updates its strategy when new information arrives mid-task

### Threads as Processes (OS Analogy)

Mapping to Karpathy's LLM OS framing:

| OS concept | Agent equivalent |
|---|---|
| Kernel | Main orchestrator thread |
| RAM | Context window |
| Processes | Tool calls / threads |
| Storage | Files / memory |
| I/O | Browsers, terminals, APIs |

Instead of letting RAM fill until the process crashes, each thread return is a natural opportunity to decide what gets retained, compressed, or discarded.

### Key Observations

- **Parallel execution**: Real tasks decompose into parallel thread workstreams. The orchestrator dispatches several threads simultaneously and synthesizes their episodes.
- **Cross-model composition**: Using different models across threads works. The episode boundary acts as a clean handoff with no loss of context coherence.
- **The real bottleneck is context management, not model intelligence.** Models are already capable enough; the gap is a systems problem.

## References

1. RLM: Recursive Language Model
2. Karpathy: LLM computer framing
3. TerminalBench 2.0 / Terminus minimal harness
4. Dex Horthy: the "Dumb Zone"
5. Altera: Project Sid / PIANO architecture
6. Devin / Cognition: don't build multi-agents
7. Manus: context engineering for AI agents
8. AlphaZero / AlphaGo (Silver et al.)
9. Geoffrey Huntley: the Ralph Wiggum loop
10. Amp: handoff mechanism
11. ADaPT: as-needed decomposition and planning
12. ReAct (Yao et al.)
13. Chain-of-thought prompting (Wei et al.)
14. Context Rot (Hong, Troynikov, Huber)
