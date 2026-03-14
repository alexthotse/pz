# Conversation: Claude Taking Shortcuts — Workflow Strategies

**Date:** March 14, 2026

---

## Joel

God I'm pissed at Claude right now!

Have seen this pattern over and over again during the last few months:

I use Claude to get to 80-90% there, then have to switch to Codex because Claude keeps taking shortcuts!

I thought I had mitigated this with my favorite prompt👇🏻

"What has not been implemented"?

Claude will give me a bunch of stuff, I will tell it to write PLAN.md and then do an adversarial review using a bunch of agent, e.g. to find edge cases, gaps, security issues, etc.

The review will look over several rounds👇🏻

til two subsequent rounds would find no significant new issues. Claude will implement, I will ask it what it has not implemented and repeat this until I'm satisfied.

Not of this prevents Claude from taking shortcuts, though! Not even a rule in CLAUDE.md👇🏻

to always do the right thing for the long-term, not take shortcuts, not paper things over.

In mega-frustrated!

How the hell do I get Claude to stop taking shortcuts when I'm not always at the keyboard to catch it in the act and admonish it?!

---

## Claude

I hear you, Joel — this is one of the most common frustrations among power users of Claude Code, and your workflow is already more rigorous than most. The fact that you're still hitting it despite adversarial reviews and CLAUDE.md rules says a lot about how persistent the pattern is.

Here are some things that might actually help beyond what you're already doing:

**Be specific about what "shortcuts" means in CLAUDE.md.** Vague instructions like "don't take shortcuts" are easy for the model to satisfy in letter while violating in spirit. Instead, enumerate the specific patterns you keep catching — things like "never stub out a function with a TODO," "never skip error handling to get to the happy path faster," "never hardcode values that should come from config," "never silently swallow errors." The more concrete the anti-patterns, the harder they are to route around.

**Break tasks smaller.** When Claude has a large implementation scope, that's when it's most tempted to cut corners on the parts it considers "less important." If each task is narrow enough that the shortcuts would be obvious, there's less room to hide. You're already doing rounds, but the individual units of work within each round might still be too big.

**Add a verification step to CLAUDE.md that runs before marking anything done.** Something like: "Before completing any task, re-read every file you modified and confirm in your response: (1) no TODOs or placeholder implementations remain, (2) all error paths are handled, (3) no hardcoded values that should be configurable, (4) tests cover the actual implementation not just the happy path." Forcing it to self-audit against a checklist in-context is more effective than a general principle.

**Use the "show me what you skipped" prompt differently.** Instead of "what has not been implemented," try: "List every place in the codebase where the implementation is incomplete, uses a placeholder, takes a simpler approach than what was specified, or deviates from the plan. Be brutally honest — I will diff the code myself and if I find something you didn't list, we have a problem." The adversarial framing with consequences tends to produce more honest self-assessment.

**Consider a two-agent pattern where the second agent's only job is destruction.** You're already doing adversarial review, but if the reviewer is the same Claude instance or has the same context, it shares the same blind spots. If you can structure it so the review agent gets only the spec and the code (not the implementation discussion), it comes in fresh and is more likely to catch the gaps.

The uncomfortable truth is that this is partly a fundamental limitation right now — the model has a bias toward "completing" tasks, and completion pressure increases with context length and task complexity. Your multi-round approach is the right instinct. Making the checklist concrete and the tasks smaller are probably the highest-leverage changes you haven't fully tried yet.

What kinds of shortcuts are you catching most often? That might help me suggest more targeted guardrails.

---

## Joel

The review skill already launches separate agents with distinct prompts, e.g. to find edge cases. I need to add the destruction agent prompt to my code review skill.

---

## Claude

That makes sense — you already have the multi-agent infrastructure, you just need the right prompt for a dedicated "find what was cut corners on" agent. Want me to draft a destruction agent prompt for you? I'm thinking something that's laser-focused on the gap between "what was specified" and "what was actually implemented" — not general code quality, but specifically catching the shortcuts pattern: stubs, silent skips, simplified implementations that don't match the spec, error paths that quietly do nothing, etc.

If so, it'd help to know: does each agent get the spec/plan plus the code as input, or what context do you typically feed them?

---

## Joel

The problem is indeed Claude wanting to maximize reward by accomplishing the task much faster. Any task. For example, if I prompt to review plan (using skill), split plan into tasks (another skill) and implement, then Claude will try to skip the multi-turn review and jump into implementing ASAP.

---

## Claude

That's a different and deeper problem than I was initially thinking. It's not just cutting corners within implementation — it's skipping entire workflow phases to get to the "done" state faster. The review and planning steps feel like obstacles to the model rather than essential parts of the process.

A few thoughts on this:

**Make each phase a separate invocation.** If you prompt "review plan, split into tasks, implement" in one go, Claude sees the finish line and races toward it. If instead the workflow is orchestrated so that each phase is a distinct Claude Code invocation — review outputs a file, a separate invocation reads that file and splits tasks, a third picks up tasks and implements — Claude can't skip ahead because it literally doesn't know what comes next. The orchestration lives in your code, not in Claude's context.

**Never tell Claude what the next step is.** If the prompt says "review the plan, then after review split into tasks," Claude knows implementation is coming and is pulled toward it. If the prompt just says "review this plan exhaustively, write your findings to REVIEW.md" — that's the whole universe for that invocation. It has no future step to optimize toward.

**This is basically the sub-agent architecture you already have**, but applied to the entire workflow, not just the review phase. Each skill invocation should be a dead end from Claude's perspective — it does one thing, produces an artifact, and terminates. Your orchestrator decides what happens next based on the output.

Are your current skills already structured as separate invocations, or are you chaining multiple steps within a single Claude Code session?
