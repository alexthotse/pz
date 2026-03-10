---
name: interview
description: Structured decision-making interview. Ask one question at a time to converge on an approach before coding.
user_invocable: true
---

# Interview

## Rules

1. **One question at a time.** Always use the AskUserQuestion tool — never ask inline in text.
2. **Concrete alternatives.** 2-4 options. Mark the recommended one with "(Recommended)" in the description.
3. **Recommend for long-term.** Best architecture, even if more work upfront.
4. **Keep short.** Option labels 1-5 words. Descriptions <=15 words.
5. **Build on prior answers.** Each question narrows the design space.
6. **3-6 questions typical.** Stop when approach is clear -> summarize.
7. **"You decide" = pick recommendation.** Move on.
8. **Challenge bad choices once.** Then accept.

## Question Format

Use AskUserQuestion with:
- `header`: short label for the decision (e.g. "Auth method", "Storage", "Approach")
- `question`: the full question ending with `?`
- `options`: 2-4 choices, each with a `label` (1-5 words) and `description` (<=15 words, append "(Recommended)" to the best one)

## After Summary

Review before implementing: missing edge cases, unclear specs, contradictions, interaction gaps, test coverage. List issues + fixes. Then implement.
