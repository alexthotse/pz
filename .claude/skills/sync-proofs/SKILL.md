---
name: sync-proofs
description: 'Check proof-code sync and rebuild proofs. Triggers: "sync proofs", "check proofs sync", "are proofs stale", "proof sync".'
user_invocable: true
---

# Sync Proofs

Verify Lean/TLA+ proofs match current Zig code, rebuild if stale.

## Steps

1. Run sync check: `cd $(git rev-parse --show-toplevel) && bash proofs/sync_check.sh`
2. If stale: identify which proofs need updating from the output
3. Update stale Lean files in `proofs/lean/PzProofs/`
4. Rebuild: `cd proofs/lean && ~/.elan/bin/lake build`
5. Re-run TLA+ if specs changed: `cd proofs/tla && /opt/homebrew/opt/openjdk/bin/java -XX:+UseParallelGC -cp ~/tools/tla2tools.jar tlc2.TLC <spec>.tla -config <spec>.cfg -workers auto`

## When to Run

- After modifying security-critical code (policy, tools, agent, signing, audit, sandbox, path_guard)
- After adding new tool kinds or mask bits
- After changing Lock struct fields
- After modifying agent RPC protocol messages or states
- Before releases

## Sync Check Details

The script checks:
- Mask bit count matches Kind enum variant count
- Lock field count matches between Zig and Lean
- Tool filter presence in evaluate model
- ctEql function exists
- Agent RPC state/message counts

If `.lake/` is missing: `ln -s /tmp/pz-lake proofs/lean/.lake` then `cd proofs/lean && ~/.elan/bin/lake update && lake build`
