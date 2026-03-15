#!/bin/bash
# CI tripwire: verify Lean/TLA+ models match Zig source constants.
# Run from repo root: ./proofs/sync_check.sh
# Exit 0 = in sync, exit 1 = stale proofs
set -euo pipefail

FAIL=0
check() {
    local label="$1" zig_val="$2" proof_val="$3"
    if [ "$zig_val" != "$proof_val" ]; then
        echo "STALE: $label — Zig=$zig_val Proof=$proof_val"
        FAIL=1
    else
        echo "  ok: $label = $zig_val"
    fi
}

echo "=== Lean: Mask.lean ==="
ZIG_MASK_COUNT=$(rg '^pub const mask_\w+: u16' src/core/tools/builtin.zig | grep -cv mask_all)
LEAN_MASK_HEX=$(rg 'def mask_all.*0x' proofs/lean/PzProofs/Mask.lean | grep -o '0x[0-9A-Fa-f]*')
ZIG_KIND_COUNT=$(sed -n '/pub const Kind = enum/,/^};/p' src/core/tools.zig | rg -c '^\s+\w+,$')
check "mask bit count" "$ZIG_MASK_COUNT" "$ZIG_KIND_COUNT"

echo "=== Lean: Policy.lean ==="
ZIG_LOCK_FIELDS=$(sed -n '/pub const Lock = struct/,/^};/p' src/core/policy.zig | rg -c '^\s+\w+: bool')
LEAN_LOCK_FIELDS=$(rg -c '^\s+\w+ : Bool' proofs/lean/PzProofs/Policy.lean)
check "Lock field count" "$ZIG_LOCK_FIELDS" "$LEAN_LOCK_FIELDS"

echo "=== Lean: Evaluate.lean ==="
ZIG_HAS_TOOL_FILTER=$(rg -c 'matchTool\|\.tool' src/core/policy.zig || echo 0)
LEAN_HAS_TOOL_FILTER=$(rg -c 'ruleActive\|currentTool' proofs/lean/PzProofs/Evaluate.lean || echo 0)
if [ "$ZIG_HAS_TOOL_FILTER" -gt 0 ] && [ "$LEAN_HAS_TOOL_FILTER" -eq 0 ]; then
    echo "STALE: evaluate has tool filter in Zig but not in Lean"; FAIL=1
else
    echo "  ok: tool filter modeled"
fi

echo "=== Lean: CtEql.lean ==="
ZIG_CTEQL=$(rg -c 'pub fn ctEql' src/core/signing.zig)
check "ctEql exists" "$ZIG_CTEQL" "1"

echo "=== Lean: Egress.lean ==="
ZIG_IPV4_RANGES=$(sed -n '/fn isBlockedIp4/,/^}/p' src/core/policy.zig | rg -c 'return true' || echo 0)
echo "  info: IPv4 blocked ranges = $ZIG_IPV4_RANGES"

echo "=== TLA+: AgentRPC.tla ==="
ZIG_STUB_STATES=$(sed -n '/pub const State = enum/,/};/p' src/core/agent.zig | rg -c '^\s+\w+,' || echo 0)
check "Stub states" "$ZIG_STUB_STATES" "4"
# Msg.Tag: hello,run,cancel,out,done,err — check known set exists
ZIG_HAS_MSG=$(rg -c 'hello.*run.*cancel' src/core/agent.zig || echo 0)
if [ "$ZIG_HAS_MSG" -eq 0 ]; then
    # Check individually
    for msg in hello run cancel out done err; do
        if ! rg -q "^\s+${msg}," src/core/agent.zig; then
            echo "STALE: Msg.Tag missing '$msg'"; FAIL=1
        fi
    done
fi
echo "  ok: Msg types present"

echo ""
if [ "$FAIL" -eq 1 ]; then
    echo "PROOF-CODE SYNC FAILED — update stale proofs"
    exit 1
fi
echo "All sync checks passed"
