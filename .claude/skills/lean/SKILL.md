---
name: lean
description: 'Build and check Lean 4 proofs. Triggers: "lean build", "check proofs", "run lean", "verify proofs", "lean".'
user_invocable: true
---

# Lean 4 Proofs

Build and type-check the formal verification proofs in `lean/`.

## Toolchain

- elan: `~/.elan/bin/`
- lean/lake/leanc: all via elan
- Project: `lean/` in pz root, initialized with `lake init pz-proofs math`

## Build

```bash
cd lean && ~/.elan/bin/lake build
```

First build downloads mathlib (~10 min). Subsequent builds are incremental (~seconds).

If `.lake/` is corrupt: `rm -rf .lake && lake update && lake build`.
After adding a dependency to `lakefile.toml`: `lake update` before `lake build`.

## Project Structure

```
lean/
  lakefile.toml          # project config, mathlib dependency
  lean-toolchain         # pinned lean version
  PzProofs.lean          # root module (imports all proof files)
  PzProofs/
    Basic.lean           # auto-generated stub
    Mask.lean            # Proof 1: tool mask sanitization
    Approval.lean        # Proof 4: approval flow (future)
    Policy.lean          # Proof 2: signed policy (future)
    Ownership.lean       # Proof 3: file ownership (future)
    Crypto.lean          # abstract signature scheme (future)
```

## Adding a Proof

1. Create `lean/PzProofs/Name.lean`
2. Add `import PzProofs.Name` to `lean/PzProofs.lean`
3. `cd lean && ~/.elan/bin/lake build`
4. If it type-checks, the proof is valid

## Key Tactics

- `bv_decide`: automatic bitvector reasoning via SAT. Handles all mask proofs.
- `omega`: linear arithmetic over naturals/integers
- `simp`: simplification with lemma database
- `intro`/`exact`/`have`: manual proof steps
- `by decide`: decidable propositions (finite enums, bool)

## BitVec for Mask Proofs

Zig `u16` maps to Lean `BitVec 16`. Operations:
- `&&&` = bitwise AND, `|||` = bitwise OR, `~~~` = complement
- `<<<` = shift left, `≤` = unsigned less-or-equal
- `.getLsbD i` = get bit at position i

`bv_decide` solves all fixed-width bitvector properties exhaustively.

## Proof Plan

See `docs/LEAN-PROOF.md` for the full verification plan with 4 proofs, acceptance criteria, and dependencies.
