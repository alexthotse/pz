# Lean 4 Policy Enforcement Proofs

**STATUS: SPECIFICATION — no proofs compiled yet. No `lean/` directory exists.**

Formal verification plan for pz's security-critical policy enforcement.
Enterprise deliverable: "mathematically proven impossible to bypass."

## Assumptions

- PLAN.md item P29 (signed policy bundle) is implemented
- EPISODES-PLAN.md file ownership is implemented
- P17 (Ed25519 signing) is already implemented (`src/core/signing.zig`)
- "No policy files on disk" = allow all (design choice, not a bug — documented as explicit assumption)

## Precedent

AWS Cedar — authorization policy language verified entirely in Lean 4.
See: [How We Built Cedar](https://assets.amazon.science/d3/86/99db1aa142ffb6981d86dc849e4c/how-we-built-cedar-a-verification-guided-approach.pdf)

## Setup

Install Lean 4 via elan:
```bash
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh
lake init pz-proofs math
```

Project: `lean/` directory in pz root. Does not compile with the Zig codebase — proofs model Zig logic abstractly.

### Model-Code Sync Strategy

Lean models will drift from Zig implementation unless actively maintained. Mitigations:
1. CI step: extract modeled constants from Zig source (mask bit count, mask operation, policy hash comparison function) and assert they match Lean model assumptions
2. Property tests in Zig encode the same invariants the Lean proofs verify — serve as canary for drift
3. Each proof's mapping doc specifies exact file:line ranges; code review of those files triggers proof review

## Proof 1: Tool Mask Sanitization

**Property**: The mask sanitizer strips unknown bits. No caller can enable a tool not in the known set.

**Status**: CAN PROVE NOW — models existing code.

**Zig code** (src/core/tools/builtin.zig:173):
```
.tool_mask = opts.tool_mask & mask_all,
```
where `mask_all` is the union of bits 0-9 (10 known tools).

**Lean model**:
```lean
def mask_all : BitVec 16 := 0x3FF  -- bits 0-9

theorem sanitize_strips_unknown (input : BitVec 16) :
    (input &&& mask_all) ≤ mask_all := by
  bv_decide

theorem sanitize_preserves_known (input : BitVec 16) :
    ∀ i : Fin 10, input.getLsbD i = true →
      (input &&& mask_all).getLsbD i = true := by
  bv_decide
```

**What it proves**: For ALL 2^16 possible mask inputs, sanitization never produces bits outside `mask_all`, and always preserves requested bits within the known set. Scope: mask layer ONLY — does not cover tool_auth or approval (separate access control layers providing defense-in-depth).

**Future extension**: When `thread_default_mask` is implemented (EPISODES-PLAN.md), add:
```lean
def thread_default : BitVec 16 := mask_all &&& ~~~(mask_bash ||| mask_agent)

theorem thread_no_escalation (parent req : BitVec 16) :
    (req &&& parent &&& thread_default) ≤ parent := by
  bv_decide
```

**Acceptance criteria**:
- Lean proof compiles and type-checks
- Models the actual expression at builtin.zig:173
- Effort: ~1 week including Lean setup
- Files: `lean/Pz/Mask.lean`
- Deps: none (models existing code)

## Proof 2: Signed Policy Tamper-Proof

**Property**: A signed policy bundle cannot be modified after signing without detection.

**Status**: PARTIALLY PROVABLE — Ed25519 primitives exist in `signing.zig`. Signed policy loading exists in `policy.zig:365-399` (`parseSignedDoc`, embedded PK verification). P29 (full signed bundle workflow) is in progress.

**Zig code** (src/core/policy.zig:365-399):
```
// parseSignedDoc verifies Ed25519 signature against embedded trusted PK
// before accepting policy content
```

RPC hash comparison (src/core/agent.zig:226):
```
if (!std.mem.eql(u8, msg.policy_hash, self.policy_hash)) return error.PolicyMismatch;
```
NOTE: `std.mem.eql` is NOT constant-time — timing side-channel. Fix in code (dot created).

**Lean model**: Abstract the crypto primitives:
```lean
class SignatureScheme where
  Key : Type
  Sig : Type
  Msg : Type
  sign : Key → Msg → Sig
  verify : Key → Msg → Sig → Bool
  correctness : ∀ k m, verify k m (sign k m) = true
  -- Conditional on crypto assumption, not absolute
  unforgeability : ∀ k m m' s, m ≠ m' → verify k m' (sign k m) = false
```

**What it proves**: Conditional on the `unforgeability` axiom (modeling EUF-CMA as an assumption, not proving Ed25519 correct), modified policy fails verification. The proof is conditional — it says "IF the signature scheme is unforgeable, THEN policy cannot be tampered." This is standard for applied crypto proofs.

**Acceptance criteria**:
- Lean proof compiles with abstract `SignatureScheme` typeclass
- Proves: modified policy fails verification
- Proves: RPC handshake rejects mismatched policy_hash
- Explicitly states the unforgeability assumption is conditional
- Reference: [Computationally-Sound Symbolic Crypto in Lean](https://eprint.iacr.org/2025/1700.pdf)
- Effort: ~2-3 months (beginner Lean + crypto modeling)
- Files: `lean/Pz/Policy.lean`, `lean/Pz/Crypto.lean`
- Deps: P29 (signed policy bundle workflow)

## Proof 3: File Ownership Exclusivity

**Property**: Two threads with disjoint `owned_paths` sets cannot both write to the same file.

**Status**: PLANNED — models code from EPISODES-PLAN.md Phase 1 (not yet implemented).

**Planned code** (EPISODES-PLAN.md):
```
-- Dispatch precondition (in runTool, loop.zig):
∀ t2 : t2 ≠ t ∧ state[t2] ∈ {pending, running} → owned[t] ∩ owned[t2] = {}
-- Write precondition:
f ∈ owned[t]
```

**Lean model**:
```lean
theorem ownership_exclusive (threads : Fin n → ThreadState)
    (dispatch_ok : ∀ i j, i ≠ j →
      threads i |>.state ∈ active →
      threads j |>.state ∈ active →
      threads i |>.owned ∩ threads j |>.owned = ∅) :
    ∀ i j f, i ≠ j →
      f ∈ threads i |>.owned →
      f ∈ threads j |>.owned →
      ¬(threads i |>.state ∈ active ∧ threads j |>.state ∈ active) := by
  intro i j f hne hfi hfj ⟨hai, haj⟩
  have := dispatch_ok i j hne hai haj
  exact Finset.not_mem_empty f (this ▸ Finset.mem_inter.mpr ⟨hfi, hfj⟩)
```

**What it proves**: Dispatch-time disjointness check → runtime write exclusivity, for arbitrary thread count `n`. Complements TLA+ spec (`FileOwnershipDisjoint` invariant) which only checks `n=3`.

**Acceptance criteria**:
- Lean proof compiles for arbitrary `n`
- Effort: ~2-3 months
- Files: `lean/Pz/Ownership.lean`
- Deps: EPISODES-PLAN.md Phase 1 file ownership implementation

## Proof 4: Approval Flow Soundness (NEW)

**Property**: Approved commands are scoped by (tool, command, location, policy hash, session lifetime). Expired approvals cannot match. Approvals cannot be replayed across policy changes.

**Status**: CAN PROVE NOW — models existing code. Note: CmdCache TTL bypass found during review (dot created) — `expires_at_ms` is never checked in `contains()`.

**Zig code** (src/core/loop.zig:157-230):
```
Key = { tool, cmd, loc: Loc, policy: ApprovalBind, life: Life }
Life = { session | expires_at_ms: i64 }
```

**What it proves**: The composite key structure ensures an approval for `(bash, "make test", cwd=/foo, policy_v3, session)` cannot match `(bash, "make test", cwd=/bar, policy_v4, session)`. The proof covers key equality semantics and scoping. After the TTL bug fix, also proves time-bounded approvals expire.

**Acceptance criteria**:
- Lean proof models CmdCache.Key structure
- Proves: different policy hash → different key → no match
- Proves: different location → no match
- Proves: expired TTL → no match (after code fix)
- Effort: ~1-2 months
- Files: `lean/Pz/Approval.lean`
- Deps: CmdCache TTL fix (dot exists)

## Future Candidates

**Path guard invariants**: `path_guard.zig` provides TOCTOU-safe file access (symlink prevention, hardlink detection, stable inode checks). Strong candidate for formal proof — the invariants (no symlink traversal, no hardlink aliasing) are expressible as decidable predicates.

**Network egress blocklist**: `isBlockedNetAddr` in `policy.zig:190-222` is a fixed function with well-defined IP range inputs. `bv_decide` could prove completeness of the RFC 1918/loopback/link-local blocklist.

**Bash command filter**: `deniesProtectedCmd` in `bash.zig` currently fails open on tokenizer errors (dot created). After fix, the filter's soundness could be proven.

## Implementation Order

1. **Mask sanitization** (POC, ~1 week) — proves existing code, validates Lean setup
2. **Approval flow** (~1-2 months) — proves existing code (after TTL fix), high security value
3. **File ownership** (~2-3 months) — after EPISODES-PLAN.md Phase 1
4. **Signed policy** (~2-3 months) — after P29, highest enterprise value

## Deliverables

Each proof produces:
- `.lean` source file (machine-checkable)
- One-paragraph natural-language statement of what was proven
- Mapping from Lean model to Zig implementation (file:line ranges)
- CI validation step ensuring model-code correspondence

Enterprise artifact (when all proofs complete): "pz's policy enforcement has been formally verified in Lean 4. The proofs establish that tool mask sanitization cannot be bypassed, approval scoping prevents cross-context replay, signed policies cannot be tampered with, and file ownership boundaries cannot be violated. These properties hold for all possible inputs, not just tested cases. Proofs are conditional on standard cryptographic assumptions for the signature scheme."

## Review Findings (Round 1 — baseline L1-314a)

4 agents. Findings incorporated above. Key results:
- All original proofs modeled planned code, not existing code. Fixed: Proof 1 now models actual `builtin.zig:173`.
- Approval flow (CmdCache) was uncovered. Fixed: added Proof 4.
- CmdCache TTL bypass found — `expires_at_ms` never checked. Dot created.
- `std.mem.eql` timing side-channel in policy hash. Dot created.
- `deniesProtectedCmd` fails open on parse error. Dot created.
- P17 already implemented. Stale dependency removed.
- Effort estimates increased for Lean beginners.
