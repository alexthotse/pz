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
-- Model mask_all as explicit OR of named bits (matches Zig source structure).
-- Note: mask bit indices ≠ Kind enum ordinals (web=Kind.8 has no mask bit,
-- ask uses bit 8, skill uses bit 9). The Lean model enumerates mask bits
-- by name, not by Kind index.
-- CI sync: assert mask_all value AND (Kind.count - unmaskable_count) == popcount(mask_all).
def mask_all : BitVec 16 :=
  (1 <<< 0) ||| (1 <<< 1) ||| (1 <<< 2) ||| (1 <<< 3) ||| (1 <<< 4) |||
  (1 <<< 5) ||| (1 <<< 6) ||| (1 <<< 7) ||| (1 <<< 8) ||| (1 <<< 9)
  -- read write bash edit grep find ls agent ask skill

theorem sanitize_strips_unknown (input : BitVec 16) :
    (input &&& mask_all) ≤ mask_all := by
  bv_decide

theorem sanitize_preserves_known (input : BitVec 16) (i : Fin 10) :
    input.getLsbD i = true →
      (input &&& mask_all).getLsbD i = true := by
  bv_decide
```

**What it proves**: For ALL 2^16 possible mask inputs, sanitization never produces bits outside `mask_all`, and always preserves requested bits within the known set. Scope: mask layer ONLY — does not cover tool_auth or approval (separate access control layers providing defense-in-depth). Note: `tools.Kind.web` (11th variant) has no mask bit and sits outside the mask system entirely — not covered by this proof. CI sync should flag `Kind` enum changes.

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
NOTE: `std.mem.eql` is NOT constant-time — timing side-channel at 3 locations:
- `agent.zig:226` (policy hash comparison)
- `policy.zig:54` (ApprovalBind hash comparison)
- `policy.zig:391` (public key comparison — highest priority, leaks signing key info)
Fix all in code (dot created).

**Lean model**: Model the parse→canonicalize→verify pipeline, not just the signature scheme:
```lean
class SignatureScheme where
  Key : Type
  Sig : Type
  Msg : Type
  sign : Key → Msg → Sig
  verify : Key → Msg → Sig → Bool
  correctness : ∀ k m, verify k m (sign k m) = true
  -- Idealized unforgeability (stronger than EUF-CMA — assumes perfect security)
  unforgeability : ∀ k m m' s, m ≠ m' → verify k m' (sign k m) = false

-- Model the actual verification pipeline
def canonicalize (raw : RawPolicy) : Policy := parseDoc raw |> encodeDoc
def verifyPolicy (key : Key) (raw : RawPolicy) (sig : Sig) : Bool :=
  verify key (canonicalize raw) sig
```

**What it proves**: The signature covers the **canonical re-serialization** (`parseDoc → encodeDoc`), not raw JSON bytes. The proof models the three-step chain and proves:
- Any modification to canonical content (including rule reordering — rules are an ordered list, not a set, because `evaluate` uses first-match-wins for path rules; note: `evalEnv` uses last-match-wins for env rules — different semantics, same `Rule` type) fails verification
- `parseDoc` is invariant to the presence/absence/content of the `signature` key in input JSON — model this as an explicit `excludeField "signature"` step, not an implicit omission. CI sync: assert `parseDoc` never reads a key named `"signature"`
- Extra JSON fields not parsed by `parseDoc` are silently dropped — proof covers canonical content integrity, not raw-byte integrity

The `unforgeability` axiom is idealized (stronger than computational EUF-CMA) — sufficient for the enterprise deliverable but should not be cited as a game-based crypto proof.

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

**Lean model**: Inductive invariant over the dispatch state machine — prove that NO sequence of valid operations can reach a state where two active threads share a file.
```lean
inductive Op
  | dispatch (t : Fin n) (files : Finset File)  -- assign files to thread t
  | complete (t : Fin n)                         -- thread t finishes, releases files

def step (s : State n) : Op → Option (State n)
  | .dispatch t files =>
    -- Precondition: t is unused, files disjoint from all active threads
    if s.threads[t].status = .unused ∧
       ∀ j, j ≠ t → s.threads[j].status ∈ active →
         files ∩ s.threads[j].owned = ∅
    then some (s.activate t files)
    else none
  | .complete t => some (s.deactivate t)

-- The inductive invariant: disjointness holds in all reachable states
theorem ownership_invariant :
    ∀ (ops : List Op) (s : State n),
      s = initial →
      (s' = foldOps s ops) →
      ∀ i j, i ≠ j →
        s'.threads[i].status ∈ active →
        s'.threads[j].status ∈ active →
        s'.threads[i].owned ∩ s'.threads[j].owned = ∅
```

**What it proves**: Starting from an empty state, no sequence of dispatch/complete/reassign operations can violate file ownership disjointness. This is the inductive invariant — not a tautology from a hypothesis, but a proof that the dispatch precondition is sufficient to maintain the invariant across all state transitions. Complements TLA+ spec (`FileOwnershipDisjoint`) which only checks `n=3`; Lean proof is universal over all `n`.

**Acceptance criteria**:
- Lean proof compiles for arbitrary `n`
- Effort: ~2-3 months
- Files: `lean/Pz/Ownership.lean`
- Deps: EPISODES-PLAN.md Phase 1 file ownership implementation

## Proof 4: Approval Flow Soundness (NEW)

**Property**: Approved commands are scoped by (tool, command, location, policy hash, session lifetime). Expired approvals cannot match. Approvals cannot be replayed across policy changes.

**Status**: PARTIALLY PROVABLE. Split into:
- **4a** (key scoping — CAN PROVE NOW): composite key ensures approvals are scoped by tool/cmd/loc/policy
- **4b** (TTL expiry — BLOCKED on code fix): `expires_at_ms` is compared for equality in `eqlLife` but never checked against wall clock in `contains()`. Dot created.

**Zig code** (src/core/loop.zig:158-208 struct+contains, 284-316 eql+eqlLife):
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

Enterprise artifact (when all proofs complete): "Four specific security properties of pz's policy enforcement have been formally verified in Lean 4: (1) tool mask sanitization strips unknown bits for all inputs, (2) approval keys are scoped by tool/command/location/policy/lifetime, (3) signed policy canonical content cannot be modified without detection under an idealized unforgeability assumption, (4) file ownership dispatch maintains disjointness across all state transitions. These properties hold for all possible inputs and all reachable states, not just tested cases."

## Review Findings (Round 1 — baseline L1-314a)

4 agents. Findings incorporated above. Key results:
- All original proofs modeled planned code, not existing code. Fixed: Proof 1 now models actual `builtin.zig:173`.
- Approval flow (CmdCache) was uncovered. Fixed: added Proof 4.
- CmdCache TTL bypass found — `expires_at_ms` never checked. Dot created.
- `std.mem.eql` timing side-channel in policy hash. Dot created.
- `deniesProtectedCmd` fails open on parse error. Dot created.
- P17 already implemented. Stale dependency removed.
- Effort estimates increased for Lean beginners.
