/-
  Proof: Agent output truncation invariant.

  Models src/core/tools/truncate.zig (apply) and
  src/core/tools/agent.zig (finish → renderAlloc → truncate.apply).

  The agent tool renders child output into a byte buffer, then truncates
  to max_bytes via truncate.apply which takes List.take on the prefix.

  Proves:
  1. Total output length never exceeds max_bytes
  2. Truncation preserves the prefix (first max_bytes bytes)
  3. Output assembly is deterministic (same inputs → same output)
-/

-- Model truncate.zig TruncMeta
structure TruncMeta where
  limit_bytes : Nat
  full_bytes : Nat
  kept_bytes : Nat
  dropped_bytes : Nat
  deriving DecidableEq, Repr

-- Model truncate.zig Truncated (tmeta avoids `meta` keyword)
structure Truncated where
  chunk : List UInt8
  truncated : Bool
  tmeta : Option TruncMeta
  deriving DecidableEq, Repr

-- Model truncate.apply: full[0..min(len, limit)]
@[reducible] def truncApply (full : List UInt8) (limit : Nat) : Truncated :=
  if full.length ≤ limit then
    { chunk := full, truncated := false, tmeta := none }
  else
    { chunk := full.take limit,
      truncated := true,
      tmeta := some {
        limit_bytes := limit,
        full_bytes := full.length,
        kept_bytes := limit,
        dropped_bytes := full.length - limit } }

-- Model agent.zig Out message
structure OutMsg where
  id : String
  text : List UInt8
  deriving DecidableEq, Repr

-- Model agent.zig Done message
inductive StopReason where
  | done | canceled | err
  deriving DecidableEq, Repr

structure DoneMsg where
  id : String
  stop : StopReason
  truncated : Bool
  deriving DecidableEq, Repr

-- Model ChildProc.RunResult
structure RunResult where
  out : Option OutMsg
  done : Option DoneMsg
  deriving DecidableEq, Repr

-- Model renderAlloc: header ++ body
@[reducible] def renderOutput (header : List UInt8) (rr : RunResult) : List UInt8 :=
  header ++ match rr.out with
  | some msg => msg.text
  | none => []

-- Model finish: render then truncate
@[reducible] def assembleOutput (header : List UInt8) (rr : RunResult) (maxBytes : Nat) : Truncated :=
  truncApply (renderOutput header rr) maxBytes

-- ============================================================
-- Theorem 1: Output length never exceeds max_bytes
-- ============================================================

theorem truncApply_length_le (full : List UInt8) (limit : Nat) :
    (truncApply full limit).chunk.length ≤ limit := by
  unfold truncApply
  split
  · assumption
  · simp [List.length_take]; omega

theorem output_bounded (header : List UInt8) (rr : RunResult) (maxBytes : Nat) :
    (assembleOutput header rr maxBytes).chunk.length ≤ maxBytes :=
  truncApply_length_le _ _

-- ============================================================
-- Theorem 2: Truncation preserves the prefix
-- ============================================================

theorem truncApply_is_prefix (full : List UInt8) (limit : Nat) :
    (truncApply full limit).chunk <+: full := by
  unfold truncApply
  split
  · exact List.prefix_refl full
  · exact List.take_prefix _ _

theorem output_preserves_prefix (header : List UInt8) (rr : RunResult) (maxBytes : Nat) :
    (assembleOutput header rr maxBytes).chunk <+: renderOutput header rr :=
  truncApply_is_prefix _ _

-- ============================================================
-- Theorem 3: Determinism — same inputs → same output
-- ============================================================

theorem output_deterministic
    (header : List UInt8) (rr : RunResult) (maxBytes : Nat) :
    assembleOutput header rr maxBytes = assembleOutput header rr maxBytes :=
  rfl

theorem output_deterministic_ext
    (h1 h2 : List UInt8) (rr1 rr2 : RunResult) (m1 m2 : Nat)
    (hh : h1 = h2) (hr : rr1 = rr2) (hm : m1 = m2) :
    assembleOutput h1 rr1 m1 = assembleOutput h2 rr2 m2 := by
  subst hh; subst hr; subst hm; rfl

-- ============================================================
-- Additional properties
-- ============================================================

-- No truncation when output fits
theorem truncApply_no_trunc_when_fits (full : List UInt8) (limit : Nat)
    (h : full.length ≤ limit) :
    (truncApply full limit).truncated = false := by
  unfold truncApply; split
  · rfl
  · omega

-- Truncation flag set when output exceeds limit
theorem truncApply_trunc_when_exceeds (full : List UInt8) (limit : Nat)
    (h : full.length > limit) :
    (truncApply full limit).truncated = true := by
  unfold truncApply; split
  · omega
  · rfl

-- Meta records correct byte counts when truncated
theorem truncApply_meta_correct (full : List UInt8) (limit : Nat) (m : TruncMeta)
    (h : full.length > limit)
    (hm : (truncApply full limit).tmeta = some m) :
    m.full_bytes = full.length ∧
    m.kept_bytes = limit ∧
    m.dropped_bytes = full.length - limit ∧
    m.limit_bytes = limit := by
  unfold truncApply at hm
  split at hm
  · omega
  · simp [Option.some.injEq] at hm; subst hm; exact ⟨rfl, rfl, rfl, rfl⟩

-- No meta when not truncated
theorem truncApply_no_meta_when_fits (full : List UInt8) (limit : Nat)
    (h : full.length ≤ limit) :
    (truncApply full limit).tmeta = none := by
  unfold truncApply; split
  · rfl
  · omega

-- Empty input always produces empty output
theorem truncApply_empty (limit : Nat) :
    (truncApply [] limit).chunk = [] := by
  unfold truncApply; simp

-- Idempotence: truncating already-truncated output is identity
theorem truncApply_idempotent (full : List UInt8) (limit : Nat) :
    (truncApply (truncApply full limit).chunk limit).chunk =
      (truncApply full limit).chunk := by
  have hle := truncApply_length_le full limit
  unfold truncApply
  split
  · -- full fits: chunk = full, second call sees full.length ≤ limit → identity
    simp_all
  · -- full exceeds: chunk = take limit full, length = min limit full.length ≤ limit
    simp only [List.length_take]
    have : min limit full.length ≤ limit := Nat.min_le_left ..
    simp_all
