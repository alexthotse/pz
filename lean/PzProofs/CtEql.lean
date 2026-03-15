import Mathlib.Data.List.Zip

/-
  Proof: XOR-accumulate constant-time comparison is correct.

  Models src/core/signing.zig:9-14:
    pub fn ctEql(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        var diff: u8 = 0;
        for (a, b) |x, y| diff |= x ^ y;
        return diff == 0;
    }

  Proves:
    1. ctEql a b = true ↔ a = b (correctness)
    2. Single byte difference always detected
    3. XOR accumulation detects any position difference
-/

set_option relaxedAutoImplicit false

/-- XOR accumulator over paired byte lists. Models the `diff |= x ^ y` loop. -/
def xorAccum : List (BitVec 8) → List (BitVec 8) → BitVec 8
  | [], [] => 0
  | x :: xs, y :: ys => (x ^^^ y) ||| xorAccum xs ys
  | _, _ => 0  -- length mismatch handled separately

/-- Constant-time equality: same length and XOR accumulator is zero. -/
def ctEql (a b : List (BitVec 8)) : Bool :=
  a.length == b.length && xorAccum a b == 0

-- Helper: xorAccum of a list with itself is zero.
theorem xorAccum_self (xs : List (BitVec 8)) : xorAccum xs xs = 0 := by
  induction xs with
  | nil => simp [xorAccum]
  | cons x xs ih =>
    simp [xorAccum]
    constructor
    · exact BitVec.xor_self x
    · exact ih

-- Helper: if xorAccum is zero, every element pair XORs to zero.
theorem xorAccum_zero_imp_heads {x y : BitVec 8} {xs ys : List (BitVec 8)}
    (h : xorAccum (x :: xs) (y :: ys) = 0) : x ^^^ y = 0 := by
  simp [xorAccum] at h
  exact h.1

theorem xorAccum_zero_imp_tails {x y : BitVec 8} {xs ys : List (BitVec 8)}
    (h : xorAccum (x :: xs) (y :: ys) = 0) : xorAccum xs ys = 0 := by
  simp [xorAccum] at h
  exact h.2

-- Helper: XOR zero means equal for 8-bit vectors.
theorem bv8_xor_zero_iff (a b : BitVec 8) : a ^^^ b = 0 ↔ a = b := by
  constructor
  · intro h
    have := BitVec.xor_cancel_right a b
    rw [show a ^^^ b ^^^ b = a ^^^ (b ^^^ b) from by
      rw [BitVec.xor_assoc]]
    rw [BitVec.xor_self, BitVec.xor_zero] at this
    rw [h, BitVec.zero_xor]
  · intro h
    rw [h, BitVec.xor_self]

-- Helper: xorAccum zero implies lists are equal (same length assumed).
theorem xorAccum_zero_imp_eq :
    ∀ (a b : List (BitVec 8)), xorAccum a b = 0 → a.length = b.length → a = b
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp at h
  | _ :: _, [], _, h => by simp at h
  | x :: xs, y :: ys, hacc, hlen => by
    have hhead := xorAccum_zero_imp_heads hacc
    have htail := xorAccum_zero_imp_tails hacc
    have heq := (bv8_xor_zero_iff x y).mp hhead
    have hlen' : xs.length = ys.length := by simp at hlen; exact hlen
    have htl := xorAccum_zero_imp_eq xs ys htail hlen'
    rw [heq, htl]

-- Helper: equal lists have xorAccum zero.
theorem eq_imp_xorAccum_zero :
    ∀ (a b : List (BitVec 8)), a = b → xorAccum a b = 0
  | _, _, rfl => xorAccum_self _

/--
  Theorem 1 (Correctness): ctEql a b = true ↔ a = b

  The XOR-accumulate comparison returns true if and only if
  the two byte lists are identical.
-/
theorem ctEql_iff (a b : List (BitVec 8)) : ctEql a b = true ↔ a = b := by
  simp [ctEql, Bool.and_eq_true]
  constructor
  · intro ⟨hlen, hacc⟩
    have hlen' := beq_iff_eq.mp hlen
    have hacc' : xorAccum a b = 0 := by
      have := beq_iff_eq.mp hacc
      exact this
    exact xorAccum_zero_imp_eq a b hacc' hlen'
  · intro h
    rw [h]
    constructor
    · exact beq_iff_eq.mpr rfl
    · have : xorAccum b b = 0 := xorAccum_self b
      exact beq_iff_eq.mpr this

/--
  Theorem 2 (Single byte difference): If two same-length lists differ at
  exactly one byte, ctEql detects it.
-/
theorem single_byte_diff_detected (x y : BitVec 8) (xs : List (BitVec 8))
    (hne : x ≠ y) : ctEql (x :: xs) (y :: xs) = false := by
  simp [ctEql, xorAccum, xorAccum_self]
  intro h
  exact hne ((bv8_xor_zero_iff x y).mp h)

/--
  Theorem 3 (Positional detection): XOR accumulation detects a difference
  at any position in the list.
-/
theorem xorAccum_detects_diff :
    ∀ (a b : List (BitVec 8)), a.length = b.length → a ≠ b → xorAccum a b ≠ 0
  | [], [], _, hne => absurd rfl hne
  | [], _ :: _, hlen, _ => by simp at hlen
  | _ :: _, [], hlen, _ => by simp at hlen
  | x :: xs, y :: ys, hlen, hne => by
    simp at hlen
    by_cases hxy : x = y
    · -- heads equal, diff must be in tails
      have htne : xs ≠ ys := by
        intro heq
        exact hne (by rw [hxy, heq])
      have ih := xorAccum_detects_diff xs ys hlen htne
      simp [xorAccum, hxy, BitVec.xor_self]
      exact ih
    · -- heads differ, XOR is nonzero, OR propagates it
      simp [xorAccum]
      intro h
      exact hxy ((bv8_xor_zero_iff x y).mp h)

/-- Corollary: any positional difference causes ctEql to return false. -/
theorem ctEql_false_of_diff (a b : List (BitVec 8))
    (hlen : a.length = b.length) (hne : a ≠ b) : ctEql a b = false := by
  simp [ctEql]
  intro _
  have := xorAccum_detects_diff a b hlen hne
  intro heq
  exact this (beq_iff_eq.mp heq)
