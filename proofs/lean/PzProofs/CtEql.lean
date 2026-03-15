import Std.Tactic.BVDecide

/-
  Proof: ctEql (XOR-accumulate constant-time comparison) is correct.
  Models src/core/signing.zig:9-14.
-/

set_option relaxedAutoImplicit false

-- XOR of two bytes is zero iff they are equal
theorem xor_zero_iff (a b : BitVec 8) : a ^^^ b = 0 ↔ a = b := by
  bv_decide

-- OR with nonzero propagates
theorem or_nonzero (a b : BitVec 8) (h : a ≠ 0) : a ||| b ≠ 0 := by
  bv_decide

-- OR is commutative for nonzero propagation
theorem or_nonzero_right (a b : BitVec 8) (h : b ≠ 0) : a ||| b ≠ 0 := by
  bv_decide

-- Single byte: XOR detects any difference
theorem single_byte_diff (a b : BitVec 8) (h : a ≠ b) : a ^^^ b ≠ 0 := by
  bv_decide

-- Single byte: XOR is zero for equal bytes
theorem single_byte_eq (a : BitVec 8) : a ^^^ a = 0 := by
  bv_decide

-- OR accumulation: zero base stays zero with zero input
theorem or_zero_zero : (0 : BitVec 8) ||| (0 : BitVec 8) = 0 := by
  bv_decide

-- OR accumulation: nonzero never becomes zero
theorem or_preserves_nonzero (acc x : BitVec 8) (h : acc ≠ 0) : acc ||| x ≠ 0 := by
  bv_decide

-- OR of a ||| b = 0 implies both a = 0 and b = 0
theorem or_eq_zero (a b : BitVec 8) : a ||| b = 0 ↔ a = 0 ∧ b = 0 := by
  bv_decide

-- Model the accumulation loop
def accumLoop : List (BitVec 8) → List (BitVec 8) → BitVec 8
  | [], [] => 0
  | x :: xs, y :: ys => (x ^^^ y) ||| accumLoop xs ys
  | _, _ => 0  -- length mismatch (handled by length check in Zig)

-- Equal lists produce zero accumulator
theorem accum_eq (xs : List (BitVec 8)) : accumLoop xs xs = 0 := by
  induction xs with
  | nil => simp [accumLoop]
  | cons x xs ih =>
    simp only [accumLoop]
    rw [single_byte_eq x, ih]
    rfl

-- The full ctEql function
def ctEql (a b : List (BitVec 8)) : Bool :=
  a.length == b.length && accumLoop a b == 0

-- Equal lists return true
theorem ctEql_refl (xs : List (BitVec 8)) : ctEql xs xs = true := by
  simp [ctEql, accum_eq]

-- Different lengths return false
theorem ctEql_diff_len (a b : List (BitVec 8)) (h : a.length ≠ b.length) :
    ctEql a b = false := by
  simp [ctEql]
  omega

-- accumLoop zero implies element-wise equality
theorem accum_zero_imp_eq :
    ∀ (a b : List (BitVec 8)), accumLoop a b = 0 → a.length = b.length → a = b
  | [], [], _, _ => rfl
  | [], _ :: _, _, h => by simp at h
  | _ :: _, [], _, h => by simp at h
  | x :: xs, y :: ys, hacc, hlen => by
    have ⟨hxor, htail⟩ := (or_eq_zero _ _).mp hacc
    have heq := (xor_zero_iff x y).mp hxor
    have hlen' : xs.length = ys.length := by simp at hlen; exact hlen
    rw [heq, accum_zero_imp_eq xs ys htail hlen']

/--
  Theorem 1 (Correctness): ctEql a b = true ↔ a = b
-/
theorem ctEql_iff (a b : List (BitVec 8)) : ctEql a b = true ↔ a = b := by
  constructor
  · intro h
    simp [ctEql] at h
    exact accum_zero_imp_eq a b h.2 h.1
  · intro h
    subst h
    exact ctEql_refl a

/--
  Theorem 2 (Single byte difference): A difference at the head is always detected.
-/
theorem single_byte_diff_detected (x y : BitVec 8) (xs : List (BitVec 8))
    (hne : x ≠ y) : ctEql (x :: xs) (y :: xs) = false := by
  rw [Bool.eq_false_iff]
  intro h
  have heq := (ctEql_iff (x :: xs) (y :: xs)).mp h
  exact hne (List.cons.inj heq |>.1)

/--
  Theorem 3 (Positional detection): XOR accumulation detects a difference
  at any position in equal-length lists.
-/
theorem accum_detects_diff :
    ∀ (a b : List (BitVec 8)), a.length = b.length → a ≠ b → accumLoop a b ≠ 0
  | [], [], _, hne => absurd rfl hne
  | [], _ :: _, hlen, _ => by simp at hlen
  | _ :: _, [], hlen, _ => by simp at hlen
  | x :: xs, y :: ys, hlen, hne => by
    simp at hlen
    intro h
    have ⟨hxor, htail⟩ := (or_eq_zero _ _).mp h
    have heq := (xor_zero_iff x y).mp hxor
    have htl := accum_zero_imp_eq xs ys htail hlen
    exact hne (by rw [heq, htl])

-- Corollary: any positional difference causes ctEql to return false
theorem ctEql_false_of_diff (a b : List (BitVec 8))
    (hlen : a.length = b.length) (hne : a ≠ b) : ctEql a b = false := by
  rw [Bool.eq_false_iff]
  intro h
  exact hne ((ctEql_iff a b).mp h)
