/-
  Proof: HMAC audit chain integrity.

  Models src/core/audit_integrity.zig:74-146 (verifyLogAlloc, calcMac).

  Chain structure (verified left-to-right):
    line[0]: prev = none,          mac[0] = HMAC(key, body[0] ++ "-")
    line[i]: prev = some mac[i-1], mac[i] = HMAC(key, body[i] ++ hex(mac[i-1]))

  Verification: recompute mac from (body, prev), compare against stored mac;
  check that stored prev matches previous line's mac.

  Proves:
  1. First line's prev is none
  2. Body modification → verification fails
  3. MAC modification → verification fails
  4. Line removal breaks verification
  5. Reordering (swap) breaks verification
  6. Valid chain implies correct MACs and linkage
-/

-- Abstract HMAC: key + message → tag, with collision resistance.
-- Models HmacSha256 from audit_integrity.zig.
structure HmacOps (Tag : Type) where
  hmac : Tag → String → Tag
  /-- Collision resistance: same key, different messages → different tags -/
  collision_resistant : ∀ (k : Tag) (m1 m2 : String), m1 ≠ m2 → hmac k m1 ≠ hmac k m2

-- A sealed log line (models audit_integrity.zig Line struct)
structure SealedLine (Tag : Type) where
  body : String
  mac : Tag
  prev : Option Tag
  deriving DecidableEq

-- MAC input construction (models calcMac: prev_serialized ++ "\n" ++ body).
-- serialize models hex encoding of tags (injective).
def macInput (Tag : Type) (serialize : Tag → String) (prev : Option Tag) (body : String) : String :=
  match prev with
  | none => "-\n" ++ body
  | some t => serialize t ++ "\n" ++ body

-- Verification with accumulator (models verifyLogAlloc's walk).
-- Walks lines left-to-right, tracking expected prev MAC.
def verifyAux (Tag : Type) [DecidableEq Tag] (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag) :
    List (SealedLine Tag) → Option Tag → Bool
  | [], _ => true
  | l :: rest, ep =>
    (decide (l.prev = ep) &&
     decide (l.mac = ops.hmac key (macInput Tag serialize l.prev l.body))) &&
    verifyAux Tag serialize ops key rest (some l.mac)

def verifyChain (Tag : Type) [DecidableEq Tag] (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag) (chain : List (SealedLine Tag)) : Bool :=
  verifyAux Tag serialize ops key chain none

-- ============================================================
-- Helper: decompose a successful verifyAux step
-- ============================================================

private theorem verifyAux_cons {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key (l :: rest) ep = true) :
    l.prev = ep ∧
    l.mac = ops.hmac key (macInput Tag serialize l.prev l.body) ∧
    verifyAux Tag serialize ops key rest (some l.mac) = true := by
  simp only [verifyAux, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.1.1, h.1.2, h.2⟩

-- ============================================================
-- Theorem 1: First line's prev is none (initial value)
-- ============================================================

theorem first_prev_none {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (rest : List (SealedLine Tag))
    (h : verifyChain Tag serialize ops key (l :: rest) = true) :
    l.prev = none :=
  (verifyAux_cons serialize ops key l rest none h).1

-- ============================================================
-- Helper: macInput is injective in body
-- ============================================================

private theorem macInput_body_ne {Tag : Type} (serialize : Tag → String)
    (prev : Option Tag) (b1 b2 : String)
    (h : b1 ≠ b2) :
    macInput Tag serialize prev b1 ≠ macInput Tag serialize prev b2 := by
  intro heq
  apply h
  unfold macInput at heq
  cases prev with
  | none =>
    have h1 : ("-\n" ++ b1).toList = ("-\n" ++ b2).toList := congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1
  | some _ =>
    have h1 : (serialize _ ++ "\n" ++ b1).toList = (serialize _ ++ "\n" ++ b2).toList :=
      congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1

-- ============================================================
-- Theorem 2: Body modification → verification fails
-- ============================================================

theorem body_tamper_detected {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (body' : String) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key (l :: rest) ep = true)
    (h_diff : l.body ≠ body') :
    verifyAux Tag serialize ops key
      ({ l with body := body' } :: rest) ep = false := by
  obtain ⟨_, h_mac, _⟩ := verifyAux_cons serialize ops key l rest ep h_valid
  have h_input_ne := macInput_body_ne serialize l.prev l.body body' h_diff
  have h_mac_ne := ops.collision_resistant key _ _ h_input_ne
  -- l.mac = hmac key (macInput prev body) ≠ hmac key (macInput prev body')
  have h_ne : l.mac ≠ ops.hmac key (macInput Tag serialize l.prev body') := by
    rw [h_mac]; exact h_mac_ne
  simp only [verifyAux]
  have : decide (l.mac = ops.hmac key (macInput Tag serialize l.prev body')) = false :=
    decide_eq_false h_ne
  rw [Bool.and_assoc, Bool.and_comm (decide (l.prev = ep)), Bool.and_assoc,
      Bool.and_comm (decide (l.mac = _)), this]
  simp

-- Corollary: body tamper at first position
theorem body_tamper_first {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (body' : String) (rest : List (SealedLine Tag))
    (h_valid : verifyChain Tag serialize ops key (l :: rest) = true)
    (h_diff : l.body ≠ body') :
    verifyChain Tag serialize ops key ({ l with body := body' } :: rest) = false :=
  body_tamper_detected serialize ops key l body' rest none h_valid h_diff

-- ============================================================
-- Theorem 3: MAC modification → verification fails
-- The tampered line itself fails: recomputed MAC won't match mac'.
-- ============================================================

theorem mac_tamper_detected {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (mac' : Tag) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key (l :: rest) ep = true)
    (h_diff : l.mac ≠ mac') :
    verifyAux Tag serialize ops key
      ({ l with mac := mac' } :: rest) ep = false := by
  obtain ⟨_, h_mac, _⟩ := verifyAux_cons serialize ops key l rest ep h_valid
  have h_ne : mac' ≠ ops.hmac key (macInput Tag serialize l.prev l.body) := by
    intro heq; exact h_diff (h_mac ▸ heq.symm ▸ rfl)
  simp only [verifyAux]
  have : decide (mac' = ops.hmac key (macInput Tag serialize l.prev l.body)) = false :=
    decide_eq_false h_ne
  rw [Bool.and_assoc, Bool.and_comm (decide (l.prev = ep)), Bool.and_assoc,
      Bool.and_comm (decide (mac' = _)), this]
  simp

-- ============================================================
-- Theorem 4: Line removal breaks chain continuity
-- Removing the middle line from [l0, l1, l2, ...] gives [l0, l2, ...].
-- l2.prev = some l1.mac but expected_prev becomes some l0.mac.
-- ============================================================

theorem removal_breaks_chain {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l0 l1 l2 : SealedLine Tag) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key (l0 :: l1 :: l2 :: rest) ep = true)
    (h_mac_diff : l0.mac ≠ l1.mac) :
    verifyAux Tag serialize ops key (l0 :: l2 :: rest) ep = false := by
  obtain ⟨h0_prev, h0_mac, h_r1⟩ := verifyAux_cons serialize ops key l0 (l1 :: l2 :: rest) ep h_valid
  obtain ⟨_, _, h_r2⟩ := verifyAux_cons serialize ops key l1 (l2 :: rest) (some l0.mac) h_r1
  obtain ⟨h2_prev, _, _⟩ := verifyAux_cons serialize ops key l2 rest (some l1.mac) h_r2
  -- l2.prev = some l1.mac, but after removal expected = some l0.mac
  have h_prev_ne : l2.prev ≠ some l0.mac := by
    rw [h2_prev]; intro h; exact h_mac_diff (Option.some.inj h.symm)
  simp only [verifyAux]
  have hd0 : decide (l0.prev = ep) = true := decide_eq_true h0_prev
  have hm0 : decide (l0.mac = ops.hmac key (macInput Tag serialize l0.prev l0.body)) = true :=
    decide_eq_true h0_mac
  have hd2 : decide (l2.prev = some l0.mac) = false := decide_eq_false h_prev_ne
  rw [hd0, hm0, hd2]
  simp

-- ============================================================
-- Theorem 5: Reordering (swap) breaks chain
-- Swapping first two lines: l1 has prev = some l0.mac ≠ none
-- ============================================================

theorem swap_breaks_chain {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l0 l1 : SealedLine Tag) (rest : List (SealedLine Tag))
    (h_valid : verifyChain Tag serialize ops key (l0 :: l1 :: rest) = true) :
    verifyChain Tag serialize ops key (l1 :: l0 :: rest) = false := by
  obtain ⟨_, _, h_r⟩ := verifyAux_cons serialize ops key l0 (l1 :: rest) none h_valid
  obtain ⟨h1_prev, _, _⟩ := verifyAux_cons serialize ops key l1 rest (some l0.mac) h_r
  -- l1.prev = some l0.mac ≠ none
  have h_ne : l1.prev ≠ none := by
    rw [h1_prev]; intro h; exact nomatch h
  simp only [verifyChain, verifyAux]
  have : decide (l1.prev = none) = false := decide_eq_false h_ne
  rw [this]
  simp

-- ============================================================
-- Theorem 6: Valid chain implies all MACs are correctly computed
-- ============================================================

theorem verify_implies_correct_mac {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key (l :: rest) ep = true) :
    l.mac = ops.hmac key (macInput Tag serialize l.prev l.body) :=
  (verifyAux_cons serialize ops key l rest ep h).2.1

-- ============================================================
-- Theorem 7: Chain linkage — each line's prev equals predecessor's mac
-- ============================================================

theorem verify_implies_linkage {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag)
    (l0 l1 : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key (l0 :: l1 :: rest) ep = true) :
    l1.prev = some l0.mac := by
  obtain ⟨_, _, h_r⟩ := verifyAux_cons serialize ops key l0 (l1 :: rest) ep h
  exact (verifyAux_cons serialize ops key l1 rest (some l0.mac) h_r).1

-- ============================================================
-- Theorem 8: Empty chain always verifies
-- ============================================================

theorem empty_chain_valid {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) :
    verifyChain Tag serialize ops key [] = true := by
  unfold verifyChain verifyAux; rfl
