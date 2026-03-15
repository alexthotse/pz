/-
  Proof: HMAC audit chain integrity.

  Models src/core/audit_integrity.zig:74-146 (verifyLogAlloc, calcMac).

  Chain structure (verified left-to-right):
    line[0]: prev = none,          mac[0] = HMAC(key, key_id ++ "\n" ++ "-" ++ "\n" ++ body[0])
    line[i]: prev = some mac[i-1], mac[i] = HMAC(key, key_id ++ "\n" ++ hex(mac[i-1]) ++ "\n" ++ body[i])

  Verification: recompute mac from (key_id, body, prev), compare against stored mac;
  check that stored prev matches previous line's mac.

  Proves:
  1. First line's prev is none
  2. Body modification → verification fails
  3. MAC modification → verification fails
  4. Line removal breaks verification
  5. Reordering (swap) breaks verification
  6. Valid chain implies correct MACs and linkage
  7. Different key_id with same body → different MAC input (key rotation safety)
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

-- MAC input construction (models calcMac: key_id ++ "\n" ++ prev_serialized ++ "\n" ++ body).
-- serialize models hex encoding of tags (injective).
-- key_id models the string rendering of Key.id (Zig: "{d}\n" format of u32).
def macInput (Tag : Type) (serialize : Tag → String) (key_id : String)
    (prev : Option Tag) (body : String) : String :=
  key_id ++ "\n" ++
  match prev with
  | none => "-\n" ++ body
  | some t => serialize t ++ "\n" ++ body

-- Verification with accumulator (models verifyLogAlloc's walk).
-- Walks lines left-to-right, tracking expected prev MAC.
def verifyAux (Tag : Type) [DecidableEq Tag] (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag) (key_id : String) :
    List (SealedLine Tag) → Option Tag → Bool
  | [], _ => true
  | l :: rest, ep =>
    (decide (l.prev = ep) &&
     decide (l.mac = ops.hmac key (macInput Tag serialize key_id l.prev l.body))) &&
    verifyAux Tag serialize ops key key_id rest (some l.mac)

def verifyChain (Tag : Type) [DecidableEq Tag] (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag) (key_id : String) (chain : List (SealedLine Tag)) : Bool :=
  verifyAux Tag serialize ops key key_id chain none

-- ============================================================
-- Helper: decompose a successful verifyAux step
-- ============================================================

private theorem verifyAux_cons {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String)
    (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key key_id (l :: rest) ep = true) :
    l.prev = ep ∧
    l.mac = ops.hmac key (macInput Tag serialize key_id l.prev l.body) ∧
    verifyAux Tag serialize ops key key_id rest (some l.mac) = true := by
  simp only [verifyAux, Bool.and_eq_true, decide_eq_true_eq] at h
  exact ⟨h.1.1, h.1.2, h.2⟩

-- ============================================================
-- Theorem 1: First line's prev is none (initial value)
-- ============================================================

theorem first_prev_none {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (rest : List (SealedLine Tag))
    (h : verifyChain Tag serialize ops key key_id (l :: rest) = true) :
    l.prev = none :=
  (verifyAux_cons serialize ops key key_id l rest none h).1

-- ============================================================
-- Helper: macInput is injective in body
-- ============================================================

private theorem macInput_body_ne {Tag : Type} (serialize : Tag → String)
    (key_id : String) (prev : Option Tag) (b1 b2 : String)
    (h : b1 ≠ b2) :
    macInput Tag serialize key_id prev b1 ≠ macInput Tag serialize key_id prev b2 := by
  intro heq
  apply h
  unfold macInput at heq
  cases prev with
  | none =>
    have h1 : (key_id ++ "\n" ++ ("-\n" ++ b1)).toList =
              (key_id ++ "\n" ++ ("-\n" ++ b2)).toList := congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1
  | some _ =>
    have h1 : (key_id ++ "\n" ++ (serialize _ ++ "\n" ++ b1)).toList =
              (key_id ++ "\n" ++ (serialize _ ++ "\n" ++ b2)).toList :=
      congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1

-- ============================================================
-- Theorem 2: Body modification → verification fails
-- ============================================================

theorem body_tamper_detected {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (body' : String) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key key_id (l :: rest) ep = true)
    (h_diff : l.body ≠ body') :
    verifyAux Tag serialize ops key key_id
      ({ l with body := body' } :: rest) ep = false := by
  obtain ⟨_, h_mac, _⟩ := verifyAux_cons serialize ops key key_id l rest ep h_valid
  have h_input_ne := macInput_body_ne serialize key_id l.prev l.body body' h_diff
  have h_mac_ne := ops.collision_resistant key _ _ h_input_ne
  -- l.mac = hmac key (macInput key_id prev body) ≠ hmac key (macInput key_id prev body')
  have h_ne : l.mac ≠ ops.hmac key (macInput Tag serialize key_id l.prev body') := by
    rw [h_mac]; exact h_mac_ne
  simp only [verifyAux]
  have : decide (l.mac = ops.hmac key (macInput Tag serialize key_id l.prev body')) = false :=
    decide_eq_false h_ne
  rw [Bool.and_assoc, Bool.and_comm (decide (l.prev = ep)), Bool.and_assoc,
      Bool.and_comm (decide (l.mac = _)), this]
  simp

-- Corollary: body tamper at first position
theorem body_tamper_first {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (body' : String) (rest : List (SealedLine Tag))
    (h_valid : verifyChain Tag serialize ops key key_id (l :: rest) = true)
    (h_diff : l.body ≠ body') :
    verifyChain Tag serialize ops key key_id ({ l with body := body' } :: rest) = false :=
  body_tamper_detected serialize ops key key_id l body' rest none h_valid h_diff

-- ============================================================
-- Theorem 3: MAC modification → verification fails
-- The tampered line itself fails: recomputed MAC won't match mac'.
-- ============================================================

theorem mac_tamper_detected {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (mac' : Tag) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key key_id (l :: rest) ep = true)
    (h_diff : l.mac ≠ mac') :
    verifyAux Tag serialize ops key key_id
      ({ l with mac := mac' } :: rest) ep = false := by
  obtain ⟨_, h_mac, _⟩ := verifyAux_cons serialize ops key key_id l rest ep h_valid
  have h_ne : mac' ≠ ops.hmac key (macInput Tag serialize key_id l.prev l.body) := by
    intro heq; exact h_diff (h_mac ▸ heq.symm ▸ rfl)
  simp only [verifyAux]
  have : decide (mac' = ops.hmac key (macInput Tag serialize key_id l.prev l.body)) = false :=
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
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l0 l1 l2 : SealedLine Tag) (rest : List (SealedLine Tag))
    (ep : Option Tag)
    (h_valid : verifyAux Tag serialize ops key key_id (l0 :: l1 :: l2 :: rest) ep = true)
    (h_mac_diff : l0.mac ≠ l1.mac) :
    verifyAux Tag serialize ops key key_id (l0 :: l2 :: rest) ep = false := by
  obtain ⟨h0_prev, h0_mac, h_r1⟩ := verifyAux_cons serialize ops key key_id l0 (l1 :: l2 :: rest) ep h_valid
  obtain ⟨_, _, h_r2⟩ := verifyAux_cons serialize ops key key_id l1 (l2 :: rest) (some l0.mac) h_r1
  obtain ⟨h2_prev, _, _⟩ := verifyAux_cons serialize ops key key_id l2 rest (some l1.mac) h_r2
  -- l2.prev = some l1.mac, but after removal expected = some l0.mac
  have h_prev_ne : l2.prev ≠ some l0.mac := by
    rw [h2_prev]; intro h; exact h_mac_diff (Option.some.inj h.symm)
  simp only [verifyAux]
  have hd0 : decide (l0.prev = ep) = true := decide_eq_true h0_prev
  have hm0 : decide (l0.mac = ops.hmac key (macInput Tag serialize key_id l0.prev l0.body)) = true :=
    decide_eq_true h0_mac
  have hd2 : decide (l2.prev = some l0.mac) = false := decide_eq_false h_prev_ne
  rw [hd0, hm0, hd2]
  simp

-- ============================================================
-- Theorem 5: Reordering (swap) breaks chain
-- Swapping first two lines: l1 has prev = some l0.mac ≠ none
-- ============================================================

theorem swap_breaks_chain {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l0 l1 : SealedLine Tag) (rest : List (SealedLine Tag))
    (h_valid : verifyChain Tag serialize ops key key_id (l0 :: l1 :: rest) = true) :
    verifyChain Tag serialize ops key key_id (l1 :: l0 :: rest) = false := by
  obtain ⟨_, _, h_r⟩ := verifyAux_cons serialize ops key key_id l0 (l1 :: rest) none h_valid
  obtain ⟨h1_prev, _, _⟩ := verifyAux_cons serialize ops key key_id l1 rest (some l0.mac) h_r
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
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key key_id (l :: rest) ep = true) :
    l.mac = ops.hmac key (macInput Tag serialize key_id l.prev l.body) :=
  (verifyAux_cons serialize ops key key_id l rest ep h).2.1

-- ============================================================
-- Theorem 7: Chain linkage — each line's prev equals predecessor's mac
-- ============================================================

theorem verify_implies_linkage {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String)
    (l0 l1 : SealedLine Tag) (rest : List (SealedLine Tag)) (ep : Option Tag)
    (h : verifyAux Tag serialize ops key key_id (l0 :: l1 :: rest) ep = true) :
    l1.prev = some l0.mac := by
  obtain ⟨_, _, h_r⟩ := verifyAux_cons serialize ops key key_id l0 (l1 :: rest) ep h
  exact (verifyAux_cons serialize ops key key_id l1 rest (some l0.mac) h_r).1

-- ============================================================
-- Theorem 8: Empty chain always verifies
-- ============================================================

theorem empty_chain_valid {Tag : Type} [DecidableEq Tag]
    (serialize : Tag → String) (ops : HmacOps Tag) (key : Tag) (key_id : String) :
    verifyChain Tag serialize ops key key_id [] = true := by
  unfold verifyChain verifyAux; rfl

-- ============================================================
-- Theorem 9: Key rotation safety — different key_id produces
-- different MAC input even with identical prev and body.
-- Models: rotating Key.id in audit_integrity.zig changes calcMac
-- output even when body and prev are unchanged.
-- ============================================================

theorem key_rotation_distinct_input {Tag : Type} (serialize : Tag → String)
    (kid1 kid2 : String) (prev : Option Tag) (body : String)
    (h : kid1 ≠ kid2) :
    macInput Tag serialize kid1 prev body ≠ macInput Tag serialize kid2 prev body := by
  intro heq
  apply h
  unfold macInput at heq
  cases prev with
  | none =>
    have h1 : (kid1 ++ "\n" ++ ("-\n" ++ body)).toList =
              (kid2 ++ "\n" ++ ("-\n" ++ body)).toList := congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1
  | some _ =>
    have h1 : (kid1 ++ "\n" ++ (serialize _ ++ "\n" ++ body)).toList =
              (kid2 ++ "\n" ++ (serialize _ ++ "\n" ++ body)).toList :=
      congrArg String.toList heq
    simp [String.toList_append] at h1
    exact String.ext_iff.mpr h1
