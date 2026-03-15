/-
  Proof: Policy evaluation invariants.

  Models src/core/policy.zig:169-188 (evaluate + isProtectedPath):
    evaluate(rules, path, tool) = first-match-wins with protected-path override
    isProtectedPath(path) = hardcoded deny for audit/session/pz/AGENTS.md

  Proves:
  1. Protected paths always return .deny regardless of rules
  2. First-match-wins: result is determined by first matching rule
  3. No rule matches → default .deny
-/

/-- Policy effect: allow or deny. -/
inductive Effect where
  | allow
  | deny
  deriving DecidableEq, Repr

/-- A policy rule: a match predicate and an effect. -/
structure Rule where
  matches : Bool
  effect : Effect
  deriving DecidableEq, Repr

section Evaluate

/-- Model of evaluate (policy.zig:169-181).
    isProtected is checked first; then first-match-wins over rules; default deny. -/
def evaluate (isProtected : Bool) (rules : List Rule) : Effect :=
  if isProtected then .deny
  else match rules.find? (·.matches) with
    | some r => r.effect
    | none => .deny

/-- Protected paths always return .deny, regardless of any rules. -/
theorem protected_always_deny (rules : List Rule) :
    evaluate true rules = .deny := by
  simp [evaluate]

/-- Protected paths return .deny even with an explicit allow rule. -/
theorem protected_overrides_allow (rules : List Rule)
    (h : ∃ r ∈ rules, r.matches = true ∧ r.effect = .allow) :
    evaluate true rules = .deny := by
  simp [evaluate]

/-- If no rule matches, default is .deny. -/
theorem no_match_deny (rules : List Rule)
    (h : ∀ r ∈ rules, r.matches = false) :
    evaluate false rules = .deny := by
  simp [evaluate]
  have : List.find? (·.matches) rules = none := by
    induction rules with
    | nil => simp [List.find?]
    | cons hd tl ih =>
      simp [List.find?]
      constructor
      · exact h hd (List.mem_cons_self hd tl)
      · exact ih (fun r hr => h r (List.mem_cons_of_mem hd hr))
  rw [this]

/-- First matching rule determines the result. -/
theorem first_match_wins (pre : List Rule) (r : Rule) (post : List Rule)
    (h_r : r.matches = true)
    (h_pre : ∀ p ∈ pre, p.matches = false) :
    evaluate false (pre ++ r :: post) = r.effect := by
  simp [evaluate]
  have : List.find? (·.matches) (pre ++ r :: post) = some r := by
    induction pre with
    | nil =>
      simp [List.find?]
      rw [h_r]
      simp
    | cons hd tl ih =>
      simp [List.find?]
      have hd_no : hd.matches = false := h_pre hd (List.mem_cons_self hd tl)
      rw [hd_no]
      simp
      exact ih (fun p hp => h_pre p (List.mem_cons_of_mem hd hp))
  rw [this]

/-- A matching allow rule is returned when path is not protected. -/
theorem allow_when_not_protected (pre : List Rule) (post : List Rule)
    (h_pre : ∀ p ∈ pre, p.matches = false) :
    evaluate false (pre ++ ⟨true, .allow⟩ :: post) = .allow := by
  exact first_match_wins pre ⟨true, .allow⟩ post rfl h_pre

/-- A matching deny rule is returned when path is not protected. -/
theorem deny_when_not_protected (pre : List Rule) (post : List Rule)
    (h_pre : ∀ p ∈ pre, p.matches = false) :
    evaluate false (pre ++ ⟨true, .deny⟩ :: post) = .deny := by
  exact first_match_wins pre ⟨true, .deny⟩ post rfl h_pre

/-- Later rules are shadowed: if an earlier rule matches, the later one is irrelevant. -/
theorem shadowing (r1 r2 : Rule) (rest : List Rule)
    (h1 : r1.matches = true) (h2 : r2.matches = true) :
    evaluate false (r1 :: r2 :: rest) = r1.effect := by
  exact first_match_wins [] r1 (r2 :: rest) h1 (fun _ h => absurd h (List.not_mem_nil _))

end Evaluate

section IsProtectedPath

/-- Model of isProtectedPath (policy.zig:183-188).
    Returns true if the path matches any protected pattern. -/
def isProtectedPath (protectedPaths : List String) (path : String) : Bool :=
  protectedPaths.any (· == path)

/-- A path in the protected list is always protected. -/
theorem in_protected_is_protected (ps : List String) (path : String)
    (h : path ∈ ps) :
    isProtectedPath ps path = true := by
  simp [isProtectedPath, List.any_eq_true]
  exact ⟨path, h, beq_self_eq_true path⟩

/-- A path not in the protected list is not protected. -/
theorem not_in_protected_not_protected (ps : List String) (path : String)
    (h : ∀ p ∈ ps, ¬(p == path) = true) :
    isProtectedPath ps path = false := by
  simp [isProtectedPath, List.any_eq_true]
  intro x hx
  exact h x hx

end IsProtectedPath

section EndToEnd

/-- Full pipeline: protected path + any rules → deny. -/
theorem evaluate_protected_e2e (ps : List String) (path : String)
    (rules : List Rule)
    (h : path ∈ ps) :
    evaluate (isProtectedPath ps path) rules = .deny := by
  rw [in_protected_is_protected ps path h]
  exact protected_always_deny rules

/-- Full pipeline: unprotected path, first-match-wins. -/
theorem evaluate_unprotected_first_match (ps : List String) (path : String)
    (pre : List Rule) (r : Rule) (post : List Rule)
    (h_not_prot : isProtectedPath ps path = false)
    (h_r : r.matches = true)
    (h_pre : ∀ p ∈ pre, p.matches = false) :
    evaluate (isProtectedPath ps path) (pre ++ r :: post) = r.effect := by
  rw [h_not_prot]
  exact first_match_wins pre r post h_r h_pre

/-- Full pipeline: unprotected path, no match → deny. -/
theorem evaluate_unprotected_no_match (ps : List String) (path : String)
    (rules : List Rule)
    (h_not_prot : isProtectedPath ps path = false)
    (h_none : ∀ r ∈ rules, r.matches = false) :
    evaluate (isProtectedPath ps path) rules = .deny := by
  rw [h_not_prot]
  exact no_match_deny rules h_none

end EndToEnd
