/-
  Proof: Policy evaluation invariants.

  Models src/core/policy.zig:187-199 (evaluate + isProtectedPath):
    evaluate(rules, path, tool) = first-match-wins with protected-path override
    isProtectedPath(path) = hardcoded deny for audit/session/pz/AGENTS.md

  Proves:
  1. Protected paths always return .deny regardless of rules
  2. First-match-wins: result is determined by first matching rule
  3. No rule matches → default .deny
  4. Tool filter doesn't affect protected path invariant
  5. First-match-wins holds with tool filtering (first match among non-skipped rules)
-/

/-- Policy effect: allow or deny. -/
inductive Effect where
  | allow
  | deny
  deriving DecidableEq, Repr

/-- A policy rule: a match predicate (pre-evaluated), an effect, and optional tool filter. -/
structure Rule where
  hit : Bool
  effect : Effect
  tool : Option String := none
  deriving DecidableEq, Repr

section Evaluate

/-- Whether a rule is active for the given tool context.
    A rule with tool = none matches any tool. A rule with tool = some t
    matches only when currentTool = some t. -/
def ruleActive (r : Rule) (currentTool : Option String) : Bool :=
  match r.tool with
  | none => true
  | some t => match currentTool with
    | none => false
    | some ct => t == ct

/-- Model of evaluate (policy.zig:187-199).
    isProtected is checked first; then first-match-wins over active rules; default deny. -/
def evaluate (isProtected : Bool) (rules : List Rule) (currentTool : Option String) : Effect :=
  if isProtected then .deny
  else match rules.find? (fun r => ruleActive r currentTool && r.hit) with
    | some r => r.effect
    | none => .deny

private theorem find_none (rules : List Rule) (currentTool : Option String)
    (h : ∀ r ∈ rules, (ruleActive r currentTool && r.hit) = false) :
    List.find? (fun r => ruleActive r currentTool && r.hit) rules = none := by
  induction rules with
  | nil => rfl
  | cons hd tl ih =>
    simp only [List.find?]
    have hd_no := h hd (List.Mem.head tl)
    rw [hd_no]
    exact ih (fun r hr => h r (List.Mem.tail hd hr))

private theorem find_first (pre : List Rule) (r : Rule) (post : List Rule)
    (currentTool : Option String)
    (h_r : (ruleActive r currentTool && r.hit) = true)
    (h_pre : ∀ p ∈ pre, (ruleActive p currentTool && p.hit) = false) :
    List.find? (fun r => ruleActive r currentTool && r.hit) (pre ++ r :: post) = some r := by
  induction pre with
  | nil =>
    simp only [List.nil_append, List.find?]
    rw [h_r]
  | cons hd tl ih =>
    simp only [List.cons_append, List.find?]
    have hd_no := h_pre hd (List.Mem.head tl)
    rw [hd_no]
    exact ih (fun p hp => h_pre p (List.Mem.tail hd hp))

/-- Protected paths always return .deny, regardless of any rules or tool. -/
theorem protected_always_deny (rules : List Rule) (currentTool : Option String) :
    evaluate true rules currentTool = .deny := by
  unfold evaluate; rfl

/-- Protected paths return .deny even with an explicit allow rule. -/
theorem protected_overrides_allow (rules : List Rule) (currentTool : Option String)
    (_h : ∃ r ∈ rules, r.hit = true ∧ r.effect = .allow) :
    evaluate true rules currentTool = .deny := by
  unfold evaluate; rfl

/-- If no active rule matches, default is .deny. -/
theorem no_match_deny (rules : List Rule) (currentTool : Option String)
    (h : ∀ r ∈ rules, (ruleActive r currentTool && r.hit) = false) :
    evaluate false rules currentTool = .deny := by
  unfold evaluate
  simp only [find_none rules currentTool h, Bool.false_eq_true, ↓reduceIte]

/-- First active matching rule determines the result. -/
theorem first_match_wins (pre : List Rule) (r : Rule) (post : List Rule)
    (currentTool : Option String)
    (h_r : (ruleActive r currentTool && r.hit) = true)
    (h_pre : ∀ p ∈ pre, (ruleActive p currentTool && p.hit) = false) :
    evaluate false (pre ++ r :: post) currentTool = r.effect := by
  unfold evaluate
  simp only [find_first pre r post currentTool h_r h_pre, Bool.false_eq_true, ↓reduceIte]

/-- A matching allow rule with matching tool is returned when path is not protected. -/
theorem allow_when_not_protected (pre : List Rule) (post : List Rule)
    (currentTool : Option String)
    (h_pre : ∀ p ∈ pre, (ruleActive p currentTool && p.hit) = false) :
    evaluate false (pre ++ ⟨true, .allow, none⟩ :: post) currentTool = .allow := by
  apply first_match_wins pre ⟨true, .allow, none⟩ post currentTool
  · simp [ruleActive]
  · exact h_pre

/-- A matching deny rule is returned when path is not protected. -/
theorem deny_when_not_protected (pre : List Rule) (post : List Rule)
    (currentTool : Option String)
    (h_pre : ∀ p ∈ pre, (ruleActive p currentTool && p.hit) = false) :
    evaluate false (pre ++ ⟨true, .deny, none⟩ :: post) currentTool = .deny := by
  apply first_match_wins pre ⟨true, .deny, none⟩ post currentTool
  · simp [ruleActive]
  · exact h_pre

/-- Later rules are shadowed: if an earlier active rule matches, the later one is irrelevant. -/
theorem shadowing (r1 r2 : Rule) (rest : List Rule) (currentTool : Option String)
    (h1 : (ruleActive r1 currentTool && r1.hit) = true)
    (_h2 : (ruleActive r2 currentTool && r2.hit) = true) :
    evaluate false (r1 :: r2 :: rest) currentTool = r1.effect :=
  first_match_wins [] r1 (r2 :: rest) currentTool h1 (fun _ h => nomatch h)

/-- Tool filter: a rule with tool = some t is skipped when currentTool ≠ some t. -/
theorem tool_filter_skip (r : Rule) (rest : List Rule) (currentTool : Option String)
    (t : String) (h_tool : r.tool = some t)
    (h_mismatch : ∀ ct, currentTool = some ct → t ≠ ct) :
    evaluate false (r :: rest) currentTool = evaluate false rest currentTool := by
  unfold evaluate
  simp only [List.find?, Bool.false_eq_true, ↓reduceIte]
  have inactive : ruleActive r currentTool = false := by
    simp only [ruleActive, h_tool]
    cases currentTool with
    | none => rfl
    | some ct =>
      have h_ne := h_mismatch ct rfl
      simp [BEq.beq, h_ne]
  simp [inactive]

/-- Tool filter: a rule with tool = some t matches when currentTool = some t. -/
theorem tool_filter_match (pre : List Rule) (r : Rule) (post : List Rule)
    (t : String)
    (h_tool : r.tool = some t) (h_hit : r.hit = true)
    (h_pre : ∀ p ∈ pre, (ruleActive p (some t) && p.hit) = false) :
    evaluate false (pre ++ r :: post) (some t) = r.effect := by
  apply first_match_wins pre r post (some t)
  · have active : ruleActive r (some t) = true := by
      simp [ruleActive, h_tool, BEq.beq]
    simp [active, h_hit]
  · exact h_pre

/-- Tool filter doesn't affect protected path invariant. -/
theorem tool_filter_protected_invariant (rules : List Rule) (currentTool : Option String) :
    evaluate true rules currentTool = .deny := by
  unfold evaluate; rfl

end Evaluate

section IsProtectedPath

/-- Model of isProtectedPath (policy.zig:201-206).
    Returns true if the path matches any protected pattern. -/
def isProtectedPath (protectedPaths : List String) (path : String) : Bool :=
  protectedPaths.any (· == path)

/-- A path in the protected list is always protected. -/
theorem in_protected_is_protected (ps : List String) (path : String)
    (h : path ∈ ps) :
    isProtectedPath ps path = true := by
  simp only [isProtectedPath, List.any_eq_true, BEq.beq]
  exact ⟨path, h, beq_self_eq_true path⟩

/-- A path not in the protected list is not protected. -/
theorem not_in_protected_not_protected (ps : List String) (path : String)
    (h : ∀ p ∈ ps, (p == path) = false) :
    isProtectedPath ps path = false := by
  simp only [isProtectedPath]
  rw [List.any_eq_false]
  intro x hx
  rw [h x hx]
  decide

end IsProtectedPath

section EndToEnd

/-- Full pipeline: protected path + any rules + any tool → deny. -/
theorem evaluate_protected_e2e (ps : List String) (path : String)
    (rules : List Rule) (currentTool : Option String)
    (h : path ∈ ps) :
    evaluate (isProtectedPath ps path) rules currentTool = .deny := by
  rw [in_protected_is_protected ps path h]
  exact protected_always_deny rules currentTool

/-- Full pipeline: unprotected path, first-match-wins with tool filtering. -/
theorem evaluate_unprotected_first_match (ps : List String) (path : String)
    (pre : List Rule) (r : Rule) (post : List Rule) (currentTool : Option String)
    (h_not_prot : isProtectedPath ps path = false)
    (h_r : (ruleActive r currentTool && r.hit) = true)
    (h_pre : ∀ p ∈ pre, (ruleActive p currentTool && p.hit) = false) :
    evaluate (isProtectedPath ps path) (pre ++ r :: post) currentTool = r.effect := by
  rw [h_not_prot]
  exact first_match_wins pre r post currentTool h_r h_pre

/-- Full pipeline: unprotected path, no active match → deny. -/
theorem evaluate_unprotected_no_match (ps : List String) (path : String)
    (rules : List Rule) (currentTool : Option String)
    (h_not_prot : isProtectedPath ps path = false)
    (h_none : ∀ r ∈ rules, (ruleActive r currentTool && r.hit) = false) :
    evaluate (isProtectedPath ps path) rules currentTool = .deny := by
  rw [h_not_prot]
  exact no_match_deny rules currentTool h_none

end EndToEnd
