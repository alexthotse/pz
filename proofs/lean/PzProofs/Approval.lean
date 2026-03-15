/-
  Proof 4a: Approval flow key scoping.

  Models src/core/loop.zig:164-316 (CmdCache.Key, eql, eqlLoc, eqlLife).

  Proves: approvals are scoped by (tool, cmd, loc, policy, life).
  Changing ANY component produces a different key that cannot match.
-/

-- Model the composite key structure
inductive Tool where
  | read | write | bash | edit | grep | find | ls | agent | ask | skill
  deriving DecidableEq, Repr

inductive Loc where
  | cwd (path : String)
  | repo_root (path : String)
  deriving DecidableEq, Repr

inductive PolicyBind where
  | version (v : Nat)
  | hash (h : String)
  deriving DecidableEq, Repr

inductive Life where
  | session (sid : String)
  | expires_at_ms (ms : Int)
  deriving DecidableEq, Repr

structure Key where
  tool : Tool
  cmd : String
  loc : Loc
  policy : PolicyBind
  life : Life
  deriving DecidableEq, Repr

-- Different tool → different key
theorem diff_tool_no_match (k1 k2 : Key) (h : k1.tool ≠ k2.tool) :
    k1 ≠ k2 := by
  intro heq; exact h (congrArg Key.tool heq)

-- Different command → different key
theorem diff_cmd_no_match (k1 k2 : Key) (h : k1.cmd ≠ k2.cmd) :
    k1 ≠ k2 := by
  intro heq; exact h (congrArg Key.cmd heq)

-- Different location → different key
theorem diff_loc_no_match (k1 k2 : Key) (h : k1.loc ≠ k2.loc) :
    k1 ≠ k2 := by
  intro heq; exact h (congrArg Key.loc heq)

-- Different policy → different key
theorem diff_policy_no_match (k1 k2 : Key) (h : k1.policy ≠ k2.policy) :
    k1 ≠ k2 := by
  intro heq; exact h (congrArg Key.policy heq)

-- Different lifetime → different key
theorem diff_life_no_match (k1 k2 : Key) (h : k1.life ≠ k2.life) :
    k1 ≠ k2 := by
  intro heq; exact h (congrArg Key.life heq)

-- Cross-context isolation: cwd vs repo_root never match
theorem cwd_repo_no_match (p1 p2 : String) :
    Loc.cwd p1 ≠ Loc.repo_root p2 := by
  intro h; exact Loc.noConfusion h

-- Cross-type isolation: session vs expires never match
theorem session_expires_no_match (sid : String) (ms : Int) :
    Life.session sid ≠ Life.expires_at_ms ms := by
  intro h; exact Life.noConfusion h

-- Cross-bind isolation: version vs hash never match
theorem version_hash_no_match (v : Nat) (h : String) :
    PolicyBind.version v ≠ PolicyBind.hash h := by
  intro heq; exact PolicyBind.noConfusion heq

-- Comprehensive: keys equal iff ALL fields equal.
theorem key_scoping_complete (k1 k2 : Key) :
    k1 = k2 ↔ (k1.tool = k2.tool ∧ k1.cmd = k2.cmd ∧ k1.loc = k2.loc ∧
                k1.policy = k2.policy ∧ k1.life = k2.life) := by
  constructor
  · intro h; subst h; exact ⟨rfl, rfl, rfl, rfl, rfl⟩
  · intro ⟨ht, hc, hl, hp, hf⟩
    cases k1; cases k2; simp_all
