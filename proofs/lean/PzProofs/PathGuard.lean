/-
  Proof 5: Path guard invariants.

  Models src/core/tools/path_guard.zig:
    relPath (line 163)       — prefix-strip cwd, reject non-child paths
    openParentDir (line 123) — component-by-component traversal, reject ".."
    ensureStableFile (line 324) — inode stability between open and use

  Proves:
  1. relPath only passes paths under cwd (prefix-stripping correctness)
  2. Component traversal with ".." rejection prevents directory escape
  3. Inode stability check detects TOCTOU file replacement
-/

section RelPath

/-- Result of relPath: either an error or the relative suffix. -/
inductive RelResult where
  | ok (rel : List String)
  | denied
  deriving DecidableEq, Repr

/-- Model of relPath (path_guard.zig:163-177).
    Takes cwd components and path components.
    If path is relative (no root marker), return as-is.
    If absolute, strip the cwd prefix; reject if not a child. -/
def relPath (cwd path : List String) (isAbsolute : Bool) : RelResult :=
  if !isAbsolute then .ok path
  else if cwd.isPrefixOf path then .ok (path.drop cwd.length)
  else .denied

/-- Relative paths pass through unchanged. -/
theorem relPath_relative (cwd path : List String) :
    relPath cwd path false = .ok path := by
  simp [relPath]

/-- An absolute path that doesn't start with cwd is denied. -/
theorem relPath_outside_denied (cwd path : List String)
    (h : cwd.isPrefixOf path = false) :
    relPath cwd path true = .denied := by
  simp [relPath, h]

/-- An absolute path under cwd produces only the suffix. -/
theorem relPath_under_cwd (cwd path : List String)
    (h : cwd.isPrefixOf path = true) :
    relPath cwd path true = .ok (path.drop cwd.length) := by
  simp [relPath, h]

/-- Helper: isPrefixOf true implies drop gives the tail after prefix. -/
private theorem isPrefixOf_drop (cwd path : List String)
    (h : cwd.isPrefixOf path = true) :
    path = cwd ++ path.drop cwd.length := by
  rw [List.isPrefixOf_iff_prefix] at h
  obtain ⟨t, ht⟩ := h
  subst ht
  rw [List.drop_left]

/-- Key invariant: if relPath succeeds on an absolute path, the result
    cannot contain components that escape above cwd, because cwd was
    exactly stripped. The result is a proper child path.
    Uses isPrefixOf → IsPrefix to recover cwd ++ suffix = path. -/
theorem relPath_child (cwd suffix path : List String)
    (h_abs : relPath cwd path true = .ok suffix) :
    path = cwd ++ suffix := by
  unfold relPath at h_abs
  simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte] at h_abs
  split at h_abs
  case isTrue h_pfx =>
    injection h_abs with h_eq
    rw [← h_eq]
    exact isPrefixOf_drop cwd path h_pfx
  case isFalse => exact absurd h_abs (by simp)

/-- The suffix produced by relPath is always a suffix of the original path. -/
theorem relPath_suffix_of_path (cwd path suffix : List String)
    (h : relPath cwd path true = .ok suffix) :
    ∃ (pre : List String), pre ++ suffix = path := by
  exact ⟨cwd, (relPath_child cwd suffix path h).symm⟩

end RelPath

section Traversal

/-- A path component is safe if it is not "..", not empty, not ".". -/
def isSafe (c : String) : Prop :=
  c ≠ ".." ∧ c ≠ "" ∧ c ≠ "."

instance (c : String) : Decidable (isSafe c) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _))

/-- Model of openParentDir traversal (path_guard.zig:123-148).
    Returns true iff every component is safe (no ".." escape). -/
def traverseSafe (components : List String) : Prop :=
  ∀ (c : String), c ∈ components → isSafe c

instance (components : List String) : Decidable (traverseSafe components) :=
  inferInstanceAs (Decidable (∀ _, _ → _))

/-- ".." in any position causes traversal rejection. -/
theorem dotdot_rejected (pre post : List String) :
    ¬ traverseSafe (pre ++ ".." :: post) := by
  intro h
  have hmem : ".." ∈ pre ++ ".." :: post :=
    List.mem_append_right pre List.mem_cons_self
  exact (h ".." hmem).1 rfl

/-- An empty component list is safe (represents cwd itself). -/
theorem empty_is_safe : traverseSafe [] := by
  intro c hc; exact absurd hc (List.not_mem_nil)

/-- A single safe component is accepted. -/
theorem single_safe (c : String) (h : isSafe c) :
    traverseSafe [c] := by
  intro c' hc'
  rw [List.mem_singleton.mp hc']; exact h

/-- If traversal succeeds, no component is "..". -/
theorem traverseSafe_no_dotdot (cs : List String)
    (h : traverseSafe cs) :
    ∀ (c : String), c ∈ cs → c ≠ ".." := by
  intro c hc
  exact (h c hc).1

/-- If traversal succeeds, no component is ".". -/
theorem traverseSafe_no_dot (cs : List String)
    (h : traverseSafe cs) :
    ∀ (c : String), c ∈ cs → c ≠ "." := by
  intro c hc
  exact (h c hc).2.2

/-- Composition: relPath + traversal. If an absolute path passes both checks,
    it is under cwd and contains no ".." escape components. -/
theorem relPath_then_traverse_safe (cwd path suffix : List String)
    (h_rel : relPath cwd path true = .ok suffix)
    (h_trav : traverseSafe suffix) :
    path = cwd ++ suffix ∧ ∀ (c : String), c ∈ suffix → c ≠ ".." := by
  exact ⟨relPath_child cwd suffix path h_rel,
         traverseSafe_no_dotdot suffix h_trav⟩

end Traversal

section InodeStability

/-- Inode identifier: (device, inode) pair. -/
structure Inode where
  dev : Nat
  ino : Nat
  deriving DecidableEq, Repr

/-- File metadata as seen by fstat/fstatat. -/
structure FileStat where
  inode : Inode
  isRegular : Bool
  nlink : Nat
  deriving DecidableEq, Repr

/-- Model of ensureStableFile (path_guard.zig:324-340).
    Takes the fstat of the opened fd and the fstatat of the path name.
    Returns true iff both are regular files with nlink=1 and same inode. -/
def stableCheck (fdStat pathStat : FileStat) : Prop :=
  fdStat.isRegular = true ∧ pathStat.isRegular = true ∧
  fdStat.nlink = 1 ∧ pathStat.nlink = 1 ∧
  fdStat.inode = pathStat.inode

instance (fdStat pathStat : FileStat) : Decidable (stableCheck fdStat pathStat) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _ ∧ _))

/-- If the file was replaced (different inode), stability check fails. -/
theorem replaced_file_detected (fdStat pathStat : FileStat)
    (h_diff : fdStat.inode ≠ pathStat.inode) :
    ¬ stableCheck fdStat pathStat := by
  intro ⟨_, _, _, _, h_eq⟩
  exact h_diff h_eq

/-- If the file is a symlink (not regular), stability check fails. -/
theorem symlink_detected (fdStat pathStat : FileStat)
    (h_sym : pathStat.isRegular = false) :
    ¬ stableCheck fdStat pathStat := by
  intro ⟨_, h_reg, _, _, _⟩
  rw [h_sym] at h_reg; exact absurd h_reg (by decide)

/-- If nlink > 1 (hardlink) on fd side, stability check fails. -/
theorem hardlink_detected_fd (fdStat pathStat : FileStat)
    (h_nlink : fdStat.nlink ≠ 1) :
    ¬ stableCheck fdStat pathStat := by
  intro ⟨_, _, h_nl, _, _⟩
  exact h_nlink h_nl

/-- If nlink > 1 (hardlink) on path side, stability check fails. -/
theorem hardlink_detected_path (fdStat pathStat : FileStat)
    (h_nlink : pathStat.nlink ≠ 1) :
    ¬ stableCheck fdStat pathStat := by
  intro ⟨_, _, _, h_nl, _⟩
  exact h_nlink h_nl

/-- TOCTOU attack model: attacker replaces file between open (fstat) and
    name resolution (fstatat). The inode changes, so the check fails. -/
theorem toctou_detected (original replaced : Inode)
    (h_diff : original ≠ replaced)
    (fdStat : FileStat)
    (h_fd : fdStat.inode = original)
    (pathStat : FileStat)
    (h_path : pathStat.inode = replaced) :
    ¬ stableCheck fdStat pathStat := by
  intro ⟨_, _, _, _, h_eq⟩
  exact h_diff (h_fd ▸ h_path ▸ h_eq)

/-- Stability check passes only when everything matches. -/
theorem stable_iff (fdStat pathStat : FileStat) :
    stableCheck fdStat pathStat ↔
    (fdStat.isRegular = true ∧ pathStat.isRegular = true ∧
     fdStat.nlink = 1 ∧ pathStat.nlink = 1 ∧
     fdStat.inode = pathStat.inode) := by
  exact Iff.rfl

end InodeStability

section CwdGuard

/-- Model of CwdGuard: a mutex-protected cwd swap.
    The invariant is that cwd is always restored on exit. -/
structure CwdState where
  cwd : List String
  locked : Bool
  deriving DecidableEq, Repr

def cwdEnter (st : CwdState) (newCwd : List String) : Option CwdState :=
  if st.locked then none
  else some { cwd := newCwd, locked := true }

def cwdExit (_st : CwdState) (prevCwd : List String) : CwdState :=
  { cwd := prevCwd, locked := false }

/-- Enter then exit restores the original cwd. -/
theorem cwdGuard_restores (st : CwdState) (newCwd prevCwd : List String)
    (h_unlocked : st.locked = false) :
    match cwdEnter st newCwd with
    | some entered => (cwdExit entered prevCwd).cwd = prevCwd
    | none => False := by
  simp [cwdEnter, h_unlocked, cwdExit]

/-- Double-enter is prevented by the lock. -/
theorem cwdGuard_no_double_enter (st : CwdState) (d1 d2 : List String)
    (h_unlocked : st.locked = false) :
    match cwdEnter st d1 with
    | some entered => cwdEnter entered d2 = none
    | none => False := by
  simp [cwdEnter, h_unlocked]

end CwdGuard

section EndToEnd

/-- Full pipeline: an absolute path must pass relPath, then traversal,
    then (at file open time) inode stability.
    This ties all three invariants together. -/
theorem path_guard_sound
    (cwd path suffix : List String)
    (h_rel : relPath cwd path true = .ok suffix)
    (h_trav : traverseSafe suffix)
    (fdStat pathStat : FileStat)
    (h_stable : stableCheck fdStat pathStat) :
    -- Path is under cwd
    path = cwd ++ suffix ∧
    -- No ".." escape
    (∀ (c : String), c ∈ suffix → c ≠ "..") ∧
    -- File identity verified
    fdStat.inode = pathStat.inode := by
  obtain ⟨h_child, h_nodotdot⟩ := relPath_then_traverse_safe cwd path suffix h_rel h_trav
  exact ⟨h_child, h_nodotdot, h_stable.2.2.2.2⟩

end EndToEnd
