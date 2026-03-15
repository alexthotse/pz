/-
  Proof: Sandbox profile quoting safety.

  Models src/core/sandbox.zig:236-246 (appendQuoted):
    Escapes `\` and `"` in strings for Apple SBPL (Sandbox Profile Language).
    SBPL uses S-expression syntax with `"..."` string literals where `\` is
    the escape character.

  Proves:
  1. The escaped output never contains an unescaped `"` (no early close)
  2. Every `"` in the output is preceded by `\` (all quotes escaped)
  3. The output placed between delimiters cannot break out of string context
  4. Round-trip: escape then unescape recovers the original
-/

section SandboxQuoting

/-- Model of appendQuoted's per-character escaping (sandbox.zig:238-244).
    Backslash and double-quote are each preceded by a backslash.
    All other characters pass through unchanged. -/
def escape : List Char → List Char
  | [] => []
  | c :: cs =>
    if c = '\\' ∨ c = '"' then '\\' :: c :: escape cs
    else c :: escape cs

/-- Unescape: inverse of escape. Strips the added backslashes. -/
def unescape : List Char → List Char
  | [] => []
  | '\\' :: c :: cs => if c = '\\' ∨ c = '"' then c :: unescape cs
                        else '\\' :: c :: unescape cs
  | c :: cs => c :: unescape cs

/-- `escape` never starts with `"`. -/
theorem escape_head_not_quote (input : List Char)
    (rest : List Char) : escape input ≠ '"' :: rest := by
  match input with
  | [] => simp [escape]
  | c :: cs =>
    simp only [escape]
    split
    case isTrue h =>
      obtain rfl | rfl := h
      · exact fun heq => absurd (List.cons.inj heq |>.1) (by decide)
      · exact fun heq => absurd (List.cons.inj heq |>.1) (by decide)
    case isFalse h =>
      have : c ≠ '"' := fun heq => h (Or.inr heq)
      exact fun heq => absurd (List.cons.inj heq |>.1) this

/-- Core safety: in `escape input`, every `"` is preceded by `\`.
    For any decomposition `escape input = pre ++ '"' :: suf`,
    `pre` ends with `\`. -/
private theorem escape_quote_preceded (input : List Char) :
    ∀ (pre suf : List Char),
      escape input = pre ++ '"' :: suf →
      (∃ (pre' : List Char), pre = pre' ++ ['\\']) := by
  induction input with
  | nil =>
    intro pre suf h
    simp [escape] at h
  | cons c cs ih =>
    intro pre suf heq
    by_cases hc : c = '\\' ∨ c = '"'
    · obtain rfl | rfl := hc
      · -- c = '\\', escape output = '\\' :: '\\' :: escape cs
        simp only [escape, ite_true, Or.inl] at heq
        match pre with
        | [] =>
          exact absurd (List.cons.inj heq |>.1) (by decide)
        | [p] =>
          have h1 := List.cons.inj heq
          have h2 := List.cons.inj h1.2
          exact absurd h2.1 (by decide)
        | p :: q :: pre' =>
          have h1 := List.cons.inj heq
          have h2 := List.cons.inj h1.2
          obtain ⟨w, hw⟩ := ih pre' suf h2.2
          exact ⟨p :: q :: w, by simp [hw]⟩
      · -- c = '"', escape output = '\\' :: '"' :: escape cs
        simp only [escape, ite_true, Or.inr] at heq
        match pre with
        | [] =>
          exact absurd (List.cons.inj heq |>.1) (by decide)
        | [p] =>
          have h1 := List.cons.inj heq
          exact ⟨[], by simp; exact h1.1.symm⟩
        | p :: q :: pre' =>
          have h1 := List.cons.inj heq
          have h2 := List.cons.inj h1.2
          obtain ⟨w, hw⟩ := ih pre' suf h2.2
          exact ⟨p :: q :: w, by simp [hw]⟩
    · -- c is plain, escape output = c :: escape cs
      simp only [escape, hc, ite_false] at heq
      match pre with
      | [] =>
        have : c ≠ '"' := fun h => hc (Or.inr h)
        exact absurd (List.cons.inj heq |>.1) this
      | p :: pre' =>
        have h1 := List.cons.inj heq
        obtain ⟨w, hw⟩ := ih pre' suf h1.2
        exact ⟨p :: w, by simp [hw]⟩

/-- Core safety theorem: the output of escape, when placed between
    delimiters `"..."`, cannot contain an unescaped `"` that closes
    the string early. Any `"` in the output is preceded by `\`. -/
theorem escape_safe_in_quotes (input : List Char)
    (pre suf : List Char)
    (h : escape input = pre ++ '"' :: suf) :
    ∃ (pre' : List Char), pre = pre' ++ ['\\'] :=
  escape_quote_preceded input pre suf h

/-- Helper: unescape on a list starting with a non-backslash char. -/
private theorem unescape_nonbs (c : Char) (cs : List Char) (hc : c ≠ '\\') :
    unescape (c :: cs) = c :: unescape cs := by
  rw [unescape.eq_def]
  split
  · next heq => exact absurd heq (List.cons_ne_nil _ _)
  · next c' rest heq => exact absurd (List.cons.inj heq |>.1) hc
  · next c' rest _ heq => obtain ⟨rfl, rfl⟩ := List.cons.inj heq; rfl

/-- Round-trip: unescape (escape input) = input. -/
theorem roundtrip (input : List Char) : unescape (escape input) = input := by
  induction input with
  | nil => rfl
  | cons c cs ih =>
    by_cases hc : c = '\\' ∨ c = '"'
    · obtain rfl | rfl := hc
      · show unescape (escape ('\\' :: cs)) = '\\' :: cs
        simp [escape, unescape, ih]
      · show unescape (escape ('"' :: cs)) = '"' :: cs
        simp [escape, unescape, ih]
    · have hc1 : c ≠ '\\' := fun h => hc (Or.inl h)
      show unescape (escape (c :: cs)) = c :: cs
      have hesc : escape (c :: cs) = c :: escape cs := by
        simp [escape, hc]
      rw [hesc, unescape_nonbs c (escape cs) hc1, ih]

/-- escape always increases or preserves length. -/
theorem escape_length_ge (input : List Char) :
    input.length ≤ (escape input).length := by
  induction input with
  | nil => simp [escape]
  | cons c cs ih =>
    simp only [escape]
    split
    · simp [List.length_cons]; omega
    · simp [List.length_cons]; omega

/-- escape of empty input is empty. -/
theorem escape_nil : escape [] = [] := rfl

/-- escape is injective (distinct inputs produce distinct outputs). -/
theorem escape_injective : Function.Injective escape := by
  intro a b h
  have ha := roundtrip a
  have hb := roundtrip b
  rw [h] at ha
  rw [← ha]; exact hb

end SandboxQuoting
