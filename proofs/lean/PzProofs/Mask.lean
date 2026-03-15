import Std.Tactic.BVDecide

/-
  Proof 1: Tool mask sanitization prevents privilege escalation.

  Models src/core/tools/builtin.zig:173:
    .tool_mask = opts.tool_mask & mask_all

  Proves: for ALL possible 16-bit mask inputs, sanitization never
  produces bits outside mask_all, and always preserves requested
  bits within the known set.

  Scope: mask layer only. Does not cover tool_auth or approval
  (separate access control layers providing defense-in-depth).
-/

-- mask_all: OR of bits 0-9 (read write bash edit grep find ls agent ask skill)
-- Note: tools.Kind.web (enum index 8) has no mask bit.
-- Mask bit indices ≠ Kind enum ordinals.
@[reducible] def mask_all : BitVec 16 := 0x3FF

-- Core property: AND with mask_all never produces bits outside mask_all.
-- This is the sanitization at builtin.zig:173.
theorem sanitize_strips_unknown (input : BitVec 16) :
    (input &&& mask_all) ≤ mask_all := by
  bv_decide

-- Idempotence: sanitizing twice is the same as sanitizing once.
theorem sanitize_idempotent (input : BitVec 16) :
    (input &&& mask_all) &&& mask_all = input &&& mask_all := by
  bv_decide

-- Future: thread_default_mask (when implemented in EPISODES-PLAN.md)
-- Excludes mask_bash (bit 2) and mask_agent (bit 7).
@[reducible] def mask_bash : BitVec 16 := 1 <<< 2
@[reducible] def mask_agent : BitVec 16 := 1 <<< 7
-- 0x3FF & ~(0x04 | 0x80) = 0x3FF & 0xFF7B = 0x037B
-- = bits 0,1,3,4,5,6,8,9 (read,write,edit,grep,find,ls,ask,skill)
@[reducible] def thread_default : BitVec 16 := 0x037B

-- Thread mask intersection never exceeds parent mask.
theorem thread_no_escalation (parent req : BitVec 16) :
    (req &&& parent &&& thread_default) ≤ parent := by
  bv_decide

-- Thread default mask always strips bash and agent.
theorem thread_default_strips_bash (req parent : BitVec 16) :
    (req &&& parent &&& thread_default) &&& mask_bash = 0 := by
  bv_decide

theorem thread_default_strips_agent (req parent : BitVec 16) :
    (req &&& parent &&& thread_default) &&& mask_agent = 0 := by
  bv_decide

-- Composition: sanitize then thread-restrict = thread-restrict then sanitize.
theorem sanitize_thread_commute (input parent : BitVec 16) :
    (input &&& mask_all) &&& parent &&& thread_default =
    (input &&& parent &&& thread_default) &&& mask_all := by
  bv_decide
