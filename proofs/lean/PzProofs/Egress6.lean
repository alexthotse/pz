import Std.Tactic.BVDecide
import PzProofs.Egress

/-
  Proof 6: IPv6 network egress blocklist completeness.

  Models src/core/policy.zig:229-240 (isBlockedIp6):
    all zeros          → blocked (unspecified)
    ::1                → blocked (loopback)
    fc00::/7           → blocked (ULA, (byte0 & 0xfe) == 0xfc)
    fe80::/10          → blocked (link-local, byte0==0xfe && (byte1 & 0xc0)==0x80)
    ff00::/8           → blocked (multicast, byte0==0xff)
    ::ffff:0:0/96      → delegates to isBlockedIp4

  Encoding: IPv6 as BitVec 128 big-endian.
-/

-- ============================================================
-- IPv6 blocklist check, mirrors policy.zig exactly.
-- ============================================================

-- Extract byte at position (0 = MSB, 15 = LSB) from 128-bit address
@[reducible] def byte6 (ip : BitVec 128) (pos : Nat) : BitVec 8 :=
  (ip >>> (8 * (15 - pos))).truncate 8

-- Unspecified: all zeros
@[reducible] def isUnspecified6 (ip : BitVec 128) : Bool :=
  ip == 0

-- Loopback: ::1
@[reducible] def isLoopback6 (ip : BitVec 128) : Bool :=
  ip == 1

-- ULA: fc00::/7 — (byte0 & 0xfe) == 0xfc
@[reducible] def isULA (ip : BitVec 128) : Bool :=
  (byte6 ip 0 &&& 0xFE) == 0xFC

-- Link-local: fe80::/10 — byte0 == 0xfe && (byte1 & 0xc0) == 0x80
@[reducible] def isLinkLocal6 (ip : BitVec 128) : Bool :=
  byte6 ip 0 == 0xFE && (byte6 ip 1 &&& 0xC0) == 0x80

-- Multicast: ff00::/8 — byte0 == 0xff
@[reducible] def isMulticast6 (ip : BitVec 128) : Bool :=
  byte6 ip 0 == 0xFF

-- IPv4-mapped: ::ffff:A.B.C.D — first 80 bits zero, bytes 10-11 = 0xff
@[reducible] def isV4Mapped (ip : BitVec 128) : Bool :=
  ip >>> 32 == (0x0000_0000_0000_0000_0000_FFFF : BitVec 128)

-- Extract the IPv4 portion (lower 32 bits) for delegation
@[reducible] def v4Part (ip : BitVec 128) : BitVec 32 :=
  ip.truncate 32

-- Full IPv6 blocklist (excluding IPv4-mapped delegation)
@[reducible] def isBlocked6Core (ip : BitVec 128) : Bool :=
  isUnspecified6 ip ||
  isLoopback6 ip ||
  isULA ip ||
  isLinkLocal6 ip ||
  isMulticast6 ip

-- Full check including IPv4-mapped delegation
@[reducible] def isBlocked6 (ip : BitVec 128) : Bool :=
  isBlocked6Core ip ||
  (isV4Mapped ip && isBlocked (v4Part ip))

-- ============================================================
-- 1. Concrete examples: all addresses in each blocked range
-- ============================================================

-- :: (unspecified, all zeros)
theorem ex_unspecified : isBlocked6 0x0 = true := by native_decide

-- ::1 (loopback)
theorem ex_loopback6 : isBlocked6 0x1 = true := by native_decide

-- fc00::1 (ULA)
theorem ex_ula_fc00 : isBlocked6 0xFC000000000000000000000000000001 = true := by native_decide

-- fd12:3456::1 (ULA)
theorem ex_ula_fd : isBlocked6 0xFD123456000000000000000000000001 = true := by native_decide

-- fe80::1 (link-local)
theorem ex_link_local6 : isBlocked6 0xFE800000000000000000000000000001 = true := by native_decide

-- fe80::abcd:1234 (link-local)
theorem ex_link_local6_b : isBlocked6 0xFE80000000000000000000000000ABCD = true := by native_decide

-- febf::ffff (link-local, top of fe80::/10)
theorem ex_link_local6_top : isBlocked6 0xFEBF00000000000000000000FFFFFFFF = true := by native_decide

-- ff02::1 (multicast)
theorem ex_multicast6 : isBlocked6 0xFF020000000000000000000000000001 = true := by native_decide

-- ff0e::1 (multicast, global scope)
theorem ex_multicast6_global : isBlocked6 0xFF0E0000000000000000000000000001 = true := by native_decide

-- ============================================================
-- 2. Edge cases at range boundaries
-- ============================================================

-- fc00::0 blocked (start of ULA fc00::/7)
theorem edge_ula_start : isBlocked6 0xFC000000000000000000000000000000 = true := by native_decide

-- fdff:ffff:...:ffff blocked (end of ULA fc00::/7)
theorem edge_ula_end : isBlocked6 0xFDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = true := by native_decide

-- fbff:ffff:...:ffff NOT blocked (just below fc00::/7)
theorem edge_ula_below : isBlocked6 0xFBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = false := by native_decide

-- fe00::0 NOT blocked (below fe80::/10)
theorem edge_ll_below : isBlocked6 0xFE000000000000000000000000000000 = false := by native_decide

-- fe80::0 blocked (start of link-local)
theorem edge_ll_start : isBlocked6 0xFE800000000000000000000000000000 = true := by native_decide

-- febf:ffff:...:ffff blocked (end of fe80::/10)
theorem edge_ll_end : isBlocked6 0xFEBFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = true := by native_decide

-- fec0::0 NOT blocked (just above fe80::/10)
theorem edge_ll_above : isBlocked6 0xFEC00000000000000000000000000000 = false := by native_decide

-- ff00::0 blocked (start of multicast)
theorem edge_mc6_start : isBlocked6 0xFF000000000000000000000000000000 = true := by native_decide

-- feff:...:ffff NOT blocked (just below ff00::/8)
theorem edge_mc6_below : isBlocked6 0xFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = false := by native_decide

-- ============================================================
-- 3. IPv4-mapped delegation: ::ffff:A.B.C.D blocked when
--    isBlockedIp4(A.B.C.D) is true
-- ============================================================

-- ::ffff:10.0.0.1 → 10.0.0.1 blocked (RFC 1918 10.0.0.0/8)
-- 0x00000000000000000000FFFF0A000001
theorem ex_v4mapped_10 : isBlocked6 0x00000000000000000000FFFF0A000001 = true := by native_decide

-- ::ffff:127.0.0.1 → loopback blocked
-- 0x00000000000000000000FFFF7F000001
theorem ex_v4mapped_127 : isBlocked6 0x00000000000000000000FFFF7F000001 = true := by native_decide

-- ::ffff:192.168.1.1 → RFC 1918 blocked
-- 0x00000000000000000000FFFFC0A80101
theorem ex_v4mapped_192 : isBlocked6 0x00000000000000000000FFFFC0A80101 = true := by native_decide

-- ::ffff:172.16.0.1 → RFC 1918 blocked
-- 0x00000000000000000000FFFFAC100001
theorem ex_v4mapped_172 : isBlocked6 0x00000000000000000000FFFFAC100001 = true := by native_decide

-- ::ffff:8.8.8.8 → public, NOT blocked
-- 0x00000000000000000000FFFF08080808
theorem ex_v4mapped_public : isBlocked6 0x00000000000000000000FFFF08080808 = false := by native_decide

-- ============================================================
-- 4. Public addresses are NOT blocked
-- ============================================================

-- 2001:db8::1 (documentation prefix, but not in our blocklist)
theorem public_2001_db8 : isBlocked6 0x20010DB8000000000000000000000001 = false := by native_decide

-- 2606:4700::1 (Cloudflare)
theorem public_2606 : isBlocked6 0x26064700000000000000000000000001 = false := by native_decide

-- 2607:f8b0::1 (Google)
theorem public_2607 : isBlocked6 0x2607F8B0000000000000000000000001 = false := by native_decide

-- 2a00:1450::1 (Google EU)
theorem public_2a00 : isBlocked6 0x2A001450000000000000000000000001 = false := by native_decide

-- 2400:cb00::1 (Cloudflare APAC)
theorem public_2400 : isBlocked6 0x2400CB00000000000000000000000001 = false := by native_decide

-- ============================================================
-- 5. Structural proofs: CIDR mask equivalences
-- ============================================================

-- fc00::/7 ↔ (byte0 & 0xfe) == 0xfc
-- The /7 prefix means top 7 bits = 1111110, i.e. byte0 ∈ {0xfc, 0xfd}
theorem cidr_ula (ip : BitVec 128) :
    (ip >>> 121 = (0x7E : BitVec 128)) ↔
    (((ip >>> 120).truncate 8 &&& 0xFE) == (0xFC : BitVec 8)) = true := by
  constructor <;> intro h <;> bv_decide

-- fe80::/10 ↔ byte0 == 0xfe && (byte1 & 0xc0) == 0x80
-- The /10 prefix means top 10 bits = 1111111010
theorem cidr_linklocal6 (ip : BitVec 128) :
    (ip >>> 118 = (0x3FA : BitVec 128)) ↔
    (((ip >>> 120).truncate 8 == (0xFE : BitVec 8)) ∧
     (((ip >>> 112).truncate 8 &&& 0xC0) == (0x80 : BitVec 8)) = true) := by
  constructor <;> intro h <;> bv_decide

-- ff00::/8 ↔ byte0 == 0xff
theorem cidr_multicast6 (ip : BitVec 128) :
    (ip >>> 120 = (0xFF : BitVec 128)) ↔
    ((ip >>> 120).truncate 8 == (0xFF : BitVec 8)) = true := by
  constructor <;> intro h <;> bv_decide

-- ============================================================
-- 6. Completeness: CIDR membership → blocked disjunct is true
-- ============================================================

-- ULA: fc00::/7 membership → isULA = true
theorem complete_ula (ip : BitVec 128) (h : ip >>> 121 = (0x7E : BitVec 128)) :
    isULA ip = true := by
  unfold isULA byte6
  bv_decide

-- Multicast: ff00::/8 membership → isMulticast6 = true
theorem complete_multicast6 (ip : BitVec 128) (h : ip >>> 120 = (0xFF : BitVec 128)) :
    isMulticast6 ip = true := by
  unfold isMulticast6 byte6
  bv_decide

-- Link-local: fe80::/10 membership → isLinkLocal6 = true
theorem complete_linklocal6 (ip : BitVec 128) (h : ip >>> 118 = (0x3FA : BitVec 128)) :
    isLinkLocal6 ip = true := by
  unfold isLinkLocal6 byte6
  bv_decide
