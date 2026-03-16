//! Ed25519 signing for policy locks and audit integrity.
const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const testing = std.testing;

/// Constant-time byte comparison. Returns true iff all bytes match.
/// Prevents timing side-channel attacks on secret comparisons.
pub fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

pub const seed_len: usize = Ed25519.KeyPair.seed_length;
pub const pk_len: usize = Ed25519.PublicKey.encoded_length;
pub const sig_len: usize = Ed25519.Signature.encoded_length;

pub const SeedError = error{
    BadSeedLen,
    BadHexLen,
    BadHex,
};

pub const PkError = error{
    BadPkLen,
    BadHexLen,
    BadHex,
    BadPk,
    BadPem,
    BadPemType,
    BadSsh,
};

pub const SigError = error{
    BadSigLen,
    BadHexLen,
    BadHex,
};

pub const KeyPairError = error{
    BadSeed,
};

pub const SignError = error{
    BadPk,
    WeakPk,
    KeyMismatch,
};

pub const VerifyError = error{
    BadPk,
    BadSig,
    WeakPk,
    SigMismatch,
};

pub const Seed = struct {
    raw: [seed_len]u8,

    pub fn parse(raw_in: []const u8) SeedError!Seed {
        if (raw_in.len != seed_len) return error.BadSeedLen;
        var buf: [seed_len]u8 = undefined;
        @memcpy(buf[0..], raw_in);
        return .{ .raw = buf };
    }

    pub fn parseHex(hex: []const u8) SeedError!Seed {
        if (hex.len != seed_len * 2) return error.BadHexLen;
        var buf: [seed_len]u8 = undefined;
        _ = std.fmt.hexToBytes(buf[0..], hex) catch return error.BadHex;
        return .{ .raw = buf };
    }

    pub fn bytes(self: Seed) [seed_len]u8 {
        return self.raw;
    }

    /// Read-only pointer to raw seed bytes (internal use only).
    pub fn rawSlice(self: *const Seed) *const [seed_len]u8 {
        return &self.raw;
    }

    /// Zero seed bytes. Uses volatile write to prevent compiler elision.
    pub fn wipe(self: *Seed) void {
        const ptr: *volatile [seed_len]u8 = @ptrCast(&self.raw);
        ptr.* = [_]u8{0} ** seed_len;
    }

    pub fn deinit(self: *Seed) void {
        self.wipe();
    }
};

pub const PublicKey = struct {
    raw: [pk_len]u8,

    pub fn parse(raw: []const u8) PkError!PublicKey {
        if (raw.len != pk_len) return error.BadPkLen;
        var buf: [pk_len]u8 = undefined;
        @memcpy(buf[0..], raw);
        _ = Ed25519.PublicKey.fromBytes(buf) catch return error.BadPk;
        return .{ .raw = buf };
    }

    pub fn parseHex(hex: []const u8) PkError!PublicKey {
        if (hex.len != pk_len * 2) return error.BadHexLen;
        var buf: [pk_len]u8 = undefined;
        _ = std.fmt.hexToBytes(buf[0..], hex) catch return error.BadHex;
        return parse(buf[0..]);
    }

    pub fn parseText(txt: []const u8) PkError!PublicKey {
        const trimmed = std.mem.trim(u8, txt, " \t\r\n");
        if (trimmed.len == 0) return error.BadPkLen;
        if (std.mem.startsWith(u8, trimmed, "ssh-ed25519 ")) return parseSsh(trimmed);
        if (std.mem.indexOf(u8, trimmed, "-----BEGIN ")) |_| return parsePem(trimmed);
        if (trimmed.len == pk_len * 2) return parseHex(trimmed);
        return parse(trimmed);
    }

    pub fn bytes(self: PublicKey) [pk_len]u8 {
        return self.raw;
    }

    pub fn verify(self: PublicKey, msg: []const u8, sig: Signature) VerifyError!Verified {
        return verifyDetached(msg, sig, self);
    }

    fn inner(self: PublicKey) VerifyError!Ed25519.PublicKey {
        return Ed25519.PublicKey.fromBytes(self.raw) catch return error.BadPk;
    }
};

const pem_begin = "-----BEGIN PUBLIC KEY-----";
const pem_end = "-----END PUBLIC KEY-----";
const ed25519_spki_prefix = [_]u8{ 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };

fn parsePem(txt: []const u8) PkError!PublicKey {
    if (!std.mem.startsWith(u8, txt, pem_begin)) return error.BadPemType;
    const end_idx = std.mem.indexOf(u8, txt, pem_end) orelse return error.BadPem;
    const body = txt[pem_begin.len..end_idx];

    var b64_buf: [256]u8 = undefined;
    var n: usize = 0;
    for (body) |c| switch (c) {
        ' ', '\t', '\r', '\n' => {},
        else => {
            if (n >= b64_buf.len) return error.BadPem;
            b64_buf[n] = c;
            n += 1;
        },
    };
    if (n == 0) return error.BadPem;

    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(b64_buf[0..n]) catch return error.BadPem;
    var der_buf: [128]u8 = undefined;
    if (dec_len > der_buf.len) return error.BadPem;
    _ = std.base64.standard.Decoder.decode(der_buf[0..dec_len], b64_buf[0..n]) catch return error.BadPem;
    if (dec_len != ed25519_spki_prefix.len + pk_len) return error.BadPem;
    if (!std.mem.eql(u8, der_buf[0..ed25519_spki_prefix.len], ed25519_spki_prefix[0..])) return error.BadPemType;
    return PublicKey.parse(der_buf[ed25519_spki_prefix.len..dec_len]);
}

fn parseSsh(txt: []const u8) PkError!PublicKey {
    var it = std.mem.tokenizeAny(u8, txt, " \t\r\n");
    const kind = it.next() orelse return error.BadSsh;
    const b64 = it.next() orelse return error.BadSsh;
    if (!std.mem.eql(u8, kind, "ssh-ed25519")) return error.BadSsh;

    const dec_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.BadSsh;
    var blob: [128]u8 = undefined;
    if (dec_len > blob.len) return error.BadSsh;
    _ = std.base64.standard.Decoder.decode(blob[0..dec_len], b64) catch return error.BadSsh;

    var off: usize = 0;
    const name = readSshStr(blob[0..dec_len], &off) catch return error.BadSsh;
    if (!std.mem.eql(u8, name, "ssh-ed25519")) return error.BadSsh;
    const key = readSshStr(blob[0..dec_len], &off) catch return error.BadSsh;
    if (off != dec_len) return error.BadSsh;
    return PublicKey.parse(key);
}

fn readSshStr(buf: []const u8, off: *usize) error{BadSsh}![]const u8 {
    if (off.* + 4 > buf.len) return error.BadSsh;
    const n = std.mem.readInt(u32, buf[off.*..][0..4], .big);
    off.* += 4;
    if (off.* + n > buf.len) return error.BadSsh;
    const out = buf[off.*..][0..n];
    off.* += n;
    return out;
}

pub const Signature = struct {
    raw: [sig_len]u8,

    pub fn parse(raw: []const u8) SigError!Signature {
        if (raw.len != sig_len) return error.BadSigLen;
        var buf: [sig_len]u8 = undefined;
        @memcpy(buf[0..], raw);
        return .{ .raw = buf };
    }

    pub fn parseHex(hex: []const u8) SigError!Signature {
        if (hex.len != sig_len * 2) return error.BadHexLen;
        var buf: [sig_len]u8 = undefined;
        _ = std.fmt.hexToBytes(buf[0..], hex) catch return error.BadHex;
        return .{ .raw = buf };
    }

    pub fn bytes(self: Signature) [sig_len]u8 {
        return self.raw;
    }

    pub fn verify(self: Signature, msg: []const u8, pk: PublicKey) VerifyError!Verified {
        return verifyDetached(msg, self, pk);
    }

    fn inner(self: Signature) Ed25519.Signature {
        return Ed25519.Signature.fromBytes(self.raw);
    }
};

pub const KeyPair = struct {
    pair: Ed25519.KeyPair,

    pub fn fromSeed(seed: Seed) KeyPairError!KeyPair {
        const pair = Ed25519.KeyPair.generateDeterministic(seed.rawSlice().*) catch return error.BadSeed;
        return .{ .pair = pair };
    }

    pub fn publicKey(self: KeyPair) PublicKey {
        return .{ .raw = self.pair.public_key.toBytes() };
    }

    pub fn sign(self: KeyPair, msg: []const u8) SignError!Signature {
        const sig = self.pair.sign(msg, null) catch |err| switch (err) {
            error.IdentityElement, error.NonCanonical => return error.BadPk,
            error.WeakPublicKey => return error.WeakPk,
            error.KeyMismatch => return error.KeyMismatch,
        };
        return .{ .raw = sig.toBytes() };
    }

    /// Zero secret key bytes. Uses volatile write to prevent compiler elision.
    pub fn wipe(self: *KeyPair) void {
        const ptr: *volatile [Ed25519.SecretKey.encoded_length]u8 = @ptrCast(&self.pair.secret_key);
        ptr.* = [_]u8{0} ** Ed25519.SecretKey.encoded_length;
    }

    pub fn deinit(self: *KeyPair) void {
        self.wipe();
    }
};

pub const Verified = struct {
    pk: PublicKey,
    sig: Signature,
};

pub fn verifyDetached(msg: []const u8, sig: Signature, pk: PublicKey) VerifyError!Verified {
    const inner_pk = try pk.inner();
    sig.inner().verify(msg, inner_pk) catch |err| switch (err) {
        error.NonCanonical, error.InvalidEncoding, error.IdentityElement => return error.BadSig,
        error.WeakPublicKey => return error.WeakPk,
        error.SignatureVerificationFailed => return error.SigMismatch,
    };
    return .{ .pk = pk, .sig = sig };
}

// ── Key identity and trust ──────────────────────────────────────────

pub const key_id_len: usize = 8;
pub const key_id_hex_len: usize = key_id_len * 2;

/// Derive key ID from public key: first 8 bytes of SHA-256(pk).
pub fn keyIdFromPk(pk: PublicKey) [key_id_len]u8 {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(pk.raw[0..], &digest, .{});
    return digest[0..key_id_len].*;
}

pub const TrustAnchor = struct {
    id: [key_id_len]u8,
    pk: PublicKey,
    revoked: bool = false,
};

pub const KeyRing = struct {
    anchors: []const TrustAnchor,

    pub fn resolve(self: KeyRing, kid: [key_id_len]u8) KeyRingError!PublicKey {
        for (self.anchors) |a| {
            if (std.mem.eql(u8, a.id[0..], kid[0..])) {
                if (a.revoked) return error.KeyRevoked;
                return a.pk;
            }
        }
        return error.KeyNotFound;
    }

    pub fn fromSingle(anchor: *const TrustAnchor) KeyRing {
        return .{ .anchors = @as(*const [1]TrustAnchor, @ptrCast(anchor)) };
    }
};

pub const KeyRingError = error{
    KeyNotFound,
    KeyRevoked,
};

// ── Keyed redaction surrogates ──────────────────────────────────────
//
// HMAC-SHA256 based surrogates so redacted values are not globally
// correlatable. Each session derives its own RedactKey from its sid.

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const rkey_len: usize = HmacSha256.mac_length;

pub const RedactKey = struct {
    bytes: [rkey_len]u8,

    /// Derive a redaction key from a session id using domain separation.
    pub fn fromSid(sid: []const u8) RedactKey {
        var out: [rkey_len]u8 = undefined;
        HmacSha256.create(&out, sid, "pz-redact-v1");
        return .{ .bytes = out };
    }

    /// Produce a 16-hex-char surrogate for `txt` under this key.
    /// Returns the hex string written into `buf`.
    pub fn surrogate(self: RedactKey, txt: []const u8, buf: *[16]u8) []const u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&mac, txt, &self.bytes);
        // Truncate to 8 bytes, format as 16 hex chars.
        const hex = std.fmt.bytesToHex(mac[0..8].*, .lower);
        buf.* = hex;
        return buf[0..16];
    }
};

// ── Release manifest ────────────────────────────────────────────────
//
// A manifest binds (version, asset, sha256, url, key_id) to a signature
// so that unsigned metadata cannot induce downgrade or content/version
// mismatch. Wire format: "pz-manifest-v1\n" header followed by
// key=value lines terminated by "\n", then 128 hex chars of Ed25519
// signature over the canonical text (header + fields, excluding the
// signature line itself).

pub const Manifest = struct {
    version: []const u8,
    asset: []const u8,
    sha256: [64]u8, // hex-encoded SHA-256
    url: []const u8,
    key_id: [key_id_hex_len]u8, // hex-encoded key ID
    sig: Signature,

    pub const header = "pz-manifest-v1\n";
    pub const max_len = 4096;

    pub const ParseError = error{
        BadHeader,
        BadField,
        MissingSig,
        MissingField,
    };

    /// Build the canonical signed payload (everything except the sig= line).
    pub fn canonical(self: Manifest, buf: *[max_len]u8) error{Overflow}![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();
        w.writeAll(header) catch return error.Overflow;
        w.print("version={s}\n", .{self.version}) catch return error.Overflow;
        w.print("asset={s}\n", .{self.asset}) catch return error.Overflow;
        w.print("sha256={s}\n", .{self.sha256}) catch return error.Overflow;
        w.print("url={s}\n", .{self.url}) catch return error.Overflow;
        w.print("key_id={s}\n", .{self.key_id}) catch return error.Overflow;
        return fbs.getWritten();
    }

    /// Parse a manifest from wire text.
    pub fn parse(txt: []const u8) (ParseError || SigError)!Manifest {
        if (!std.mem.startsWith(u8, txt, header)) return error.BadHeader;
        var ver: ?[]const u8 = null;
        var asset: ?[]const u8 = null;
        var sha: ?[64]u8 = null;
        var url: ?[]const u8 = null;
        var kid: ?[key_id_hex_len]u8 = null;
        var sig: ?Signature = null;

        var it = std.mem.splitScalar(u8, txt[header.len..], '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "version=")) {
                ver = line["version=".len..];
            } else if (std.mem.startsWith(u8, line, "asset=")) {
                asset = line["asset=".len..];
            } else if (std.mem.startsWith(u8, line, "sha256=")) {
                const val = line["sha256=".len..];
                if (val.len != 64) return error.BadField;
                sha = val[0..64].*;
            } else if (std.mem.startsWith(u8, line, "url=")) {
                url = line["url=".len..];
            } else if (std.mem.startsWith(u8, line, "key_id=")) {
                const val = line["key_id=".len..];
                if (val.len != key_id_hex_len) return error.BadField;
                kid = val[0..key_id_hex_len].*;
            } else if (std.mem.startsWith(u8, line, "sig=")) {
                const val = line["sig=".len..];
                sig = try Signature.parseHex(std.mem.trim(u8, val, " \t\r"));
            }
        }
        return .{
            .version = ver orelse return error.MissingField,
            .asset = asset orelse return error.MissingField,
            .sha256 = sha orelse return error.MissingField,
            .url = url orelse return error.MissingField,
            .key_id = kid orelse return error.MissingField,
            .sig = sig orelse return error.MissingSig,
        };
    }
};

pub const ManifestVerifyError = VerifyError || Manifest.ParseError || SigError || KeyRingError || error{
    Overflow,
    DigestMismatch,
    VersionMismatch,
    AssetMismatch,
    Downgrade,
    BadKeyId,
};

/// Verify a signed manifest against a single public key.
pub fn verifyManifest(
    txt: []const u8,
    pk: PublicKey,
    archive: []const u8,
    expected_ver: []const u8,
    expected_asset: []const u8,
) ManifestVerifyError!Manifest {
    const kid = keyIdFromPk(pk);
    const kid_hex = std.fmt.bytesToHex(kid, .lower);
    const anchor = TrustAnchor{ .id = kid, .pk = pk };
    return verifyManifestRing(txt, KeyRing.fromSingle(&anchor), archive, expected_ver, expected_asset, kid_hex);
}

/// Verify a signed manifest against a key ring. The manifest key_id
/// selects the signing key; the ring enforces revocation.
pub fn verifyManifestRing(
    txt: []const u8,
    ring: KeyRing,
    archive: []const u8,
    expected_ver: []const u8,
    expected_asset: []const u8,
    expected_kid_hex: ?[key_id_hex_len]u8,
) ManifestVerifyError!Manifest {
    const m = try Manifest.parse(txt);

    var kid_raw: [key_id_len]u8 = undefined;
    _ = std.fmt.hexToBytes(kid_raw[0..], m.key_id[0..]) catch return error.BadKeyId;
    const pk = try ring.resolve(kid_raw);

    if (expected_kid_hex) |exp| {
        if (!ctEql(exp[0..], m.key_id[0..])) return error.BadKeyId;
    }

    var buf: [Manifest.max_len]u8 = undefined;
    const payload = try m.canonical(&buf);
    _ = try verifyDetached(payload, m.sig, pk);

    const Sha256 = std.crypto.hash.sha2.Sha256;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(archive, &digest, .{});
    const actual_hex = std.fmt.bytesToHex(digest, .lower);
    if (!ctEql(actual_hex[0..], m.sha256[0..])) return error.DigestMismatch;

    if (!std.mem.eql(u8, m.version, expected_ver)) return error.VersionMismatch;
    if (!std.mem.eql(u8, m.asset, expected_asset)) return error.AssetMismatch;

    return m;
}

/// Anti-downgrade: manifest version must be strictly newer.
pub fn checkNotDowngrade(manifest_ver: []const u8, current_ver: []const u8) error{Downgrade}!void {
    const cur = parseSemver(current_ver) orelse return;
    const mfst = parseSemver(manifest_ver) orelse return error.Downgrade;
    if (!mfst.isNewer(cur)) return error.Downgrade;
}

const SimpleSemver = struct {
    major: u16,
    minor: u16,
    patch: u16,

    fn isNewer(self: SimpleSemver, other: SimpleSemver) bool {
        if (self.major != other.major) return self.major > other.major;
        if (self.minor != other.minor) return self.minor > other.minor;
        return self.patch > other.patch;
    }
};

fn parseSemver(raw: []const u8) ?SimpleSemver {
    var s = raw;
    if (s.len > 0 and s[0] == 'v') s = s[1..];
    if (std.mem.indexOfScalar(u8, s, '-')) |i| s = s[0..i];
    var it = std.mem.splitScalar(u8, s, '.');
    const major = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    const patch = std.fmt.parseInt(u16, it.next() orelse return null, 10) catch return null;
    return .{ .major = major, .minor = minor, .patch = patch };
}

pub fn signManifestAlloc(
    alloc: std.mem.Allocator,
    ver: []const u8,
    asset: []const u8,
    archive: []const u8,
    url: []const u8,
    kp_in: KeyPair,
) (std.mem.Allocator.Error || SignError || error{Overflow})![]u8 {
    var kp = kp_in;
    defer kp.wipe();

    const Sha256 = std.crypto.hash.sha2.Sha256;
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(archive, &digest, .{});
    const sha_hex = std.fmt.bytesToHex(digest, .lower);

    const kid = keyIdFromPk(kp.publicKey());
    const kid_hex = std.fmt.bytesToHex(kid, .lower);

    const m = Manifest{
        .version = ver,
        .asset = asset,
        .sha256 = sha_hex,
        .url = url,
        .key_id = kid_hex,
        .sig = undefined,
    };
    var buf: [Manifest.max_len]u8 = undefined;
    const payload = m.canonical(&buf) catch return error.Overflow;
    const sig = try kp.sign(payload);
    const sig_hex_arr = std.fmt.bytesToHex(sig.raw, .lower);

    return std.fmt.allocPrint(alloc, "{s}sig={s}\n", .{ payload, sig_hex_arr[0..] });
}

const seed_hex = "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166";
const pk_hex = "2d6f7455d97b4a3a10d7293909d1a4f2058cb9a370e43fa8154bb280db839083";
const sig_hex = "10a442b4a80cc4225b154f43bef28d2472ca80221951262eb8e0df9091575e2687cc486e77263c3418c757522d54f84b0359236abbbd4acd20dc297fdca66808";
const pk_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MCowBQYDK2VwAyEALW90Vdl7SjoQ1yk5CdGk8gWMuaNw5D+oFUuygNuDkIM=
    \\-----END PUBLIC KEY-----
;
const pk_ssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC1vdFXZe0o6ENcpOQnRpPIFjLmjcOQ/qBVLsoDbg5CD fixture@example";

fn fixtureSeed() !Seed {
    return Seed.parseHex(seed_hex);
}

fn fixtureKeyPair() !KeyPair {
    return KeyPair.fromSeed(try fixtureSeed());
}

fn fixturePublicKey() !PublicKey {
    return PublicKey.parseHex(pk_hex);
}

fn fixtureSignature() !Signature {
    return Signature.parseHex(sig_hex);
}

fn seedFromParts(a: u64, b: u64, c: u64, d: u64) Seed {
    var raw: [seed_len]u8 = undefined;
    std.mem.writeInt(u64, raw[0..8], a, .little);
    std.mem.writeInt(u64, raw[8..16], b, .little);
    std.mem.writeInt(u64, raw[16..24], c, .little);
    std.mem.writeInt(u64, raw[24..32], d, .little);
    return .{ .raw = raw };
}

fn mutateMsg(alloc: std.mem.Allocator, msg: []const u8, flip: u8) ![]u8 {
    const n = if (msg.len == 0) @as(usize, 1) else msg.len;
    const buf = try alloc.alloc(u8, n);
    if (msg.len == 0) {
        buf[0] = flip | 1;
        return buf;
    }

    @memcpy(buf, msg);
    const idx = @as(usize, flip) % msg.len;
    buf[idx] ^= flip | 1;
    return buf;
}

fn mutateSig(sig: Signature, flip: u8) Signature {
    var raw = sig.raw;
    const idx = @as(usize, flip) % sig_len;
    raw[idx] ^= flip | 1;
    return .{ .raw = raw };
}

test "seed derives expected public key" {
    const kp = try fixtureKeyPair();
    const exp = try fixturePublicKey();

    try testing.expectEqualSlices(u8, exp.raw[0..], kp.publicKey().raw[0..]);
}

test "deterministic sign matches fixture" {
    const kp = try fixtureKeyPair();
    const got = try kp.sign("test");
    const exp = try fixtureSignature();

    try testing.expectEqualSlices(u8, exp.raw[0..], got.raw[0..]);
}

test "verify accepts known good signature" {
    const pk = try fixturePublicKey();
    const sig = try fixtureSignature();
    const checked = try verifyDetached("test", sig, pk);

    try testing.expectEqualSlices(u8, pk.raw[0..], checked.pk.raw[0..]);
    try testing.expectEqualSlices(u8, sig.raw[0..], checked.sig.raw[0..]);
}

test "verify rejects mutated message" {
    const pk = try fixturePublicKey();
    const sig = try fixtureSignature();

    try testing.expectError(error.SigMismatch, verifyDetached("TEST", sig, pk));
}

test "verify rejects wrong signature" {
    const pk = try fixturePublicKey();
    const kp = try fixtureKeyPair();
    const sig = try kp.sign("TEST");

    try testing.expectError(error.SigMismatch, verifyDetached("test", sig, pk));
}

test "parse rejects malformed input" {
    try testing.expectError(error.BadSeedLen, Seed.parse("short"));
    try testing.expectError(error.BadPkLen, PublicKey.parse("short"));
    try testing.expectError(error.BadSigLen, Signature.parse("short"));
    try testing.expectError(error.BadHexLen, Seed.parseHex("00"));
    try testing.expectError(error.BadHex, PublicKey.parseHex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
}

test "verify rejects malformed signature bytes" {
    const pk = try fixturePublicKey();
    var raw = (try fixtureSignature()).raw;
    raw[0] ^= 0x01;
    const sig = try Signature.parse(raw[0..]);

    try testing.expectError(error.BadSig, verifyDetached("test", sig, pk));
}

test "parsed fixture keys preserve behavior across hex pem and ssh forms" {
    const exp = try fixturePublicKey();
    const sig = try fixtureSignature();
    const hex = try PublicKey.parseText(pk_hex);
    const pem = try PublicKey.parseText(pk_pem);
    const ssh = try PublicKey.parseText(pk_ssh);
    const pks = [_]PublicKey{ hex, pem, ssh };

    for (pks) |pk| {
        try testing.expectEqualSlices(u8, exp.raw[0..], pk.raw[0..]);
        const checked = try verifyDetached("test", sig, pk);
        try testing.expectEqualSlices(u8, pk.raw[0..], checked.pk.raw[0..]);
        try testing.expectEqualSlices(u8, sig.raw[0..], checked.sig.raw[0..]);
    }
}

test "parseText rejects wrong pem type and malformed ssh payload" {
    const bad_pem =
        \\-----BEGIN PRIVATE KEY-----
        \\MC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        \\-----END PRIVATE KEY-----
    ;

    try testing.expectError(error.BadPemType, PublicKey.parseText(bad_pem));
    try testing.expectError(error.BadSsh, PublicKey.parseText("ssh-ed25519 AAAA"));
}

test "signing property: valid signatures verify" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u64, b: u64, c: u64, d: u64, msg: zc.String }) bool {
            const msg = args.msg.slice();
            const seed = seedFromParts(args.a, args.b, args.c, args.d);
            const kp = KeyPair.fromSeed(seed) catch return false;
            const pk = kp.publicKey();
            const sig = kp.sign(msg) catch return false;
            const checked = verifyDetached(msg, sig, pk) catch return false;

            return std.mem.eql(u8, pk.raw[0..], checked.pk.raw[0..]) and
                std.mem.eql(u8, sig.raw[0..], checked.sig.raw[0..]);
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0x5eed_ed25,
    });
}

test "signing property: message mutation fails verification" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u64, b: u64, c: u64, d: u64, msg: zc.String, flip: u8 }) bool {
            const msg = args.msg.slice();
            const seed = seedFromParts(args.a, args.b, args.c, args.d);
            const kp = KeyPair.fromSeed(seed) catch return false;
            const sig = kp.sign(msg) catch return false;
            const bad = mutateMsg(testing.allocator, msg, args.flip) catch return false;
            defer testing.allocator.free(bad);

            _ = verifyDetached(bad, sig, kp.publicKey()) catch |err| return err == error.SigMismatch;
            return false;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0x5eed_bad1,
    });
}

test "signing property: signature mutation fails verification" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: u64, b: u64, c: u64, d: u64, msg: zc.String, flip: u8 }) bool {
            const msg = args.msg.slice();
            const seed = seedFromParts(args.a, args.b, args.c, args.d);
            const kp = KeyPair.fromSeed(seed) catch return false;
            const sig = kp.sign(msg) catch return false;
            const bad = mutateSig(sig, args.flip);

            _ = verifyDetached(msg, bad, kp.publicKey()) catch return true;
            return false;
        }
    }.prop, .{
        .iterations = 500,
        .seed = 0x5eed_51a9,
    });
}

test "manifest roundtrip sign and verify" {
    const kp = try fixtureKeyPair();
    const pk = kp.publicKey();
    const archive = "binary-content-here";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.2.3",
        "pz-aarch64-macos.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    const m = try verifyManifest(txt, pk, archive, "v1.2.3", "pz-aarch64-macos.tar.gz");
    try testing.expectEqualStrings("v1.2.3", m.version);
    try testing.expectEqualStrings("pz-aarch64-macos.tar.gz", m.asset);
    try testing.expectEqualStrings("https://dl.example/pz.tar.gz", m.url);
}

test "manifest rejects tampered archive" {
    const kp = try fixtureKeyPair();
    const pk = kp.publicKey();
    const archive = "binary-content-here";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.2.3",
        "pz-aarch64-macos.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    try testing.expectError(
        error.DigestMismatch,
        verifyManifest(txt, pk, "tampered-binary", "v1.2.3", "pz-aarch64-macos.tar.gz"),
    );
}

test "manifest rejects version mismatch" {
    const kp = try fixtureKeyPair();
    const pk = kp.publicKey();
    const archive = "binary-content-here";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.2.3",
        "pz-aarch64-macos.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    try testing.expectError(
        error.VersionMismatch,
        verifyManifest(txt, pk, archive, "v9.9.9", "pz-aarch64-macos.tar.gz"),
    );
}

test "manifest rejects asset mismatch" {
    const kp = try fixtureKeyPair();
    const pk = kp.publicKey();
    const archive = "binary-content-here";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.2.3",
        "pz-aarch64-macos.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    try testing.expectError(
        error.AssetMismatch,
        verifyManifest(txt, pk, archive, "v1.2.3", "pz-x86_64-linux.tar.gz"),
    );
}

test "manifest rejects wrong signing key" {
    const kp = try fixtureKeyPair();
    const archive = "binary-content-here";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.2.3",
        "pz-aarch64-macos.tar.gz",
        archive,
        "https://dl.example/pz.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    // Different key -- manifest key_id won't match the other key's ring.
    const other_seed = seedFromParts(1, 2, 3, 4);
    const other_kp = try KeyPair.fromSeed(other_seed);
    const other_pk = other_kp.publicKey();

    const err = verifyManifest(txt, other_pk, archive, "v1.2.3", "pz-aarch64-macos.tar.gz");
    try testing.expectError(error.KeyNotFound, err);
}

test "manifest parse rejects bad header" {
    try testing.expectError(error.BadHeader, Manifest.parse("bad-header\nversion=v1\n"));
}

test "manifest parse rejects missing fields" {
    try testing.expectError(error.MissingField, Manifest.parse("pz-manifest-v1\nsig=00" ++ "00" ** 63 ++ "\n"));
}

test "ctEql matches identical slices" {
    try testing.expect(ctEql("hello", "hello"));
    try testing.expect(ctEql("", ""));
    try testing.expect(ctEql(&[_]u8{ 0, 0xff }, &[_]u8{ 0, 0xff }));
}

test "ctEql rejects different slices" {
    try testing.expect(!ctEql("hello", "world"));
    try testing.expect(!ctEql("hello", "hellp"));
    try testing.expect(!ctEql(&[_]u8{0x00}, &[_]u8{0x01}));
}

test "ctEql rejects different lengths" {
    try testing.expect(!ctEql("abc", "ab"));
    try testing.expect(!ctEql("", "a"));
}

test "keyIdFromPk is deterministic" {
    const pk = try fixturePublicKey();
    const id1 = keyIdFromPk(pk);
    const id2 = keyIdFromPk(pk);
    try testing.expectEqualSlices(u8, id1[0..], id2[0..]);
    try testing.expectEqual(@as(usize, 8), id1.len);
}

test "keyIdFromPk differs for different keys" {
    const pk1 = try fixturePublicKey();
    const kp2 = try KeyPair.fromSeed(seedFromParts(1, 2, 3, 4));
    const id1 = keyIdFromPk(pk1);
    const id2 = keyIdFromPk(kp2.publicKey());
    try testing.expect(!std.mem.eql(u8, id1[0..], id2[0..]));
}

test "key ring resolves known key" {
    const pk = try fixturePublicKey();
    const kid = keyIdFromPk(pk);
    const anchor = TrustAnchor{ .id = kid, .pk = pk };
    const ring = KeyRing.fromSingle(&anchor);
    const got = try ring.resolve(kid);
    try testing.expectEqualSlices(u8, pk.raw[0..], got.raw[0..]);
}

test "key ring rejects unknown key" {
    const pk = try fixturePublicKey();
    const kid = keyIdFromPk(pk);
    const anchor = TrustAnchor{ .id = kid, .pk = pk };
    const ring = KeyRing.fromSingle(&anchor);
    var bad = kid;
    bad[0] ^= 0xff;
    try testing.expectError(error.KeyNotFound, ring.resolve(bad));
}

test "key ring rejects revoked key" {
    const pk = try fixturePublicKey();
    const kid = keyIdFromPk(pk);
    const anchor = TrustAnchor{ .id = kid, .pk = pk, .revoked = true };
    const ring = KeyRing.fromSingle(&anchor);
    try testing.expectError(error.KeyRevoked, ring.resolve(kid));
}

test "manifest ring roundtrip with multi-key ring" {
    const kp1 = try fixtureKeyPair();
    const pk1 = kp1.publicKey();
    const kid1 = keyIdFromPk(pk1);

    const kp2 = try KeyPair.fromSeed(seedFromParts(10, 20, 30, 40));
    const pk2 = kp2.publicKey();
    const kid2 = keyIdFromPk(pk2);

    const anchors = [_]TrustAnchor{
        .{ .id = kid1, .pk = pk1 },
        .{ .id = kid2, .pk = pk2 },
    };
    const ring = KeyRing{ .anchors = anchors[0..] };

    const archive = "ring-test-content";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v2.0.0",
        "pz-test.tar.gz",
        archive,
        "https://dl.example/pz2.tar.gz",
        kp2,
    );
    defer testing.allocator.free(txt);

    const m = try verifyManifestRing(txt, ring, archive, "v2.0.0", "pz-test.tar.gz", null);
    try testing.expectEqualStrings("v2.0.0", m.version);
}

test "manifest ring rejects revoked signer" {
    const kp = try fixtureKeyPair();
    const pk = kp.publicKey();
    const kid = keyIdFromPk(pk);

    const anchor = TrustAnchor{ .id = kid, .pk = pk, .revoked = true };
    const ring = KeyRing.fromSingle(&anchor);

    const archive = "revoked-test";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v3.0.0",
        "pz-test.tar.gz",
        archive,
        "https://dl.example/pz3.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);

    try testing.expectError(
        error.KeyRevoked,
        verifyManifestRing(txt, ring, archive, "v3.0.0", "pz-test.tar.gz", null),
    );
}

test "checkNotDowngrade allows newer version" {
    try checkNotDowngrade("v2.0.0", "v1.0.0");
    try checkNotDowngrade("v1.1.0", "v1.0.0");
    try checkNotDowngrade("v1.0.1", "v1.0.0");
}

test "checkNotDowngrade rejects same or older" {
    try testing.expectError(error.Downgrade, checkNotDowngrade("v1.0.0", "v1.0.0"));
    try testing.expectError(error.Downgrade, checkNotDowngrade("v0.9.0", "v1.0.0"));
    try testing.expectError(error.Downgrade, checkNotDowngrade("v1.0.0", "v2.0.0"));
}

test "checkNotDowngrade allows unparseable current" {
    try checkNotDowngrade("v1.0.0", "dev");
}

test "checkNotDowngrade rejects unparseable manifest" {
    try testing.expectError(error.Downgrade, checkNotDowngrade("bad", "v1.0.0"));
}

test "manifest key_id in canonical form" {
    const kp = try fixtureKeyPair();
    const archive = "canonical-test";
    const txt = try signManifestAlloc(
        testing.allocator,
        "v1.0.0",
        "test.tar.gz",
        archive,
        "https://dl.example/t.tar.gz",
        kp,
    );
    defer testing.allocator.free(txt);
    try testing.expect(std.mem.indexOf(u8, txt, "key_id=") != null);
}

test "manifest parse rejects missing key_id" {
    const raw = "pz-manifest-v1\nversion=v1\nasset=a\nsha256=" ++ "aa" ** 32 ++ "\nurl=u\nsig=" ++ "00" ** 64 ++ "\n";
    try testing.expectError(error.MissingField, Manifest.parse(raw));
}

test "manifest parse rejects bad key_id length" {
    const raw = "pz-manifest-v1\nversion=v1\nasset=a\nsha256=" ++ "aa" ** 32 ++ "\nurl=u\nkey_id=short\nsig=" ++ "00" ** 64 ++ "\n";
    try testing.expectError(error.BadField, Manifest.parse(raw));
}

test "redact key from sid is deterministic" {
    const k1 = RedactKey.fromSid("sess-01");
    const k2 = RedactKey.fromSid("sess-01");
    try testing.expectEqualSlices(u8, k1.bytes[0..], k2.bytes[0..]);
}

test "redact key differs across sessions" {
    const k1 = RedactKey.fromSid("sess-01");
    const k2 = RedactKey.fromSid("sess-02");
    try testing.expect(!std.mem.eql(u8, k1.bytes[0..], k2.bytes[0..]));
}

test "surrogate is deterministic under same key" {
    const key = RedactKey.fromSid("sess-x");
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    _ = key.surrogate("secret", &b1);
    _ = key.surrogate("secret", &b2);
    try testing.expectEqualSlices(u8, b1[0..], b2[0..]);
}

test "surrogate differs across keys for same input" {
    const k1 = RedactKey.fromSid("sess-a");
    const k2 = RedactKey.fromSid("sess-b");
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    _ = k1.surrogate("secret", &b1);
    _ = k2.surrogate("secret", &b2);
    try testing.expect(!std.mem.eql(u8, b1[0..], b2[0..]));
}

test "surrogate differs for different inputs under same key" {
    const key = RedactKey.fromSid("sess-z");
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    _ = key.surrogate("alpha", &b1);
    _ = key.surrogate("beta", &b2);
    try testing.expect(!std.mem.eql(u8, b1[0..], b2[0..]));
}

test "P36b RedactKey rotation produces different surrogates after rekey" {
    // Simulates session key rotation: same input text under two different
    // session-derived keys must produce distinct surrogates, proving that
    // a rekey (new sid) decorrelates previously redacted values.
    const txt = "api-key-12345";
    const k1 = RedactKey.fromSid("sess-before-rotation");
    const k2 = RedactKey.fromSid("sess-after-rotation");

    // Keys themselves must differ.
    try testing.expect(!std.mem.eql(u8, k1.bytes[0..], k2.bytes[0..]));

    // Surrogates for identical input must differ.
    var b1: [16]u8 = undefined;
    var b2: [16]u8 = undefined;
    _ = k1.surrogate(txt, &b1);
    _ = k2.surrogate(txt, &b2);
    try testing.expect(!std.mem.eql(u8, b1[0..], b2[0..]));

    // Each key is individually deterministic (idempotent).
    var b1b: [16]u8 = undefined;
    var b2b: [16]u8 = undefined;
    _ = k1.surrogate(txt, &b1b);
    _ = k2.surrogate(txt, &b2b);
    try testing.expectEqualSlices(u8, b1[0..], b1b[0..]);
    try testing.expectEqualSlices(u8, b2[0..], b2b[0..]);
}

test "seed wipe zeroes bytes" {
    var seed = try Seed.parseHex(seed_hex);
    // Confirm non-zero before wipe.
    var any_nonzero = false;
    for (seed.rawSlice()) |b| if (b != 0) {
        any_nonzero = true;
        break;
    };
    try testing.expect(any_nonzero);
    seed.wipe();
    for (seed.rawSlice()) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "seed deinit zeroes bytes" {
    var seed = try Seed.parseHex(seed_hex);
    seed.deinit();
    for (seed.rawSlice()) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "keypair wipe zeroes secret key" {
    var kp = try fixtureKeyPair();
    // Confirm non-zero before wipe.
    const sk_bytes: []const u8 = std.mem.asBytes(&kp.pair.secret_key);
    var any_nonzero = false;
    for (sk_bytes) |b| if (b != 0) {
        any_nonzero = true;
        break;
    };
    try testing.expect(any_nonzero);
    kp.wipe();
    const wiped: []const u8 = std.mem.asBytes(&kp.pair.secret_key);
    for (wiped) |b| try testing.expectEqual(@as(u8, 0), b);
}

test "keypair deinit zeroes secret key" {
    var kp = try fixtureKeyPair();
    kp.deinit();
    const wiped: []const u8 = std.mem.asBytes(&kp.pair.secret_key);
    for (wiped) |b| try testing.expectEqual(@as(u8, 0), b);
}

// ── Proof canary ────────────────────────────────────────────────────

test "canary: ctEql correctness (Lean CtEql.ctEql_iff)" {
    const zc = @import("zcheck");
    try zc.check(struct {
        fn prop(args: struct { a: zc.Id, b: zc.Id }) bool {
            const sa = args.a.slice();
            const sb = args.b.slice();
            const ct = ctEql(sa, sb);
            const eq = std.mem.eql(u8, sa, sb);
            return ct == eq;
        }
    }.prop, .{ .iterations = 5000 });
}
