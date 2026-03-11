const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const testing = std.testing;

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

    pub fn parse(raw: []const u8) SeedError!Seed {
        if (raw.len != seed_len) return error.BadSeedLen;
        var buf: [seed_len]u8 = undefined;
        @memcpy(buf[0..], raw);
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
        const pair = Ed25519.KeyPair.generateDeterministic(seed.raw) catch return error.BadSeed;
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
