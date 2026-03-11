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
