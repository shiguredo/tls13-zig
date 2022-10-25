const std = @import("std");
const io = std.io;
const math = std.math;
const bigInt = math.big.int;

const expect = std.testing.expect;

pub const Rsa1024 = Rsa(1024);
pub const Rsa2048 = Rsa(2048);
pub const Rsa4096 = Rsa(4096);

pub fn Rsa(comptime modulus_bits: usize) type {
    const modulus_length = modulus_bits / 8;

    return struct {
        const Error = error{
            InvalidKeyLength,
            BufferTooSmall,
            MessageTooLong,
            EncodingError,
        };

        pub const SecretKey = struct {
            n: bigInt.Managed,
            d: bigInt.Managed,

            const Self = @This();

            pub fn deinit(self: *Self) void {
                self.n.deinit();
                self.d.deinit();
            }

            pub fn fromBytes(priv_bytes: []u8, modulus_bytes: []u8, allocator: std.mem.Allocator) !SecretKey {
                if (modulus_bytes.len != modulus_length) {
                    return Error.InvalidKeyLength;
                }

                if (priv_bytes.len > modulus_length) {
                    return Error.InvalidKeyLength;
                }

                var _n = try bigInt.Managed.init(allocator);
                errdefer _n.deinit();
                try setBytes(&_n, modulus_bytes, allocator);

                var _d = try bigInt.Managed.init(allocator);
                errdefer _d.deinit();
                try setBytes(&_d, priv_bytes, allocator);

                return Self{
                    .n = _n,
                    .d = _d,
                };
            }

            pub fn fromString(base: u8, priv_str: []const u8, modulus_str: []const u8, allocator: std.mem.Allocator) !SecretKey {
                var _n = try bigInt.Managed.init(allocator);
                errdefer _n.deinit();
                try _n.setString(base, modulus_str);

                var _d = try bigInt.Managed.init(allocator);
                errdefer _d.deinit();
                try _d.setString(base, priv_str);

                return Self{
                    .n = _n,
                    .d = _d,
                };
            }
        };

        pub const PublicKey = struct {
            n: bigInt.Managed,
            e: bigInt.Managed,

            const Self = @This();

            pub fn deinit(self: *Self) void {
                self.n.deinit();
                self.e.deinit();
            }

            pub fn fromBytes(pub_bytes: []u8, modulus_bytes: []u8, allocator: std.mem.Allocator) !PublicKey {
                if (modulus_bytes.len != modulus_length) {
                    return Error.InvalidKeyLength;
                }

                if (pub_bytes.len > modulus_length) {
                    return Error.InvalidKeyLength;
                }

                var _n = try bigInt.Managed.init(allocator);
                errdefer _n.deinit();
                try setBytes(&_n, modulus_bytes, allocator);

                var _e = try bigInt.Managed.init(allocator);
                errdefer _e.deinit();
                try setBytes(&_e, pub_bytes, allocator);

                return Self{
                    .n = _n,
                    .e = _e,
                };
            }

            pub fn fromString(base: u8, pub_str: []const u8, modulus_str: []const u8, allocator: std.mem.Allocator) !PublicKey {
                var _n = try bigInt.Managed.init(allocator);
                errdefer _n.deinit();
                try _n.setString(base, modulus_str);

                var _e = try bigInt.Managed.init(allocator);
                errdefer _e.deinit();
                try _e.setString(base, pub_str);

                return Self{
                    .n = _n,
                    .e = _e,
                };
            }
        };

        pub const PKCS1V15Signature = struct {
            signature: [modulus_length]u8,

            const Self = @This();

            fn EMSA_PKCS1_v1_5_ENCODE(msg: []const u8, comptime Hash: type) ![modulus_length]u8 {
                if (Hash != std.crypto.hash.sha2.Sha256) {
                    @compileError("Unsupported Hash algorithm");
                }
                const hash_der = [_]u8{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
                var hashed: [Hash.digest_length]u8 = undefined;
                Hash.hash(msg, &hashed, .{});

                var out: [modulus_length]u8 = [_]u8{0} ** modulus_length;

                out[0] = 0x00;
                out[1] = 0x01;
                const ps_len = out.len - (hash_der.len + hashed.len) - 3;
                var i: usize = 0;
                while (i < ps_len) : (i += 1) {
                    out[2 + i] = 0xFF;
                }
                var idx: usize = 2 + ps_len;
                out[idx] = 0x00;
                idx += 1;
                std.mem.copy(u8, out[idx..], &hash_der);
                idx += hash_der.len;
                std.mem.copy(u8, out[idx..], &hashed);
                idx += hashed.len;

                return out;
            }

            pub fn sign(msg: []const u8, secret_key: SecretKey, comptime Hash: type, allocator: std.mem.Allocator) !Self {
                const em = try EMSA_PKCS1_v1_5_ENCODE(msg, Hash);

                return Self{
                    .signature = try decrypt(em, secret_key, allocator),
                };
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey, comptime Hash: type, allocator: std.mem.Allocator) !bool {
                const em_dec = try encrypt(self.signature, public_key, allocator);
                const em = try EMSA_PKCS1_v1_5_ENCODE(msg, Hash);
                return std.mem.eql(u8, &em, &em_dec);
            }
        };

        pub const PSSSignature = struct {
            signature: [modulus_length]u8,

            const Self = @This();

            const Error = error{
                EncodingError,
                InvalidSignature,
            };

            pub fn sign(msg: []const u8, secret_key: SecretKey, comptime Hash: type, allocator: std.mem.Allocator) !Self {
                const mod_bits = try countBits(secret_key.n.toConst(), allocator);

                var out: [modulus_length]u8 = undefined;
                const em = try EMSA_PSS_ENCODE(&out, msg, mod_bits - 1, Hash.digest_length, Hash, allocator, null);

                return Self{
                    .signature = try decrypt(em[0..modulus_length].*, secret_key, allocator),
                };
            }

            pub fn fromBytes(msg: []const u8) Self {
                var res = Self{
                    .signature = [_]u8{0} ** modulus_length,
                };
                std.mem.copy(u8, &res.signature, msg);
                return res;
            }

            pub fn verify(self: Self, msg: []const u8, public_key: PublicKey, comptime Hash: type, allocator: std.mem.Allocator) !void {
                const mod_bits = try countBits(public_key.n.toConst(), allocator);
                const em_dec = try encrypt(self.signature, public_key, allocator);

                try EMSA_PSS_VERIFY(msg, &em_dec, mod_bits - 1, Hash.digest_length, Hash, allocator);
            }

            fn MGF1(out: []u8, seed: []const u8, len: usize, comptime Hash: type, allocator: std.mem.Allocator) ![]u8 {
                var counter: usize = 0;
                var idx: usize = 0;
                var c: [4]u8 = undefined;

                var hash = try allocator.alloc(u8, seed.len + c.len);
                defer allocator.free(hash);
                std.mem.copy(u8, hash, seed);
                var hashed: [Hash.digest_length]u8 = undefined;

                while (idx < len) {
                    c[0] = @intCast(u8, (counter >> 24) & 0xFF);
                    c[1] = @intCast(u8, (counter >> 16) & 0xFF);
                    c[2] = @intCast(u8, (counter >> 8) & 0xFF);
                    c[3] = @intCast(u8, counter & 0xFF);

                    std.mem.copy(u8, hash[seed.len..], &c);
                    Hash.hash(hash, &hashed, .{});

                    std.mem.copy(u8, out[idx..], &hashed);
                    idx += hashed.len;

                    counter += 1;
                }

                return out[0..len];
            }

            // RFC8017 Section 9.1.1 Encoding Operation
            fn EMSA_PSS_ENCODE(
                out: []u8,
                msg: []const u8,
                emBit: usize,
                sLen: usize,
                comptime Hash: type,
                allocator: std.mem.Allocator,
                salt: ?[]const u8,
            ) ![]u8 {
                // TODO:
                // 1.   If the length of M is greater than the input limitation for
                //      the hash function (2^61 - 1 octets for SHA-1), output
                //      "message too long" and stop.

                // emLen = \c2yyeil(emBits/8)
                const emLen = ((emBit - 1) / 8) + 1;

                // 2.   Let mHash = Hash(M), an octet string of length hLen.
                var mHash: [Hash.digest_length]u8 = undefined;
                Hash.hash(msg, &mHash, .{});

                // 3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
                if (emLen < Hash.digest_length + sLen + 2) {
                    return Self.Error.EncodingError;
                }

                // 4.   Generate a random octet string salt of length sLen; if sLen =
                //      0, then salt is the empty string.
                // 5.   Let
                //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
                //      M' is an octet string of length 8 + hLen + sLen with eight
                //      initial zero octets.
                var m_p = try allocator.alloc(u8, 8 + Hash.digest_length + sLen);
                defer allocator.free(m_p);

                std.mem.copy(u8, m_p, &([_]u8{0} ** 8));
                std.mem.copy(u8, m_p[8..], &mHash);
                if (salt) |s| {
                    std.mem.copy(u8, m_p[(8 + Hash.digest_length)..], s);
                } else {
                    std.crypto.random.bytes(m_p[(8 + Hash.digest_length)..]);
                }

                // 6.   Let H = Hash(M'), an octet string of length hLen.
                var hash: [Hash.digest_length]u8 = undefined;
                Hash.hash(m_p, &hash, .{});

                // 7.   Generate an octet string PS consisting of emLen - sLen - hLen
                //      - 2 zero octets.  The length of PS may be 0.
                const ps_len = emLen - sLen - Hash.digest_length - 2;

                // 8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
                //      emLen - hLen - 1.
                var db = try allocator.alloc(u8, emLen - Hash.digest_length - 1);
                defer allocator.free(db);
                var i: usize = 0;
                while (i < ps_len) : (i += 1) {
                    db[i] = 0x00;
                }
                db[i] = 0x01;
                i += 1;
                if (salt) |s| {
                    std.mem.copy(u8, db[i..], s);
                } else {
                    std.mem.copy(u8, db[i..], m_p[(8 + Hash.digest_length)..]);
                }

                // 9.   Let dbMask = MGF(H, emLen - hLen - 1).
                const mgf_len = emLen - Hash.digest_length - 1;
                var mgf_out = try allocator.alloc(u8, ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length);
                defer allocator.free(mgf_out);
                const dbMask = try MGF1(mgf_out, &hash, mgf_len, Hash, allocator);

                // 10.  Let maskedDB = DB \xor dbMask.
                i = 0;
                while (i < db.len) : (i += 1) {
                    db[i] = db[i] ^ dbMask[i];
                }

                // 11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
                //      in maskedDB to zero.
                const zero_bits = emLen * 8 - emBit;
                var mask: u8 = 0;
                i = 0;
                while (i < 8 - zero_bits) : (i += 1) {
                    mask = mask << 1;
                    mask += 1;
                }
                db[0] = db[0] & mask;

                // 12.  Let EM = maskedDB || H || 0xbc.
                i = 0;
                std.mem.copy(u8, out, db);
                i += db.len;
                std.mem.copy(u8, out[i..], &hash);
                i += hash.len;
                out[i] = 0xbc;
                i += 1;

                // 13.  Output EM.
                return out[0..i];
            }

            fn EMSA_PSS_VERIFY(msg: []const u8, em: []const u8, emBit: usize, sLen: usize, comptime Hash: type, allocator: std.mem.Allocator) !void {
                // TODO
                // 1.   If the length of M is greater than the input limitation for
                //      the hash function (2^61 - 1 octets for SHA-1), output
                //      "inconsistent" and stop.

                // emLen = \ceil(emBits/8)
                const emLen = ((emBit - 1) / 8) + 1;
                std.debug.assert(emLen == em.len);

                // 2.   Let mHash = Hash(M), an octet string of length hLen.
                var mHash: [Hash.digest_length]u8 = undefined;
                Hash.hash(msg, &mHash, .{});

                // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
                if (emLen < Hash.digest_length + sLen + 2) {
                    return Self.Error.InvalidSignature;
                }

                // 4.   If the rightmost octet of EM does not have hexadecimal value
                //      0xbc, output "inconsistent" and stop.
                if (em[em.len - 1] != 0xbc) {
                    return Self.Error.InvalidSignature;
                }

                // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
                //      and let H be the next hLen octets.
                const maskedDB = em[0..(emLen - Hash.digest_length - 1)];
                const h = em[(emLen - Hash.digest_length - 1)..(emLen - 1)];

                // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
                //      maskedDB are not all equal to zero, output "inconsistent" and
                //      stop.
                const zero_bits = emLen * 8 - emBit;
                var mask: u8 = maskedDB[0];
                var i: usize = 0;
                while (i < 8 - zero_bits) : (i += 1) {
                    mask = mask >> 1;
                }
                if (mask != 0) {
                    return Self.Error.InvalidSignature;
                }

                // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
                const mgf_len = emLen - Hash.digest_length - 1;
                var mgf_out = try allocator.alloc(u8, ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length);
                defer allocator.free(mgf_out);
                var dbMask = try MGF1(mgf_out, h, mgf_len, Hash, allocator);

                // 8.   Let DB = maskedDB \xor dbMask.
                i = 0;
                while (i < dbMask.len) : (i += 1) {
                    dbMask[i] = maskedDB[i] ^ dbMask[i];
                }

                // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
                //      in DB to zero.
                i = 0;
                mask = 0;
                while (i < 8 - zero_bits) : (i += 1) {
                    mask = mask << 1;
                    mask += 1;
                }
                dbMask[0] = dbMask[0] & mask;

                // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
                //      zero or if the octet at position emLen - hLen - sLen - 1 (the
                //      leftmost position is "position 1") does not have hexadecimal
                //      value 0x01, output "inconsistent" and stop.
                if (dbMask[mgf_len - sLen - 2] != 0x00) {
                    return Self.Error.InvalidSignature;
                }

                if (dbMask[mgf_len - sLen - 1] != 0x01) {
                    return Self.Error.InvalidSignature;
                }

                // 11.  Let salt be the last sLen octets of DB.
                const salt = dbMask[(mgf_len - sLen)..];

                // 12.  Let
                //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
                //      M' is an octet string of length 8 + hLen + sLen with eight
                //      initial zero octets.
                var m_p = try allocator.alloc(u8, 8 + Hash.digest_length + sLen);
                defer allocator.free(m_p);
                std.mem.copy(u8, m_p, &([_]u8{0} ** 8));
                std.mem.copy(u8, m_p[8..], &mHash);
                std.mem.copy(u8, m_p[(8 + Hash.digest_length)..], salt);

                // 13.  Let H' = Hash(M'), an octet string of length hLen.
                var h_p: [Hash.digest_length]u8 = undefined;
                Hash.hash(m_p, &h_p, .{});

                // 14.  If H = H', output "consistent".  Otherwise, output
                //      "inconsistent".
                if (!std.mem.eql(u8, h, &h_p)) {
                    return Self.Error.InvalidSignature;
                }
            }
        };

        pub fn encrypt(msg: [modulus_length]u8, public_key: PublicKey, allocator: std.mem.Allocator) ![modulus_length]u8 {
            var m = try bigInt.Managed.init(allocator);
            defer m.deinit();

            try setBytes(&m, &msg, allocator);

            if (m.order(public_key.n) != .lt) {
                return Error.MessageTooLong;
            }

            var e = try bigInt.Managed.init(allocator);
            defer e.deinit();

            try pow_montgomery(&e, &m, &public_key.e, &public_key.n, allocator);

            var res: [modulus_length]u8 = undefined;

            try toBytes(&res, &e, allocator);

            return res;
        }

        pub fn decrypt(msg: [modulus_length]u8, secret_key: SecretKey, allocator: std.mem.Allocator) ![modulus_length]u8 {
            var m = try bigInt.Managed.init(allocator);
            defer m.deinit();

            try setBytes(&m, &msg, allocator);

            if (m.order(secret_key.n) != .lt) {
                return Error.MessageTooLong;
            }

            var e = try bigInt.Managed.init(allocator);
            defer e.deinit();

            try pow_montgomery(&e, &m, &secret_key.d, &secret_key.n, allocator);

            var res: [modulus_length]u8 = undefined;

            try toBytes(&res, &e, allocator);

            return res;
        }
    };
}

fn countBits(a: bigInt.Const, allocator: std.mem.Allocator) !usize {
    var i: usize = 0;
    var a_copy = try bigInt.Managed.init(allocator);
    defer a_copy.deinit();
    try a_copy.copy(a);

    while (!a_copy.eqZero()) {
        try a_copy.shiftRight(&a_copy, 1);
        i += 1;
    }

    return i;
}

fn toBytes(out: []u8, a: *const bigInt.Managed, allocator: std.mem.Allocator) !void {
    const Error = error{
        BufferTooSmall,
    };

    var mask = try bigInt.Managed.initSet(allocator, 0xFF);
    defer mask.deinit();
    var tmp = try bigInt.Managed.init(allocator);
    defer tmp.deinit();

    var a_copy = try bigInt.Managed.init(allocator);
    defer a_copy.deinit();
    try a_copy.copy(a.toConst());

    // Encoding into big-endian bytes
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        try tmp.bitAnd(&a_copy, &mask);
        const b = try tmp.to(u8);
        out[out.len - i - 1] = b;
        try a_copy.shiftRight(&a_copy, 8);
    }

    if (!a_copy.eqZero()) {
        return Error.BufferTooSmall;
    }
}

fn setBytes(r: *bigInt.Managed, bytes: []const u8, allcator: std.mem.Allocator) !void {
    try r.set(0);
    var tmp = try bigInt.Managed.init(allcator);
    defer tmp.deinit();
    for (bytes) |b| {
        try r.shiftLeft(r, 8);
        try tmp.set(b);
        try r.add(r, &tmp);
    }
}

// rem = a mod n
fn mod(rem: *bigInt.Managed, a: *const bigInt.Managed, n: *const bigInt.Managed, allocator: std.mem.Allocator) !void {
    var q = try bigInt.Managed.init(allocator);
    defer q.deinit();

    try bigInt.Managed.divFloor(&q, rem, a, n);
}

// r = a^x mod n
fn pow_montgomery(r: *bigInt.Managed, a: *const bigInt.Managed, x: *const bigInt.Managed, n: *const bigInt.Managed, allocator: std.mem.Allocator) !void {
    var bin_raw: [512]u8 = undefined;
    try toBytes(&bin_raw, x, allocator);

    var i: usize = 0;
    while (bin_raw[i] == 0x00) : (i += 1) {}
    const bin = bin_raw[i..];

    try r.set(1);
    var r1 = try bigInt.Managed.init(allocator);
    defer r1.deinit();
    try bigInt.Managed.copy(&r1, a.toConst());
    i = 0;
    while (i < bin.len * 8) : (i += 1) {
        if (((bin[i / 8] >> @intCast(u3, (7 - (i % 8)))) & 0x1) == 0) {
            try bigInt.Managed.mul(&r1, r, &r1);
            try mod(&r1, &r1, n, allocator);
            try bigInt.Managed.sqr(r, r);
            try mod(r, r, n, allocator);
        } else {
            try bigInt.Managed.mul(r, r, &r1);
            try mod(r, r, n, allocator);
            try bigInt.Managed.sqr(&r1, &r1);
            try mod(&r1, &r1, n, allocator);
        }
    }
}

test "pow_montgomery" {
    var a = try bigInt.Managed.initSet(std.testing.allocator, 125069);
    defer a.deinit();
    var x = try bigInt.Managed.initSet(std.testing.allocator, 0b1011);
    defer x.deinit();
    var n = try bigInt.Managed.initSet(std.testing.allocator, 329159);
    defer n.deinit();
    var r = try bigInt.Managed.init(std.testing.allocator);
    defer r.deinit();
    var ans = try bigInt.Managed.initSet(std.testing.allocator, 151303);
    defer ans.deinit();

    try pow_montgomery(&r, &a, &x, &n, std.testing.allocator);
    try expect(bigInt.Managed.eq(r, ans));
}

test "countBits" {
    var x = try bigInt.Managed.initSet(std.testing.allocator, 0b01011);
    defer x.deinit();

    try expect((try countBits(x.toConst(), std.testing.allocator)) == 4);
}

test "MGF1" {
    var out: [100]u8 = undefined;
    const padding = try Rsa2048.PSSSignature.MGF1(&out, "bar", 50, std.crypto.hash.sha2.Sha256, std.testing.allocator);

    // zig fmt: off
    const padding_ans = [_]u8{
    0x38, 0x25, 0x76, 0xa7, 0x84, 0x10, 0x21, 0xcc, 0x28, 0xfc, 0x4c, 0x09, 0x48,
    0x75, 0x3f, 0xb8, 0x31, 0x20, 0x90, 0xce, 0xa9, 0x42, 0xea, 0x4c, 0x4e, 0x73,
    0x5d, 0x10, 0xdc, 0x72, 0x4b, 0x15, 0x5f, 0x9f, 0x60, 0x69, 0xf2, 0x89, 0xd6,
    0x1d, 0xac, 0xa0, 0xcb, 0x81, 0x45, 0x02, 0xef, 0x04, 0xea, 0xe1
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, padding, &padding_ans));
}

test "EMSA_PSS_ENCODE" {
    // zig fmt: off
    const msg = [_]u8{
    0x85, 0x9e, 0xef, 0x2f, 0xd7, 0x8a, 0xca, 0x00, 0x30, 0x8b, 0xdc, 0x47, 0x11,
    0x93, 0xbf, 0x55, 0xbf, 0x9d, 0x78, 0xdb, 0x8f, 0x8a, 0x67, 0x2b, 0x48, 0x46,
    0x34, 0xf3, 0xc9, 0xc2, 0x6e, 0x64, 0x78, 0xae, 0x10, 0x26, 0x0f, 0xe0, 0xdd,
    0x8c, 0x08, 0x2e, 0x53, 0xa5, 0x29, 0x3a, 0xf2, 0x17, 0x3c, 0xd5, 0x0c, 0x6d,
    0x5d, 0x35, 0x4f, 0xeb, 0xf7, 0x8b, 0x26, 0x02, 0x1c, 0x25, 0xc0, 0x27, 0x12,
    0xe7, 0x8c, 0xd4, 0x69, 0x4c, 0x9f, 0x46, 0x97, 0x77, 0xe4, 0x51, 0xe7, 0xf8,
    0xe9, 0xe0, 0x4c, 0xd3, 0x73, 0x9c, 0x6b, 0xbf, 0xed, 0xae, 0x48, 0x7f, 0xb5,
    0x56, 0x44, 0xe9, 0xca, 0x74, 0xff, 0x77, 0xa5, 0x3c, 0xb7, 0x29, 0x80, 0x2f,
    0x6e, 0xd4, 0xa5, 0xff, 0xa8, 0xba, 0x15, 0x98, 0x90, 0xfc
    };

    const salt = [_]u8{
    0xe3, 0xb5, 0xd5, 0xd0, 0x02, 0xc1, 0xbc, 0xe5, 0x0c, 0x2b, 0x65, 0xef, 0x88,
    0xa1, 0x88, 0xd8, 0x3b, 0xce, 0x7e, 0x61
    };

    const em_ans = [_]u8{
    0x66, 0xe4, 0x67, 0x2e, 0x83, 0x6a, 0xd1, 0x21, 0xba, 0x24, 0x4b, 0xed, 0x65,
    0x76, 0xb8, 0x67, 0xd9, 0xa4, 0x47, 0xc2, 0x8a, 0x6e, 0x66, 0xa5, 0xb8, 0x7d,
    0xee, 0x7f, 0xbc, 0x7e, 0x65, 0xaf, 0x50, 0x57, 0xf8, 0x6f, 0xae, 0x89, 0x84,
    0xd9, 0xba, 0x7f, 0x96, 0x9a, 0xd6, 0xfe, 0x02, 0xa4, 0xd7, 0x5f, 0x74, 0x45,
    0xfe, 0xfd, 0xd8, 0x5b, 0x6d, 0x3a, 0x47, 0x7c, 0x28, 0xd2, 0x4b, 0xa1, 0xe3,
    0x75, 0x6f, 0x79, 0x2d, 0xd1, 0xdc, 0xe8, 0xca, 0x94, 0x44, 0x0e, 0xcb, 0x52,
    0x79, 0xec, 0xd3, 0x18, 0x3a, 0x31, 0x1f, 0xc8, 0x96, 0xda, 0x1c, 0xb3, 0x93,
    0x11, 0xaf, 0x37, 0xea, 0x4a, 0x75, 0xe2, 0x4b, 0xdb, 0xfd, 0x5c, 0x1d, 0xa0,
    0xde, 0x7c, 0xec, 0xdf, 0x1a, 0x89, 0x6f, 0x9d, 0x8b, 0xc8, 0x16, 0xd9, 0x7c,
    0xd7, 0xa2, 0xc4, 0x3b, 0xad, 0x54, 0x6f, 0xbe, 0x8c, 0xfe, 0xbc
    };

    // zig fmt: on

    const Hash = std.crypto.hash.Sha1;

    var hashed: [Hash.digest_length]u8 = undefined;
    Hash.hash(&msg, &hashed, .{});

    var out: [1000]u8 = undefined;
    const em = try Rsa1024.PSSSignature.EMSA_PSS_ENCODE(&out, &msg, 1024, salt.len, Hash, std.testing.allocator, &salt);

    try expect(std.mem.eql(u8, em, &em_ans));
    try Rsa1024.PSSSignature.EMSA_PSS_VERIFY(&msg, em, 1024, salt.len, Hash, std.testing.allocator);
}

// from http://cryptomanager.com/tv.html
test "1024-bit RSA bare exponentiation" {
    const priv_key = "2489108B0B6AF86BED9E44C2336442D5E227DBA55EF8E26A7E437194119077F003BC9C027852BB3126C99C16D5F1057BC8361DCB26A5B2DB4229DB3DE5BD979B2E597D1916D7BBC92746FC07595C76B44B39A476A65C86F086DC9283CA6D1EEFC14915982F9C4CED5F62A9FF3BE24218A99357B5B65C3B10AEB367E911EB9E21";
    const pub_key = "010001";
    const modulus = "F0C42DB8486FEB9595D8C78F908D04A9B6C8C77A36105B1BF2755377A6893DC4383C54EC6B5262E5688E5F9D9DD16497D0E3EA833DEE2C8EBCD1438389FCCA8FEDE7A88A81257E8B2709C494D42F723DEC2E0B5C09731C550DCC9D7E752589891CBBC3021307DD918E100B34C014A559E0E182AFB21A72B307CC395DEC995747";

    var secret_key = try Rsa1024.SecretKey.fromString(16, priv_key, modulus, std.testing.allocator);
    defer secret_key.deinit();

    var public_key = try Rsa1024.PublicKey.fromString(16, pub_key, modulus, std.testing.allocator);
    defer public_key.deinit();

    var plain: [128]u8 = [_]u8{0} ** 128;
    plain[124] = 0x11;
    plain[125] = 0x22;
    plain[126] = 0x33;
    plain[127] = 0x44;

    // zig fmt: off
    const enc_ans = [_]u8{
    0x50, 0x5B, 0x09, 0xBD, 0x5D, 0x0E, 0x66, 0xD7, 0xC8, 0x82, 0x9F, 0x5B, 0x47,
    0x3E, 0xD3, 0x4D, 0xB5, 0xCF, 0xDB, 0xB5, 0xD5, 0x8C, 0xE7, 0x83, 0x29, 0xC8,
    0xBF, 0x85, 0x20, 0xE4, 0x86, 0xD3, 0xC4, 0xCF, 0x9B, 0x70, 0xC6, 0x34, 0x65,
    0x94, 0x35, 0x80, 0x80, 0xF4, 0x3F, 0x47, 0xEE, 0x86, 0x3C, 0xFA, 0xF2, 0xA2,
    0xE5, 0xF0, 0x3D, 0x1E, 0x13, 0xD6, 0xFE, 0xC5, 0x7D, 0xFB, 0x1D, 0x55, 0x22,
    0x24, 0xC4, 0x61, 0xDA, 0x41, 0x1C, 0xFE, 0x5D, 0x0B, 0x05, 0xBA, 0x87, 0x7E,
    0x3A, 0x42, 0xF6, 0xDE, 0x4D, 0xA4, 0x6A, 0x96, 0x5C, 0x9B, 0x69, 0x5E, 0xE2,
    0xD5, 0x0E, 0x40, 0x08, 0x94, 0x06, 0x1C, 0xB0, 0xA2, 0x1C, 0xA3, 0xA5, 0x24,
    0xB4, 0x07, 0xE9, 0xFF, 0xBA, 0x87, 0xFC, 0x96, 0x6B, 0x3B, 0xA9, 0x45, 0x90,
    0x84, 0x9A, 0xEB, 0x90, 0x8A, 0xAF, 0xF4, 0xC7, 0x19, 0xC2, 0xE4
    };
    // zig fmt: on

    const enc = try Rsa1024.encrypt(plain, public_key, std.testing.allocator);
    try expect(std.mem.eql(u8, &enc, &enc_ans));

    const dec = try Rsa1024.decrypt(enc, secret_key, std.testing.allocator);
    try expect(std.mem.eql(u8, &dec, &plain));
}

test "2048-bit RSA PKCS1 v1.5" {
    const n = "21229582239580466143216004510287597427160456192729569346260473754199171024195611152779037660175809566720571033841542391940935952137451771345627164316943553104808728592889114789834535273390427934182478006531445311208751199552533176586078610995241865067611132723492595200278775877284389730792234765622969148628356698568797059775483198641557831385626843410338141428158012255581403262320698279973721727574490855790618457467908898646232852678060549505347442863509611519891053013233036144118198126380175690349451825073450877282768604882491552769863794727273453004967009716978579719400611350278947055225539862862721192966363";
    const priv_key = "3865651763981163201246138667066192286754341882843864012597454316580493574885001231238668933849703579115002737878573113420314618991291647670064875801093212856496863796988605693646191108610474567840557262171643539089516340996080910978378154390828368658686504605883682268375524847514736177310666243123147265440178853214366008075678195169457814822572470391924456497054962375029623887457415526393365843574675120900389282672536384719036876000213531715291670931265169191722513942148897269442071336785178318678634620291864786349513052818757897635583017960845392285969063411817968506373433092511656954008452567930273042334937";
    const pub_key = "65537";

    var secret_key = try Rsa2048.SecretKey.fromString(10, priv_key, n, std.testing.allocator);
    defer secret_key.deinit();

    var public_key = try Rsa2048.PublicKey.fromString(10, pub_key, n, std.testing.allocator);
    defer public_key.deinit();

    const msg = "test data 16byte";
    const sig = try Rsa2048.PKCS1V15Signature.sign(msg, secret_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);

    // zig fmt: off
    const sig_ans = [_]u8{
    0x75, 0x6d, 0x71, 0x38, 0xa4, 0xb8, 0x9a, 0x5c, 0x49, 0x32, 0x3f, 0xcd, 0xa1,
    0xaa, 0x6e, 0xa4, 0x83, 0xce, 0x4b, 0xeb, 0xec, 0xd2, 0x7b, 0x2a, 0x6b, 0x3f,
    0x96, 0x9a, 0xea, 0x9d, 0xc3, 0xb6, 0x5a, 0xc2, 0xee, 0x05, 0x9e, 0x06, 0x42,
    0xc1, 0x25, 0x53, 0xd9, 0x7f, 0x19, 0xa8, 0x67, 0x65, 0x75, 0xce, 0x37, 0x74,
    0xc2, 0x02, 0xb3, 0xfd, 0x7f, 0xbc, 0x6a, 0xd1, 0x23, 0x65, 0xb3, 0x62, 0x25,
    0x45, 0x0d, 0x16, 0x98, 0x8c, 0x67, 0xb4, 0x67, 0x10, 0xe8, 0xa0, 0xd6, 0x00,
    0xd5, 0x3e, 0x66, 0x0d, 0xbc, 0xa0, 0xdb, 0xb4, 0x7b, 0x87, 0xb2, 0x5d, 0x13,
    0x04, 0x88, 0xbb, 0x0a, 0x29, 0x98, 0xef, 0xdd, 0xe2, 0xb3, 0x50, 0xc4, 0x4e,
    0x42, 0x30, 0xd9, 0x6e, 0x47, 0x14, 0x76, 0x45, 0x7e, 0x8c, 0xfa, 0x06, 0xc6,
    0x5b, 0xbb, 0x5f, 0x65, 0x1f, 0xb2, 0x96, 0x62, 0x20, 0x18, 0x34, 0x13, 0x9f,
    0x0a, 0xd3, 0x1b, 0x69, 0x90, 0x65, 0x8b, 0x80, 0xc4, 0xc7, 0x44, 0xac, 0xd2,
    0xef, 0x75, 0x9b, 0xe6, 0x35, 0xae, 0x59, 0xfd, 0x4f, 0xd5, 0x61, 0xd5, 0xfe,
    0x6c, 0x5d, 0x17, 0x64, 0xb1, 0x47, 0x14, 0x58, 0x96, 0xd9, 0xe0, 0x0b, 0xaa,
    0x59, 0x5e, 0xe5, 0xe3, 0x47, 0x9e, 0xb1, 0xcc, 0x45, 0x56, 0xf9, 0xe2, 0xd6,
    0x83, 0x2f, 0x44, 0x15, 0x90, 0x0f, 0x12, 0x9a, 0x3e, 0xe8, 0xb4, 0xab, 0xd9,
    0xc4, 0x38, 0x8f, 0x17, 0x8e, 0xdd, 0x88, 0x49, 0xc3, 0xbd, 0xfa, 0x9d, 0x2d,
    0x5a, 0x07, 0x13, 0x8a, 0xa3, 0xaf, 0xd7, 0xab, 0xdc, 0x5d, 0xc6, 0xc9, 0x5a,
    0xab, 0xe2, 0xba, 0x03, 0xd9, 0x94, 0x2c, 0x73, 0x3d, 0x54, 0xd3, 0xf4, 0xee,
    0x2a, 0xad, 0xaf, 0x76, 0x81, 0x04, 0xe5, 0xfc, 0xb1, 0x04, 0xff, 0x97, 0x7a,
    0xc2, 0x73, 0x38, 0x56, 0xbf, 0xbf, 0x79, 0xaa, 0x1e
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, &sig.signature, &sig_ans));
    try expect(try sig.verify(msg, public_key, std.crypto.hash.sha2.Sha256, std.testing.allocator));
}

test "2048-bit RSA PSS Sign" {
    const n = "23919682004983319653113024109510798927190730483459155114124635852511683171702990071714179227838542975507400881419965032168292173145626910251896686359830368225942857209995228220809900272395494813989889087736537901064753969683151039818892990656012074606394135983145065401832175387153987481974888128780363024001465382365089020018667469572784508021139027094627097811559996317936508250029452373223388611875825585628651809429434775232528424381140872224720066194500370441280449656053417312065616112716063994984412819781068240997277634109127329059805468681621385058680389516782842964092223178451517822636463417183878014509981";
    const priv_key = "1486654023327254936555573576057263251753660419942170126319608358427197056306196565445622786209215331415620498958510041156590873770014263884272062769354395950017879108451913626659961949502341414026951427844162122244106521613926407570415274946817846146306588864204123436349129627473411653126542458009286566176552129970046811837701765340557994069410882942701121486471145988540096901826278540244413249604872804226780677276938685017701419235603015806653407321564847148984500582927127427146187517633208784284960396011662843170868728284448114027499723814587749054791910184390948448899927688162118497912308347570322628907705";
    const pub_key = "65537";

    var secret_key = try Rsa2048.SecretKey.fromString(10, priv_key, n, std.testing.allocator);
    defer secret_key.deinit();

    var public_key = try Rsa2048.PublicKey.fromString(10, pub_key, n, std.testing.allocator);
    defer public_key.deinit();

    const msg = "test data 16byte";
    const sig = try Rsa2048.PSSSignature.sign(msg, secret_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);

    try sig.verify(msg, public_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);
}

test "2048-bit RSA PSS Verify" {
    const n = "23919682004983319653113024109510798927190730483459155114124635852511683171702990071714179227838542975507400881419965032168292173145626910251896686359830368225942857209995228220809900272395494813989889087736537901064753969683151039818892990656012074606394135983145065401832175387153987481974888128780363024001465382365089020018667469572784508021139027094627097811559996317936508250029452373223388611875825585628651809429434775232528424381140872224720066194500370441280449656053417312065616112716063994984412819781068240997277634109127329059805468681621385058680389516782842964092223178451517822636463417183878014509981";
    const pub_key = "65537";

    // zig fmt: off
    const sig_bytes = [_]u8{
    0xab, 0x54, 0xfc, 0x58, 0xc1, 0x43, 0x17, 0x98, 0x26, 0x75, 0xc8, 0x66, 0x02,
    0xfe, 0x63, 0x3c, 0xfd, 0x3b, 0xf5, 0xcc, 0xcf, 0x3f, 0xa7, 0xb0, 0x0e, 0xcf,
    0xb9, 0xf8, 0xac, 0x55, 0x6d, 0x68, 0x3a, 0x7e, 0x40, 0x43, 0xcc, 0xb1, 0xdc,
    0x25, 0xfb, 0xd7, 0x95, 0x16, 0x16, 0xf9, 0x7a, 0x08, 0xb6, 0x8b, 0x51, 0xdd,
    0xd1, 0xc9, 0x15, 0x56, 0x0a, 0x86, 0xfe, 0xa1, 0x23, 0xa7, 0x1d, 0x2b, 0xa4,
    0xc4, 0xa4, 0x8d, 0xcb, 0x4f, 0x46, 0x72, 0xa6, 0xfd, 0xaf, 0x58, 0x51, 0x96,
    0x13, 0xf6, 0x4d, 0x46, 0x4b, 0x10, 0x03, 0xcd, 0xb6, 0x8e, 0xee, 0x2e, 0x72,
    0x16, 0x27, 0x9d, 0x0d, 0xee, 0x65, 0x2c, 0xeb, 0x43, 0x82, 0x70, 0x82, 0x7e,
    0x55, 0xbf, 0xdb, 0x2c, 0x5c, 0x35, 0x2d, 0x29, 0x8d, 0x4d, 0x17, 0xc9, 0x7d,
    0x9e, 0x87, 0x42, 0xdd, 0xc9, 0x65, 0x6e, 0x53, 0xb1, 0xe3, 0x84, 0x2d, 0x46,
    0x04, 0xed, 0x5e, 0xc4, 0x09, 0x53, 0x18, 0x23, 0xdc, 0xc6, 0x50, 0xcf, 0x95,
    0x01, 0xc4, 0x9c, 0x57, 0xc3, 0x24, 0xbb, 0x0d, 0x27, 0xe9, 0xdd, 0x2b, 0xc0,
    0xcb, 0x49, 0x89, 0xbe, 0xa5, 0x1d, 0xba, 0x85, 0x17, 0x2b, 0xa5, 0x2f, 0xde,
    0x71, 0x40, 0x95, 0xd8, 0x56, 0x4a, 0x94, 0x4a, 0x1a, 0x06, 0x6b, 0x99, 0x2e,
    0x1a, 0xff, 0x1b, 0x67, 0x84, 0xb0, 0x6a, 0xe3, 0x41, 0x15, 0x00, 0x2f, 0xc2,
    0x43, 0x08, 0xe1, 0xee, 0xa7, 0x26, 0x0a, 0xe7, 0xb8, 0x59, 0x73, 0x5a, 0x05,
    0x1c, 0xb0, 0x53, 0x26, 0x48, 0x3a, 0xc0, 0x90, 0xd7, 0x59, 0x7a, 0x85, 0x27,
    0x86, 0xcf, 0x5f, 0x9c, 0xb8, 0x0b, 0x2d, 0x90, 0x3d, 0x16, 0x0f, 0x38, 0xff,
    0xf3, 0x9a, 0x22, 0x79, 0xa4, 0xbc, 0x6e, 0x6d, 0x76, 0x49, 0xcf, 0x5a, 0x79,
    0xac, 0x28, 0xa8, 0x9b, 0xe2, 0x84, 0xec, 0xdd, 0x3a
    };
    // zig fmt: on

    var sig = Rsa2048.PSSSignature{ .signature = sig_bytes };

    var public_key = try Rsa2048.PublicKey.fromString(10, pub_key, n, std.testing.allocator);
    defer public_key.deinit();

    const msg = "test data 16byte";

    try sig.verify(msg, public_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);
}

test "4096-bit RSA PSS Sign" {
    const n = "897535301620306077188891079301907673125963912211192741122348613922246072092610345250186564091181400747109015531089356444806090560753638865734563036738554165050798024801158167412934556646185261962016595023541314883422949023710685340675718103915652978942180795194958506158094483342012886642270027276693240459935208829184592396531495966261943744036979064638695422454818147885749109150302195425802819921308694143152344723082163813571934345758846689544769319697350655550031613804772387776701371526717638610510574001767592411627528450046156985403290908168738173358873495129077354640905355468389357577765586870921839988193004595009224627588073057372612891486057015942512692199236238168622228912025469578187459510803480351610523595706885613463758753288312263653456211204943914707207549073787942894431218381469240793425136973023446713462231486076209118140018376420926146941327295910991417167199375689590611101067683147180807440499150825756043075062581640588650519959175779521560663031612401158232135271870806087162232823153837034102908050667626930890079184403053749722256052973876704644595920341800544323289556048189453983881150373002292335443797850064651998186411619890589268469639972399875480015742895242553860437592274314253396272624328229";
    const priv_key = "124765719846596478931139584589013906329185234771533922361564863511987766884076222558486231373295777288498861845096766857672683927111491805797615131993338313962403416473820150368092635376747627794825238946140611622697162234207551018888428839528778820382501527220117959789535381034630405733139150647687483313244804251584279611219632591156718693167415178046365792947785327857182138664213201334786763815678205148506243015601252466280020673412721562681008204445928083521135778410133629030054681629480741674953140314625375112806959291118497973301651448741081327247855062926280985857108320714342953520497412725495761062490421801944855566452675835332573294821067060364950225705181619044543374076046907857122339032132846458480459136994242930101676476634188331767976638972984292912772276454185106765455221936971234365412634972593988655306479329613012757794413721878817071086573880767173140552020830621393269768369436403209385438185082303210338201068744790834660283297579174434214336074750446053936741306386786314295925388699142167339273101476895448918346646048310067201771725165523372705823852777288497167237929363410260986664538816810108649851181733006891679372699037976134443225602046316464534714173380580082384920433288426890331571214521201";
    const pub_key = "65537";

    var secret_key = try Rsa4096.SecretKey.fromString(10, priv_key, n, std.testing.allocator);
    defer secret_key.deinit();

    var public_key = try Rsa4096.PublicKey.fromString(10, pub_key, n, std.testing.allocator);
    defer public_key.deinit();

    const msg = "test data 16byte";
    const sig = try Rsa4096.PKCS1V15Signature.sign(msg, secret_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);

    try expect(try sig.verify(msg, public_key, std.crypto.hash.sha2.Sha256, std.testing.allocator));
}

test "1024-bit RSA PSS Sign" {
    const n = "132379107402679919165171865620956884932493794394268210529821686924495515049897816049791754567775403042641020016873857657023789634961669862624896688369645162893925903729161862383562055232421425080516054744420973967593163722256021558574090119760313528619828245538983231115360642688817218248940217148000129578773";
    const priv_key = "950273376351400380441085222235235744469007650144682201278792972614200078135045106227828874021971662942686651928866991690311274328208505560873768022533188565287153566930060932531064741693039138344314734857685605309659233992374225880820629095915167477606086894679092229184107533984322761876483641135744180033";
    const pub_key = "65537";

    var secret_key = try Rsa1024.SecretKey.fromString(10, priv_key, n, std.testing.allocator);
    defer secret_key.deinit();

    var public_key = try Rsa1024.PublicKey.fromString(10, pub_key, n, std.testing.allocator);
    defer public_key.deinit();

    const msg = "test data 16byte";
    const sig = try Rsa1024.PSSSignature.sign(msg, secret_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);

    try sig.verify(msg, public_key, std.crypto.hash.sha2.Sha256, std.testing.allocator);
}
