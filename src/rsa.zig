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
        };

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
