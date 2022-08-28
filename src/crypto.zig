const std = @import("std");
const mem = std.mem;

const BoundedArray = std.BoundedArray;

pub const HashType = enum {
    SHA256,
};

fn max(comptime T: type, comptime a: T, comptime b: T) T {
    return if (a > b) a else b;
}

// abstraction struct for Hkdf functions
pub const Hkdf = struct {
    pub const MAX_DIGEST_LENGTH = Sha256.Hash.digest_length;

    hash_type: HashType,
    digest_length: usize,

    hash: fn (out: []u8, m: []const u8) void, // hash
    create: fn (out: []u8, m: []const u8, k: []const u8) void, // hmac
    extract: fn (out: []u8, salt: []const u8, ikm: []const u8) void, // hkdf
    expand: fn (out: []u8, ctx: []const u8, prk: []const u8) void, // hkdf

    pub const Self = @This();

    pub const Sha256 = struct {
        const Hash = std.crypto.hash.sha2.Sha256;
        const Hmac = std.crypto.auth.hmac.Hmac(Hash);
        const H = std.crypto.kdf.hkdf.Hkdf(Hmac);

        fn hash(out: []u8, m: []const u8) void {
            Hash.hash(m, out[0..Hash.digest_length], .{});
        }

        fn create(out: []u8, m: []const u8, k: []const u8) void {
            Hmac.create(out[0..Hmac.mac_length], m, k);
        }

        fn extract(out: []u8, salt: []const u8, ikm: []const u8) void {
            const res = H.extract(salt, ikm);
            std.mem.copy(u8, out, &res);
        }

        fn expand(out: []u8, ctx: []const u8, prk: []const u8) void {
            H.expand(out, ctx, prk[0..Hmac.mac_length].*);
        }

        pub const hkdf = Hkdf {
            .hash_type = .SHA256,
            .digest_length = Hash.digest_length,
            .hash = hash,
            .create = create,
            .extract = extract,
            .expand = expand,
        };
    };

    pub fn fromHashType(t: HashType) Self {
        switch (t) {
            .SHA256 => return Sha256.h,
            else => unreachable,
        }
    }

    pub const MAX_LABEL_LENGTH: usize = 256;
    pub const MAX_CONTENT_LENGTH: usize = 256;
    pub const MAX_HKDF_LABEL_LENGTH: usize = 2 + MAX_LABEL_LENGTH + MAX_CONTENT_LENGTH;

    // @param(out) out.len >= digest_length
    pub fn deriveEarlySecret(self: Self, out: []u8, ikm: []const u8) void {
        const salt = [_]u8{0};
        self.extract(out, &salt, ikm);
    }

    // @param(out) out.len >= digest_length
    // @param(prk) prk.len >= digest_length
    pub fn deriveSecret(self: Self, out: []u8, prk: []const u8, label: []const u8, msg: []const u8) !void {
        var hash: [MAX_DIGEST_LENGTH]u8 = undefined;
        self.hash(&hash, msg);

        try self.hkdfExpandLabel(out, prk, label, hash[0..self.digest_length], self.digest_length);
    }

    fn generateHkdfLabel(len: u16, label: []const u8, ctx: []const u8) !BoundedArray(u8, MAX_HKDF_LABEL_LENGTH) {
        var hkdf_label = try BoundedArray(u8, MAX_HKDF_LABEL_LENGTH).init(0);

        var len_buf = [_]u8{0} ** 2;
        mem.writeIntBig(u16, &len_buf, len);

        try hkdf_label.appendSlice(&len_buf);
        try hkdf_label.append(@intCast(u8, 6 + label.len)); // "tls13 ".len + label.len
        try hkdf_label.appendSlice("tls13 ");
        try hkdf_label.appendSlice(label);
        try hkdf_label.append(@intCast(u8, ctx.len));
        try hkdf_label.appendSlice(ctx);

        return hkdf_label;
    }

    fn hkdfExpandLabel(self:Self, out: []u8, prk: []const u8, label: []const u8, ctx: []const u8, len: usize) !void {
        const info = try generateHkdfLabel(@intCast(u16, len), label, ctx);
        self.expand(out, info.slice(), prk);
    }
};

// abstraction struct for Aead functions
pub const Aead = struct {
    const MAX_KEY_LEGNTH = Aes128Gcm.C.key_length;
    const MAX_NONCE_LENGTH = Aes128Gcm.C.nonce_length;
    // encrypt
    // decrypt

    key_length: usize,
    nonce_length: usize,

    pub const Aes128Gcm = struct {
        const C = std.crypto.aead.aes_gcm.Aes128Gcm;

        pub const aead = Aead {
            .key_length = C.key_length,
            .nonce_length = C.nonce_length,
        };
    };
};

pub const Secret = struct {
    // TODO: Is using allocator better in terms of spece efficiency?
    const DigestBoundedArray = BoundedArray(u8, Hkdf.MAX_DIGEST_LENGTH);
    const KeyBoundedArray = BoundedArray(u8, Aead.MAX_KEY_LEGNTH);
    const NonceBoundedArray = BoundedArray(u8, Aead.MAX_NONCE_LENGTH);

    early_secret: DigestBoundedArray,

    hs_derived_secret: DigestBoundedArray,
    hs_secret: DigestBoundedArray,

    s_hs_secret: DigestBoundedArray,
    c_hs_secret: DigestBoundedArray,
    master_derived_secret: DigestBoundedArray,
    master_secret: DigestBoundedArray,

    s_hs_key: KeyBoundedArray,
    s_hs_iv: NonceBoundedArray,
    c_hs_key: KeyBoundedArray,
    c_hs_iv: NonceBoundedArray,

    s_hs_finished_secret: DigestBoundedArray,
    c_hs_finished_secret: DigestBoundedArray,
    s_ap_secret: DigestBoundedArray,
    c_ap_secret: DigestBoundedArray,

    s_ap_key: KeyBoundedArray,
    s_ap_iv: NonceBoundedArray,
    c_ap_key: KeyBoundedArray,
    c_ap_iv: NonceBoundedArray,

    exp_master_secret: DigestBoundedArray,
    res_master_secret: DigestBoundedArray,

    const Self = @This();

    pub fn init(hkdf: Hkdf, aead: Aead) !Self {
        const d_len = hkdf.digest_length;
        const k_len = aead.key_length;
        const n_len = aead.nonce_length;

        var res = Self{
            .early_secret = try DigestBoundedArray.init(d_len),

            .hs_derived_secret = try DigestBoundedArray.init(d_len),
            .hs_secret = try DigestBoundedArray.init(d_len),

            .s_hs_secret = try DigestBoundedArray.init(d_len),
            .c_hs_secret = try DigestBoundedArray.init(d_len),
            .master_derived_secret = try DigestBoundedArray.init(d_len),
            .master_secret = try DigestBoundedArray.init(d_len),

            .s_hs_key = try KeyBoundedArray.init(k_len),
            .s_hs_iv = try NonceBoundedArray.init(n_len),
            .c_hs_key = try KeyBoundedArray.init(k_len),
            .c_hs_iv = try NonceBoundedArray.init(n_len),

            .s_hs_finished_secret = try DigestBoundedArray.init(d_len),
            .c_hs_finished_secret = try DigestBoundedArray.init(d_len),
            .s_ap_secret = try DigestBoundedArray.init(d_len),
            .c_ap_secret = try DigestBoundedArray.init(d_len),

            .s_ap_key = try KeyBoundedArray.init(k_len),
            .s_ap_iv = try NonceBoundedArray.init(n_len),
            .c_ap_key = try KeyBoundedArray.init(k_len),
            .c_ap_iv = try NonceBoundedArray.init(n_len),

            .exp_master_secret = try DigestBoundedArray.init(d_len),
            .res_master_secret = try DigestBoundedArray.init(d_len),
        };

        return res;
    }
};

const expect = std.testing.expect;

test "HKDF-SHA256" {
    var hkdf: Hkdf = undefined;
    hkdf = Hkdf.Sha256.hkdf;

    var hash: [Hkdf.MAX_DIGEST_LENGTH]u8 = undefined;
    const hash_ans = [_]u8{ 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 };
    hkdf.hash(&hash, "");

    try expect(std.mem.eql(u8, hash[0..hkdf.digest_length], &hash_ans));

}

test "HKDF-SHA256 secret deriviation" {
    var hkdf: Hkdf = undefined;
    hkdf = Hkdf.Sha256.hkdf;
    var secret = try Secret.init(hkdf, Aead.Aes128Gcm.aead);

    const shared_key = [_]u8{ 0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };
    const early_secret_ans = [_]u8{ 0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b, 0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2, 0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60, 0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a };
    const hs_derived_secret_ans = [_]u8{ 0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97, 0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba };
    const hs_secret_ans = [_]u8{ 0x1d, 0xc8, 0x26, 0xe9, 0x36, 0x06, 0xaa, 0x6f, 0xdc, 0x0a, 0xad, 0xc1, 0x2f, 0x74, 0x1b, 0x01, 0x04, 0x6a, 0xa6, 0xb9, 0x9f, 0x69, 0x1e, 0xd2, 0x21, 0xa9, 0xf0, 0xca, 0x04, 0x3f, 0xbe, 0xac };

    hkdf.deriveEarlySecret(secret.early_secret.slice(), &([_]u8{0} ** 32));
    try expect(std.mem.eql(u8, secret.early_secret.slice(), &early_secret_ans));

    try hkdf.deriveSecret(secret.hs_derived_secret.slice(), secret.early_secret.slice(), "derived", "");
    try expect(std.mem.eql(u8, secret.hs_derived_secret.slice(), &hs_derived_secret_ans));

    hkdf.extract(secret.hs_secret.slice(), secret.hs_derived_secret.slice(), &shared_key);
    try expect(std.mem.eql(u8, secret.hs_secret.slice(), &hs_secret_ans));
}