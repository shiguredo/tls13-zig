const std = @import("std");
const io = std.io;
const asn1 = @import("asn1.zig");
const cert = @import("cert.zig");
const errs = @import("errors.zig");
const expect = std.testing.expect;

pub const PrivateKeyType = enum(u8) {
    rsa,
    ec,
};

pub const PrivateKey = union(PrivateKeyType) {
    rsa: RSAPrivateKey,
    ec: ECPrivateKey,

    const Self = @This();
    pub fn deinit(self: Self) void {
        switch (self) {
            .rsa => |r| r.deinit(),
            .ec => |e| e.deinit(),
        }
    }
};

/// RFC5915 Section3 Eppliptic Curve Private KEy Format
///
/// ECPrivateKey ::= SEQUENCE {
///   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///   privateKey     OCTET STRING,
///   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///   publicKey  [1] BIT STRING OPTIONAL
/// }
///
/// RFC 5480 Section 2.1.1.1 Named Curve
///
/// ECParameters ::= CHOICE {
///   namedCurve         OBJECT IDENTIFIER
///   -- implicitCurve   NULL
///   -- specifiedCurve  SpecifiedECDomain
/// }
pub const ECPrivateKey = struct {
    privateKey: []u8,
    namedCurve: ?asn1.ObjectIdentifier = null,
    publicKey: []u8 = &([_]u8{}),

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();

        var t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return errs.DecodingError.InvalidType;
        }
        var t_len: usize = try reader.readByte();
        if (t_len != 0x01) { // length is assumed to be 1(u8)
            return errs.DecodingError.InvalidLength;
        }
        const ec_version = try reader.readByte();
        if (ec_version != 0x01) {
            return errs.DecodingError.InvalidFormat;
        }

        t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .OCTET_STRING) {
            return errs.DecodingError.InvalidType;
        }
        t_len = try asn1.Decoder.decodeLength(reader);
        var privKey = try allocator.alloc(u8, t_len);
        errdefer allocator.free(privKey);
        try reader.readNoEof(privKey);

        var res = Self{
            .privateKey = privKey,
            .allocator = allocator,
        };
        errdefer res.deinit();

        var optional_t = try reader.readByte();
        if (optional_t == 0xA0) { // [0] OPTIONAL
            t_len = try asn1.Decoder.decodeLength(reader);
            // Currently, only 'namedCurve' is supported.
            res.namedCurve = try asn1.ObjectIdentifier.decode(reader, allocator);

            optional_t = try reader.readByte();
        }

        if (optional_t == 0xA1) { // [1] OPTIONAL
            t_len = try asn1.Decoder.decodeLength(reader);
            const t_key = @intToEnum(asn1.Tag, try reader.readByte());
            if (t_key != .BIT_STRING) {
                return errs.DecodingError.InvalidType;
            }
            const key_len = try asn1.Decoder.decodeLength(reader);
            // the first byte of 'BIT STRING' specifies
            // the number of bits not used in the last of the octets
            const b = try reader.readByte();
            if (b != 0x00) {
                // TODO: handle this
                return errs.DecodingError.InvalidFormat;
            }

            res.publicKey = try allocator.alloc(u8, key_len - 1);
            try reader.readNoEof(res.publicKey);
        }

        return res;
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.privateKey);
        if (self.namedCurve) |p| {
            p.deinit();
        }
        if (self.publicKey.len != 0) {
            self.allocator.free(self.publicKey);
        }
    }

    pub fn fromDer(der_path: []const u8, allocator: std.mem.Allocator) !Self {
        // Get the path
        var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.fs.realpath(der_path, &path_buffer);

        // Open the file
        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();

        const fb = try file.readToEndAlloc(allocator, 10000);
        defer allocator.free(fb);

        var stream = io.fixedBufferStream(fb);

        return try Self.decode(stream.reader(), allocator);
    }
};

/// PKCS#1(RFC8017) A.1.2.  RSA Private Key Syntax
///
/// RSAPrivateKey ::= SEQUENCE {
///     version           Version,
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER,  -- e
///     privateExponent   INTEGER,  -- d
///     prime1            INTEGER,  -- p
///     prime2            INTEGER,  -- q
///     exponent1         INTEGER,  -- d mod (p-1)
///     exponent2         INTEGER,  -- d mod (q-1)
///     coefficient       INTEGER,  -- (inverse of q) mod p
///     otherPrimeInfos   OtherPrimeInfos OPTIONAL
/// }
pub const RSAPrivateKey = struct {
    version: u8,
    modulus: []u8,
    modulus_length_bits: usize,
    publicExponent: []u8,
    privateExponent: []u8,
    prime1: []u8,
    prime2: []u8,
    exponent1: []u8,
    exponent2: []u8,
    coefficient: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();

        var t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return errs.DecodingError.InvalidType;
        }
        var t_len: usize = try reader.readByte();
        if (t_len != 0x01) { // length is assumed to be 1(u8)
            return errs.DecodingError.InvalidLength;
        }
        const version = try reader.readByte();
        if (version != 0x00) { // currently, only 'two-prime(0)' is supported.
            return errs.DecodingError.InvalidFormat;
        }

        const modulus = try asn1.Decoder.decodeINTEGER(reader, allocator);
        defer allocator.free(modulus);

        var modulus_len = modulus.len;
        var i: usize = 0;
        while (i < modulus_len) : (i += 1) {
            if (modulus[i] != 0) {
                break;
            }
            modulus_len -= 1;
        }

        var modulus_new = try allocator.alloc(u8, modulus_len);
        errdefer allocator.free(modulus_new);
        std.mem.copy(u8, modulus_new, modulus[i..]);

        const publicExponent = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(publicExponent);

        const privateExponent = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(privateExponent);

        const prime1 = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(prime1);

        const prime2 = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(prime2);

        const exponent1 = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(exponent1);

        const exponent2 = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(exponent2);

        const coef = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(coef);

        return Self{
            .version = version,
            .modulus = modulus_new,
            .modulus_length_bits = modulus_len * 8,
            .publicExponent = publicExponent,
            .privateExponent = privateExponent,
            .prime1 = prime1,
            .prime2 = prime2,
            .exponent1 = exponent1,
            .exponent2 = exponent2,
            .coefficient = coef,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.modulus);
        self.allocator.free(self.publicExponent);
        self.allocator.free(self.privateExponent);
        self.allocator.free(self.prime1);
        self.allocator.free(self.prime2);
        self.allocator.free(self.exponent1);
        self.allocator.free(self.exponent2);
        self.allocator.free(self.coefficient);
    }

    pub fn fromDer(der_path: []const u8, allocator: std.mem.Allocator) !Self {
        // Get the path
        var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
        const path = try std.fs.realpath(der_path, &path_buffer);

        // Open the file
        const file = try std.fs.openFileAbsolute(path, .{});
        defer file.close();

        const fb = try file.readToEndAlloc(allocator, 10000);
        defer allocator.free(fb);

        var stream = io.fixedBufferStream(fb);

        return try Self.decode(stream.reader(), allocator);
    }

    pub fn decodeFromPEM(pem: []const u8, allocator: std.mem.Allocator) !Self {
        const keys = try cert.convertPEMsToDERs(pem, "RSA PRIVATE KEY", allocator);
        defer {
            for (keys.items) |k| {
                allocator.free(k);
            }
            keys.deinit();
        }
        if (keys.items.len != 1) {
            return errs.DecodingError.InvalidFormat;
        }

        var stream_decode = io.fixedBufferStream(keys.items[0]);
        const key = try Self.decode(stream_decode.reader(), allocator);

        return key;
    }
};

test "PrivateKey secp256r1 decode" {
    // zig fmt: off
    const priv_key = [_]u8{
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x64, 0xc4, 0x67, 0xe8, 0xf2, 0x49,
    0xb1, 0x67, 0x9b, 0xd0, 0x52, 0x1e, 0x27, 0xe9, 0x10, 0xd0, 0xe6, 0x64, 0xd8,
    0x14, 0x5d, 0xbf, 0x43, 0xac, 0x84, 0xe9, 0x3d, 0xf9, 0xa8, 0xf2, 0x19, 0x0c,
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1,
    0x44, 0x03, 0x42, 0x00, 0x04, 0xd6, 0x35, 0x7d, 0x04, 0xd2, 0xa7, 0xc0, 0x4f,
    0xd8, 0x45, 0x5c, 0x26, 0x63, 0xae, 0x6b, 0xc9, 0x82, 0xdf, 0x08, 0x84, 0xb4,
    0xec, 0xce, 0xd2, 0xaa, 0xcd, 0x31, 0xe9, 0xc7, 0x9a, 0xaa, 0xcb, 0x04, 0x54,
    0x8e, 0xde, 0x25, 0xe5, 0xbb, 0x2c, 0x11, 0x8d, 0x1d, 0xec, 0xf1, 0x47, 0xec,
    0xe8, 0x64, 0x54, 0xd9, 0xc5, 0xa0, 0x6f, 0xf6, 0x9c, 0x06, 0x93, 0x21, 0xa1,
    0x95, 0x2e, 0x12, 0x25
    };
    const priv_key_ans = [_]u8{
    0x64, 0xc4, 0x67, 0xe8, 0xf2, 0x49,
    0xb1, 0x67, 0x9b, 0xd0, 0x52, 0x1e, 0x27, 0xe9, 0x10, 0xd0, 0xe6, 0x64, 0xd8,
    0x14, 0x5d, 0xbf, 0x43, 0xac, 0x84, 0xe9, 0x3d, 0xf9, 0xa8, 0xf2, 0x19, 0x0c,
    };
    const pub_key_ans = [_]u8{
    0x04, 0xd6, 0x35, 0x7d, 0x04, 0xd2, 0xa7, 0xc0, 0x4f,
    0xd8, 0x45, 0x5c, 0x26, 0x63, 0xae, 0x6b, 0xc9, 0x82, 0xdf, 0x08, 0x84, 0xb4,
    0xec, 0xce, 0xd2, 0xaa, 0xcd, 0x31, 0xe9, 0xc7, 0x9a, 0xaa, 0xcb, 0x04, 0x54,
    0x8e, 0xde, 0x25, 0xe5, 0xbb, 0x2c, 0x11, 0x8d, 0x1d, 0xec, 0xf1, 0x47, 0xec,
    0xe8, 0x64, 0x54, 0xd9, 0xc5, 0xa0, 0x6f, 0xf6, 0x9c, 0x06, 0x93, 0x21, 0xa1,
    0x95, 0x2e, 0x12, 0x25
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&priv_key);
    const ec_key = try ECPrivateKey.decode(stream.reader(), std.testing.allocator);
    defer ec_key.deinit();

    try expect(std.mem.eql(u8, ec_key.privateKey, &priv_key_ans));
    try expect(std.mem.eql(u8, ec_key.namedCurve.?.id, "1.2.840.10045.3.1.7"));
    try expect(std.mem.eql(u8, ec_key.publicKey, &pub_key_ans));
}
