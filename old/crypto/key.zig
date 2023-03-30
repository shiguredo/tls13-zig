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

        var modulus_new = try removeZeros(modulus, allocator);
        errdefer allocator.free(modulus_new);

        const publicExponent = try asn1.Decoder.decodeINTEGER(reader, allocator);
        errdefer allocator.free(publicExponent);

        const privateExponent = try asn1.Decoder.decodeINTEGER(reader, allocator);
        defer allocator.free(privateExponent);

        var privExponent_new = try removeZeros(privateExponent, allocator);
        errdefer allocator.free(privExponent_new);

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
            .modulus_length_bits = modulus_new.len * 8,
            .publicExponent = publicExponent,
            .privateExponent = privExponent_new,
            .prime1 = prime1,
            .prime2 = prime2,
            .exponent1 = exponent1,
            .exponent2 = exponent2,
            .coefficient = coef,
            .allocator = allocator,
        };
    }

    fn removeZeros(src: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var len = src.len;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            if (src[i] != 0) {
                break;
            }
            len -= 1;
        }

        var res = try allocator.alloc(u8, len);
        errdefer allocator.free(res);
        std.mem.copy(u8, res, src[i..]);
        return res;
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

pub const PublicKeyType = enum(usize) {
    rsa,
    secp256r1,
    secp384r1,
};

pub const PublicKey = union(PublicKeyType) {
    rsa: RSAPublicKey,
    secp256r1: Secp256r1PublicKey,
    secp384r1: Secp384r1PublicKey,

    const Self = @This();

    pub fn decode(t: PublicKeyType, reader: anytype, len: usize, allocator: std.mem.Allocator) !Self {
        switch (t) {
            .rsa => return Self{ .rsa = try RSAPublicKey.decode(reader, allocator) },
            .secp256r1 => return Self{ .secp256r1 = try Secp256r1PublicKey.decode(reader, len) },
            .secp384r1 => return Self{ .secp384r1 = try Secp384r1PublicKey.decode(reader, len) },
        }
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .rsa => |p| p.deinit(),
            .secp256r1 => |p| p.deinit(),
            .secp384r1 => |p| p.deinit(),
        }
    }

    pub fn copy(self: Self, allocator: std.mem.Allocator) !Self {
        switch (self) {
            .rsa => |p| return Self{ .rsa = try p.copy(allocator) },
            .secp256r1 => |p| return Self{ .secp256r1 = try p.copy(allocator) },
            .secp384r1 => |p| return Self{ .secp384r1 = try p.copy(allocator) },
        }
    }
};

// RFC3279 Section-2.3.1 (p. 8)
// RSAPublicKey ::= SEQUENCE {
//    modulus            INTEGER,    -- n
//    publicExponent     INTEGER  }  -- e
const RSAPublicKey = struct {
    modulus: []u8,
    modulus_length_bits: usize,
    publicExponent: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.modulus);
        self.allocator.free(self.publicExponent);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();

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

        return Self{
            .modulus = modulus_new,
            .modulus_length_bits = modulus_len * 8,
            .publicExponent = publicExponent,
            .allocator = allocator,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeByte(@enumToInt(asn1.Tag.SEQUENCE));
        len += 1;
        len += try asn1.Encoder.encodeLength(self.lengthContent(), writer);

        try writer.writeByte(@enumToInt(asn1.Tag.INTEGER));
        len += 1;
        len += try asn1.Encoder.encodeLength(self.modulus.len, writer);
        try writer.writeAll(self.modulus);
        len += self.modulus.len;

        try writer.writeByte(@enumToInt(asn1.Tag.INTEGER));
        len += 1;
        len += try asn1.Encoder.encodeLength(self.publicExponent.len, writer);
        try writer.writeAll(self.publicExponent);
        len += self.publicExponent.len;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = self.lengthContent();
        len += 1 + asn1.Decoder.getLengthSize(len); // SEQUENCE
        return len;
    }

    fn lengthContent(self: Self) usize {
        var len: usize = 0;
        len += 1 + asn1.Decoder.getLengthSize(self.modulus.len) + self.modulus.len; // modulus(INTEGER)
        len += 1 + asn1.Decoder.getLengthSize(self.publicExponent.len) + self.publicExponent.len; // exponent(INTEGER)
        return len;
    }

    pub fn copy(self: Self, allocator: std.mem.Allocator) !Self {
        var buf = try allocator.alloc(u8, self.length());
        defer allocator.free(buf);
        var stream = io.fixedBufferStream(buf);

        _ = try self.encode(stream.writer());
        stream.reset();

        return try decode(stream.reader(), allocator);
    }

    pub fn eql(a: Self, b: Self) bool {
        if (!std.mem.eql(u8, a.modulus, b.modulus)) {
            return false;
        }

        if (!std.mem.eql(u8, a.publicExponent, b.publicExponent)) {
            return false;
        }

        return true;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}Modulus:{}", .{ prefix, std.fmt.fmtSliceHexLower(self.modulus) });
        pf("{s}PublicExponent:{}", .{ prefix, std.fmt.fmtSliceHexLower(self.publicExponent) });
    }
};

// ECPoint ::= OCTET STRING
const Secp256r1PublicKey = struct {
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    key: P256.PublicKey,

    const Self = @This();

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, len: usize) !Self {
        var buf: [100]u8 = undefined;
        // Currently, only uncompressed format supported.
        if (len != P256.PublicKey.uncompressed_sec1_encoded_length) {
            return errs.DecodingError.UnsupportedFormat;
        }
        _ = try reader.readNoEof(buf[0..len]);
        const key = try P256.PublicKey.fromSec1(buf[0..len]);

        return Self{
            .key = key,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        const uncomp = self.key.toUncompressedSec1();
        try writer.writeAll(&uncomp);

        return uncomp.len;
    }

    pub fn length(self: Self) usize {
        _ = self;
        return P256.PublicKey.uncompressed_sec1_encoded_length;
    }

    pub fn copy(self: Self, allocator: std.mem.Allocator) !Self {
        var buf = try allocator.alloc(u8, self.length());
        defer allocator.free(buf);
        var stream = io.fixedBufferStream(buf);

        _ = try self.encode(stream.writer());
        stream.reset();

        return try decode(stream.reader(), self.length());
    }

    pub fn eql(a: Self, b: Self) bool {
        return std.mem.eql(u8, &(a.key.toUncompressedSec1()), &(b.key.toUncompressedSec1()));
    }
};

const Secp384r1PublicKey = struct {
    const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

    key: P384.PublicKey,

    const Self = @This();

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, len: usize) !Self {
        var buf: [100]u8 = undefined;
        // Currently, only uncompressed format supported.
        if (len != P384.PublicKey.uncompressed_sec1_encoded_length) {
            return errs.DecodingError.UnsupportedFormat;
        }
        _ = try reader.readNoEof(buf[0..len]);
        const key = try P384.PublicKey.fromSec1(buf[0..len]);

        return Self{
            .key = key,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        const uncomp = self.key.toUncompressedSec1();
        try writer.writeAll(&uncomp);

        return uncomp.len;
    }

    pub fn length(self: Self) usize {
        _ = self;
        return P384.PublicKey.uncompressed_sec1_encoded_length;
    }

    pub fn copy(self: Self, allocator: std.mem.Allocator) !Self {
        var buf = try allocator.alloc(u8, self.length());
        defer allocator.free(buf);
        var stream = io.fixedBufferStream(buf);

        _ = try self.encode(stream.writer());
        stream.reset();

        return try decode(stream.reader(), self.length());
    }

    pub fn eql(a: Self, b: Self) bool {
        return std.mem.eql(u8, &(a.key.toUncompressedSec1()), &(b.key.toUncompressedSec1()));
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

test "RSAPublicKey copy" {
    // zig fmt: off
    const rsa_bytes = [_]u8{
    0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
    0x01, 0x01, 0x00, 0xC7, 0x85, 0xE4, 0x64, 0x6D, 0xBD, 0x45, 0x09, 0xCE, 0xF1,
    0x44, 0xAB, 0x2D, 0xC0, 0xAD, 0x09, 0x20, 0x66, 0x8A, 0x63, 0xCB, 0x7B, 0x25,
    0xB4, 0xB6, 0x6D, 0x0D, 0x9B, 0xE9, 0x82, 0x09, 0x0E, 0x09, 0xC7, 0xB8, 0x86,
    0x07, 0xA8, 0x1A, 0xC2, 0x51, 0x5E, 0xFD, 0xA1, 0xE9, 0x62, 0x92, 0x4A, 0x24,
    0x46, 0x41, 0x6F, 0x72, 0xFA, 0x5A, 0x2A, 0x29, 0xC5, 0x1C, 0x34, 0x07, 0x52,
    0x95, 0x84, 0x23, 0xA4, 0x54, 0x11, 0x16, 0x26, 0x48, 0x28, 0x37, 0x3B, 0xC5,
    0xA2, 0xE3, 0x6B, 0x8E, 0x71, 0x5D, 0x81, 0xE5, 0x96, 0x9B, 0x99, 0x70, 0xA4,
    0xC1, 0xDC, 0x58, 0xE4, 0x47, 0x25, 0xE7, 0x50, 0x5B, 0x33, 0xC5, 0x27, 0x19,
    0xDA, 0x00, 0x19, 0xB7, 0x4D, 0x9A, 0x24, 0x66, 0x4A, 0x64, 0xE3, 0x72, 0xCF,
    0xA5, 0x84, 0xCC, 0x60, 0xE1, 0xF1, 0x58, 0xEA, 0x50, 0x69, 0x88, 0x45, 0x45,
    0x88, 0x65, 0x23, 0x19, 0x14, 0x7E, 0xEB, 0x54, 0x7A, 0xEC, 0xBC, 0xFA, 0x53,
    0x82, 0x89, 0x78, 0xB3, 0x5C, 0x0A, 0x6D, 0x3B, 0x43, 0x01, 0x58, 0x28, 0x19,
    0xA9, 0x8B, 0x4F, 0x20, 0x77, 0x28, 0x12, 0xBD, 0x17, 0x54, 0xC3, 0x9E, 0x49,
    0xA2, 0x9A, 0xDE, 0x76, 0x3F, 0x95, 0x1A, 0xD8, 0xD4, 0x90, 0x1E, 0x21, 0x15,
    0x3E, 0x06, 0x41, 0x7F, 0xE0, 0x86, 0xDE, 0xBD, 0x46, 0x5A, 0xB3, 0xFF, 0xEF,
    0x2E, 0xD1, 0xD1, 0x10, 0x92, 0x1B, 0x94, 0xBA, 0xE7, 0x2B, 0xA9, 0xA9, 0x66,
    0x48, 0x6C, 0xB8, 0xDC, 0x74, 0x70, 0x05, 0xF0, 0xCA, 0x17, 0x06, 0x1E, 0x58,
    0xCE, 0xC2, 0x3C, 0xC7, 0x79, 0x7B, 0xF7, 0x4E, 0xFA, 0xDD, 0x3C, 0xB7, 0xC3,
    0xDB, 0x8F, 0x35, 0x53, 0x4E, 0xFE, 0x61, 0x40, 0x30, 0xAC, 0x11, 0x82, 0x15,
    0xD9, 0x3E, 0xC0, 0x14, 0x8F, 0x52, 0x70, 0xDC, 0x4C, 0x92, 0x1E, 0xFF, 0x02,
    0x03, 0x01, 0x00, 0x01
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&rsa_bytes);
    const r = try RSAPublicKey.decode(stream.reader(), std.testing.allocator);
    defer r.deinit();

    const r2 = try r.copy(std.testing.allocator);
    defer r2.deinit();

    try expect(r.eql(r2));
}

test "Secp256r1PublicKey copy" {
    // zig fmt: off
    const secp_bytes = [_]u8{
    0x04, 0x9d, 0x92, 0x3d, 0x57, 0xe4, 0xb8, 0xfc, 0xb1, 0x7b, 0x92, 0x1b, 0x66,
    0x07, 0x82, 0xd7, 0x5f, 0x93, 0x75, 0x37, 0xbe, 0xfb, 0x08, 0xdc, 0xc5, 0x2d,
    0x5b, 0x10, 0x65, 0xcf, 0x6a, 0xc3, 0xbe, 0xb2, 0x0d, 0x82, 0x9f, 0x47, 0xfc,
    0x68, 0xed, 0xb6, 0xcf, 0xfa, 0xfa, 0xd5, 0x8c, 0x2a, 0xc8, 0xce, 0xd2, 0xb6,
    0xed, 0x1f, 0xbd, 0x08, 0xd8, 0x65, 0x16, 0x3a, 0x3e, 0x69, 0x22, 0x4a, 0x84
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&secp_bytes);
    const secp = try Secp256r1PublicKey.decode(stream.reader(), secp_bytes.len);
    defer secp.deinit();

    const secp2 = try secp.copy(std.testing.allocator);
    defer secp2.deinit();

    try expect(secp.eql(secp2));
}

test "PublicKey copy" {
    // zig fmt: off
    const secp_bytes = [_]u8{
    0x04, 0x9d, 0x92, 0x3d, 0x57, 0xe4, 0xb8, 0xfc, 0xb1, 0x7b, 0x92, 0x1b, 0x66,
    0x07, 0x82, 0xd7, 0x5f, 0x93, 0x75, 0x37, 0xbe, 0xfb, 0x08, 0xdc, 0xc5, 0x2d,
    0x5b, 0x10, 0x65, 0xcf, 0x6a, 0xc3, 0xbe, 0xb2, 0x0d, 0x82, 0x9f, 0x47, 0xfc,
    0x68, 0xed, 0xb6, 0xcf, 0xfa, 0xfa, 0xd5, 0x8c, 0x2a, 0xc8, 0xce, 0xd2, 0xb6,
    0xed, 0x1f, 0xbd, 0x08, 0xd8, 0x65, 0x16, 0x3a, 0x3e, 0x69, 0x22, 0x4a, 0x84
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&secp_bytes);
    const secp = try Secp256r1PublicKey.decode(stream.reader(), secp_bytes.len);
    const pub_key = PublicKey{ .secp256r1 = secp };
    defer pub_key.deinit();

    const pub_key2 = try pub_key.copy(std.testing.allocator);
    defer pub_key2.deinit();

    try expect(secp.eql(pub_key2.secp256r1));
}
