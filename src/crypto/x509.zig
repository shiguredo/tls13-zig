const std = @import("std");
const io = std.io;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const asn1 = @import("asn1.zig");
const rsa = @import("rsa.zig");

const BoundedArray = std.BoundedArray;
const ArrayList = std.ArrayList;

const OIDEntry = struct {
    oid: []const u8,
    display_name: []const u8,
};

pub const OIDMap = struct {
    const map: [24]OIDEntry = [_]OIDEntry{ OIDEntry{
        .oid = "2.5.4.3",
        .display_name = "CN",
    }, OIDEntry{
        .oid = "2.5.4.5",
        .display_name = "S/N",
    }, OIDEntry{
        .oid = "2.5.4.6",
        .display_name = "C",
    }, OIDEntry{
        .oid = "2.5.4.7",
        .display_name = "L",
    }, OIDEntry{
        .oid = "2.5.4.8",
        .display_name = "ST",
    }, OIDEntry{
        .oid = "2.5.4.10",
        .display_name = "O",
    }, OIDEntry{
        .oid = "2.5.4.15",
        .display_name = "businessCategory",
    }, OIDEntry{
        .oid = "1.3.6.1.4.1.311.60.2.1.2",
        .display_name = "jurisdictionST",
    }, OIDEntry{
        .oid = "1.3.6.1.4.1.311.60.2.1.3",
        .display_name = "jurisdictionC",
    }, OIDEntry{
        .oid = "1.2.840.113549.1.1.1",
        .display_name = "rsaEncryption",
    }, OIDEntry{
        .oid = "1.2.840.113549.1.1.11",
        .display_name = "sha256WithRSAEncryption",
    }, OIDEntry{
        .oid = "2.5.29.35",
        .display_name = "authorityKeyIdentifier",
    }, OIDEntry{
        .oid = "1.3.6.1.5.5.7.1.1",
        .display_name = "authorityInfoAccess",
    }, OIDEntry{
        .oid = "2.5.29.17",
        .display_name = "subjectAltName",
    }, OIDEntry{
        .oid = "2.5.29.32",
        .display_name = "certificatePolicies",
    }, OIDEntry{
        .oid = "2.5.29.37",
        .display_name = "extKeyUsage",
    }, OIDEntry{
        .oid = "2.5.29.31",
        .display_name = "cRLDistributionPoints",
    }, OIDEntry{
        .oid = "2.5.29.14",
        .display_name = "subjectKeyIdentifier",
    }, OIDEntry{
        .oid = "2.5.29.15",
        .display_name = "keyUsage",
    }, OIDEntry{
        .oid = "1.3.6.1.4.1.11129.2.4.2",
        .display_name = "extendedValidationCertificates",
    }, OIDEntry{
        .oid = "2.5.29.19",
        .display_name = "basicConstraints",
    }, OIDEntry{
        .oid = "1.2.840.10045.4.3.2",
        .display_name = "ecdsa-with-SHA256",
    }, OIDEntry{
        .oid = "1.2.840.10045.2.1",
        .display_name = "id-ecPublicKey",
    }, OIDEntry{
        .oid = "2.5.29.19",
        .display_name = "id-ce-basicConstraints",
    } };

    const Error = error{
        NotFound,
    };

    const Self = @This();

    fn getEntryByBytes(oid_bytes: []const u8) !OIDEntry {
        var oid_c: [100]u8 = undefined;
        const oid_len = asn1.Decoder.decodeOID(&oid_c, oid_bytes);
        const oid = oid_c[0..oid_len];
        for (map) |e| {
            if (std.mem.eql(u8, oid, e.oid)) {
                return e;
            }
        }

        return Error.NotFound;
    }

    pub fn getEntryByName(name: []const u8) !OIDEntry {
        for (map) |e| {
            if (std.mem.eql(u8, name, e.display_name)) {
                return e;
            }
        }

        return Error.NotFound;
    }
};

// From RFC5280 Section-4.1 (p. 16)
// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signatureValue       BIT STRING  }
pub const Certificate = struct {
    tbs_certificate: TBSCertificate,
    cert_data: []u8 = &([_]u8{}),
    signature_algorithm: AlgorithmIdentifier,
    signature_value: SignatureValue,

    allocator: std.mem.Allocator,

    const Self = @This();

    const Error = error{
        UnsupportedSignatureAlgorithm,
        UnknownModulusLength,
        InvalidCACertificate,
    };

    pub fn deinit(self: Self) void {
        self.tbs_certificate.deinit();
        self.signature_algorithm.deinit();
        self.signature_value.deinit();
        if (self.cert_data.len != 0) {
            self.allocator.free(self.cert_data);
        }
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        const begin_idx = try stream.getPos();
        const tbs_certificate = try TBSCertificate.decode(reader, allocator);
        errdefer tbs_certificate.deinit();
        const end_idx = try stream.getPos();

        var cert_data = try allocator.alloc(u8, end_idx - begin_idx);
        errdefer allocator.free(cert_data);

        std.mem.copy(u8, cert_data, stream.buffer[begin_idx..end_idx]);

        const signature_algorithm = try AlgorithmIdentifier.decode(reader, allocator);
        errdefer signature_algorithm.deinit();

        const signature_value = try SignatureValue.decode(reader, allocator);
        errdefer signature_value.deinit();

        return Self{
            .tbs_certificate = tbs_certificate,
            .cert_data = cert_data,
            .signature_algorithm = signature_algorithm,
            .signature_value = signature_value,
            .allocator = allocator,
        };
    }

    pub fn verify(self: Self, issuer_cert: ?Self) !void {
        var issuer_c: Self = undefined;
        if (issuer_cert) |c| {
            issuer_c = c;
        } else {
            issuer_c = self;
        }

        // Check cert's issuer and issuer_cert's subject
        // TODO: is this ok?
        if (!self.tbs_certificate.issuer.eql(issuer_c.tbs_certificate.subject)) {
            return Error.InvalidCACertificate;
        }

        switch (issuer_c.tbs_certificate.subjectPublicKeyInfo.publicKey) {
            .rsa => |pubkey| {
                const algo_id = self.signature_algorithm.algorithm.id;
                // Currently, only supports '' abd
                if (!std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.5") and // sha1WithRSAEncryption
                    !std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.11") and // sha256WithRsaEncryption
                    !std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.12") and // sha384WithRsaEncryption
                    !std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.13")) // sha512WithRSAEncryption
                {
                    std.log.warn("UnsupportedSignatureAlgorithm: {s}", .{self.signature_algorithm.algorithm.id});
                    return Error.UnsupportedSignatureAlgorithm;
                }
                if (pubkey.modulus_length_bits != self.signature_value.value.len * 8) {
                    std.log.warn("Invalid signature length {}", .{self.signature_value.value.len});
                    return Error.UnknownModulusLength;
                }
                if (pubkey.modulus_length_bits == 2048) {
                    const sig = rsa.Rsa2048.PKCS1V15Signature{ .signature = self.signature_value.value[0 .. 2048 / 8].* };
                    var p = try rsa.Rsa2048.PublicKey.fromBytes(pubkey.publicExponent, pubkey.modulus, self.allocator);
                    defer p.deinit();
                    if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.5")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.Sha1, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.11")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha256, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.12")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha384, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.13")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha512, self.allocator);
                    } else {
                        unreachable;
                    }
                } else if (pubkey.modulus_length_bits == 4096) {
                    const sig = rsa.Rsa4096.PKCS1V15Signature{ .signature = self.signature_value.value[0 .. 4096 / 8].* };
                    var p = try rsa.Rsa4096.PublicKey.fromBytes(pubkey.publicExponent, pubkey.modulus, self.allocator);
                    defer p.deinit();
                    if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.5")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.Sha1, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.11")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha256, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.12")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha384, self.allocator);
                    } else if (std.mem.eql(u8, algo_id, "1.2.840.113549.1.1.13")) {
                        try sig.verify(self.cert_data, p, std.crypto.hash.sha2.Sha512, self.allocator);
                    } else {
                        unreachable;
                    }
                } else {
                    std.log.err("Unknown modulus length {}", .{pubkey.modulus_length_bits});
                    return Error.UnknownModulusLength;
                }
            },
            .secp256r1 => |pubkey| {
                // ecdsa-with-SHA256
                if (!std.mem.eql(u8, self.signature_algorithm.algorithm.id, "1.2.840.10045.4.3.2")) {
                    std.log.err("Secp256r1 UnsupportedSignatureAlgorithm: {s}", .{self.signature_algorithm.algorithm.id});
                    return Error.UnsupportedSignatureAlgorithm;
                }
                const ecdsa_sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
                const sig = try ecdsa_sha256.Signature.fromDer(self.signature_value.value);
                try sig.verify(self.cert_data, pubkey.key);
            },
            .secp384r1 => |pubkey| {
                const algo_id = self.signature_algorithm.algorithm.id;
                if (!std.mem.eql(u8, algo_id, "1.2.840.10045.4.3.3")) // ecdsa-with-SHA384
                {
                    std.log.warn("Secp384r1 UnsupportedSignatureAlgorithm: {s}", .{self.signature_algorithm.algorithm.id});
                    return Error.UnsupportedSignatureAlgorithm;
                }

                if (std.mem.eql(u8, algo_id, "1.2.840.10045.4.3.2")) {
                    unreachable;
                    // ecdsa-with-SHA256 is not supported due to a std's ecdsa issue.
                    // this code does not work now.
                    // const ecdsa_sha256 = std.crypto.sign.ecdsa.Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha256);
                    // const sig = try ecdsa_sha256.Signature.fromDer(self.signature_value.value);
                    // const pk = try ecdsa_sha256.PublicKey.fromSec1(&pubkey.key.toCompressedSec1());
                    // try sig.verify(self.cert_data, pk);
                } else if (std.mem.eql(u8, algo_id, "1.2.840.10045.4.3.3")) {
                    const ecdsa_sha384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
                    const sig = try ecdsa_sha384.Signature.fromDer(self.signature_value.value);
                    try sig.verify(self.cert_data, pubkey.key);
                } else {
                    unreachable;
                }
            },
        }
    }

    pub fn print(self: Self, pf: *const fn ([]const u8, anytype) void) void {
        pf("-- TBSCertificate --", .{});
        self.tbs_certificate.print(pf, " ");
        pf("-- SignatureAlgorithm --", .{});
        self.signature_algorithm.print(pf, " ");
        pf("-- SignatureValue --", .{});
        self.signature_value.print(pf, " ");
    }
};

// From RFC5280 Section-4.1 (pp. 16-17)
// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  EXPLICIT Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo,
//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      extensions      [3]  EXPLICIT Extensions OPTIONAL
//                           -- If present, version MUST be v3
//      }
pub const TBSCertificate = struct {
    version: Version,
    serial_number: CertificateSerialNumber,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subjectPublicKeyInfo: SubjectPublicKeyInfo,
    extensions: ?Extensions = null,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.signature.deinit();
        self.issuer.deinit();
        self.subject.deinit();
        self.subjectPublicKeyInfo.deinit();
        if (self.extensions) |ext| {
            ext.deinit();
        }
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        const v = try reader.readByte();
        var version = Version.v1;
        if (v == 0xA0) { // [0] EXPLICIT
            const v_len = try reader.readByte();
            if (v_len != 0x03) { // length is assumed to be 3
                return asn1.Decoder.Error.InvalidLength;
            }
            version = try Version.decode(reader);
        } else {
            stream.reset();
        }

        const serial_number = try CertificateSerialNumber.decode(reader);

        const signature = try AlgorithmIdentifier.decode(reader, allocator);
        errdefer signature.deinit();

        const issuer = try Name.decode(reader, allocator);
        errdefer issuer.deinit();

        const validity = try Validity.decode(reader, allocator);
        errdefer validity.deinit();

        const subject = try Name.decode(reader, allocator);
        errdefer subject.deinit();

        const subjectPublicKeyInfo = try SubjectPublicKeyInfo.decode(reader, allocator);
        errdefer subjectPublicKeyInfo.deinit();

        var res = Self{
            .version = version,
            .serial_number = serial_number,
            .signature = signature,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .subjectPublicKeyInfo = subjectPublicKeyInfo,
        };

        if (version != .v1) {
            if ((try reader.readByte()) != 0xA3) { // [3] EXPLICIT
                return asn1.Decoder.Error.InvalidType;
            }
            const exts_len = try asn1.Decoder.decodeLength(reader);
            _ = exts_len;

            res.extensions = try Extensions.decode(reader, allocator);
            errdefer res.extensions.?.deinit();
        }

        return res;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}{}", .{ prefix, self.version });
        pf("{s}SerialNumber: {}", .{ prefix, std.fmt.fmtSliceHexLower(self.serial_number.serial.slice()) });
        pf("{s}SignatureAlgorithm:", .{prefix});
        self.signature.print(pf, prefix ++ " ");
        pf("{s}Issuer:", .{prefix});
        self.issuer.print(pf, prefix ++ " ");
        pf("{s}Validity:", .{prefix});
        self.validity.print(pf, prefix ++ " ");
        pf("{s}Subject:", .{prefix});
        self.subject.print(pf, prefix ++ " ");
        pf("{s}SubjectPublicKeyInfo:", .{prefix});
        self.subjectPublicKeyInfo.print(pf, prefix ++ " ");
        pf("{s}Extensions:", .{prefix});
        self.extensions.print(pf, prefix ++ " ");
    }
};

pub const Version = enum(u8) {
    v1 = 0,
    v2 = 1,
    v3 = 2,

    const Self = @This();
    pub fn decode(reader: anytype) !Self {
        const t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return asn1.Decoder.Error.InvalidType;
        }
        const t_len = try reader.readByte();
        if (t_len != 0x01) { // length is assumed to be 1(u8)
            return asn1.Decoder.Error.InvalidLength;
        }

        return @intToEnum(Self, try reader.readByte());
    }
};

const CertificateSerialNumber = struct {
    // RFC5280 4.1.2.2. Serial Number (p.19)
    // Certificate users MUST be able to handle serialNumber values up to 20 octets.
    // Some certificates exceeds 20 octets.
    serial: BoundedArray(u8, 32),

    const Self = @This();

    pub fn init(len: usize) !Self {
        return Self{
            .serial = try BoundedArray(u8, 32).init(len),
        };
    }

    pub fn decode(reader: anytype) !Self {
        const t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return asn1.Decoder.Error.InvalidType;
        }
        const len = try asn1.Decoder.decodeLength(reader);
        var res = try Self.init(len);

        try reader.readNoEof(res.serial.slice());
        return res;
    }
};

// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }
pub const AlgorithmIdentifier = struct {
    algorithm: asn1.ObjectIdentifier,
    parameters: []u8 = &([_]u8{}),

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.algorithm.deinit();
        if (self.parameters.len != 0) {
            self.allocator.free(self.parameters);
        }
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();

        const algorithm = try asn1.ObjectIdentifier.decode(reader, allocator);
        errdefer algorithm.deinit();

        // some algorithm do not have parameters
        if ((try stream.getPos()) == (try stream.getEndPos())) {
            return Self{
                .algorithm = algorithm,
                .allocator = allocator,
            };
        }

        const rest_len = (try stream.getEndPos()) - (try stream.getPos());
        var parameters = try allocator.alloc(u8, rest_len);
        errdefer allocator.free(parameters);

        try reader.readNoEof(parameters);

        return Self{
            .algorithm = algorithm,
            .parameters = parameters,
            .allocator = allocator,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = asn1.Decoder.decodeOID(&oid, self.algorithm);
        if (OIDMap.getEntryByBytes(self.algorithm)) |e| {
            pf("{s}Algorithm = {s}", .{ prefix, e.display_name });
        } else |e| {
            pf("{s}Algorithm = {s}({})", .{ prefix, oid[0..oid_len], e });
        }
    }
};

/// Name ::= CHOICE { -- only one possibility for now --
///   rdnSequence  RDNSequence }
///
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
///
/// RelativeDistinguishedName ::=
///   SET SIZE (1..MAX) OF AttributeTypeAndValue
///
/// AttributeTypeAndValue ::= SEQUENCE {
///   type     AttributeType,
///   value    AttributeValue }
///
/// AttributeType ::= OBJECT IDENTIFIER
///
/// AttributeValue ::= ANY -- DEFINED BY AttributeType
///
/// DirectoryString ::= CHOICE {
///       teletexString           TeletexString (SIZE (1..MAX)),
///       printableString         PrintableString (SIZE (1..MAX)),
///       universalString         UniversalString (SIZE (1..MAX)),
///       utf8String              UTF8String (SIZE (1..MAX)),
///       bmpString               BMPString (SIZE (1..MAX)) }
pub const Name = struct {
    rdn_sequence: ArrayList(RelativeDistinguishedName),

    const Self = @This();

    pub fn deinit(self: Self) void {
        for (self.rdn_sequence.items) |r| {
            r.deinit();
        }
        self.rdn_sequence.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        var rdn_seq = ArrayList(RelativeDistinguishedName).init(allocator);
        errdefer rdn_seq.deinit();

        const len = try stream.getEndPos();
        var cur: usize = 0;
        while (cur < len) {
            const r = try RelativeDistinguishedName.decode(reader, allocator);
            try rdn_seq.append(r);
            cur += r.length();
        }

        return Self{
            .rdn_sequence = rdn_seq,
        };
    }

    pub fn eql(a: Self, b: Self) bool {
        var res = a.rdn_sequence.items.len == b.rdn_sequence.items.len;
        if (!res) {
            return res;
        }
        var i: usize = 0;
        while (i < a.rdn_sequence.items.len) : (i += 1) {
            res = res and a.rdn_sequence.items[i].eql(b.rdn_sequence.items[i]);
        }
        return res;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        for (self.rdn_sequence.items) |r| {
            r.print(pf, prefix ++ " ");
        }
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) !ArrayList(u8) {
        var res = ArrayList(u8).init(allocator);
        for (self.rdn_sequence.items) |r| {
            const r_str = try r.toString(allocator);
            defer r_str.deinit();
            try res.appendSlice(r_str.items);
            try res.appendSlice(",");
        }

        return res;
    }
};

const RelativeDistinguishedName = struct {
    attrs: ArrayList(AttributeTypeAndValue),
    len: usize = 0,

    const Self = @This();

    pub fn deinit(self: Self) void {
        for (self.attrs.items) |a| {
            a.deinit();
        }
        self.attrs.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .SET) {
            return asn1.Decoder.Error.InvalidType;
        }
        const len = try asn1.Decoder.decodeLength(reader);
        var attrs = ArrayList(AttributeTypeAndValue).init(allocator);
        errdefer attrs.deinit();
        var cur: usize = 0;
        while (cur < len) {
            const a = try AttributeTypeAndValue.decode(reader, allocator);
            errdefer a.deinit();
            try attrs.append(a);
            cur += a.length();
        }
        return Self{
            .attrs = attrs,
            .len = len,
        };
    }

    pub fn length(self: Self) usize {
        return self.len + 1 + asn1.Decoder.getLengthSize(self.len);
    }

    pub fn eql(a: Self, b: Self) bool {
        var res = a.attrs.items.len == b.attrs.items.len;
        if (!res) {
            return res;
        }
        var i: usize = 0;
        while (i < a.attrs.items.len) : (i += 1) {
            res = res and a.attrs.items[i].eql(b.attrs.items[i]);
        }
        return res;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}RelativeDistinguishedName", .{prefix});
        for (self.attrs.items) |a| {
            a.print(pf, prefix ++ " ");
        }
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) !ArrayList(u8) {
        var res = ArrayList(u8).init(allocator);
        for (self.attrs.items) |a| {
            const attr_str = try a.toString(allocator);
            defer attr_str.deinit();
            try res.appendSlice(attr_str.items);
            try res.appendSlice(",");
        }

        return res;
    }
};

const AttributeTypeAndValue = struct {
    attr_type: asn1.ObjectIdentifier,
    attr_value: []u8,
    len: usize = 0,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.attr_type.deinit();
        self.allocator.free(self.attr_value);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const len = try stream.getEndPos();
        const reader = stream.reader();

        const attr_type = try asn1.ObjectIdentifier.decode(reader, allocator);
        errdefer attr_type.deinit();

        const t_value = try reader.readByte(); // TODO: check value type defined by attr_type
        _ = t_value;
        const value_len = try asn1.Decoder.decodeLength(reader);
        var attr_value = try allocator.alloc(u8, value_len);
        errdefer allocator.free(attr_value);
        try reader.readNoEof(attr_value);

        return Self{
            .attr_type = attr_type,
            .attr_value = attr_value,
            .len = len,
            .allocator = allocator,
        };
    }

    pub fn length(self: Self) usize {
        return self.len + 1 + asn1.Decoder.getLengthSize(self.len);
    }

    pub fn eql(a: Self, b: Self) bool {
        var res = a.attr_type.eql(b.attr_type);
        res = res and std.mem.eql(u8, a.attr_value, b.attr_value);
        return res;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = asn1.Decoder.decodeOID(&oid, self.attr_type);
        if (OIDMap.getEntryByBytes(self.attr_type)) |e| {
            pf("{s}{s} = {s}", .{ prefix, e.display_name, self.attr_value });
        } else |e| {
            pf("{s}{s}({}) = {s} ", .{ prefix, oid[0..oid_len], e, self.attr_value });
        }
    }

    pub fn toString(self: Self, allocator: std.mem.Allocator) !ArrayList(u8) {
        var res = ArrayList(u8).init(allocator);
        if (OIDMap.getEntryByBytes(self.attr_type.id)) |e| {
            try res.appendSlice(e.display_name);
        } else |_| {
            try res.appendSlice(self.attr_type.id);
        }
        try res.appendSlice(" = ");
        try res.appendSlice(self.attr_value);

        return res;
    }
};

// Validity ::= SEQUENCE {
//      notBefore      Time,
//      notAfter       Time }
//
// Time ::= CHOICE {
//      utcTime        UTCTime,
//      generalTime    GeneralizedTime }
const Validity = struct {
    notBefore: Time,
    notAfter: Time,

    const Self = @This();

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        _ = allocator;
        const reader = stream.reader();
        const notBefore = try Time.decode(reader);
        const notAfter = try Time.decode(reader);
        return Self{
            .notBefore = notBefore,
            .notAfter = notAfter,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        self.notBefore.print(pf, prefix ++ " notBefore:");
        self.notAfter.print(pf, prefix ++ " notAfter:");
    }
};

const Time = struct {
    time_type: asn1.Tag,

    year: usize = 0,
    month: usize = 0,
    day: usize = 0,
    hour: usize = 0,
    minute: usize = 0,
    second: usize = 0,
    plus: bool = true,
    t_hour: usize = 0,
    t_minute: usize = 0,

    const Self = @This();

    pub fn decode(reader: anytype) !Self {
        const time_type = @intToEnum(asn1.Tag, try reader.readByte());
        var res = Self{
            .time_type = time_type,
        };
        const len = try asn1.Decoder.decodeLength(reader);
        _ = len;

        if (res.time_type == .UTCTime) {
            try res.decodeUTCTime(reader);
        } else if (res.time_type == .GeneralizedTime) {
            try res.decodeGeneralizedTime(reader);
        } else {
            std.log.warn("Unknown Tag {s}", .{@tagName(time_type)});
            unreachable;
        }

        return res;
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var out: [100]u8 = undefined;
        const len = self.writeToBuf(&out) catch 0;
        pf("{s}{s}", .{ prefix, out[0..len] });
    }

    // "YYMMDDhhmm[ss]Z" or "YYMMDDhhmm[ss](+|-)hhmm"
    fn decodeUTCTime(self: *Self, reader: anytype) !void {
        // TODO: check array length
        self.year = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        if (self.year >= 50) {
            self.year = self.year + 1900;
        } else {
            self.year = self.year + 2000;
        }
        self.month = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.day = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.hour = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.minute = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());

        // [ss]
        var s = try reader.readByte();
        if ('0' <= s and s <= '9') {
            self.second = c_to_i(s) * 10 + c_to_i(try reader.readByte());
            s = try reader.readByte();
        }

        //Z or (+|-)
        if (s == 'Z') {
            return;
        } else if (s == '+') {
            self.plus = true;
        } else if (s == '-') {
            self.plus = false;
        } else {
            return asn1.Decoder.Error.InvalidFormat;
        }

        // hhmm
        self.t_hour = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.t_minute = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());

        return;
    }

    // "YYYYMMDDhhmm[ss][.d]Z" or "YYYYMMDDhhmm[ss][.d](+|-)hhmm"
    fn decodeGeneralizedTime(self: *Self, reader: anytype) !void {
        // TODO: check array length
        self.year = c_to_i(try reader.readByte()) * 1000 + c_to_i(try reader.readByte()) * 100;
        self.year += c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte()) * 1;
        self.month = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.day = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.hour = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.minute = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());

        // [ss]
        var s = try reader.readByte();
        if ('0' <= s and s <= '9') {
            self.second = c_to_i(s) * 10 + c_to_i(try reader.readByte());
            s = try reader.readByte();
        }

        // .d
        if (s == '.') {
            s = try reader.readByte();
            if (s == 'd') {
                s = try reader.readByte();
            } else {
                return asn1.Decoder.Error.InvalidFormat;
            }
        }

        //Z or (+|-)
        if (s == 'Z') {
            return;
        } else if (s == '+') {
            self.plus = true;
        } else if (s == '-') {
            self.plus = false;
        } else {
            return asn1.Decoder.Error.InvalidFormat;
        }

        // hhmm
        self.t_hour = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());
        self.t_minute = c_to_i(try reader.readByte()) * 10 + c_to_i(try reader.readByte());

        return;
    }

    fn c_to_i(c: u8) usize {
        return c - '0';
    }

    pub fn writeToBuf(self: Self, out: []u8) !usize {
        var stream = io.fixedBufferStream(out);
        var plus_s = if (self.plus) "+" else "-";
        try std.fmt.format(stream.writer(), "{d:0>2}-{d:0>2}-{d:0>2}-{d:0>2}:{d:0>2}:{d:0>2}{s}{d:0>2}:{d:0>2}", .{ self.year, self.month, self.day, self.hour, self.minute, self.second, plus_s, self.t_hour, self.t_minute });

        return try stream.getPos();
    }
};

// SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }
const SubjectPublicKeyInfo = struct {
    algorithm: AlgorithmIdentifier,
    publicKey: PublicKey,

    const Error = error{
        UnsupportedCurve,
    };

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.algorithm.deinit();
        self.publicKey.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        const algorithm = try AlgorithmIdentifier.decode(reader, allocator);
        errdefer algorithm.deinit();

        var pub_key_type: PublicKeyType = undefined;
        if (std.mem.eql(u8, algorithm.algorithm.id, "1.2.840.113549.1.1.1")) {
            pub_key_type = PublicKeyType.rsa;
        } else if (std.mem.eql(u8, algorithm.algorithm.id, "1.2.840.10045.2.1")) {
            // RFC 5480 Section 2.1.1.1 Named Curve
            //ECParameters ::= CHOICE {
            //  namedCurve         OBJECT IDENTIFIER
            //  -- implicitCurve   NULL
            //  -- specifiedCurve  SpecifiedECDomain
            //}
            var ec_stream = io.fixedBufferStream(algorithm.parameters);

            // Currently, only 'namedCurve' is supported.
            const named_curve = try asn1.ObjectIdentifier.decode(ec_stream.reader(), allocator);
            defer named_curve.deinit();

            if (std.mem.eql(u8, named_curve.id, "1.2.840.10045.3.1.7")) {
                pub_key_type = PublicKeyType.secp256r1;
            } else if (std.mem.eql(u8, named_curve.id, "1.3.132.0.34")) {
                pub_key_type = PublicKeyType.secp384r1;
            } else {
                return Error.UnsupportedCurve;
            }
        } else {
            //currently, only accepts 'rsaEncryption'
            return asn1.Decoder.Error.InvalidFormat;
        }

        const t_key = @intToEnum(asn1.Tag, try reader.readByte());
        if (t_key != .BIT_STRING) {
            return asn1.Decoder.Error.InvalidType;
        }
        const key_len = try asn1.Decoder.decodeLength(reader);

        // the first byte of 'BIT STRING' specifies
        // the number of bits not used in the last of the octets
        const b = try reader.readByte();
        if (b != 0x00) {
            // TODO: handle this
            return asn1.Decoder.Error.InvalidFormat;
        }

        const pub_key = try PublicKey.decode(pub_key_type, reader, key_len - 1, allocator);

        return Self{
            .algorithm = algorithm,
            .publicKey = pub_key,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        const a = OIDMap.getEntryByBytes(self.algorithm.algorithm) catch OIDEntry{ .oid = "", .display_name = "Unexpected" };
        pf("{s}Algorithm: {s}", .{ prefix, a.display_name });
        pf("{s}RASPublicKey:", .{prefix});
        self.rsaPublicKey.print(pf, prefix ++ " ");
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

    const Error = error{
        UnsupportedFormat,
    };

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, len: usize) !Self {
        var buf: [100]u8 = undefined;
        // Currently, only uncompressed format supported.
        if (len != P256.PublicKey.uncompressed_sec1_encoded_length) {
            return Error.UnsupportedFormat;
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

    const Error = error{
        UnsupportedFormat,
    };

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, len: usize) !Self {
        var buf: [100]u8 = undefined;
        // Currently, only uncompressed format supported.
        if (len != P384.PublicKey.uncompressed_sec1_encoded_length) {
            return Error.UnsupportedFormat;
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

// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
const Extensions = struct {
    extensions: ArrayList(Extension),

    const Self = @This();

    pub fn deinit(self: Self) void {
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        const len = try stream.getEndPos();
        var extensions = ArrayList(Extension).init(allocator);
        errdefer extensions.deinit();

        var i: usize = 0;
        while (i < len) {
            const e = try Extension.decode(reader, allocator);
            try extensions.append(e);
            i += e.length();
        }

        return Self{
            .extensions = extensions,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}ExtensionNum={}", .{ prefix, self.extensions.items.len });
        for (self.extensions.items) |e| {
            e.print(pf, prefix ++ " ");
        }
    }
};

// Extension  ::=  SEQUENCE  {
//      extnID      OBJECT IDENTIFIER,
//      critical    BOOLEAN DEFAULT FALSE,
//      extnValue   OCTET STRING
//                  -- contains the DER encoding of an ASN.1 value
//                  -- corresponding to the extension type identified
//                  -- by extnID
//      }

const ExtensionType = enum {
    unknown,

    pub fn fromOID(oid: []const u8) ExtensionType {
        _ = oid;
        return .unknown;
    }
};

const Extension = struct {
    len: usize,
    oid: asn1.ObjectIdentifier,
    ciritcal: bool = false,
    value: ExtensionValue,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.oid.deinit();
        self.value.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        return try asn1.Decoder.decodeSEQUENCE(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: std.mem.Allocator) !Self {
        const reader = stream.reader();
        const len = try stream.getEndPos();

        const oid = try asn1.ObjectIdentifier.decode(reader, allocator);
        errdefer oid.deinit();

        var t_default = @intToEnum(asn1.Tag, try reader.readByte());
        if (t_default == .BOOLEAN) {
            const criti_len = try asn1.Decoder.decodeLength(reader);
            var i: usize = 0;
            while (i < criti_len) : (i += 1) {
                _ = try reader.readByte();
            }
            t_default = @intToEnum(asn1.Tag, try reader.readByte());
        }

        if (t_default != .OCTET_STRING) {
            return asn1.Decoder.Error.InvalidType;
        }
        const value_len = try asn1.Decoder.decodeLength(reader);

        const value = try ExtensionValue.decode(reader, oid.id, value_len, allocator);

        return Self{
            .len = len,
            .oid = oid,
            .value = value,
            .allocator = allocator,
        };
    }

    pub fn length(self: Self) usize {
        return self.len + 1 + asn1.Decoder.getLengthSize(self.len);
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = asn1.Decoder.decodeOID(&oid, self.oid);
        if (OIDMap.getEntryByBytes(self.oid)) |e| {
            pf("{s}ExtensionName = {s}", .{ prefix, e.display_name });
        } else |e| {
            pf("{s}ExtensionName = {s}({})", .{ prefix, oid[0..oid_len], e });
        }
    }
};

const ExtensionValue = union(ExtensionType) {
    unknown: Dummy,

    const Self = @This();

    pub fn deinit(self: Self) void {
        switch (self) {
            .unknown => |e| e.deinit(),
        }
    }

    pub fn decode(reader: anytype, oid: []const u8, len: usize, allocator: std.mem.Allocator) !Self {
        _ = oid;
        var i: usize = 0;
        while (i < len) : (i += 1) {
            _ = try reader.readByte();
        }

        return Self{ .unknown = Dummy{ .allocator = allocator } };
    }
};

pub const SignatureValue = struct {
    value: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.value);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .BIT_STRING) {
            return asn1.Decoder.Error.InvalidType;
        }
        const len = try asn1.Decoder.decodeLength(reader);

        // the first byte of 'BIT STRING' specifies
        // the number of bits not used in the last of the octets
        const b = try reader.readByte();
        if (b != 0x00) {
            // TODO: handle this
            return asn1.Decoder.Error.InvalidFormat;
        }

        var value = try allocator.alloc(u8, len - 1);
        errdefer allocator.free(value);

        // read all content
        try reader.readNoEof(value);

        return Self{
            .value = value,
            .allocator = allocator,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}Value = {}", .{ prefix, std.fmt.fmtSliceHexLower(self.value) });
    }
};

const Dummy = struct {
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(asn1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return asn1.Error.InvalidType;
        }
        const len = try asn1.Decoder.decodeLength(reader);
        _ = len;

        return Self{
            .allocator = allocator,
        };
    }
};

//from https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/
//Certificate:
//    Data:
//        Version: 3 (0x2)
//        Serial Number:
//            68:16:04:df:f3:34:f1:71:d8:0a:73:55:99:c1:41:72
//        Signature Algorithm: sha256WithRSAEncryption
//        Issuer: C = US, ST = Texas, L = Houston, O = SSL Corp, CN = SSL.com EV SSL Intermediate CA RSA R3
//        Validity
//            Not Before: Apr  1 00:58:33 2020 GMT
//            Not After : Jul 16 00:58:33 2021 GMT
//        Subject: C = US, ST = Texas, L = Houston, O = SSL Corp, serialNumber = NV20081614243, CN = www.ssl.com, businessCategory = Private Organization, jurisdictionST = Nevada, jurisdictionC = US
//        Subject Public Key Info:
//            Public Key Algorithm: rsaEncryption
//                Public-Key: (2048 bit)
//                Modulus:
//                    00:c7:85:e4:64:6d:bd:45:09:ce:f1:44:ab:2d:c0:
//                    ad:09:20:66:8a:63:cb:7b:25:b4:b6:6d:0d:9b:e9:
//                    82:09:0e:09:c7:b8:86:07:a8:1a:c2:51:5e:fd:a1:
//                    e9:62:92:4a:24:46:41:6f:72:fa:5a:2a:29:c5:1c:
//                    34:07:52:95:84:23:a4:54:11:16:26:48:28:37:3b:
//                    c5:a2:e3:6b:8e:71:5d:81:e5:96:9b:99:70:a4:c1:
//                    dc:58:e4:47:25:e7:50:5b:33:c5:27:19:da:00:19:
//                    b7:4d:9a:24:66:4a:64:e3:72:cf:a5:84:cc:60:e1:
//                    f1:58:ea:50:69:88:45:45:88:65:23:19:14:7e:eb:
//                    54:7a:ec:bc:fa:53:82:89:78:b3:5c:0a:6d:3b:43:
//                    01:58:28:19:a9:8b:4f:20:77:28:12:bd:17:54:c3:
//                    9e:49:a2:9a:de:76:3f:95:1a:d8:d4:90:1e:21:15:
//                    3e:06:41:7f:e0:86:de:bd:46:5a:b3:ff:ef:2e:d1:
//                    d1:10:92:1b:94:ba:e7:2b:a9:a9:66:48:6c:b8:dc:
//                    74:70:05:f0:ca:17:06:1e:58:ce:c2:3c:c7:79:7b:
//                    f7:4e:fa:dd:3c:b7:c3:db:8f:35:53:4e:fe:61:40:
//                    30:ac:11:82:15:d9:3e:c0:14:8f:52:70:dc:4c:92:
//                    1e:ff
//                Exponent: 65537 (0x10001)
//        X509v3 extensions:
//            X509v3 Authority Key Identifier:
//                BF:C1:5A:87:FF:28:FA:41:3D:FD:B7:4F:E4:1D:AF:A0:61:58:29:BD
//            Authority Information Access:
//                CA Issuers - URI:http://www.ssl.com/repository/SSLcom-SubCA-EV-SSL-RSA-4096-R3.crt
//                OCSP - URI:http://ocsps.ssl.com
//            X509v3 Subject Alternative Name:
//                DNS:www.ssl.com, DNS:ssl.com
//            X509v3 Certificate Policies:
//                Policy: 2.23.140.1.1
//                Policy: 1.2.616.1.113527.2.5.1.1
//                Policy: 1.3.6.1.4.1.38064.1.3.1.4
//                  CPS: https://www.ssl.com/repository
//            X509v3 Extended Key Usage:
//                TLS Web Client Authentication, TLS Web Server Authentication
//            X509v3 CRL Distribution Points:
//                Full Name:
//                  URI:http://crls.ssl.com/SSLcom-SubCA-EV-SSL-RSA-4096-R3.crl
//            X509v3 Subject Key Identifier:
//                00:C0:15:42:1A:CF:0E:6B:64:81:DA:A6:74:71:21:49:E9:C3:E1:8B
//            X509v3 Key Usage: critical
//                Digital Signature, Key Encipherment
//            CT Precertificate SCTs:
//                Signed Certificate Timestamp:
//                    Version   : v1 (0x0)
//                    Log ID    : F6:5C:94:2F:D1:77:30:22:14:54:18:08:30:94:56:8E:
//                                E3:4D:13:19:33:BF:DF:0C:2F:20:0B:CC:4E:F1:64:E3
//                    Timestamp : Apr  1 01:08:35.567 2020 GMT
//                    Extensions: none
//                    Signature : ecdsa-with-SHA256
//                                30:46:02:21:00:EB:17:A5:88:D4:7C:1A:4F:FA:DE:96:
//                                1D:9D:2F:EF:3B:1F:C2:8E:9B:44:30:4B:FC:F5:65:A1:
//                                D7:FB:AB:58:81:02:21:00:F2:06:B7:87:53:6E:43:CF:
//                                0B:A4:41:A4:50:8F:05:BA:E7:96:4B:92:A0:A7:C5:BC:
//                                50:59:18:8E:7A:68:FD:24
//                Signed Certificate Timestamp:
//                    Version   : v1 (0x0)
//                    Log ID    : 94:20:BC:1E:8E:D5:8D:6C:88:73:1F:82:8B:22:2C:0D:
//                                D1:DA:4D:5E:6C:4F:94:3D:61:DB:4E:2F:58:4D:A2:C2
//                    Timestamp : Apr  1 01:08:35.676 2020 GMT
//                    Extensions: none
//                    Signature : ecdsa-with-SHA256
//                                30:44:02:20:19:11:38:C3:36:9B:35:17:43:F2:4A:BF:
//                                BC:53:F7:B5:07:B6:86:6D:31:E6:75:EE:96:8C:21:E0:
//                                86:F0:DE:59:02:20:56:1B:FF:79:52:0E:99:52:EC:07:
//                                11:E2:BF:97:A5:6B:44:29:24:C5:58:99:8D:09:16:DC:
//                                5C:9B:AB:D9:11:81
//                Signed Certificate Timestamp:
//                    Version   : v1 (0x0)
//                    Log ID    : EE:C0:95:EE:8D:72:64:0F:92:E3:C3:B9:1B:C7:12:A3:
//                                69:6A:09:7B:4B:6A:1A:14:38:E6:47:B2:CB:ED:C5:F9
//                    Timestamp : Apr  1 01:08:35.699 2020 GMT
//                    Extensions: none
//                    Signature : ecdsa-with-SHA256
//                                30:44:02:20:7A:22:F6:E8:5A:CB:37:47:82:2D:57:08:
//                                DE:6E:5E:C3:DF:2A:05:69:7D:0D:0E:1D:9D:5A:18:60:
//                                C0:2C:6B:1F:02:20:09:FA:BB:A1:C3:02:E6:DF:B5:8E:
//                                2E:4C:E7:16:8B:98:F0:B8:23:E5:97:DC:8F:C0:46:45:
//                                92:CA:23:BB:21:07
//    Signature Algorithm: sha256WithRSAEncryption
//    Signature Value:
//        27:ae:ba:be:10:9e:e8:ea:9a:0b:92:ac:75:37:9a:17:fe:70:
//        9a:1d:cd:34:0d:aa:8e:2d:75:ef:8f:0f:5f:de:15:d6:00:10:
//        bb:bc:c4:5f:b4:02:de:f1:26:23:d8:8b:94:4a:c2:29:72:3f:
//        9e:af:fb:78:98:d9:3f:65:c3:b4:bc:4c:9d:38:d5:52:e1:68:
//        82:a9:d7:83:33:49:4c:d1:c9:ea:0e:02:c2:7b:40:00:cc:0a:
//        51:ca:50:39:47:51:4d:a9:36:ea:3c:f1:8e:a2:82:8b:d3:dd:
//        bb:27:c0:93:62:11:03:6a:ca:64:92:62:19:2d:c3:4b:5a:76:
//        ea:2a:8e:a5:e7:d3:a8:2c:56:2a:16:4d:50:d7:ca:c7:79:a8:
//        4c:78:b7:ab:08:80:87:0c:9b:6e:98:1f:5b:c9:a4:24:04:84:
//        aa:5c:db:2d:3b:81:19:24:94:16:51:b4:c8:d3:86:fe:1c:5f:
//        2c:8c:5f:bb:93:71:d4:fb:00:90:4f:b9:e8:9f:0a:85:76:e4:
//        9c:57:ba:8f:1d:e7:5d:fd:83:03:f5:04:07:bb:20:15:4f:c7:
//        6b:bb:28:df:d4:c8:e5:dd:66:6c:0c:7f:f4:e6:14:6c:03:74:
//        27:ec:c8:77:ff:66:c0:76:c0:b1:e8:cd:36:28:01:59:90:f4:
//        5a:14:d4:92:e0:71:58:af:a8:9f:af:36:50:61:1d:78:65:c4:
//        c7:4d:d2:3f:34:47:d3:73:e8:42:20:95:08:de:2b:73:bc:23:
//        f7:05:1a:6f:c1:f3:ee:36:84:e9:42:21:df:59:76:d9:dd:25:
//        c4:49:56:38:b4:c0:3d:2a:c1:eb:c2:69:f0:3d:8c:99:47:bf:
//        f8:ec:13:e2:3d:53:3e:9c:a4:2c:a1:b3:0f:a5:ac:57:71:52:
//        0a:94:e7:c6:b1:a9:e2:bc:f4:54:7e:36:8e:2a:d0:82:0e:f8:
//        98:b5:ac:92:ab:f6:79:12:07:40:6a:5e:8c:d5:9c:4d:58:07:
//        f2:8b:bd:d2:2c:b9:86:49:ba:a6:f6:a4:a9:2e:fb:3c:d3:ea:
//        05:30:1d:44:d9:bc:18:8d:3a:d5:cb:e0:dc:70:73:f2:93:ed:
//        6c:ce:49:dd:b0:3f:5d:10:23:c0:ca:83:8b:df:88:d0:ec:1d:
//        69:81:d5:ce:0a:8e:2e:a0:3a:00:39:b9:25:33:68:69:aa:fe:
//        fe:15:9d:c2:b9:52:bf:a7:f4:b6:df:9d:f2:dc:db:c2:79:7e:
//        df:c6:a2:d8:a7:33:20:e4:de:26:ab:17:5d:18:96:a7:0e:99:
//        e5:f5:b8:59:8a:6d:d8:bf:5e:8a:c6:96:40:a8:30:5d:d3:0f:
//        1f:2b:9a:9f:43:06:20:7f
test "X.509 decode" {
    // zig fmt: off
    const cert_bytes = [_]u8{
    0x30, 0x82, 0x07, 0xFD, 0x30, 0x82, 0x05, 0xE5, 0xA0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x10, 0x68, 0x16, 0x04, 0xDF, 0xF3, 0x34, 0xF1, 0x71, 0xD8, 0x0A, 0x73,
    0x55, 0x99, 0xC1, 0x41, 0x72, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x72, 0x31, 0x0B, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0E, 0x30, 0x0C,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31,
    0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x48, 0x6F, 0x75,
    0x73, 0x74, 0x6F, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A,
    0x0C, 0x08, 0x53, 0x53, 0x4C, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x31, 0x2E, 0x30,
    0x2C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x25, 0x53, 0x53, 0x4C, 0x2E, 0x63,
    0x6F, 0x6D, 0x20, 0x45, 0x56, 0x20, 0x53, 0x53, 0x4C, 0x20, 0x49, 0x6E, 0x74,
    0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x20,
    0x52, 0x53, 0x41, 0x20, 0x52, 0x33, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x30,
    0x34, 0x30, 0x31, 0x30, 0x30, 0x35, 0x38, 0x33, 0x33, 0x5A, 0x17, 0x0D, 0x32,
    0x31, 0x30, 0x37, 0x31, 0x36, 0x30, 0x30, 0x35, 0x38, 0x33, 0x33, 0x5A, 0x30,
    0x81, 0xBD, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x05,
    0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04,
    0x07, 0x0C, 0x07, 0x48, 0x6F, 0x75, 0x73, 0x74, 0x6F, 0x6E, 0x31, 0x11, 0x30,
    0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53, 0x53, 0x4C, 0x20, 0x43,
    0x6F, 0x72, 0x70, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13,
    0x0D, 0x4E, 0x56, 0x32, 0x30, 0x30, 0x38, 0x31, 0x36, 0x31, 0x34, 0x32, 0x34,
    0x33, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x77,
    0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1D, 0x30,
    0x1B, 0x06, 0x03, 0x55, 0x04, 0x0F, 0x0C, 0x14, 0x50, 0x72, 0x69, 0x76, 0x61,
    0x74, 0x65, 0x20, 0x4F, 0x72, 0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69,
    0x6F, 0x6E, 0x31, 0x17, 0x30, 0x15, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01,
    0x82, 0x37, 0x3C, 0x02, 0x01, 0x02, 0x0C, 0x06, 0x4E, 0x65, 0x76, 0x61, 0x64,
    0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
    0x37, 0x3C, 0x02, 0x01, 0x03, 0x13, 0x02, 0x55, 0x53, 0x30, 0x82, 0x01, 0x22,
    0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82,
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
    0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x03, 0x41, 0x30, 0x82, 0x03, 0x3D, 0x30,
    0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xBF,
    0xC1, 0x5A, 0x87, 0xFF, 0x28, 0xFA, 0x41, 0x3D, 0xFD, 0xB7, 0x4F, 0xE4, 0x1D,
    0xAF, 0xA0, 0x61, 0x58, 0x29, 0xBD, 0x30, 0x7F, 0x06, 0x08, 0x2B, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x73, 0x30, 0x71, 0x30, 0x4D, 0x06, 0x08,
    0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x41, 0x68, 0x74, 0x74,
    0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63,
    0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x6F, 0x72, 0x79,
    0x2F, 0x53, 0x53, 0x4C, 0x63, 0x6F, 0x6D, 0x2D, 0x53, 0x75, 0x62, 0x43, 0x41,
    0x2D, 0x45, 0x56, 0x2D, 0x53, 0x53, 0x4C, 0x2D, 0x52, 0x53, 0x41, 0x2D, 0x34,
    0x30, 0x39, 0x36, 0x2D, 0x52, 0x33, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x20, 0x06,
    0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x14, 0x68, 0x74,
    0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x73, 0x2E, 0x73, 0x73,
    0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04,
    0x18, 0x30, 0x16, 0x82, 0x0B, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E,
    0x63, 0x6F, 0x6D, 0x82, 0x07, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30,
    0x5F, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x58, 0x30, 0x56, 0x30, 0x07, 0x06,
    0x05, 0x67, 0x81, 0x0C, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x84, 0x68,
    0x01, 0x86, 0xF6, 0x77, 0x02, 0x05, 0x01, 0x01, 0x30, 0x3C, 0x06, 0x0C, 0x2B,
    0x06, 0x01, 0x04, 0x01, 0x82, 0xA9, 0x30, 0x01, 0x03, 0x01, 0x04, 0x30, 0x2C,
    0x30, 0x2A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16,
    0x1E, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E,
    0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70, 0x6F, 0x73,
    0x69, 0x74, 0x6F, 0x72, 0x79, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04,
    0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
    0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x48, 0x06,
    0x03, 0x55, 0x1D, 0x1F, 0x04, 0x41, 0x30, 0x3F, 0x30, 0x3D, 0xA0, 0x3B, 0xA0,
    0x39, 0x86, 0x37, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C,
    0x73, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x53, 0x53, 0x4C,
    0x63, 0x6F, 0x6D, 0x2D, 0x53, 0x75, 0x62, 0x43, 0x41, 0x2D, 0x45, 0x56, 0x2D,
    0x53, 0x53, 0x4C, 0x2D, 0x52, 0x53, 0x41, 0x2D, 0x34, 0x30, 0x39, 0x36, 0x2D,
    0x52, 0x33, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
    0x04, 0x16, 0x04, 0x14, 0x00, 0xC0, 0x15, 0x42, 0x1A, 0xCF, 0x0E, 0x6B, 0x64,
    0x81, 0xDA, 0xA6, 0x74, 0x71, 0x21, 0x49, 0xE9, 0xC3, 0xE1, 0x8B, 0x30, 0x0E,
    0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x05,
    0xA0, 0x30, 0x82, 0x01, 0x7D, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6,
    0x79, 0x02, 0x04, 0x02, 0x04, 0x82, 0x01, 0x6D, 0x04, 0x82, 0x01, 0x69, 0x01,
    0x67, 0x00, 0x77, 0x00, 0xF6, 0x5C, 0x94, 0x2F, 0xD1, 0x77, 0x30, 0x22, 0x14,
    0x54, 0x18, 0x08, 0x30, 0x94, 0x56, 0x8E, 0xE3, 0x4D, 0x13, 0x19, 0x33, 0xBF,
    0xDF, 0x0C, 0x2F, 0x20, 0x0B, 0xCC, 0x4E, 0xF1, 0x64, 0xE3, 0x00, 0x00, 0x01,
    0x71, 0x33, 0x48, 0x68, 0x6F, 0x00, 0x00, 0x04, 0x03, 0x00, 0x48, 0x30, 0x46,
    0x02, 0x21, 0x00, 0xEB, 0x17, 0xA5, 0x88, 0xD4, 0x7C, 0x1A, 0x4F, 0xFA, 0xDE,
    0x96, 0x1D, 0x9D, 0x2F, 0xEF, 0x3B, 0x1F, 0xC2, 0x8E, 0x9B, 0x44, 0x30, 0x4B,
    0xFC, 0xF5, 0x65, 0xA1, 0xD7, 0xFB, 0xAB, 0x58, 0x81, 0x02, 0x21, 0x00, 0xF2,
    0x06, 0xB7, 0x87, 0x53, 0x6E, 0x43, 0xCF, 0x0B, 0xA4, 0x41, 0xA4, 0x50, 0x8F,
    0x05, 0xBA, 0xE7, 0x96, 0x4B, 0x92, 0xA0, 0xA7, 0xC5, 0xBC, 0x50, 0x59, 0x18,
    0x8E, 0x7A, 0x68, 0xFD, 0x24, 0x00, 0x75, 0x00, 0x94, 0x20, 0xBC, 0x1E, 0x8E,
    0xD5, 0x8D, 0x6C, 0x88, 0x73, 0x1F, 0x82, 0x8B, 0x22, 0x2C, 0x0D, 0xD1, 0xDA,
    0x4D, 0x5E, 0x6C, 0x4F, 0x94, 0x3D, 0x61, 0xDB, 0x4E, 0x2F, 0x58, 0x4D, 0xA2,
    0xC2, 0x00, 0x00, 0x01, 0x71, 0x33, 0x48, 0x68, 0xDC, 0x00, 0x00, 0x04, 0x03,
    0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x19, 0x11, 0x38, 0xC3, 0x36, 0x9B, 0x35,
    0x17, 0x43, 0xF2, 0x4A, 0xBF, 0xBC, 0x53, 0xF7, 0xB5, 0x07, 0xB6, 0x86, 0x6D,
    0x31, 0xE6, 0x75, 0xEE, 0x96, 0x8C, 0x21, 0xE0, 0x86, 0xF0, 0xDE, 0x59, 0x02,
    0x20, 0x56, 0x1B, 0xFF, 0x79, 0x52, 0x0E, 0x99, 0x52, 0xEC, 0x07, 0x11, 0xE2,
    0xBF, 0x97, 0xA5, 0x6B, 0x44, 0x29, 0x24, 0xC5, 0x58, 0x99, 0x8D, 0x09, 0x16,
    0xDC, 0x5C, 0x9B, 0xAB, 0xD9, 0x11, 0x81, 0x00, 0x75, 0x00, 0xEE, 0xC0, 0x95,
    0xEE, 0x8D, 0x72, 0x64, 0x0F, 0x92, 0xE3, 0xC3, 0xB9, 0x1B, 0xC7, 0x12, 0xA3,
    0x69, 0x6A, 0x09, 0x7B, 0x4B, 0x6A, 0x1A, 0x14, 0x38, 0xE6, 0x47, 0xB2, 0xCB,
    0xED, 0xC5, 0xF9, 0x00, 0x00, 0x01, 0x71, 0x33, 0x48, 0x68, 0xF3, 0x00, 0x00,
    0x04, 0x03, 0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x7A, 0x22, 0xF6, 0xE8, 0x5A,
    0xCB, 0x37, 0x47, 0x82, 0x2D, 0x57, 0x08, 0xDE, 0x6E, 0x5E, 0xC3, 0xDF, 0x2A,
    0x05, 0x69, 0x7D, 0x0D, 0x0E, 0x1D, 0x9D, 0x5A, 0x18, 0x60, 0xC0, 0x2C, 0x6B,
    0x1F, 0x02, 0x20, 0x09, 0xFA, 0xBB, 0xA1, 0xC3, 0x02, 0xE6, 0xDF, 0xB5, 0x8E,
    0x2E, 0x4C, 0xE7, 0x16, 0x8B, 0x98, 0xF0, 0xB8, 0x23, 0xE5, 0x97, 0xDC, 0x8F,
    0xC0, 0x46, 0x45, 0x92, 0xCA, 0x23, 0xBB, 0x21, 0x07, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82,
    0x02, 0x01, 0x00, 0x27, 0xAE, 0xBA, 0xBE, 0x10, 0x9E, 0xE8, 0xEA, 0x9A, 0x0B,
    0x92, 0xAC, 0x75, 0x37, 0x9A, 0x17, 0xFE, 0x70, 0x9A, 0x1D, 0xCD, 0x34, 0x0D,
    0xAA, 0x8E, 0x2D, 0x75, 0xEF, 0x8F, 0x0F, 0x5F, 0xDE, 0x15, 0xD6, 0x00, 0x10,
    0xBB, 0xBC, 0xC4, 0x5F, 0xB4, 0x02, 0xDE, 0xF1, 0x26, 0x23, 0xD8, 0x8B, 0x94,
    0x4A, 0xC2, 0x29, 0x72, 0x3F, 0x9E, 0xAF, 0xFB, 0x78, 0x98, 0xD9, 0x3F, 0x65,
    0xC3, 0xB4, 0xBC, 0x4C, 0x9D, 0x38, 0xD5, 0x52, 0xE1, 0x68, 0x82, 0xA9, 0xD7,
    0x83, 0x33, 0x49, 0x4C, 0xD1, 0xC9, 0xEA, 0x0E, 0x02, 0xC2, 0x7B, 0x40, 0x00,
    0xCC, 0x0A, 0x51, 0xCA, 0x50, 0x39, 0x47, 0x51, 0x4D, 0xA9, 0x36, 0xEA, 0x3C,
    0xF1, 0x8E, 0xA2, 0x82, 0x8B, 0xD3, 0xDD, 0xBB, 0x27, 0xC0, 0x93, 0x62, 0x11,
    0x03, 0x6A, 0xCA, 0x64, 0x92, 0x62, 0x19, 0x2D, 0xC3, 0x4B, 0x5A, 0x76, 0xEA,
    0x2A, 0x8E, 0xA5, 0xE7, 0xD3, 0xA8, 0x2C, 0x56, 0x2A, 0x16, 0x4D, 0x50, 0xD7,
    0xCA, 0xC7, 0x79, 0xA8, 0x4C, 0x78, 0xB7, 0xAB, 0x08, 0x80, 0x87, 0x0C, 0x9B,
    0x6E, 0x98, 0x1F, 0x5B, 0xC9, 0xA4, 0x24, 0x04, 0x84, 0xAA, 0x5C, 0xDB, 0x2D,
    0x3B, 0x81, 0x19, 0x24, 0x94, 0x16, 0x51, 0xB4, 0xC8, 0xD3, 0x86, 0xFE, 0x1C,
    0x5F, 0x2C, 0x8C, 0x5F, 0xBB, 0x93, 0x71, 0xD4, 0xFB, 0x00, 0x90, 0x4F, 0xB9,
    0xE8, 0x9F, 0x0A, 0x85, 0x76, 0xE4, 0x9C, 0x57, 0xBA, 0x8F, 0x1D, 0xE7, 0x5D,
    0xFD, 0x83, 0x03, 0xF5, 0x04, 0x07, 0xBB, 0x20, 0x15, 0x4F, 0xC7, 0x6B, 0xBB,
    0x28, 0xDF, 0xD4, 0xC8, 0xE5, 0xDD, 0x66, 0x6C, 0x0C, 0x7F, 0xF4, 0xE6, 0x14,
    0x6C, 0x03, 0x74, 0x27, 0xEC, 0xC8, 0x77, 0xFF, 0x66, 0xC0, 0x76, 0xC0, 0xB1,
    0xE8, 0xCD, 0x36, 0x28, 0x01, 0x59, 0x90, 0xF4, 0x5A, 0x14, 0xD4, 0x92, 0xE0,
    0x71, 0x58, 0xAF, 0xA8, 0x9F, 0xAF, 0x36, 0x50, 0x61, 0x1D, 0x78, 0x65, 0xC4,
    0xC7, 0x4D, 0xD2, 0x3F, 0x34, 0x47, 0xD3, 0x73, 0xE8, 0x42, 0x20, 0x95, 0x08,
    0xDE, 0x2B, 0x73, 0xBC, 0x23, 0xF7, 0x05, 0x1A, 0x6F, 0xC1, 0xF3, 0xEE, 0x36,
    0x84, 0xE9, 0x42, 0x21, 0xDF, 0x59, 0x76, 0xD9, 0xDD, 0x25, 0xC4, 0x49, 0x56,
    0x38, 0xB4, 0xC0, 0x3D, 0x2A, 0xC1, 0xEB, 0xC2, 0x69, 0xF0, 0x3D, 0x8C, 0x99,
    0x47, 0xBF, 0xF8, 0xEC, 0x13, 0xE2, 0x3D, 0x53, 0x3E, 0x9C, 0xA4, 0x2C, 0xA1,
    0xB3, 0x0F, 0xA5, 0xAC, 0x57, 0x71, 0x52, 0x0A, 0x94, 0xE7, 0xC6, 0xB1, 0xA9,
    0xE2, 0xBC, 0xF4, 0x54, 0x7E, 0x36, 0x8E, 0x2A, 0xD0, 0x82, 0x0E, 0xF8, 0x98,
    0xB5, 0xAC, 0x92, 0xAB, 0xF6, 0x79, 0x12, 0x07, 0x40, 0x6A, 0x5E, 0x8C, 0xD5,
    0x9C, 0x4D, 0x58, 0x07, 0xF2, 0x8B, 0xBD, 0xD2, 0x2C, 0xB9, 0x86, 0x49, 0xBA,
    0xA6, 0xF6, 0xA4, 0xA9, 0x2E, 0xFB, 0x3C, 0xD3, 0xEA, 0x05, 0x30, 0x1D, 0x44,
    0xD9, 0xBC, 0x18, 0x8D, 0x3A, 0xD5, 0xCB, 0xE0, 0xDC, 0x70, 0x73, 0xF2, 0x93,
    0xED, 0x6C, 0xCE, 0x49, 0xDD, 0xB0, 0x3F, 0x5D, 0x10, 0x23, 0xC0, 0xCA, 0x83,
    0x8B, 0xDF, 0x88, 0xD0, 0xEC, 0x1D, 0x69, 0x81, 0xD5, 0xCE, 0x0A, 0x8E, 0x2E,
    0xA0, 0x3A, 0x00, 0x39, 0xB9, 0x25, 0x33, 0x68, 0x69, 0xAA, 0xFE, 0xFE, 0x15,
    0x9D, 0xC2, 0xB9, 0x52, 0xBF, 0xA7, 0xF4, 0xB6, 0xDF, 0x9D, 0xF2, 0xDC, 0xDB,
    0xC2, 0x79, 0x7E, 0xDF, 0xC6, 0xA2, 0xD8, 0xA7, 0x33, 0x20, 0xE4, 0xDE, 0x26,
    0xAB, 0x17, 0x5D, 0x18, 0x96, 0xA7, 0x0E, 0x99, 0xE5, 0xF5, 0xB8, 0x59, 0x8A,
    0x6D, 0xD8, 0xBF, 0x5E, 0x8A, 0xC6, 0x96, 0x40, 0xA8, 0x30, 0x5D, 0xD3, 0x0F,
    0x1F, 0x2B, 0x9A, 0x9F, 0x43, 0x06, 0x20, 0x7F
    };
    // zig fmt: on
    var cert_stream = io.fixedBufferStream(&cert_bytes);

    const cert = try Certificate.decode(cert_stream.reader(), std.testing.allocator);
    defer cert.deinit();
    const tbs = cert.tbs_certificate;
    try expectError(error.EndOfStream, cert_stream.reader().readByte());

    try expect(tbs.version == .v3);

    const serial_number_ans = [_]u8{ 0x68, 0x16, 0x04, 0xdf, 0xf3, 0x34, 0xf1, 0x71, 0xd8, 0x0a, 0x73, 0x55, 0x99, 0xc1, 0x41, 0x72 };
    try expect(std.mem.eql(u8, tbs.serial_number.serial.slice(), &serial_number_ans));

    try expect(std.mem.eql(u8, tbs.signature.algorithm.id, "1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
    const rd_seq = tbs.issuer.rdn_sequence.items;

    try expect(rd_seq.len == 5);
    try expect(std.mem.eql(u8, rd_seq[0].attrs.items[0].attr_value, "US"));
    try expect(std.mem.eql(u8, rd_seq[1].attrs.items[0].attr_value, "Texas"));
    try expect(std.mem.eql(u8, rd_seq[2].attrs.items[0].attr_value, "Houston"));
    try expect(std.mem.eql(u8, rd_seq[3].attrs.items[0].attr_value, "SSL Corp"));
    try expect(std.mem.eql(u8, rd_seq[4].attrs.items[0].attr_value, "SSL.com EV SSL Intermediate CA RSA R3"));

    var time_out: [100]u8 = undefined;
    var time_len = try tbs.validity.notBefore.writeToBuf(&time_out);
    try expect(std.mem.eql(u8, time_out[0..time_len], "2020-04-01-00:58:33+00:00"));
    time_len = try tbs.validity.notAfter.writeToBuf(&time_out);
    try expect(std.mem.eql(u8, time_out[0..time_len], "2021-07-16-00:58:33+00:00"));

    const rd_seq2 = tbs.subject.rdn_sequence.items;
    try expect(rd_seq2.len == 9);
    try expect(std.mem.eql(u8, rd_seq2[0].attrs.items[0].attr_value, "US"));
    try expect(std.mem.eql(u8, rd_seq2[1].attrs.items[0].attr_value, "Texas"));
    try expect(std.mem.eql(u8, rd_seq2[2].attrs.items[0].attr_value, "Houston"));
    try expect(std.mem.eql(u8, rd_seq2[3].attrs.items[0].attr_value, "SSL Corp"));
    try expect(std.mem.eql(u8, rd_seq2[4].attrs.items[0].attr_value, "NV20081614243"));
    try expect(std.mem.eql(u8, rd_seq2[5].attrs.items[0].attr_value, "www.ssl.com"));
    try expect(std.mem.eql(u8, rd_seq2[6].attrs.items[0].attr_value, "Private Organization"));
    try expect(std.mem.eql(u8, rd_seq2[7].attrs.items[0].attr_value, "Nevada"));
    try expect(std.mem.eql(u8, rd_seq2[8].attrs.items[0].attr_value, "US"));

    try expect(std.mem.eql(u8, tbs.subjectPublicKeyInfo.algorithm.algorithm.id, "1.2.840.113549.1.1.1")); // rsaEncryption

    const exts = tbs.extensions.?.extensions.items;
    try expect(exts.len == 9);

    try expect(std.mem.eql(u8, exts[0].oid.id, "2.5.29.35")); // authorityKeyIdentifier
    try expect(std.mem.eql(u8, exts[1].oid.id, "1.3.6.1.5.5.7.1.1")); // authorityInfoAccess
    try expect(std.mem.eql(u8, exts[2].oid.id, "2.5.29.17")); // subjectAltName
    try expect(std.mem.eql(u8, exts[3].oid.id, "2.5.29.32")); // certificatePolicies
    try expect(std.mem.eql(u8, exts[4].oid.id, "2.5.29.37")); // extKeyUsage
    try expect(std.mem.eql(u8, exts[5].oid.id, "2.5.29.31")); // cRLDistributionPoints
    try expect(std.mem.eql(u8, exts[6].oid.id, "2.5.29.14")); // subjectKeyIdentifier
    try expect(std.mem.eql(u8, exts[7].oid.id, "2.5.29.15")); // keyUsage
    try expect(std.mem.eql(u8, exts[8].oid.id, "1.3.6.1.4.1.11129.2.4.2")); // Extended validation certificates

    try expect(std.mem.eql(u8, cert.signature_algorithm.algorithm.id, "1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
    //std.log.warn("{}", .{std.fmt.fmtSliceHexLower(cert.signature_value.value)});

    // Below line causes compiler crash
    // https://github.com/ziglang/zig/issues/12373
    // TODO: FIX
    //cert.print(std.log.warn);
}

// openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Kyoto/L=Kyoto/CN=example.com' -newkey ec:<(openssl ecparam -name prime256v1) -nodes -sha256 -keyout prikey.pem -out cert.pem
//
// Certificate:
//     Data:
//         Version: 3 (0x2)
//         Serial Number:
//             10:3c:4c:84:2d:21:08:59:92:6c:e4:73:e0:b7:7a:12:52:36:a0:fc
//         Signature Algorithm: ecdsa-with-SHA256
//         Issuer: C = JP, ST = Kyoto, L = Kyoto, CN = example.com
//         Validity
//             Not Before: Sep  6 01:19:51 2022 GMT
//             Not After : Sep  6 01:19:51 2023 GMT
//         Subject: C = JP, ST = Kyoto, L = Kyoto, CN = example.com
//         Subject Public Key Info:
//             Public Key Algorithm: id-ecPublicKey
//                 Public-Key: (256 bit)
//                 pub:
//                     04:9d:92:3d:57:e4:b8:fc:b1:7b:92:1b:66:07:82:
//                     d7:5f:93:75:37:be:fb:08:dc:c5:2d:5b:10:65:cf:
//                     6a:c3:be:b2:0d:82:9f:47:fc:68:ed:b6:cf:fa:fa:
//                     d5:8c:2a:c8:ce:d2:b6:ed:1f:bd:08:d8:65:16:3a:
//                     3e:69:22:4a:84
//                 ASN1 OID: prime256v1
//                 NIST CURVE: P-256
//         X509v3 extensions:
//             X509v3 Subject Key Identifier:
//                 DC:3E:BB:5E:21:40:5E:C4:B9:2C:9A:27:66:37:10:B7:A9:97:98:A5
//             X509v3 Authority Key Identifier:
//                 DC:3E:BB:5E:21:40:5E:C4:B9:2C:9A:27:66:37:10:B7:A9:97:98:A5
//             X509v3 Basic Constraints: critical
//                 CA:TRUE
//     Signature Algorithm: ecdsa-with-SHA256
//     Signature Value:
//         30:45:02:21:00:b7:6f:3b:65:1a:79:53:82:8a:54:5c:2e:75:
//         48:0c:21:8b:85:8b:29:85:78:ef:2d:5a:ee:77:05:72:f3:b3:
//         b8:02:20:68:31:4b:91:7d:a9:71:0d:87:6a:b5:e9:4e:22:df:
//         ac:bb:be:b1:e1:bc:4c:f6:30:f8:3d:00:5c:9b:c3:7f:63
test "decode Certificate with ecdsa and secp256r1" {
    // zig fmt: off
    const cert_bytes = [_]u8{
    0x30, 0x82, 0x01, 0xdb, 0x30, 0x82, 0x01, 0x81, 0xa0, 0x03, 0x02, 0x01, 0x02,
    0x02, 0x14, 0x10, 0x3c, 0x4c, 0x84, 0x2d, 0x21, 0x08, 0x59, 0x92, 0x6c, 0xe4,
    0x73, 0xe0, 0xb7, 0x7a, 0x12, 0x52, 0x36, 0xa0, 0xfc, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x43, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30,
    0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x4b, 0x79, 0x6f, 0x74, 0x6f,
    0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x05, 0x4b, 0x79,
    0x6f, 0x74, 0x6f, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x30, 0x36, 0x30, 0x31, 0x31, 0x39,
    0x35, 0x31, 0x5a, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x39, 0x30, 0x36, 0x30, 0x31,
    0x31, 0x39, 0x35, 0x31, 0x5a, 0x30, 0x43, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x4a, 0x50, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0c, 0x05, 0x4b, 0x79, 0x6f, 0x74, 0x6f, 0x31, 0x0e, 0x30,
    0x0c, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x05, 0x4b, 0x79, 0x6f, 0x74, 0x6f,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x65, 0x78,
    0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x9d, 0x92, 0x3d,
    0x57, 0xe4, 0xb8, 0xfc, 0xb1, 0x7b, 0x92, 0x1b, 0x66, 0x07, 0x82, 0xd7, 0x5f,
    0x93, 0x75, 0x37, 0xbe, 0xfb, 0x08, 0xdc, 0xc5, 0x2d, 0x5b, 0x10, 0x65, 0xcf,
    0x6a, 0xc3, 0xbe, 0xb2, 0x0d, 0x82, 0x9f, 0x47, 0xfc, 0x68, 0xed, 0xb6, 0xcf,
    0xfa, 0xfa, 0xd5, 0x8c, 0x2a, 0xc8, 0xce, 0xd2, 0xb6, 0xed, 0x1f, 0xbd, 0x08,
    0xd8, 0x65, 0x16, 0x3a, 0x3e, 0x69, 0x22, 0x4a, 0x84, 0xa3, 0x53, 0x30, 0x51,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xdc, 0x3e,
    0xbb, 0x5e, 0x21, 0x40, 0x5e, 0xc4, 0xb9, 0x2c, 0x9a, 0x27, 0x66, 0x37, 0x10,
    0xb7, 0xa9, 0x97, 0x98, 0xa5, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0xdc, 0x3e, 0xbb, 0x5e, 0x21, 0x40, 0x5e, 0xc4,
    0xb9, 0x2c, 0x9a, 0x27, 0x66, 0x37, 0x10, 0xb7, 0xa9, 0x97, 0x98, 0xa5, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
    0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xb7, 0x6f, 0x3b,
    0x65, 0x1a, 0x79, 0x53, 0x82, 0x8a, 0x54, 0x5c, 0x2e, 0x75, 0x48, 0x0c, 0x21,
    0x8b, 0x85, 0x8b, 0x29, 0x85, 0x78, 0xef, 0x2d, 0x5a, 0xee, 0x77, 0x05, 0x72,
    0xf3, 0xb3, 0xb8, 0x02, 0x20, 0x68, 0x31, 0x4b, 0x91, 0x7d, 0xa9, 0x71, 0x0d,
    0x87, 0x6a, 0xb5, 0xe9, 0x4e, 0x22, 0xdf, 0xac, 0xbb, 0xbe, 0xb1, 0xe1, 0xbc,
    0x4c, 0xf6, 0x30, 0xf8, 0x3d, 0x00, 0x5c, 0x9b, 0xc3, 0x7f, 0x63
    };
    // zig fmt: on

    var cert_stream = io.fixedBufferStream(&cert_bytes);

    const cert = try Certificate.decode(cert_stream.reader(), std.testing.allocator);
    defer cert.deinit();

    const tbs = cert.tbs_certificate;
    try expectError(error.EndOfStream, cert_stream.reader().readByte());

    try expect(tbs.version == .v3);

    const serial_number_ans = [_]u8{ 0x10, 0x3c, 0x4c, 0x84, 0x2d, 0x21, 0x08, 0x59, 0x92, 0x6c, 0xe4, 0x73, 0xe0, 0xb7, 0x7a, 0x12, 0x52, 0x36, 0xa0, 0xfc };
    try expect(std.mem.eql(u8, tbs.serial_number.serial.slice(), &serial_number_ans));

    try expect(std.mem.eql(u8, tbs.signature.algorithm.id, (try OIDMap.getEntryByName("ecdsa-with-SHA256")).oid));
    const rd_seq = tbs.issuer.rdn_sequence.items;

    try expect(rd_seq.len == 4);
    try expect(std.mem.eql(u8, rd_seq[0].attrs.items[0].attr_value, "JP"));
    try expect(std.mem.eql(u8, rd_seq[1].attrs.items[0].attr_value, "Kyoto"));
    try expect(std.mem.eql(u8, rd_seq[2].attrs.items[0].attr_value, "Kyoto"));
    try expect(std.mem.eql(u8, rd_seq[3].attrs.items[0].attr_value, "example.com"));

    var time_out: [100]u8 = undefined;
    var time_len = try tbs.validity.notBefore.writeToBuf(&time_out);
    try expect(std.mem.eql(u8, time_out[0..time_len], "2022-09-06-01:19:51+00:00"));
    time_len = try tbs.validity.notAfter.writeToBuf(&time_out);
    try expect(std.mem.eql(u8, time_out[0..time_len], "2023-09-06-01:19:51+00:00"));

    const rd_seq2 = tbs.subject.rdn_sequence.items;
    try expect(rd_seq2.len == 4);
    try expect(std.mem.eql(u8, rd_seq2[0].attrs.items[0].attr_value, "JP"));
    try expect(std.mem.eql(u8, rd_seq2[1].attrs.items[0].attr_value, "Kyoto"));
    try expect(std.mem.eql(u8, rd_seq2[2].attrs.items[0].attr_value, "Kyoto"));
    try expect(std.mem.eql(u8, rd_seq2[3].attrs.items[0].attr_value, "example.com"));

    try expect(std.mem.eql(u8, tbs.subjectPublicKeyInfo.algorithm.algorithm.id, (try OIDMap.getEntryByName("id-ecPublicKey")).oid));

    const exts = tbs.extensions.?.extensions.items;
    try expect(exts.len == 3);

    try expect(std.mem.eql(u8, exts[0].oid.id, (try OIDMap.getEntryByName("subjectKeyIdentifier")).oid));
    try expect(std.mem.eql(u8, exts[1].oid.id, (try OIDMap.getEntryByName("authorityKeyIdentifier")).oid));
    try expect(std.mem.eql(u8, exts[2].oid.id, (try OIDMap.getEntryByName("id-ce-basicConstraints")).oid));

    try expect(std.mem.eql(u8, cert.signature_algorithm.algorithm.id, (try OIDMap.getEntryByName("ecdsa-with-SHA256")).oid));
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

test "PEM certificate 1" {
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIEGjCCAwICEQCbfgZJoz5iudXukEhxKe9XMA0GCSqGSIb3DQEBBQUAMIHKMQsw
        \\CQYDVQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZl
        \\cmlTaWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWdu
        \\LCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlT
        \\aWduIENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3Jp
        \\dHkgLSBHMzAeFw05OTEwMDEwMDAwMDBaFw0zNjA3MTYyMzU5NTlaMIHKMQswCQYD
        \\VQQGEwJVUzEXMBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlT
        \\aWduIFRydXN0IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAxOTk5IFZlcmlTaWduLCBJ
        \\bmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxRTBDBgNVBAMTPFZlcmlTaWdu
        \\IENsYXNzIDMgUHVibGljIFByaW1hcnkgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkg
        \\LSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMu6nFL8eB8aHm8b
        \\N3O9+MlrlBIwT/A2R/XQkQr1F8ilYcEWQE37imGQ5XYgwREGfassbqb1EUGO+i2t
        \\KmFZpGcmTNDovFJbcCAEWNF6yaRpvIMXZK0Fi7zQWM6NjPXr8EJJC52XJ2cybuGu
        \\kxUccLwgTS8Y3pKI6GyFVxEa6X7jJhFUokWWVYPKMIno3Nij7SqAP395ZVc+FSBm
        \\CC+Vk7+qRy+oRpfwEuL+wgorUeZ25rdGt+INpsyow0xZVYnm6FNcHOqd8GIWC6fJ
        \\Xwzw3sJ2zq/3avL6QaaiMxTJ5Xpj055iN9WFZZ4O5lMkdBteHRJTW8cs54NJOxWu
        \\imi5V5cCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAERSWwauSCPc/L8my/uRan2Te
        \\2yFPhpk0djZX3dAVL8WtfxUfN2JzPtTnX84XA9s1+ivbrmAJXx5fj267Cz3qWhMe
        \\DGBvtcC1IyIuBwvLqXTLR7sdwdela8wv0kL9Sd2nic9TutoAWii/gt/4uhMdUIaC
        \\/Y4wjylGsB49Ndo4YhYYSq3mtlFs3q9i6wHQHiT+eo8SGhJouPtmmRQURVyu565p
        \\F4ErWjfJXir0xuKhXFSbplQAz/DxwceYMBo7Nhbbo27q/a2ywtrvAkcTisDxszGt
        \\TxzhT5yvDwyd93gN2PQ1VoDat20Xj50egWTh/sVFuq1ruQp6Tk9LhO5L8X3dEQ==
        \\-----END CERTIFICATE-----
    ;

    const certs = try @import("cert.zig").convertPEMsToDERs(cert_pem, "CERTIFICATE", std.testing.allocator);
    defer {
        for (certs.items) |cert| {
            std.testing.allocator.free(cert);
        }
        certs.deinit();
    }

    try expect(certs.items.len == 1);
    var stream = io.fixedBufferStream(certs.items[0]);
    const cert_dec = try Certificate.decode(stream.reader(), std.testing.allocator);
    defer cert_dec.deinit();
}

test "PEM certificate 2" {
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIDcTCCAlmgAwIBAgIVAOYJ/nrqAGiM4CS07SAbH+9StETRMA0GCSqGSIb3DQEB
        \\BQUAMFAxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9LcmFqb3dhIEl6YmEgUm96bGlj
        \\emVuaW93YSBTLkEuMRcwFQYDVQQDDA5TWkFGSVIgUk9PVCBDQTAeFw0xMTEyMDYx
        \\MTEwNTdaFw0zMTEyMDYxMTEwNTdaMFAxCzAJBgNVBAYTAlBMMSgwJgYDVQQKDB9L
        \\cmFqb3dhIEl6YmEgUm96bGljemVuaW93YSBTLkEuMRcwFQYDVQQDDA5TWkFGSVIg
        \\Uk9PVCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxHL49ZMTml
        \\6g3wpYwrvQKkvc0Kc6oJ5sxfgmp1qZfluwbv88BdocHSiXlY8NzrVYzuWBp7J/9K
        \\ULMAoWoTIzOQ6C9TNm4YbA9A1jdX1wYNL5Akylf8W5L/I4BXhT9KnlI6x+a7BVAm
        \\nr/Ttl+utT/Asms2fRfEsF2vZPMxH4UFqOAhFjxTkmJWf2Cu4nvRQJHcttB+cEAo
        \\ag/hERt/+tzo4URz6x6r19toYmxx4FjjBkUhWQw1X21re//Hof2+0YgiwYT84zLb
        \\eqDqCOMOXxvH480yGDkh/QoazWX3U75HQExT/iJlwnu7I1V6HXztKIwCBjsxffbH
        \\3jOshCJtywcCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
        \\AQYwHQYDVR0OBBYEFFOSo33/gnbwM9TrkmdHYTMbaDsqMA0GCSqGSIb3DQEBBQUA
        \\A4IBAQA5UFWd5EL/pBviIMm1zD2JLUCpp0mJG7JkwznIOzawhGmFFaxGoxAhQBEg
        \\haP+E0KR66oAwVC6xe32QUVSHfWqWndzbODzLB8yj7WAR0cDM45ZngSBPBuFE3Wu
        \\GLJX9g100ETfIX+4YBR/4NR/uvTnpnd9ete7Whl0ZfY94yuu4xQqB5QFv+P7IXXV
        \\lTOjkjuGXEcyQAjQzbFaT9vIABSbeCXWBbjvOXukJy6WgAiclzGNSYprre8Ryydd
        \\fmjW9HIGwsIO03EldivvqEYL1Hv1w/Pur+6FUEOaL68PEIUovfgwIB2BAw+vZDuw
        \\cH0mX548PojGyg434cDjkSXa3mHF
        \\-----END CERTIFICATE-----
    ;

    const certs = try @import("cert.zig").convertPEMsToDERs(cert_pem, "CERTIFICATE", std.testing.allocator);
    defer {
        for (certs.items) |cert| {
            std.testing.allocator.free(cert);
        }
        certs.deinit();
    }

    try expect(certs.items.len == 1);
    var stream = io.fixedBufferStream(certs.items[0]);
    const cert_dec = try Certificate.decode(stream.reader(), std.testing.allocator);
    defer cert_dec.deinit();
}
