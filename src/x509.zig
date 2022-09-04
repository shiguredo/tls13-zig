const std = @import("std");
const io = std.io;
const expect = std.testing.expect;
const expectError = std.testing.expectError;

const BoundedArray = std.BoundedArray;
const ArrayList = std.ArrayList;

pub const ASN1 = struct {
    const Tag = enum(u8) {
        BOOLEAN = 0x01,
        INTEGER = 0x02,
        BIT_STRING = 0x03,
        OCTET_STRING = 0x04,
        NULL = 0x05,
        OBJECT_IDENTIFIER = 0x06,
        UTCTime = 0x17,
        GeneralizedTime = 0x18,
        SEQUENCE = 0x30, // SEQUENCE OF
        SET = 0x31, // SET OF
    };

    const Error = error{
        InvalidType,
        InvalidLength,
        InvalidFormat,
        TooLarge,
        NotAllDecoded,
    };

    fn decodeLength(reader: anytype) !u64 {
        const len = try reader.readByte();

        // Short form
        if (len & 0x80 == 0) {
            return len;
        }

        // Long form
        const len_size = len & 0x7F;

        // length field larger than u64 is ignored
        if (len_size > 4) {
            return Error.TooLarge;
        }

        var i: usize = 0;
        var res: u64 = 0;
        while (i < len_size) : (i += 1) {
            res = (res << 8) | (try reader.readByte());
        }

        return res;
    }

    fn getLengthSize(len: u64) usize {
        if (len < 0x80) {
            return 1;
        }

        var res: usize = 1;
        var cur = len;
        while (cur > 0) {
            cur = cur >> 8;
            res += 1;
        }

        return res;
    }

    // https://docs.microsoft.com/ja-jp/windows/win32/seccertenroll/about-object-identifier
    fn encodeOID(out: []u8, id: []const u8) !usize {
        var count: usize = 0;
        var out_idx: usize = 0;
        var start_idx: usize = 0;
        for (id) |c, i| {
            if (i != (id.len - 1) and c != '.') {
                continue;
            }
            var end_idx = i;
            if (i == (id.len - 1)) {
                end_idx = id.len;
            }

            const code = try std.fmt.parseInt(usize, id[start_idx..end_idx], 10);
            if (count == 0) {
                out[out_idx] = @intCast(u8, code);
                count += 1;
            } else if (count == 1) {
                out[out_idx] = @intCast(u8, out[out_idx] * 40 + code);
                out_idx += 1;
                count += 1;
            } else {
                out_idx += encodeOIDInt(out[out_idx..], code);
            }
            start_idx = i + 1;
        }

        return out_idx;
    }

    fn decodeOID(out: []u8, id: []const u8) usize {
        var start_idx: usize = 0;
        var cur_idx: usize = 0;
        var out_idx: usize = 0;
        while (start_idx < id.len) {
            if (start_idx == 0) {
                out[out_idx] = (id[0] / 40) + '0';
                out_idx += 1;
                out[out_idx] = '.';
                out_idx += 1;
                out[out_idx] = (id[0] % 40) + '0';
                out_idx += 1;
                start_idx += 1;
            } else {
                cur_idx = start_idx;
                while (id[cur_idx] > 0x80) {
                    cur_idx += 1;
                }
                cur_idx += 1;

                const code = decodeOIDInt(id[start_idx..cur_idx]);
                start_idx = cur_idx;

                const s = std.fmt.bufPrintIntToSlice(out[out_idx..], code, 10, .lower, .{});
                out_idx += s.len;
            }

            if (start_idx != id.len) {
                out[out_idx] = '.';
                out_idx += 1;
            }
        }

        return out_idx;
    }

    fn encodeOIDInt(out: []u8, i: usize) usize {
        var tmp: [100]u8 = undefined;
        var idx: usize = 0;
        var cur = i;
        while (cur > 0) {
            tmp[idx] = @intCast(u8, cur % 128);
            if (idx > 0) {
                tmp[idx] += 0x80;
            }
            cur = cur / 128;
            idx += 1;
        }

        var rev_i: usize = 0;
        while (rev_i < idx) : (rev_i += 1) {
            out[rev_i] = tmp[idx - rev_i - 1];
        }

        return idx;
    }

    fn decodeOIDInt(bytes: []const u8) usize {
        var res: usize = 0;
        for (bytes) |b, i| {
            res *= 128;
            if (i == bytes.len - 1) {
                res += b;
            } else {
                res += (b - 0x80);
            }
        }

        return res;
    }
};

const OIDEntry = struct {
    oid: []const u8,
    display_name: []const u8,
};

const OIDMap = struct {
    const map: [21]OIDEntry = [_]OIDEntry{
        OIDEntry{
            .oid = "2.5.4.3",
            .display_name = "CN",
        },
        OIDEntry{
            .oid = "2.5.4.5",
            .display_name = "S/N",
        },
        OIDEntry{
            .oid = "2.5.4.6",
            .display_name = "C",
        },
        OIDEntry{
            .oid = "2.5.4.7",
            .display_name = "L",
        },
        OIDEntry{
            .oid = "2.5.4.8",
            .display_name = "ST",
        },
        OIDEntry{
            .oid = "2.5.4.10",
            .display_name = "O",
        },
        OIDEntry{
            .oid = "2.5.4.15",
            .display_name = "businessCategory",
        },
        OIDEntry{
            .oid = "1.3.6.1.4.1.311.60.2.1.2",
            .display_name = "jurisdictionST",
        },
        OIDEntry{
            .oid = "1.3.6.1.4.1.311.60.2.1.3",
            .display_name = "jurisdictionC",
        },
        OIDEntry{
            .oid = "1.2.840.113549.1.1.1",
            .display_name = "rsaEncryption",
        },
        OIDEntry{
            .oid = "1.2.840.113549.1.1.11",
            .display_name = "sha256WithRSAEncryption",
        },
        OIDEntry{
            .oid = "2.5.29.35",
            .display_name = "authorityKeyIdentifier",
        },
        OIDEntry{
            .oid = "1.3.6.1.5.5.7.1.1",
            .display_name = "authorityInfoAccess",
        },
        OIDEntry{
            .oid = "2.5.29.17",
            .display_name = "subjectAltName",
        },
        OIDEntry{
            .oid = "2.5.29.32",
            .display_name = "certificatePolicies",
        },
        OIDEntry{
            .oid = "2.5.29.37",
            .display_name = "extKeyUsage",
        },
        OIDEntry{
            .oid = "2.5.29.31",
            .display_name = "cRLDistributionPoints",
        },
        OIDEntry{
            .oid = "2.5.29.14",
            .display_name = "subjectKeyIdentifier",
        },
        OIDEntry{
            .oid = "2.5.29.15",
            .display_name = "keyUsage",
        },
        OIDEntry{
            .oid = "1.3.6.1.4.1.11129.2.4.2",
            .display_name = "extendedValidationCertificates",
        },
        OIDEntry{
            .oid = "2.5.29.19",
            .display_name = "basicConstraints",
        },
    };

    const Error = error{
        NotFound,
    };

    const Self = @This();

    fn getEntryByBytes(oid_bytes: []const u8) !OIDEntry {
        var oid_c: [100]u8 = undefined;
        const oid_len = ASN1.decodeOID(&oid_c, oid_bytes);
        const oid = oid_c[0..oid_len];
        for (map) |e| {
            if (std.mem.eql(u8, oid, e.oid)) {
                return e;
            }
        }

        return Error.NotFound;
    }
};

test "encodeOIDInt & decodeOIDInt 1" {
    var res: [100]u8 = undefined;
    const len = ASN1.encodeOIDInt(&res, 311);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x82, 0x37 })));
    try expect(ASN1.decodeOIDInt(res[0..len]) == 311);
}

test "encodeOIDInt & decodeOIDInt 2" {
    var res: [100]u8 = undefined;
    const len = ASN1.encodeOIDInt(&res, 56789);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x83, 0xbb, 0x55 })));
    try expect(ASN1.decodeOIDInt(res[0..len]) == 56789);
}

test "encodeOIDInt & decodeOIDInt 3" {
    var res: [100]u8 = undefined;
    const len = ASN1.encodeOIDInt(&res, 113549);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x86, 0xf7, 0x0d })));
    try expect(ASN1.decodeOIDInt(res[0..len]) == 113549);
}

test "encodeOID" {
    var res: [100]u8 = undefined;
    const len = try ASN1.encodeOID(&res, "1.3.6.1.4.1.311.21.20");
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14 })));
}

test "decodeOID" {
    var res: [100]u8 = undefined;
    const len = ASN1.decodeOID(&res, &([_]u8{ 0x2b, 0x06, 0x1, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14 }));
    try expect(std.mem.eql(u8, res[0..len], "1.3.6.1.4.1.311.21.20"));
}

// From RFC5280 Section-4.1 (p. 16)
// Certificate  ::=  SEQUENCE  {
//      tbsCertificate       TBSCertificate,
//      signatureAlgorithm   AlgorithmIdentifier,
//      signatureValue       BIT STRING  }
pub const Certificate = struct {
    tbs_certificate: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: SignatureValue,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.tbs_certificate.deinit();
        self.signature_algorithm.deinit();
        self.signature_value.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        defer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        var content_stream = io.fixedBufferStream(content);
        var content_reader = content_stream.reader();

        const tbs_certificate = try TBSCertificate.decode(content_reader, allocator);
        errdefer tbs_certificate.deinit();

        const signature_algorithm = try AlgorithmIdentifier.decode(content_reader, allocator);
        errdefer signature_algorithm.deinit();

        const signature_value = try SignatureValue.decode(content_reader, allocator);
        errdefer signature_value.deinit();

        if ((try content_stream.getPos()) != (try content_stream.getEndPos())) {
            return ASN1.Error.NotAllDecoded;
        }

        return Self{
            .tbs_certificate = tbs_certificate,
            .signature_algorithm = signature_algorithm,
            .signature_value = signature_value,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void) void {
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
    extensions: Extensions,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.signature.deinit();
        self.issuer.deinit();
        self.subject.deinit();
        self.subjectPublicKeyInfo.deinit();
        self.extensions.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        defer allocator.free(content);

        // read all content
        try reader.readNoEof(content);
        var content_stream = io.fixedBufferStream(content);
        var content_reader = content_stream.reader();

        const v = try content_reader.readByte();
        if (v != 0xA0) { // [0] EXPLICIT
            return ASN1.Error.InvalidType;
        }
        const v_len = try content_reader.readByte();
        if (v_len != 0x03) { // length is assumed to be 3
            return ASN1.Error.InvalidLength;
        }
        const version = try Version.decode(content_reader);

        const serial_number = try CertificateSerialNumber.decode(content_reader);

        const signature = try AlgorithmIdentifier.decode(content_reader, allocator);
        errdefer signature.deinit();

        const issuer = try Name.decode(content_reader, allocator);
        errdefer issuer.deinit();

        const validity = try Validity.decode(content_reader);

        const subject = try Name.decode(content_reader, allocator);
        errdefer subject.deinit();

        const subjectPublicKeyInfo = try SubjectPublicKeyInfo.decode(content_reader, allocator);
        errdefer subjectPublicKeyInfo.deinit();

        if ((try content_reader.readByte()) != 0xA3) { // [3] EXPLICIT
            return ASN1.Error.InvalidType;
        }
        const exts_len = try ASN1.decodeLength(content_reader);
        _ = exts_len;

        const extensions = try Extensions.decode(content_reader, allocator);
        errdefer extensions.deinit();

        if ((try content_stream.getPos()) != (try content_stream.getEndPos())) {
            return ASN1.Error.NotAllDecoded;
        }

        return Self{
            .version = version,
            .serial_number = serial_number,
            .signature = signature,
            .issuer = issuer,
            .validity = validity,
            .subject = subject,
            .subjectPublicKeyInfo = subjectPublicKeyInfo,
            .extensions = extensions,
        };
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
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return ASN1.Error.InvalidType;
        }
        const t_len = try reader.readByte();
        if (t_len != 0x01) { // length is assumed to be 1(u8)
            return ASN1.Error.InvalidLength;
        }

        return @intToEnum(Self, try reader.readByte());
    }
};

const CertificateSerialNumber = struct {
    // RFC5280 4.1.2.2. Serial Number (p.19)
    // Certificate users MUST be able to handle serialNumber values up to 20 octets.
    serial: BoundedArray(u8, 20),

    const Self = @This();

    pub fn init(len: usize) !Self {
        return Self{
            .serial = try BoundedArray(u8, 20).init(len),
        };
    }

    pub fn decode(reader: anytype) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .INTEGER) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var res = try Self.init(len);

        try reader.readNoEof(res.serial.slice());
        return res;
    }
};

// AlgorithmIdentifier  ::=  SEQUENCE  {
//      algorithm               OBJECT IDENTIFIER,
//      parameters              ANY DEFINED BY algorithm OPTIONAL  }
pub const AlgorithmIdentifier = struct {
    algorithm: []u8,
    parameters: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.algorithm);
        self.allocator.free(self.parameters);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        defer allocator.free(content);

        // read all content
        try reader.readNoEof(content);
        var content_stream = io.fixedBufferStream(content);
        var content_reader = content_stream.reader();

        const t_algo = @intToEnum(ASN1.Tag, try content_reader.readByte());
        if (t_algo != .OBJECT_IDENTIFIER) {
            return ASN1.Error.InvalidType;
        }
        const algo_len = try ASN1.decodeLength(content_reader);
        var algorithm = try allocator.alloc(u8, algo_len);
        errdefer allocator.free(algorithm);

        try content_reader.readNoEof(algorithm);

        const t_param = @intToEnum(ASN1.Tag, try content_reader.readByte());
        _ = t_param; // Tag is defined by algorithm
        const param_len = try ASN1.decodeLength(content_reader);
        var parameters = try allocator.alloc(u8, param_len);
        errdefer allocator.free(parameters);

        try content_reader.readNoEof(parameters);

        if ((try content_stream.getPos()) != (try content_stream.getEndPos())) {
            return ASN1.Error.NotAllDecoded;
        }

        return Self{
            .algorithm = algorithm,
            .parameters = parameters,
            .allocator = allocator,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = ASN1.decodeOID(&oid, self.algorithm);
        if (OIDMap.getEntryByBytes(self.algorithm)) |e| {
            pf("{s}Algorithm = {s}", .{ prefix, e.display_name });
        } else |e| {
            pf("{s}Algorithm = {s}({})", .{ prefix, oid[0..oid_len], e });
        }
    }
};

// Name ::= CHOICE { -- only one possibility for now --
//   rdnSequence  RDNSequence }

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

// RelativeDistinguishedName ::=
//   SET SIZE (1..MAX) OF AttributeTypeAndValue

// AttributeTypeAndValue ::= SEQUENCE {
//   type     AttributeType,
//   value    AttributeValue }

// AttributeType ::= OBJECT IDENTIFIER

// AttributeValue ::= ANY -- DEFINED BY AttributeType

// DirectoryString ::= CHOICE {
//       teletexString           TeletexString (SIZE (1..MAX)),
//       printableString         PrintableString (SIZE (1..MAX)),
//       universalString         UniversalString (SIZE (1..MAX)),
//       utf8String              UTF8String (SIZE (1..MAX)),
//       bmpString               BMPString (SIZE (1..MAX)) }
const Name = struct {
    rdn_sequence: ArrayList(RelativeDistinguishedName),

    const Self = @This();

    pub fn deinit(self: Self) void {
        for (self.rdn_sequence.items) |r| {
            r.deinit();
        }
        self.rdn_sequence.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) { // currently RDNSequence(SEQUENCE OF) only
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var rdn_seq = ArrayList(RelativeDistinguishedName).init(allocator);
        errdefer rdn_seq.deinit();

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

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        for (self.rdn_sequence.items) |r| {
            r.print(pf, prefix ++ " ");
        }
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
        _ = self;
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SET) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        var attrs = ArrayList(AttributeTypeAndValue).init(allocator);
        var cur: usize = 0;
        while (cur < len) {
            const a = try AttributeTypeAndValue.decode(reader, allocator);
            try attrs.append(a);
            cur += a.length();
        }
        return Self{
            .attrs = attrs,
            .len = len,
        };
    }

    pub fn length(self: Self) usize {
        return self.len + 1 + ASN1.getLengthSize(self.len);
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}RelativeDistinguishedName", .{prefix});
        for (self.attrs.items) |a| {
            a.print(pf, prefix ++ " ");
        }
    }
};

const AttributeTypeAndValue = struct {
    attr_type: []u8,
    attr_value: []u8,
    len: usize = 0,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.attr_type);
        self.allocator.free(self.attr_value);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);

        const t_type = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t_type != .OBJECT_IDENTIFIER) {
            return ASN1.Error.InvalidType;
        }
        const type_len = try ASN1.decodeLength(reader);
        var attr_type = try allocator.alloc(u8, type_len);
        errdefer allocator.free(attr_type);
        try reader.readNoEof(attr_type);

        const t_value = try reader.readByte(); // TODO: check value type defined by attr_type
        _ = t_value;
        const value_len = try ASN1.decodeLength(reader);
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
        return self.len + 1 + ASN1.getLengthSize(self.len);
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = ASN1.decodeOID(&oid, self.attr_type);
        if (OIDMap.getEntryByBytes(self.attr_type)) |e| {
            pf("{s}{s} = {s}", .{ prefix, e.display_name, self.attr_value });
        } else |e| {
            pf("{s}{s}({}) = {s} ", .{ prefix, oid[0..oid_len], e, self.attr_value });
        }
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

    pub fn decode(reader: anytype) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        _ = len; //TODO: validate

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
    time_type: ASN1.Tag,

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
        const time_type = @intToEnum(ASN1.Tag, try reader.readByte());
        var res = Self{
            .time_type = time_type,
        };
        const len = try ASN1.decodeLength(reader);
        _ = len;

        if (res.time_type == .UTCTime) {
            try res.decodeUTCTime(reader);
        } else {
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
            return ASN1.Error.InvalidFormat;
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
    rsaPublicKey: RSAPublicKey,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.algorithm.deinit();
        self.rsaPublicKey.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        _ = len;

        const algorithm = try AlgorithmIdentifier.decode(reader, allocator);

        var oid_out: [100]u8 = undefined;
        const oid_len = ASN1.decodeOID(&oid_out, algorithm.algorithm);
        if (!std.mem.eql(u8, oid_out[0..oid_len], "1.2.840.113549.1.1.1")) {
            //currently, only accepts 'rsaEncryption'
            return ASN1.Error.InvalidFormat;
        }

        const t_key = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t_key != .BIT_STRING) {
            return ASN1.Error.InvalidType;
        }
        const key_len = try ASN1.decodeLength(reader);
        _ = key_len;

        // the first byte of 'BIT STRING' specifies
        // the number of bits not used in the last of the octets
        const b = try reader.readByte();
        if (b != 0x00) {
            // TODO: handle this
            return ASN1.Error.InvalidFormat;
        }

        const rsaPublicKey = try RSAPublicKey.decode(reader, allocator);

        return Self{
            .algorithm = algorithm,
            .rsaPublicKey = rsaPublicKey,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        const a = OIDMap.getEntryByBytes(self.algorithm.algorithm) catch OIDEntry{ .oid = "", .display_name = "Unexpected" };
        pf("{s}Algorithm: {s}", .{ prefix, a.display_name });
        pf("{s}RASPublicKey:", .{prefix});
        self.rsaPublicKey.print(pf, prefix ++ " ");
    }
};

// RFC3279 Section-2.3.1 (p. 8)
// RSAPublicKey ::= SEQUENCE {
//    modulus            INTEGER,    -- n
//    publicExponent     INTEGER  }  -- e
const RSAPublicKey = struct {
    modulus: []u8,
    publicExponent: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.modulus);
        self.allocator.free(self.publicExponent);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        _ = len;

        const t_modu = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t_modu != .INTEGER) {
            return ASN1.Error.InvalidType;
        }
        const modu_len = try ASN1.decodeLength(reader);
        var modulus = try allocator.alloc(u8, modu_len);
        errdefer allocator.free(modulus);

        try reader.readNoEof(modulus);

        const t_exp = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t_exp != .INTEGER) {
            return ASN1.Error.InvalidType;
        }
        const exp_len = try ASN1.decodeLength(reader);
        var publicExponent = try allocator.alloc(u8, exp_len);
        errdefer allocator.free(publicExponent);

        try reader.readNoEof(publicExponent);

        return Self{
            .modulus = modulus,
            .publicExponent = publicExponent,
            .allocator = allocator,
        };
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        pf("{s}Modulus:{}", .{ prefix, std.fmt.fmtSliceHexLower(self.modulus) });
        pf("{s}PublicExponent:{}", .{ prefix, std.fmt.fmtSliceHexLower(self.publicExponent) });
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
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
        _ = len;
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
    oid: []u8,
    ciritcal: bool = false,
    value: ExtensionValue,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.oid);
        self.value.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);

        if (@intToEnum(ASN1.Tag, try reader.readByte()) != .OBJECT_IDENTIFIER) {
            return ASN1.Error.InvalidType;
        }
        var oid_len = try ASN1.decodeLength(reader);
        var oid = try allocator.alloc(u8, oid_len);
        errdefer allocator.free(oid);

        try reader.readNoEof(oid);

        var t_default = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t_default == .BOOLEAN) {
            const criti_len = try ASN1.decodeLength(reader);
            _ = criti_len;
            var i: usize = 0;
            while (i < criti_len) : (i += 1) {
                _ = try reader.readByte();
            }
            t_default = @intToEnum(ASN1.Tag, try reader.readByte());
        }

        if (t_default != .OCTET_STRING) {
            return ASN1.Error.InvalidType;
        }
        const value_len = try ASN1.decodeLength(reader);

        var oid_out: [100]u8 = undefined;
        oid_len = ASN1.decodeOID(&oid_out, oid);
        const value = try ExtensionValue.decode(reader, oid_out[0..oid_len], value_len, allocator);

        return Self{
            .len = len,
            .oid = oid,
            .value = value,
            .allocator = allocator,
        };
    }

    pub fn length(self: Self) usize {
        return self.len + 1 + ASN1.getLengthSize(self.len);
    }

    pub fn print(self: Self, comptime pf: fn ([]const u8, anytype) void, comptime prefix: []const u8) void {
        var oid: [100]u8 = undefined;
        const oid_len = ASN1.decodeOID(&oid, self.oid);
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
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .BIT_STRING) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);

        // the first byte of 'BIT STRING' specifies
        // the number of bits not used in the last of the octets
        const b = try reader.readByte();
        if (b != 0x00) {
            // TODO: handle this
            return ASN1.Error.InvalidFormat;
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
        const t = @intToEnum(ASN1.Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return ASN1.Error.InvalidType;
        }
        const len = try ASN1.decodeLength(reader);
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
    const cert_bytes = [_]u8{ 0x30, 0x82, 0x07, 0xFD, 0x30, 0x82, 0x05, 0xE5, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x68, 0x16, 0x04, 0xDF, 0xF3, 0x34, 0xF1, 0x71, 0xD8, 0x0A, 0x73, 0x55, 0x99, 0xC1, 0x41, 0x72, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x72, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x48, 0x6F, 0x75, 0x73, 0x74, 0x6F, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53, 0x53, 0x4C, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x31, 0x2E, 0x30, 0x2C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x25, 0x53, 0x53, 0x4C, 0x2E, 0x63, 0x6F, 0x6D, 0x20, 0x45, 0x56, 0x20, 0x53, 0x53, 0x4C, 0x20, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x20, 0x52, 0x53, 0x41, 0x20, 0x52, 0x33, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x30, 0x34, 0x30, 0x31, 0x30, 0x30, 0x35, 0x38, 0x33, 0x33, 0x5A, 0x17, 0x0D, 0x32, 0x31, 0x30, 0x37, 0x31, 0x36, 0x30, 0x30, 0x35, 0x38, 0x33, 0x33, 0x5A, 0x30, 0x81, 0xBD, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x07, 0x48, 0x6F, 0x75, 0x73, 0x74, 0x6F, 0x6E, 0x31, 0x11, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x08, 0x53, 0x53, 0x4C, 0x20, 0x43, 0x6F, 0x72, 0x70, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x0D, 0x4E, 0x56, 0x32, 0x30, 0x30, 0x38, 0x31, 0x36, 0x31, 0x34, 0x32, 0x34, 0x33, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0B, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x0F, 0x0C, 0x14, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x20, 0x4F, 0x72, 0x67, 0x61, 0x6E, 0x69, 0x7A, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x31, 0x17, 0x30, 0x15, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x02, 0x0C, 0x06, 0x4E, 0x65, 0x76, 0x61, 0x64, 0x61, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x03, 0x13, 0x02, 0x55, 0x53, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xC7, 0x85, 0xE4, 0x64, 0x6D, 0xBD, 0x45, 0x09, 0xCE, 0xF1, 0x44, 0xAB, 0x2D, 0xC0, 0xAD, 0x09, 0x20, 0x66, 0x8A, 0x63, 0xCB, 0x7B, 0x25, 0xB4, 0xB6, 0x6D, 0x0D, 0x9B, 0xE9, 0x82, 0x09, 0x0E, 0x09, 0xC7, 0xB8, 0x86, 0x07, 0xA8, 0x1A, 0xC2, 0x51, 0x5E, 0xFD, 0xA1, 0xE9, 0x62, 0x92, 0x4A, 0x24, 0x46, 0x41, 0x6F, 0x72, 0xFA, 0x5A, 0x2A, 0x29, 0xC5, 0x1C, 0x34, 0x07, 0x52, 0x95, 0x84, 0x23, 0xA4, 0x54, 0x11, 0x16, 0x26, 0x48, 0x28, 0x37, 0x3B, 0xC5, 0xA2, 0xE3, 0x6B, 0x8E, 0x71, 0x5D, 0x81, 0xE5, 0x96, 0x9B, 0x99, 0x70, 0xA4, 0xC1, 0xDC, 0x58, 0xE4, 0x47, 0x25, 0xE7, 0x50, 0x5B, 0x33, 0xC5, 0x27, 0x19, 0xDA, 0x00, 0x19, 0xB7, 0x4D, 0x9A, 0x24, 0x66, 0x4A, 0x64, 0xE3, 0x72, 0xCF, 0xA5, 0x84, 0xCC, 0x60, 0xE1, 0xF1, 0x58, 0xEA, 0x50, 0x69, 0x88, 0x45, 0x45, 0x88, 0x65, 0x23, 0x19, 0x14, 0x7E, 0xEB, 0x54, 0x7A, 0xEC, 0xBC, 0xFA, 0x53, 0x82, 0x89, 0x78, 0xB3, 0x5C, 0x0A, 0x6D, 0x3B, 0x43, 0x01, 0x58, 0x28, 0x19, 0xA9, 0x8B, 0x4F, 0x20, 0x77, 0x28, 0x12, 0xBD, 0x17, 0x54, 0xC3, 0x9E, 0x49, 0xA2, 0x9A, 0xDE, 0x76, 0x3F, 0x95, 0x1A, 0xD8, 0xD4, 0x90, 0x1E, 0x21, 0x15, 0x3E, 0x06, 0x41, 0x7F, 0xE0, 0x86, 0xDE, 0xBD, 0x46, 0x5A, 0xB3, 0xFF, 0xEF, 0x2E, 0xD1, 0xD1, 0x10, 0x92, 0x1B, 0x94, 0xBA, 0xE7, 0x2B, 0xA9, 0xA9, 0x66, 0x48, 0x6C, 0xB8, 0xDC, 0x74, 0x70, 0x05, 0xF0, 0xCA, 0x17, 0x06, 0x1E, 0x58, 0xCE, 0xC2, 0x3C, 0xC7, 0x79, 0x7B, 0xF7, 0x4E, 0xFA, 0xDD, 0x3C, 0xB7, 0xC3, 0xDB, 0x8F, 0x35, 0x53, 0x4E, 0xFE, 0x61, 0x40, 0x30, 0xAC, 0x11, 0x82, 0x15, 0xD9, 0x3E, 0xC0, 0x14, 0x8F, 0x52, 0x70, 0xDC, 0x4C, 0x92, 0x1E, 0xFF, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x82, 0x03, 0x41, 0x30, 0x82, 0x03, 0x3D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xBF, 0xC1, 0x5A, 0x87, 0xFF, 0x28, 0xFA, 0x41, 0x3D, 0xFD, 0xB7, 0x4F, 0xE4, 0x1D, 0xAF, 0xA0, 0x61, 0x58, 0x29, 0xBD, 0x30, 0x7F, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01, 0x04, 0x73, 0x30, 0x71, 0x30, 0x4D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x41, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x6F, 0x72, 0x79, 0x2F, 0x53, 0x53, 0x4C, 0x63, 0x6F, 0x6D, 0x2D, 0x53, 0x75, 0x62, 0x43, 0x41, 0x2D, 0x45, 0x56, 0x2D, 0x53, 0x53, 0x4C, 0x2D, 0x52, 0x53, 0x41, 0x2D, 0x34, 0x30, 0x39, 0x36, 0x2D, 0x52, 0x33, 0x2E, 0x63, 0x72, 0x74, 0x30, 0x20, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x14, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6F, 0x63, 0x73, 0x70, 0x73, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x18, 0x30, 0x16, 0x82, 0x0B, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x07, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x5F, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x58, 0x30, 0x56, 0x30, 0x07, 0x06, 0x05, 0x67, 0x81, 0x0C, 0x01, 0x01, 0x30, 0x0D, 0x06, 0x0B, 0x2A, 0x84, 0x68, 0x01, 0x86, 0xF6, 0x77, 0x02, 0x05, 0x01, 0x01, 0x30, 0x3C, 0x06, 0x0C, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA9, 0x30, 0x01, 0x03, 0x01, 0x04, 0x30, 0x2C, 0x30, 0x2A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1E, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x65, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x6F, 0x72, 0x79, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x48, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04, 0x41, 0x30, 0x3F, 0x30, 0x3D, 0xA0, 0x3B, 0xA0, 0x39, 0x86, 0x37, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x63, 0x72, 0x6C, 0x73, 0x2E, 0x73, 0x73, 0x6C, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x53, 0x53, 0x4C, 0x63, 0x6F, 0x6D, 0x2D, 0x53, 0x75, 0x62, 0x43, 0x41, 0x2D, 0x45, 0x56, 0x2D, 0x53, 0x53, 0x4C, 0x2D, 0x52, 0x53, 0x41, 0x2D, 0x34, 0x30, 0x39, 0x36, 0x2D, 0x52, 0x33, 0x2E, 0x63, 0x72, 0x6C, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x00, 0xC0, 0x15, 0x42, 0x1A, 0xCF, 0x0E, 0x6B, 0x64, 0x81, 0xDA, 0xA6, 0x74, 0x71, 0x21, 0x49, 0xE9, 0xC3, 0xE1, 0x8B, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x05, 0xA0, 0x30, 0x82, 0x01, 0x7D, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xD6, 0x79, 0x02, 0x04, 0x02, 0x04, 0x82, 0x01, 0x6D, 0x04, 0x82, 0x01, 0x69, 0x01, 0x67, 0x00, 0x77, 0x00, 0xF6, 0x5C, 0x94, 0x2F, 0xD1, 0x77, 0x30, 0x22, 0x14, 0x54, 0x18, 0x08, 0x30, 0x94, 0x56, 0x8E, 0xE3, 0x4D, 0x13, 0x19, 0x33, 0xBF, 0xDF, 0x0C, 0x2F, 0x20, 0x0B, 0xCC, 0x4E, 0xF1, 0x64, 0xE3, 0x00, 0x00, 0x01, 0x71, 0x33, 0x48, 0x68, 0x6F, 0x00, 0x00, 0x04, 0x03, 0x00, 0x48, 0x30, 0x46, 0x02, 0x21, 0x00, 0xEB, 0x17, 0xA5, 0x88, 0xD4, 0x7C, 0x1A, 0x4F, 0xFA, 0xDE, 0x96, 0x1D, 0x9D, 0x2F, 0xEF, 0x3B, 0x1F, 0xC2, 0x8E, 0x9B, 0x44, 0x30, 0x4B, 0xFC, 0xF5, 0x65, 0xA1, 0xD7, 0xFB, 0xAB, 0x58, 0x81, 0x02, 0x21, 0x00, 0xF2, 0x06, 0xB7, 0x87, 0x53, 0x6E, 0x43, 0xCF, 0x0B, 0xA4, 0x41, 0xA4, 0x50, 0x8F, 0x05, 0xBA, 0xE7, 0x96, 0x4B, 0x92, 0xA0, 0xA7, 0xC5, 0xBC, 0x50, 0x59, 0x18, 0x8E, 0x7A, 0x68, 0xFD, 0x24, 0x00, 0x75, 0x00, 0x94, 0x20, 0xBC, 0x1E, 0x8E, 0xD5, 0x8D, 0x6C, 0x88, 0x73, 0x1F, 0x82, 0x8B, 0x22, 0x2C, 0x0D, 0xD1, 0xDA, 0x4D, 0x5E, 0x6C, 0x4F, 0x94, 0x3D, 0x61, 0xDB, 0x4E, 0x2F, 0x58, 0x4D, 0xA2, 0xC2, 0x00, 0x00, 0x01, 0x71, 0x33, 0x48, 0x68, 0xDC, 0x00, 0x00, 0x04, 0x03, 0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x19, 0x11, 0x38, 0xC3, 0x36, 0x9B, 0x35, 0x17, 0x43, 0xF2, 0x4A, 0xBF, 0xBC, 0x53, 0xF7, 0xB5, 0x07, 0xB6, 0x86, 0x6D, 0x31, 0xE6, 0x75, 0xEE, 0x96, 0x8C, 0x21, 0xE0, 0x86, 0xF0, 0xDE, 0x59, 0x02, 0x20, 0x56, 0x1B, 0xFF, 0x79, 0x52, 0x0E, 0x99, 0x52, 0xEC, 0x07, 0x11, 0xE2, 0xBF, 0x97, 0xA5, 0x6B, 0x44, 0x29, 0x24, 0xC5, 0x58, 0x99, 0x8D, 0x09, 0x16, 0xDC, 0x5C, 0x9B, 0xAB, 0xD9, 0x11, 0x81, 0x00, 0x75, 0x00, 0xEE, 0xC0, 0x95, 0xEE, 0x8D, 0x72, 0x64, 0x0F, 0x92, 0xE3, 0xC3, 0xB9, 0x1B, 0xC7, 0x12, 0xA3, 0x69, 0x6A, 0x09, 0x7B, 0x4B, 0x6A, 0x1A, 0x14, 0x38, 0xE6, 0x47, 0xB2, 0xCB, 0xED, 0xC5, 0xF9, 0x00, 0x00, 0x01, 0x71, 0x33, 0x48, 0x68, 0xF3, 0x00, 0x00, 0x04, 0x03, 0x00, 0x46, 0x30, 0x44, 0x02, 0x20, 0x7A, 0x22, 0xF6, 0xE8, 0x5A, 0xCB, 0x37, 0x47, 0x82, 0x2D, 0x57, 0x08, 0xDE, 0x6E, 0x5E, 0xC3, 0xDF, 0x2A, 0x05, 0x69, 0x7D, 0x0D, 0x0E, 0x1D, 0x9D, 0x5A, 0x18, 0x60, 0xC0, 0x2C, 0x6B, 0x1F, 0x02, 0x20, 0x09, 0xFA, 0xBB, 0xA1, 0xC3, 0x02, 0xE6, 0xDF, 0xB5, 0x8E, 0x2E, 0x4C, 0xE7, 0x16, 0x8B, 0x98, 0xF0, 0xB8, 0x23, 0xE5, 0x97, 0xDC, 0x8F, 0xC0, 0x46, 0x45, 0x92, 0xCA, 0x23, 0xBB, 0x21, 0x07, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x27, 0xAE, 0xBA, 0xBE, 0x10, 0x9E, 0xE8, 0xEA, 0x9A, 0x0B, 0x92, 0xAC, 0x75, 0x37, 0x9A, 0x17, 0xFE, 0x70, 0x9A, 0x1D, 0xCD, 0x34, 0x0D, 0xAA, 0x8E, 0x2D, 0x75, 0xEF, 0x8F, 0x0F, 0x5F, 0xDE, 0x15, 0xD6, 0x00, 0x10, 0xBB, 0xBC, 0xC4, 0x5F, 0xB4, 0x02, 0xDE, 0xF1, 0x26, 0x23, 0xD8, 0x8B, 0x94, 0x4A, 0xC2, 0x29, 0x72, 0x3F, 0x9E, 0xAF, 0xFB, 0x78, 0x98, 0xD9, 0x3F, 0x65, 0xC3, 0xB4, 0xBC, 0x4C, 0x9D, 0x38, 0xD5, 0x52, 0xE1, 0x68, 0x82, 0xA9, 0xD7, 0x83, 0x33, 0x49, 0x4C, 0xD1, 0xC9, 0xEA, 0x0E, 0x02, 0xC2, 0x7B, 0x40, 0x00, 0xCC, 0x0A, 0x51, 0xCA, 0x50, 0x39, 0x47, 0x51, 0x4D, 0xA9, 0x36, 0xEA, 0x3C, 0xF1, 0x8E, 0xA2, 0x82, 0x8B, 0xD3, 0xDD, 0xBB, 0x27, 0xC0, 0x93, 0x62, 0x11, 0x03, 0x6A, 0xCA, 0x64, 0x92, 0x62, 0x19, 0x2D, 0xC3, 0x4B, 0x5A, 0x76, 0xEA, 0x2A, 0x8E, 0xA5, 0xE7, 0xD3, 0xA8, 0x2C, 0x56, 0x2A, 0x16, 0x4D, 0x50, 0xD7, 0xCA, 0xC7, 0x79, 0xA8, 0x4C, 0x78, 0xB7, 0xAB, 0x08, 0x80, 0x87, 0x0C, 0x9B, 0x6E, 0x98, 0x1F, 0x5B, 0xC9, 0xA4, 0x24, 0x04, 0x84, 0xAA, 0x5C, 0xDB, 0x2D, 0x3B, 0x81, 0x19, 0x24, 0x94, 0x16, 0x51, 0xB4, 0xC8, 0xD3, 0x86, 0xFE, 0x1C, 0x5F, 0x2C, 0x8C, 0x5F, 0xBB, 0x93, 0x71, 0xD4, 0xFB, 0x00, 0x90, 0x4F, 0xB9, 0xE8, 0x9F, 0x0A, 0x85, 0x76, 0xE4, 0x9C, 0x57, 0xBA, 0x8F, 0x1D, 0xE7, 0x5D, 0xFD, 0x83, 0x03, 0xF5, 0x04, 0x07, 0xBB, 0x20, 0x15, 0x4F, 0xC7, 0x6B, 0xBB, 0x28, 0xDF, 0xD4, 0xC8, 0xE5, 0xDD, 0x66, 0x6C, 0x0C, 0x7F, 0xF4, 0xE6, 0x14, 0x6C, 0x03, 0x74, 0x27, 0xEC, 0xC8, 0x77, 0xFF, 0x66, 0xC0, 0x76, 0xC0, 0xB1, 0xE8, 0xCD, 0x36, 0x28, 0x01, 0x59, 0x90, 0xF4, 0x5A, 0x14, 0xD4, 0x92, 0xE0, 0x71, 0x58, 0xAF, 0xA8, 0x9F, 0xAF, 0x36, 0x50, 0x61, 0x1D, 0x78, 0x65, 0xC4, 0xC7, 0x4D, 0xD2, 0x3F, 0x34, 0x47, 0xD3, 0x73, 0xE8, 0x42, 0x20, 0x95, 0x08, 0xDE, 0x2B, 0x73, 0xBC, 0x23, 0xF7, 0x05, 0x1A, 0x6F, 0xC1, 0xF3, 0xEE, 0x36, 0x84, 0xE9, 0x42, 0x21, 0xDF, 0x59, 0x76, 0xD9, 0xDD, 0x25, 0xC4, 0x49, 0x56, 0x38, 0xB4, 0xC0, 0x3D, 0x2A, 0xC1, 0xEB, 0xC2, 0x69, 0xF0, 0x3D, 0x8C, 0x99, 0x47, 0xBF, 0xF8, 0xEC, 0x13, 0xE2, 0x3D, 0x53, 0x3E, 0x9C, 0xA4, 0x2C, 0xA1, 0xB3, 0x0F, 0xA5, 0xAC, 0x57, 0x71, 0x52, 0x0A, 0x94, 0xE7, 0xC6, 0xB1, 0xA9, 0xE2, 0xBC, 0xF4, 0x54, 0x7E, 0x36, 0x8E, 0x2A, 0xD0, 0x82, 0x0E, 0xF8, 0x98, 0xB5, 0xAC, 0x92, 0xAB, 0xF6, 0x79, 0x12, 0x07, 0x40, 0x6A, 0x5E, 0x8C, 0xD5, 0x9C, 0x4D, 0x58, 0x07, 0xF2, 0x8B, 0xBD, 0xD2, 0x2C, 0xB9, 0x86, 0x49, 0xBA, 0xA6, 0xF6, 0xA4, 0xA9, 0x2E, 0xFB, 0x3C, 0xD3, 0xEA, 0x05, 0x30, 0x1D, 0x44, 0xD9, 0xBC, 0x18, 0x8D, 0x3A, 0xD5, 0xCB, 0xE0, 0xDC, 0x70, 0x73, 0xF2, 0x93, 0xED, 0x6C, 0xCE, 0x49, 0xDD, 0xB0, 0x3F, 0x5D, 0x10, 0x23, 0xC0, 0xCA, 0x83, 0x8B, 0xDF, 0x88, 0xD0, 0xEC, 0x1D, 0x69, 0x81, 0xD5, 0xCE, 0x0A, 0x8E, 0x2E, 0xA0, 0x3A, 0x00, 0x39, 0xB9, 0x25, 0x33, 0x68, 0x69, 0xAA, 0xFE, 0xFE, 0x15, 0x9D, 0xC2, 0xB9, 0x52, 0xBF, 0xA7, 0xF4, 0xB6, 0xDF, 0x9D, 0xF2, 0xDC, 0xDB, 0xC2, 0x79, 0x7E, 0xDF, 0xC6, 0xA2, 0xD8, 0xA7, 0x33, 0x20, 0xE4, 0xDE, 0x26, 0xAB, 0x17, 0x5D, 0x18, 0x96, 0xA7, 0x0E, 0x99, 0xE5, 0xF5, 0xB8, 0x59, 0x8A, 0x6D, 0xD8, 0xBF, 0x5E, 0x8A, 0xC6, 0x96, 0x40, 0xA8, 0x30, 0x5D, 0xD3, 0x0F, 0x1F, 0x2B, 0x9A, 0x9F, 0x43, 0x06, 0x20, 0x7F };
    var cert_stream = io.fixedBufferStream(&cert_bytes);

    const cert = try Certificate.decode(cert_stream.reader(), std.testing.allocator);
    defer cert.deinit();
    const tbs = cert.tbs_certificate;
    try expectError(error.EndOfStream, cert_stream.reader().readByte());

    try expect(tbs.version == .v3);

    const serial_number_ans = [_]u8{ 0x68, 0x16, 0x04, 0xdf, 0xf3, 0x34, 0xf1, 0x71, 0xd8, 0x0a, 0x73, 0x55, 0x99, 0xc1, 0x41, 0x72 };
    try expect(std.mem.eql(u8, tbs.serial_number.serial.slice(), &serial_number_ans));

    var oid_out: [100]u8 = undefined;
    var oid_len = ASN1.decodeOID(&oid_out, tbs.signature.algorithm);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
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

    oid_len = ASN1.decodeOID(&oid_out, tbs.subjectPublicKeyInfo.algorithm.algorithm);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "1.2.840.113549.1.1.1")); // rsaEncryption

    const exts = tbs.extensions.extensions.items;
    try expect(exts.len == 9);

    oid_len = ASN1.decodeOID(&oid_out, exts[0].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.35")); // authorityKeyIdentifier
    oid_len = ASN1.decodeOID(&oid_out, exts[1].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "1.3.6.1.5.5.7.1.1")); // authorityInfoAccess
    oid_len = ASN1.decodeOID(&oid_out, exts[2].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.17")); // subjectAltName
    oid_len = ASN1.decodeOID(&oid_out, exts[3].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.32")); // certificatePolicies
    oid_len = ASN1.decodeOID(&oid_out, exts[4].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.37")); // extKeyUsage
    oid_len = ASN1.decodeOID(&oid_out, exts[5].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.31")); // cRLDistributionPoints
    oid_len = ASN1.decodeOID(&oid_out, exts[6].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.14")); // subjectKeyIdentifier
    oid_len = ASN1.decodeOID(&oid_out, exts[7].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "2.5.29.15")); // keyUsage
    oid_len = ASN1.decodeOID(&oid_out, exts[8].oid);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "1.3.6.1.4.1.11129.2.4.2")); // Extended validation certificates

    oid_len = ASN1.decodeOID(&oid_out, cert.signature_algorithm.algorithm);
    try expect(std.mem.eql(u8, oid_out[0..oid_len], "1.2.840.113549.1.1.11")); // sha256WithRSAEncryption
    //std.log.warn("{}", .{std.fmt.fmtSliceHexLower(cert.signature_value.value)});
    //cert.print(std.log.warn);
}
