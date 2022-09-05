const std = @import("std");
const log = std.log;
const io = std.io;
const assert = std.debug.assert;
const hmac = std.crypto.auth.hmac;

const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;
const Extension = @import("extension.zig").Extension;
const ExtensionType = @import("extension.zig").ExtensionType;
const Certificate = @import("certificate.zig").Certificate;
const CertificateVerify = @import("certificate.zig").CertificateVerify;
const ServerHello = @import("server_hello.zig").ServerHello;

pub const NamedGroup = enum(u16) {
    x25519 = 0x001D,
    x448 = 0x001e,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,

    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
};

pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x0,
};

pub const SessionID = struct {
    const MAX_SESSIONID_LENGTH = 32;

    session_id: BoundedArray(u8, MAX_SESSIONID_LENGTH),

    const Self = @This();

    pub fn init(len: usize) !Self {
        return Self{
            .session_id = try BoundedArray(u8, 32).init(len),
        };
    }

    pub fn decode(reader: anytype) !Self {
        var res = try Self.init(try reader.readIntBig(u8));
        _ = try reader.readAll(res.session_id.slice());

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u8, @intCast(u8, self.session_id.len));
        len += @sizeOf(u8);

        try writer.writeAll(self.session_id.slice());
        len += self.session_id.len;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8);
        len += self.session_id.len;

        return len;
    }

    pub fn print(self: Self) void {
        log.debug("SessionID", .{});
        log.debug("- id = {}", .{std.fmt.fmtSliceHexLower(&self.session_id.slice())});
    }
};

fn decodeCipherSuites(reader: anytype, suites: *ArrayList(CipherSuite)) !void {
    var len: usize = try reader.readIntBig(u16);
    assert(len % 2 == 0);

    var i: usize = 0;
    while (i < len) : (i += @sizeOf(u16)) {
        try suites.append(@intToEnum(CipherSuite, try reader.readIntBig(u16)));
    }

    assert(i == len);
}

pub fn encodeCipherSuites(writer: anytype, suites: ArrayList(CipherSuite)) !usize {
    var len: usize = 0;
    try writer.writeIntBig(u16, @intCast(u16, suites.items.len * @sizeOf(CipherSuite)));
    len += @sizeOf(u16);

    for (suites.items) |suite| {
        try writer.writeIntBig(u16, @enumToInt(suite));
        len += @sizeOf(CipherSuite);
    }

    return len;
}

pub fn decodeExtensions(reader: anytype, allocator: std.mem.Allocator, extensions: *ArrayList(Extension), ht: HandshakeType, is_hello_retry: bool) !void {
    const ext_len = try reader.readIntBig(u16);
    var i: usize = 0;
    while (i < ext_len) {
        var ext = try Extension.decode(reader, allocator, ht, is_hello_retry);
        try extensions.append(ext);
        i += ext.length();
    }
    assert(i == ext_len);
}

pub fn encodeExtensions(writer: anytype, extensions: ArrayList(Extension)) !usize {
    var ext_len: usize = 0;
    for (extensions.items) |ext| {
        ext_len += ext.length();
    }

    var len: usize = 0;
    try writer.writeIntBig(u16, @intCast(u16, ext_len));
    len += @sizeOf(u16);

    for (extensions.items) |ext| {
        len += try ext.encode(writer);
    }

    return len;
}

pub const ExtensionError = error{
    ExtensionNotFound,
};

pub const DecodeError = error{
    HashNotSpecified,
    NotAllDecoded,
};

pub fn getExtension(extensions: ArrayList(Extension), ext_type: ExtensionType) !Extension {
    for (extensions.items) |e| {
        if (e == ext_type) {
            return e;
        }
    }

    return ExtensionError.ExtensionNotFound;
}

pub const HandshakeType = enum(u8) {
    client_hello = 0x1,
    server_hello = 0x2,
    new_session_ticket = 0x04,
    encrypted_extensions = 0x8,
    certificate = 0xb,
    certificate_verify = 0xf,
    finished = 0x14,
};

pub const Handshake = union(HandshakeType) {
    client_hello: ClientHello,
    server_hello: ServerHello,
    new_session_ticket: NewSessionTicket,
    encrypted_extensions: EncryptedExtensions,
    certificate: Certificate,
    certificate_verify: CertificateVerify,
    finished: Finished,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator, comptime Hash: ?type) !Self {
        const t_raw = try reader.readIntBig(u8);
        const t = @intToEnum(HandshakeType, t_raw);
        const len = try reader.readIntBig(u24);
        _ = len; // TODO: check the length is less than readable size.
        switch (t) {
            HandshakeType.client_hello => return Self{ .client_hello = try ClientHello.decode(reader, allocator) },
            HandshakeType.server_hello => return Self{ .server_hello = try ServerHello.decode(reader, allocator) },
            HandshakeType.new_session_ticket => return Self{ .new_session_ticket = try NewSessionTicket.decode(reader, allocator) },
            HandshakeType.encrypted_extensions => return Self{ .encrypted_extensions = try EncryptedExtensions.decode(reader, allocator) },
            HandshakeType.certificate => return Self{ .certificate = try Certificate.decode(reader, allocator) },
            HandshakeType.certificate_verify => return Self{ .certificate_verify = try CertificateVerify.decode(reader, allocator) },
            HandshakeType.finished => if (Hash) |h| {
                _ = h;
                return Self{ .finished = try Finished.decode(reader, @import("crypto.zig").Hkdf.Sha256.hkdf) };
            } else {
                return DecodeError.HashNotSpecified;
            },
        }
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u8, @enumToInt(self));
        len += @sizeOf(HandshakeType);

        try writer.writeIntBig(u24, @intCast(u24, self.length() - (@sizeOf(u8) + 3)));
        len += 3;

        switch (self) {
            HandshakeType.client_hello => |e| len += try e.encode(writer),
            HandshakeType.server_hello => |e| len += try e.encode(writer),
            HandshakeType.finished => |e| len += try e.encode(writer),
            else => unreachable,
        }

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // type
        len += 3; // @sizeOf(u24) = 4, so that the length is directly specified;
        switch (self) {
            HandshakeType.client_hello => |e| len += e.length(),
            HandshakeType.server_hello => |e| len += e.length(),
            HandshakeType.encrypted_extensions => |e| len += e.length(),
            HandshakeType.certificate => |e| len += e.length(),
            HandshakeType.certificate_verify => |e| len += e.length(),
            HandshakeType.finished => |e| len += e.length(),
            else => unreachable,
        }

        return len;
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            HandshakeType.client_hello => |e| e.deinit(),
            HandshakeType.server_hello => |e| e.deinit(),
            HandshakeType.new_session_ticket => |e| e.deinit(),
            HandshakeType.encrypted_extensions => |e| e.deinit(),
            HandshakeType.certificate => |e| e.deinit(),
            HandshakeType.certificate_verify => |e| e.deinit(),
            HandshakeType.finished => |e| e.deinit(),
        }
    }
};

pub const ClientHello = struct {
    protocol_version: u16 = 0x0303, // TLS v1.2 version
    random: [32]u8 = [_]u8{0} ** 32,
    legacy_session_id: SessionID = undefined,
    cipher_suites: ArrayList(CipherSuite) = undefined,
    legacy_compression_methods: [2]u8 = [_]u8{ 0x1, 0x0 }, // "null" compression method
    extensions: ArrayList(Extension) = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .cipher_suites = ArrayList(CipherSuite).init(allocator),
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        res.protocol_version = try reader.readIntBig(u16);

        var readSize = try reader.readAll(&res.random);
        assert(readSize == res.random.len);

        res.legacy_session_id = try SessionID.decode(reader);

        try decodeCipherSuites(reader, &res.cipher_suites);

        const comp_len = try reader.readIntBig(u8);

        var i: usize = 0;
        while (i < comp_len) : (i += 1) {
            _ = try reader.readIntBig(u8); //TODO: store compression methods
        }

        try decodeExtensions(reader, allocator, &res.extensions, .client_hello, false);

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u16, self.protocol_version);
        len += @sizeOf(u16);

        try writer.writeAll(&self.random);
        len += self.random.len;

        len += try self.legacy_session_id.encode(writer);

        len += try encodeCipherSuites(writer, self.cipher_suites);

        try writer.writeAll(&self.legacy_compression_methods);
        len += self.legacy_compression_methods.len;

        len += try encodeExtensions(writer, self.extensions);

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(@TypeOf(self.protocol_version));
        len += self.random.len;
        len += self.legacy_session_id.length();

        len += @sizeOf(u16); // cipher_suites length
        len += self.cipher_suites.items.len * @sizeOf(CipherSuite);

        len += self.legacy_compression_methods.len;

        len += @sizeOf(u16); // extensions length
        for (self.extensions.items) |ext| {
            len += ext.length();
        }
        return len;
    }

    pub fn deinit(self: Self) void {
        self.cipher_suites.deinit();
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("=== ClientHello ===", .{});
        log.debug("ProtocolVersion = 0x{x:0>4}", .{self.protocol_version});
        log.debug("Random = {}", .{std.fmt.fmtSliceHexLower(&self.random)});
        self.legacy_session_id.print();
        self.cipher_suites.print();
        self.extensions.print();
    }
};

pub const EncryptedExtensions = struct {
    extensions: ArrayList(Extension) = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();
        try decodeExtensions(reader, allocator, &res.extensions, .server_hello, false);
        return res;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // extensions length
        for (self.extensions.items) |e| {
            len += e.length();
        }

        return len;
    }

    pub fn deinit(self: Self) void {
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }
};

pub const Finished = struct {
    const my_crypto = @import("crypto.zig");
    const MAX_DIGEST_LENGTH = my_crypto.Hkdf.MAX_DIGEST_LENGTH;

    hkdf: my_crypto.Hkdf,
    verify_data: BoundedArray(u8, MAX_DIGEST_LENGTH) = undefined,

    const Self = @This();

    pub fn init(hkdf: my_crypto.Hkdf) !Self {
        return Self{
            .hkdf = hkdf,
            .verify_data = try BoundedArray(u8, MAX_DIGEST_LENGTH).init(hkdf.digest_length),
        };
    }

    pub fn deinit(self: Self) void {
        _ = self;
    }

    pub fn decode(reader: anytype, hkdf: my_crypto.Hkdf) !Self {
        var res = try Self.init(hkdf);
        _ = try reader.readAll(res.verify_data.slice());

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        try writer.writeAll(self.verify_data.slice());
        return self.verify_data.len;
    }

    pub fn length(self: Self) usize {
        return self.verify_data.len;
    }

    pub fn fromMessageBytes(m: []const u8, secret: []const u8, hkdf: my_crypto.Hkdf) !Self {
        var res = try Self.init(hkdf);
        var hash: [MAX_DIGEST_LENGTH]u8 = undefined;
        var digest: [MAX_DIGEST_LENGTH]u8 = undefined;
        hkdf.hash(&hash, m);
        hkdf.create(&digest, &hash, secret);
        std.mem.copy(u8, res.verify_data.slice(), digest[0..hkdf.digest_length]);

        return res;
    }

    pub fn verify(self: Self, m: []const u8, secret: []const u8) bool {
        var hash: [MAX_DIGEST_LENGTH]u8 = undefined;
        var digest: [MAX_DIGEST_LENGTH]u8 = undefined;
        self.hkdf.hash(&hash, m);
        self.hkdf.create(&digest, &hash, secret);

        return std.mem.eql(u8, digest[0..self.hkdf.digest_length], self.verify_data.slice());
    }
};

pub const NewSessionTicket = struct {
    const MAX_TICKET_NONCE_LENGTH = 256;

    ticket_lifetime: u32 = undefined,
    ticket_age_add: u32 = undefined,
    ticket_nonce: BoundedArray(u8, MAX_TICKET_NONCE_LENGTH) = undefined,
    ticket: []u8 = undefined,
    extensions: ArrayList(Extension) = undefined,

    allocator: std.mem.Allocator = undefined,

    const Self = @This();
    fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .extensions = ArrayList(Extension).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = try Self.init(allocator);

        res.ticket_lifetime = try reader.readIntBig(u32);
        res.ticket_age_add = try reader.readIntBig(u32);
        const nonce_len = try reader.readIntBig(u8);
        res.ticket_nonce = try BoundedArray(u8, MAX_TICKET_NONCE_LENGTH).init(nonce_len);
        try reader.readNoEof(res.ticket_nonce.slice());

        const ticket_len = try reader.readIntBig(u16);
        res.ticket = try allocator.alloc(u8, ticket_len);
        try reader.readNoEof(res.ticket);

        try decodeExtensions(reader, allocator, &res.extensions, .new_session_ticket, false);

        return res;
    }

    pub fn deinit(self: Self) void {
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }
};

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "ClientHello decode & encode" {
    const recv_data = [_]u8{ 0x03, 0x03, 0xf0, 0x5d, 0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4, 0x24, 0x9d, 0x4a, 0x69, 0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec, 0xc7, 0x8f, 0xd0, 0x25, 0xc6, 0xeb, 0xe1, 0x33, 0x20, 0x67, 0x7e, 0xb6, 0x52, 0xad, 0x12, 0x51, 0xda, 0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf, 0xca, 0xa8, 0xc5, 0xfe, 0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83, 0x35, 0xae, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00, 0x45, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51, 0x50, 0xa9, 0x0a, 0x47, 0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc, 0xf0, 0xce, 0x0d, 0xee, 0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7, 0xd3, 0x93, 0x64, 0x2f, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try ClientHello.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.protocol_version == 0x0303);
    try expect(res.cipher_suites.items.len == 1);
    try expect(res.cipher_suites.items[0] == .TLS_AES_256_GCM_SHA384);

    try expect(res.extensions.items.len == 4);
    try expect(res.extensions.items[0] == .supported_versions);

    try expect(res.extensions.items[1] == .supported_groups);
    const sg = res.extensions.items[1].supported_groups;
    try expect(sg.groups.items.len == 2);
    try expect(sg.groups.items[0] == .x25519);
    try expect(sg.groups.items[1] == .secp256r1);

    try expect(res.extensions.items[2] == .key_share);
    const ks = res.extensions.items[2].key_share;
    try expect(ks.entries.items.len == 1);
    try expect(ks.entries.items[0] == .x25519);

    try expect(res.extensions.items[3] == .signature_algorithms);
    const sa = res.extensions.items[3].signature_algorithms;
    try expect(sa.algos.items.len == 2);
    try expect(sa.algos.items[0] == .ecdsa_secp256r1_sha256);
    try expect(sa.algos.items[1] == .ed25519);

    var send_bytes: [1000]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &recv_data));
    try expect(write_len == res.length());
}

test "EncryptedExtensions decode" {
    const recv_data = [_]u8{ 0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Handshake.decode(readStream.reader(), std.testing.allocator, null);
    defer res.deinit();
}

test "Finished decode" {
    const recv_data = [_]u8{ 0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Handshake.decode(readStream.reader(), std.testing.allocator, std.crypto.hash.sha2.Sha256);
    defer res.deinit();

    // check all data was read.
    try expectError(error.EndOfStream, readStream.reader().readByte());

    try expect(res == .finished);
}
