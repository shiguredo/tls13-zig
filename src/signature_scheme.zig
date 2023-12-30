const std = @import("std");
const log = @import("log.zig");
const utils = @import("utils.zig");
const io = std.io;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;

/// RFC8446 Seection 4.2.3 Signature Algorithms
///
// enum {
//     /* RSASSA-PKCS1-v1_5 algorithms */
//     rsa_pkcs1_sha256(0x0401),
//     rsa_pkcs1_sha384(0x0501),
//     rsa_pkcs1_sha512(0x0601),

//     /* ECDSA algorithms */
//     ecdsa_secp256r1_sha256(0x0403),
//     ecdsa_secp384r1_sha384(0x0503),
//     ecdsa_secp521r1_sha512(0x0603),

//     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
//     rsa_pss_rsae_sha256(0x0804),
//     rsa_pss_rsae_sha384(0x0805),
//     rsa_pss_rsae_sha512(0x0806),

//     /* EdDSA algorithms */
//     ed25519(0x0807),
//     ed448(0x0808),

//     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
//     rsa_pss_pss_sha256(0x0809),
//     rsa_pss_pss_sha384(0x080a),
//     rsa_pss_pss_sha512(0x080b),

//     /* Legacy algorithms */
//     rsa_pkcs1_sha1(0x0201),
//     ecdsa_sha1(0x0203),

//     /* Reserved Code Points */
//     private_use(0xFE00..0xFFFF),
//     (0xFFFF)
// } SignatureScheme;
///
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
};

/// RFC8446 Seection 4.2.3 Signature Algorithms
///
/// struct {
///     SignatureScheme supported_signature_algorithms<2..2^16-2>;
/// } SignatureSchemeList;
///
pub const SignatureSchemeList = struct {
    algos: ArrayList(SignatureScheme),
    grease_length: usize = 0,

    const Self = @This();

    const Error = error{
        InvalidAlgorithmsLength,
    };

    /// initialize SignatureSchemeList.
    /// @param allocator allcator to allocate ArrayList.
    /// @return initialized SignatureSchemeList.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .algos = ArrayList(SignatureScheme).init(allocator),
        };
    }

    /// decode SignatureSchemeList reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator to initialize SignatureSchemeList.
    /// @return decoded SignatureSchemeList.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        // Decoding SignatureSchemes.
        const algos_len = try reader.readInt(u16, .big);
        if (algos_len % 2 != 0) {
            return Error.InvalidAlgorithmsLength;
        }
        var i: usize = 0;
        while (i < algos_len) : (i += 2) {
            const ss_raw = try reader.readInt(u16, .big);
            const ss = utils.intToEnum(SignatureScheme, ss_raw) catch {
                log.warn("Unknown SignatureScheme 0x{x:0>4}", .{ss_raw});
                res.grease_length += 2;
                continue;
            };
            try res.algos.append(ss);
        }

        return res;
    }

    /// encode SignatureSchemeList writing to io.Writer.
    /// @param self   SignatureSchemeList to be encoded.
    /// @param writer io.Writer to write encoded SignatureSchemeList.
    /// @return length of encoded SignatureSchemeList.
    pub fn encode(self: Self, writer: anytype) !usize {
        // Encoding SignatureSchemes.
        var len: usize = 0;
        try writer.writeInt(u16, @as(u16, @intCast(self.algos.items.len * @sizeOf(SignatureScheme))), .big);
        len += @sizeOf(u16);
        for (self.algos.items) |e| {
            try writer.writeInt(u16, @intFromEnum(e), .big);
            len += @sizeOf(SignatureScheme);
        }

        return len;
    }

    /// get the length of encoded SignatureSchemeList.
    /// @param self the target SignatureSchemeList.
    /// @return length of encoded SignatureSchemeList.
    pub fn length(self: Self) usize {
        var len: usize = self.grease_length;
        len += @sizeOf(u16); // supported groups length
        len += self.algos.items.len * @sizeOf(SignatureScheme);
        return len;
    }

    /// deinitialize SignatureSchemeList.
    /// @param self SignatureSchemeList to be deinitialized.
    pub fn deinit(self: Self) void {
        self.algos.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("Extension: SignatureAlgrotihms", .{});
        for (self.algos.items) |algo| {
            log.debug("- {s}(0x{x:0>4})", .{ @tagName(algo), @intFromEnum(algo) });
        }
    }
};

const expect = std.testing.expect;

test "SignatureSchemeList decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08,
    0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
    0x05, 0x01, 0x06, 0x01
    };
    // zif fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const res = try SignatureSchemeList.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.algos.items.len == 14);
    try expect(res.algos.items[0] == .ecdsa_secp256r1_sha256);
    try expect(res.algos.items[1] == .ecdsa_secp384r1_sha384);
    try expect(res.algos.items[2] == .ecdsa_secp521r1_sha512);
    try expect(res.algos.items[3] == .ed25519);
    try expect(res.algos.items[4] == .ed448);
    try expect(res.algos.items[5] == .rsa_pss_pss_sha256);
    try expect(res.algos.items[6] == .rsa_pss_pss_sha384);
    try expect(res.algos.items[7] == .rsa_pss_pss_sha512);
    try expect(res.algos.items[8] == .rsa_pss_rsae_sha256);
    try expect(res.algos.items[9] == .rsa_pss_rsae_sha384);
    try expect(res.algos.items[10] == .rsa_pss_rsae_sha512);
    try expect(res.algos.items[11] == .rsa_pkcs1_sha256);
    try expect(res.algos.items[12] == .rsa_pkcs1_sha384);
    try expect(res.algos.items[13] == .rsa_pkcs1_sha512);
}

test "SignatureSchemeList encode" {
    var res = SignatureSchemeList.init(std.testing.allocator);
    defer res.deinit();

    try res.algos.append(.ecdsa_secp256r1_sha256);
    try res.algos.append(.ecdsa_secp384r1_sha384);
    try res.algos.append(.ecdsa_secp521r1_sha512);
    try res.algos.append(.ed25519);
    try res.algos.append(.ed448);
    try res.algos.append(.rsa_pss_pss_sha256);
    try res.algos.append(.rsa_pss_pss_sha384);
    try res.algos.append(.rsa_pss_pss_sha512);
    try res.algos.append(.rsa_pss_rsae_sha256);
    try res.algos.append(.rsa_pss_rsae_sha384);
    try res.algos.append(.rsa_pss_rsae_sha512);
    try res.algos.append(.rsa_pkcs1_sha256);
    try res.algos.append(.rsa_pkcs1_sha384);
    try res.algos.append(.rsa_pkcs1_sha512);

    // zig fmt: off
    const algos_ans = [_]u8{
    0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08,
    0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
    0x05, 0x01, 0x06, 0x01
    };
    // zig fmt: on

    var send_bytes: [100]u8 = undefined;

    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &algos_ans));
}
