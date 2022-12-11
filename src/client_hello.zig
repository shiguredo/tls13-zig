const std = @import("std");
const io = std.io;
const assert = std.debug.assert;
const expect = std.testing.expect;
const ArrayList = std.ArrayList;

const log = @import("log.zig");
const msg = @import("msg.zig");
const SessionID = msg.SessionID;
const CipherSuite = msg.CipherSuite;
const Extension = @import("extension.zig").Extension;

/// RFC8446 Section 4.1.2 Client Hello
///
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id<0..32>;
///     CipherSuite cipher_suites<2..2^16-2>;
///     opaque legacy_compression_methods<1..2^8-1>;
///     Extension extensions<8..2^16-1>;
/// } ClientHello;
///
pub const ClientHello = struct {
    protocol_version: u16 = 0x0303, // TLS v1.2 version
    random: [32]u8 = [_]u8{0} ** 32,
    legacy_session_id: SessionID,
    cipher_suites: ArrayList(CipherSuite),
    legacy_compression_methods: [2]u8 = [_]u8{ 0x1, 0x0 }, // "null" compression method
    extensions: ArrayList(Extension),

    const Self = @This();

    const Error = error{
        UnsupportedVersion,
        UnsupportedCompressionMethod,
    };

    /// initialize ClientHello message with given random and session_id.
    /// @param random     random for ClientHello.
    /// @param session_id session_id for ClientHello.
    /// @param allocator  allocator to allocate ArrayLists.
    /// @return the initialized ClientHello
    pub fn init(random: [32]u8, session_id: SessionID, allocator: std.mem.Allocator) Self {
        return Self{
            .random = random,
            .legacy_session_id = session_id,
            .extensions = ArrayList(Extension).init(allocator),
            .cipher_suites = ArrayList(CipherSuite).init(allocator),
        };
    }

    /// decode ClientHello message reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator to allocate ArrayLists.
    /// @return the result of decoded ClientHello.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // protocol_version must be TLSv1.2(0x0303).
        const protocol_version = try reader.readIntBig(u16);
        if (protocol_version != 0x0303) {
            return Error.UnsupportedVersion;
        }

        // Reading random array.
        var random: [32]u8 = undefined;
        try reader.readNoEof(&random);

        // Decoding legacy_session_id.
        const legacy_session_id = try SessionID.decode(reader);

        // Decoding CipherSuites.
        var suites = ArrayList(CipherSuite).init(allocator);
        try msg.decodeCipherSuites(reader, &suites);
        errdefer suites.deinit();

        // Decoding legacy_compression_methods.
        // only compression method 'null' is allowed.
        const comp_len = try reader.readIntBig(u8);
        if (comp_len != 0x01) {
            return Error.UnsupportedCompressionMethod;
        }
        if (try reader.readIntBig(u8) != 0x00) {
            return Error.UnsupportedCompressionMethod;
        }

        // Decoding Extensions.
        var exts = ArrayList(Extension).init(allocator);
        try msg.decodeExtensions(reader, allocator, &exts, .client_hello, false);
        errdefer exts.deinit();

        return Self{
            .protocol_version = protocol_version,
            .random = random,
            .legacy_session_id = legacy_session_id,
            .cipher_suites = suites,
            .extensions = exts,
        };
    }

    /// encode ClientHello message writing to io.Writer.
    /// @param self ClientHello to be encoded.
    /// @param writer io.Writer to be written encoded message.
    /// @return encoded length
    pub fn encode(self: Self, writer: anytype) !usize {
        // Verifying ClientHello.
        try self.verify();
        var len: usize = 0;

        // Encoding protocol_version.
        try writer.writeIntBig(u16, self.protocol_version);
        len += @sizeOf(u16);

        // Encoding random.
        try writer.writeAll(&self.random);
        len += self.random.len;

        // Encoding legacy_session_id.
        len += try self.legacy_session_id.encode(writer);

        // Encoding CipherSuites.
        len += try msg.encodeCipherSuites(writer, self.cipher_suites);

        // Encoding legacy_compression_methods.
        try writer.writeAll(&self.legacy_compression_methods);
        len += self.legacy_compression_methods.len;

        // Encoding extensions.
        len += try msg.encodeExtensions(writer, self.extensions);

        return len;
    }

    /// verify ClientHello message.
    /// @param self ClientHello to be verified.
    fn verify(self: Self) !void {
        // This must be TLSv1.2(0x0303)
        if (self.protocol_version != 0x0303) {
            return Error.UnsupportedVersion;
        }

        // This must be null(0x00)
        if (!std.mem.eql(u8, &self.legacy_compression_methods, &([_]u8{ 0x01, 0x00 }))) {
            return Error.UnsupportedCompressionMethod;
        }
    }

    /// get length of encoded ClientHello.
    /// @param self the target ClientHello.
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

    /// deinitialize ClientHello.
    /// @param self ClientHello to be deinitialized.
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

test "ClientHello decode & encode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x03, 0x03, 0xf0, 0x5d, 0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4,
    0x24, 0x9d, 0x4a, 0x69, 0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec,
    0xc7, 0x8f, 0xd0, 0x25, 0xc6, 0xeb, 0xe1, 0x33, 0x20, 0x67, 0x7e, 0xb6, 0x52,
    0xad, 0x12, 0x51, 0xda, 0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf,
    0xca, 0xa8, 0xc5, 0xfe, 0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83,
    0x35, 0xae, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00, 0x45, 0x00, 0x2b, 0x00,
    0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51,
    0x50, 0xa9, 0x0a, 0x47, 0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc,
    0xf0, 0xce, 0x0d, 0xee, 0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7,
    0xd3, 0x93, 0x64, 0x2f, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08,
    0x07
    };
    // zig fmt: on

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
    try expect(ks.entries.items[0].group == .x25519);

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
