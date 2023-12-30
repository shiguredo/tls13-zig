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

/// RFC8446 Section 4.1.3 ServerHello
///
/// struct {
///     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
///     Random random;
///     opaque legacy_session_id_echo<0..32>;
///     CipherSuite cipher_suite;
///     uint8 legacy_compression_method = 0;
///     Extension extensions<6..2^16-1>;
/// } ServerHello;
///
pub const ServerHello = struct {
    protocol_version: u16 = 0x0303,
    random: [32]u8 = [_]u8{0} ** 32,
    legacy_session_id: SessionID,
    cipher_suite: CipherSuite,
    legacy_compression_methods: u8 = 0x0, // "null" compression method
    extensions: ArrayList(Extension),
    is_hello_retry_request: bool = false,

    // zig fmt: off
    pub const hello_retry_request_magic: [32]u8 = [_]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e,
    0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e,
    0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };
    // zig fmt: on

    const Self = @This();

    const Error = error{
        UnsupportedVersion,
        UnsupportedCompressionMethod,
    };

    /// initialize ServerHello message with given random and session_id.
    /// @param random     random for ServerHello.
    /// @param session_id session_id for ServerHello.
    /// @param allocator  allocator to allocate ArrayLists.
    /// @return the initialized ServerHello
    pub fn init(random: [32]u8, session_id: SessionID, cipher_suite: CipherSuite, allocator: std.mem.Allocator) Self {
        return Self{
            .random = random,
            .legacy_session_id = session_id,
            .cipher_suite = cipher_suite,
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    /// decode ServerHello message reading from io.Reader.
    /// @param reader     io.Reader to read messages.
    /// @param allocator  allocator to allocate ArrayList(Extension).
    /// @return the result of decoded ServerHello.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // procotol_version must be TLSv1.2(0x0303)
        const protocol_version = try reader.readInt(u16, .big);
        if (protocol_version != 0x0303) {
            return Error.UnsupportedVersion;
        }

        // Reading random array.
        var random: [32]u8 = undefined;
        try reader.readNoEof(&random);

        // Checking if random is equal to hello retry magic.
        var is_hello_retry_request = false;
        if (std.mem.eql(u8, &random, &ServerHello.hello_retry_request_magic)) {
            is_hello_retry_request = true;
        }

        // Decoding SessionID.
        const legacy_session_id = try SessionID.decode(reader);

        // Decoding CipherSuite.
        const cipher_suite = @as(CipherSuite, @enumFromInt(try reader.readInt(u16, .big)));

        // Decoding legacy_compression_methods.
        // This must be null(0x00)
        const legacy_compression_methods = try reader.readInt(u8, .big);
        if (legacy_compression_methods != 0x00) {
            return Error.UnsupportedCompressionMethod;
        }

        // Decoding Extensions.
        var extensions = ArrayList(Extension).init(allocator);
        errdefer extensions.deinit();

        try msg.decodeExtensions(reader, allocator, &extensions, .server_hello, is_hello_retry_request);

        return Self{
            .protocol_version = protocol_version,
            .random = random,
            .legacy_session_id = legacy_session_id,
            .cipher_suite = cipher_suite,
            .legacy_compression_methods = legacy_compression_methods,
            .extensions = extensions,
            .is_hello_retry_request = is_hello_retry_request,
        };
    }

    /// encode ServerHello message writing to io.Writer.
    /// @param self   ServerHello to be encoded.
    /// @param writer io.Writer to be written encoded message.
    /// @return encoded length.
    pub fn encode(self: Self, writer: anytype) !usize {
        // Verifying ServerHello.
        try self.verify();

        var len: usize = 0;

        // Encoding protocol_version.
        try writer.writeInt(u16, self.protocol_version, .big);
        len += @sizeOf(u16);

        // Encoding random.
        try writer.writeAll(&self.random);
        len += self.random.len;

        // Encoding legacy_session_id.
        len += try self.legacy_session_id.encode(writer);

        // Encoding CipherSuite.
        try writer.writeInt(u16, @intFromEnum(self.cipher_suite), .big);
        len += @sizeOf(CipherSuite);

        // Encoding legacy_compression_methods.
        try writer.writeInt(u8, self.legacy_compression_methods, .big);
        len += @sizeOf(u8);

        // Encoding extensions.
        len += try msg.encodeExtensions(writer, self.extensions);

        return len;
    }

    /// verify ServerHello message.
    /// @param self ServerHello to be verified.
    fn verify(self: Self) !void {
        // This must be TLSv1.2(0x0303)
        if (self.protocol_version != 0x0303) {
            return Error.UnsupportedVersion;
        }

        // This must be null(0x00)
        if (self.legacy_compression_methods != 0x00) {
            return Error.UnsupportedCompressionMethod;
        }
    }

    /// get length of encoded ServerHello.
    /// @param self the target ServerHello.
    /// @return length of encoded ServerHello.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(@TypeOf(self.protocol_version));
        len += self.random.len;
        len += self.legacy_session_id.length();
        len += @sizeOf(u16); // cipher_suite
        len += @sizeOf(u8); // compression_methods

        len += @sizeOf(u16); // extensions length
        for (self.extensions.items) |ext| {
            len += ext.length();
        }
        return len;
    }

    /// deinitialize ServerHello.
    /// @param self ServerHello to be deinitialized.
    pub fn deinit(self: Self) void {
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("=== ServerHello ===", .{});
        log.debug("ProtocolVersion = 0x{x:0>4}", .{self.protocol_version});
        log.debug("Random = {}", .{std.fmt.fmtSliceHexLower(&self.random)});
        self.legacy_session_id.print();
        log.debug("CompresssionMethod = 0x{x:0>2}", .{self.legacy_compression_methods});
        self.extensions.print();
    }
};

test "ServerHello decode & encode" {
    // zig fmt: off
    const recv_data = [_]u8{ 
    0x03, 0x03, 0x11, 0x08, 0x43, 0x1b, 0xd0, 0x42, 0x9e, 0x61, 0xff, 0x65, 0x44,
    0x41, 0x91, 0xfc, 0x56, 0x10, 0xf8, 0x27, 0x53, 0xd9, 0x68, 0xc8, 0x13, 0x00,
    0xb1, 0xec, 0x11, 0xd5, 0x7d, 0x90, 0xa5, 0x43, 0x20, 0xc4, 0x8a, 0x5c, 0x30,
    0xa8, 0x50, 0x1b, 0x2e, 0xc2, 0x45, 0x76, 0xd7, 0xf0, 0x11, 0x52, 0xa0, 0x16,
    0x57, 0x07, 0xdf, 0x01, 0x30, 0x47, 0x5b, 0x94, 0xbc, 0xe7, 0x86, 0x1e, 0x41,
    0x97, 0x65, 0x13, 0x02, 0x00, 0x00, 0x4f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
    0x00, 0x33, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04, 0x27, 0x66, 0x69, 0x3d,
    0xd8, 0xd1, 0x76, 0xa8, 0x8f, 0x6a, 0xe6, 0x61, 0x06, 0x89, 0xe1, 0xe9, 0xcd,
    0x63, 0xef, 0x2e, 0x79, 0x41, 0x24, 0x86, 0x26, 0x37, 0xfa, 0x83, 0xd9, 0xfd,
    0xa3, 0xc5, 0xaa, 0xbc, 0xaa, 0xb5, 0x85, 0x86, 0x98, 0x21, 0x54, 0xbc, 0x81,
    0xed, 0x30, 0x35, 0x42, 0xb2, 0x89, 0xd6, 0xa4, 0xc4, 0x94, 0x75, 0x41, 0x49,
    0x90, 0x78, 0x03, 0xaa, 0xf5, 0x6d, 0xfc, 0x47
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const res = try ServerHello.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    // check extensions
    try expect(res.extensions.items.len == 2);
    try expect(res.extensions.items[0] == .supported_versions);
    try expect(res.extensions.items[1] == .key_share);

    // check key_share selected group is secp256r1
    const ks = res.extensions.items[1].key_share;
    try expect(ks.entries.items.len == 1);
    try expect(ks.entries.items[0].group == .secp256r1);

    var send_bytes: [1000]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &recv_data));
    try expect(write_len == res.length());
}
