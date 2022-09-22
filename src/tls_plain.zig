const std = @import("std");
const io = std.io;
const crypto = @import("crypto.zig");

const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;

/// RFC8446 Section 5.1 Record Layer
///
/// struct {
///     ContentType type;
///     ProtocolVersion legacy_record_version;
///     uint16 length;
///     opaque fragment[TLSPlaintext.length];
/// } TLSPlaintext;
///
pub const TLSPlainText = struct {
    proto_version: u16 = 0x0303,
    content: Content,

    const Self = @This();

    const Error = error{
        InvalidProtocolVersion,
        NotAllDecoded,
    };

    /// decode TLSPlainText reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param t         ContentType to be decoded.
    /// @param allocator allocator to allocate TLSPlainText.
    /// @param Hash      the type of hash function. It is used to decode handshake message.
    /// @param writer    if not null, fragment is written to the writer (used for KeySchedule etc.)
    /// @return decoded TLSPlainText.
    pub fn decode(reader: anytype, t: ContentType, allocator: std.mem.Allocator, hkdf: ?crypto.Hkdf, writer: anytype) !Self {
        // Decoding ProtocolVersion.
        const proto_version = try reader.readIntBig(u16);
        std.log.debug("protocol_version=0x{x:0>4}", .{proto_version});

        // Decoding length.
        const len = try reader.readIntBig(u16);

        // Reading the fragment.
        var fragment: []u8 = try allocator.alloc(u8, len);
        defer allocator.free(fragment);
        _ = try reader.readAll(fragment);

        // Decoding Content.
        var fragmentStream = io.fixedBufferStream(fragment);
        const cont = try Content.decode(fragmentStream.reader(), t, len, allocator, hkdf);
        errdefer cont.deinit();

        // Checking the entire of fragment has been decoded
        if ((try fragmentStream.getPos()) != (try fragmentStream.getEndPos())) {
            return Error.NotAllDecoded;
        }

        // If writer is not null, writing fragment into writer.
        if (@TypeOf(writer) != @TypeOf(null)) {
            try writer.writeAll(fragment);
        }

        return Self{
            .proto_version = proto_version,
            .content = cont,
        };
    }

    /// encode TLSPlainText writing to io.Writer.
    /// @param self   TLSPlainText to be encoded.
    /// @param writer io.Writer to write encoded TLSPlainText.
    /// @return the length of encoded TLSPlainText.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding ContentType.
        try writer.writeIntBig(u8, @enumToInt(self.content));
        len += @sizeOf(u8);

        // Encoding ProtocolVersion(TLS1.2 0x0303).
        try writer.writeIntBig(u16, self.proto_version);
        len += @sizeOf(u16);

        // Encoding length.
        len += @sizeOf(u16);
        try writer.writeIntBig(u16, @intCast(u16, self.length() - len));

        // Encoding Content as fragment.
        len += try self.content.encode(writer);

        return len;
    }

    /// get the length of encoded TLSPlainText.
    /// @param self TLSPlainText to get the length.
    /// @return the length of encoded TLSPlainText.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // content_type
        len += @sizeOf(u16); // protocol_version
        len += @sizeOf(u16); // length
        len += self.content.length();

        return len;
    }

    /// deinitialize TLSPlainText.
    /// @param self TLSPlainText to be deinitialized.
    pub fn deinit(self: Self) void {
        self.content.deinit();
    }
};

const expect = std.testing.expect;

test "TLSPlainText ClientHello decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x94, 0x01, 0x00, 0x00, 0x90, 0x03, 0x03, 0xf0, 0x5d,
    0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4, 0x24, 0x9d, 0x4a, 0x69,
    0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec, 0xc7, 0x8f, 0xd0, 0x25,
    0xc6, 0xeb, 0xe1, 0x33, 0x20, 0x67, 0x7e, 0xb6, 0x52, 0xad, 0x12, 0x51, 0xda,
    0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf, 0xca, 0xa8, 0xc5, 0xfe,
    0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83, 0x35, 0xae, 0x00, 0x02,
    0x13, 0x02, 0x01, 0x00, 0x00, 0x45, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x33, 0x00,
    0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51, 0x50, 0xa9, 0x0a, 0x47,
    0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc, 0xf0, 0xce, 0x0d, 0xee,
    0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7, 0xd3, 0x93, 0x64, 0x2f,
    0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const t = try readStream.reader().readEnum(ContentType, .Big);
    const res = try TLSPlainText.decode(readStream.reader(), t, std.testing.allocator, null, null);
    defer res.deinit();

    try expect(res.content == .handshake);
    try expect(res.content.handshake == .client_hello);
}
