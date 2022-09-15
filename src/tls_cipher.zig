const std = @import("std");
const io = std.io;
const ArrayList = std.ArrayList;

const Alert = @import("alert.zig").Alert;
const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;
const crypto = @import("crypto.zig");

/// RFC8446 Section 5.2 Record Payload Protection
///
/// struct {
///     ContentType opaque_type = application_data; /* 23 */
///     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
///     uint16 length;
///     opaque encrypted_record[TLSCiphertext.length];
/// } TLSCiphertext;
///
pub const TLSCipherText = struct {
    record: []u8 = undefined,
    allocator: std.mem.Allocator = undefined,

    const Self = @This();

    const Error = error{
        InvalidContentType,
        InvalidProtocolVersion,
    };

    /// initialize TLSCipherText.
    /// @param len       the length of record.
    /// @param allocator allocator to allocate TLSCipherText.
    /// @return initialized TLSCipherText.
    pub fn init(len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .record = try allocator.alloc(u8, len),
            .allocator = allocator,
        };
    }

    /// deinitialize TLSCipherText.
    /// @param self TLSCipherText to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.record);
    }

    /// decode TLSCipherText reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param t         ContentType(must be application_data).
    /// @param allocator allocator to allocate TLSCipherText.
    /// @return TLSCipherText decoded.
    pub fn decode(reader: anytype, t: ContentType, allocator: std.mem.Allocator) !Self {
        // TLSCipherText's ContentType must be application_data.
        if (t != .application_data) {
            return Error.InvalidContentType;
        }

        // ProtocolVersion must be TLSv1.2(0x0303).
        const proto_version = try reader.readIntBig(u16);
        if (proto_version != 0x0303) {
            return Error.InvalidProtocolVersion;
        }

        // Decoding length.
        const len = try reader.readIntBig(u16);

        // Decoding record.
        var res = try Self.init(len, allocator);
        errdefer res.deinit();
        try reader.readNoEof(res.record);

        return res;
    }

    /// encode TLSCipherText writing to io.Writer.
    /// @param self   TLSCipherText to be encoded.
    /// @param writer io.Writer to write encoded TLSCipherText.
    /// @return the length of encoded TLSCipherText.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = try self.writeHeader(writer);

        // Encoding record.
        try writer.writeAll(self.record);
        len += self.record.len;

        return len;
    }

    /// encode TLSCipherText header.
    /// @param self   TLSCipherText to be encoded.
    /// @param writer io.Writer to write encoded TLSCipherText header.
    /// @return the length of encoded TLSCipherText header.
    pub fn writeHeader(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding ContentType.
        try writer.writeIntBig(u8, @enumToInt(ContentType.application_data));
        len += @sizeOf(u8);

        // Encoding ProtocolVersion(TLSv1.2, 0x0303).
        try writer.writeIntBig(u16, 0x0303);
        len += @sizeOf(u16);

        // Encoding length.
        try writer.writeIntBig(u16, @intCast(u16, self.record.len));
        len += @sizeOf(u16);

        return len;
    }

    /// get the length of encoded TLSCipherText.
    /// @param self TLSCipherText to get the length.
    /// @return the length of encoded TLSCipherText.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // ContentType
        len += @sizeOf(u16); // protocol_version
        len += @sizeOf(u16); // record length
        len += self.record.len; // record

        return len;
    }
};

/// RFC8446 Section 5.2 Record Payload Protection
///
/// struct {
///     opaque content[TLSPlaintext.length];
///     ContentType type;
///     uint8 zeros[length_of_padding];
/// } TLSInnerPlaintext;
///
pub const TLSInnerPlainText = struct {
    content: []u8,
    content_type: ContentType,
    zero_pad_length: usize = 0,

    allocator: std.mem.Allocator,

    const Self = @This();

    const Error = error{
        NoContents,
        InvalidData,
        EncodeFailed,
        DecodeFailed,
    };

    /// initialize TLSInnerPlainText.
    /// @param len          the length of content.
    /// @param content_type ContentType.
    /// @param allocator    allocator to allocate content.
    /// @return initialized TLSInnerPlainText.
    pub fn init(len: usize, content_type: ContentType, allocator: std.mem.Allocator) !Self {
        return Self{
            .content = try allocator.alloc(u8, len),
            .content_type = content_type,
            .allocator = allocator,
        };
    }

    /// initialize TLSInnerPlainText with Content.
    /// @param content   content to be encoded into TLSInnerPlainText.
    /// @param allocator allocator to allocate TLSInnerPlainText.
    /// @return initialized TLSInnerPlainText.
    pub fn initWithContent(content: Content, allocator: std.mem.Allocator) !Self {
        var pt = try Self.init(content.length(), content, allocator);
        errdefer pt.deinit();

        pt.content_type = content;

        // Encoding Content into content.
        var stream = io.fixedBufferStream(pt.content);
        const enc_len = try content.encode(stream.writer());
        if (enc_len != pt.content.len) {
            return Error.EncodeFailed;
        }

        return pt;
    }

    /// deinitialize TLSInnerPlainText.
    /// @param self TLSInnerPlainText to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.content);
    }

    /// decode TLSInnerPlainText reading from bytes array.
    /// @param m         bytes array to be decoded.
    /// @param allocator allocator to allocate TLSInnerPlainText.
    /// @return decoded TLSInnerPlainText.
    pub fn decode(m: []const u8, allocator: std.mem.Allocator) !Self {
        // specify the length of zero padding
        var i: usize = m.len - 1;
        while (i > 0) : (i -= 1) {
            if (m[i] != 0x0) {
                break;
            }
            if (i == 0) {
                // if the 'm' does not contains non-zero value(ContentType), it must be invalid data.
                return Error.InvalidData;
            }
        }

        const zero_pad_length = (m.len - 1) - i;
        const content_len = m.len - zero_pad_length - 1;

        // Decoding content_type.
        const content_type = @intToEnum(ContentType, m[content_len]);

        // Decoding content.
        var res = try Self.init(content_len, content_type, allocator);
        errdefer res.deinit();
        res.zero_pad_length = zero_pad_length;
        std.mem.copy(u8, res.content, m[0..content_len]);

        return res;
    }

    /// decode a Content reading from content.
    /// @param self      TLSInnerPlainText to decode a content.
    /// @param allocator allocator to allocate Content.
    /// @param hkdf      HKDF used to decode Content.
    /// @return a decoded Content.
    pub fn decodeContent(self: Self, allocator: std.mem.Allocator, hkdf: ?crypto.Hkdf) !Content {
        var stream = io.fixedBufferStream(self.content);
        return try Content.decode(stream.reader(), self.content_type, self.content.len, allocator, hkdf);
    }

    /// decode Contents reading from content.
    /// @param self      TLSInnerPlainText to decode contents.
    /// @param allocator allocator to allocate Contents and ArrayList.
    /// @param hkdf      HKDF used to decode Contents.
    /// @return decoded Contents.
    pub fn decodeContents(self: Self, allocator: std.mem.Allocator, hkdf: ?crypto.Hkdf) !ArrayList(Content) {
        var res = ArrayList(Content).init(allocator);
        errdefer res.deinit();

        // Decoding Contents.
        var stream = io.fixedBufferStream(self.content);
        while ((try stream.getPos() != (try stream.getEndPos()))) {
            const rest_size = (try stream.getEndPos()) - (try stream.getPos());
            const cont = try Content.decode(stream.reader(), self.content_type, rest_size, allocator, hkdf);
            errdefer cont.deinit();
            try res.append(cont);
        }

        // If some bytes are rest, it must be something wrong.
        if ((try stream.getPos() != (try stream.getEndPos()))) {
            return Error.DecodeFailed;
        }

        return res;
    }

    /// encode TLSInnerPlainText writing to io.Writer.
    /// @param self   TLSInnerPlainText to be encoded.
    /// @param writer io.Writer to write encoded TLSInnerPlainText.
    /// @return the length of encoded TLSInnerPlainText.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding content.
        try writer.writeAll(self.content);
        len += self.content.len;

        // Encoding content_type.
        try writer.writeByte(@enumToInt(self.content_type));
        len += @sizeOf(u8);

        // Encoding zero-fill.
        // TODO: more efficient way to zero filling
        var i: usize = 0;
        while (i < self.zero_pad_length) : (i += 1) {
            try writer.writeByte(0x00);
            len += @sizeOf(u8);
        }

        return len;
    }

    /// encode TLSInnerPlainText writing to io.Writer with Contents.
    /// @param contents  Contents to be encoded.
    /// @param writer    io.Writer to write encoded TLSInnerPlainText.
    /// @param allocator allocator used to encode Contents.
    /// @return the length of encoded TLSInnerPlainText.
    pub fn encodeContents(contents: ArrayList(Content), writer: anytype, allocator: std.mem.Allocator) !usize {
        // If no items are contained, return error.
        if (contents.items.len != 0) {
            return Error.NoContents;
        }

        // Encoding Contents into TLSInnerPlainText.
        var len: usize = 0;
        for (contents.items) |c| {
            len += c.length();
        }

        var pt = Self.init(len, allocator);
        defer pt.deinit();

        for (contents.items) |c| {
            try c.encode(pt.stream.writer());
        }

        // Encoding TLSInnerPlainText.
        return try pt.encode(writer);
    }

    /// get the length of encoded TLSInnerPlainText.
    /// @param self TLSInnerPlainText to get the length.
    /// @return the length of encoded TLSInnerPlainText.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += self.content.len;
        len += @sizeOf(u8); // ContentType
        len += self.zero_pad_length;

        return len;
    }
};

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "TLSCipherText decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99,
    0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const t = try readStream.reader().readEnum(ContentType, .Big);
    const res = try TLSCipherText.decode(readStream.reader(), t, std.testing.allocator);
    defer res.deinit();

    try expectError(error.EndOfStream, readStream.reader().readByte());

    // zig fmt: off
    const record_ans = [_]u8{
    0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE,
    0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, res.record, &record_ans));
}

test "TLSCipherText encode" {
    // zig fmt: off
    const record = [_]u8{
    0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE,
    0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    var ct = try TLSCipherText.init(record.len, std.testing.allocator);
    defer ct.deinit();
    std.mem.copy(u8, ct.record, &record);

    var send_data: [1000]u8 = undefined;
    var sendStream = io.fixedBufferStream(&send_data);
    const write_len = try ct.encode(sendStream.writer());
    try expect(write_len == try sendStream.getPos());

    // zig fmt: off
    const send_data_ans = [_]u8{
    0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99,
    0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, send_data[0..write_len], &send_data_ans));
}

test "TLSInnerPlainText decode" {
    const recv_data = [_]u8{ 0x01, 0x00, 0x15, 0x00, 0x00, 0x00 }; // ContentType alert

    var pt = try TLSInnerPlainText.decode(&recv_data, std.testing.allocator);
    defer pt.deinit();
    const content = try pt.decodeContent(std.testing.allocator, null);
    defer content.deinit();

    try expect(content == .alert);
    const alert = content.alert;
    try expect(alert.level == .warning);
    try expect(alert.description == .close_notify);
    try expect(pt.zero_pad_length == 3);
}

test "TLSInnerPlainText encode" {
    const alert = Content{ .alert = Alert{
        .level = .warning,
        .description = .close_notify,
    } };
    var mt = try TLSInnerPlainText.initWithContent(alert, std.testing.allocator);
    defer mt.deinit();
    mt.zero_pad_length = 2;

    var send_data: [1000]u8 = undefined;
    var sendStream = io.fixedBufferStream(&send_data);
    const write_len = try mt.encode(sendStream.writer());
    try expect(write_len == try sendStream.getPos());

    const send_data_ans = [_]u8{ 0x01, 0x00, 0x15, 0x00, 0x00 };
    try expect(std.mem.eql(u8, send_data[0..write_len], &send_data_ans));
}
