const std = @import("std");
const io = std.io;
const Handshake = @import("msg.zig").Handshake;
const DecodeError = @import("msg.zig").DecodeError;
const crypto = @import("crypto.zig");

pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

const Dummy = struct {};

pub const TLSPlainText = union(ContentType) {
    invalid: Dummy,
    change_cipher_spec: ChangeCipherSpec,
    alert: Dummy,
    handshake: Handshake,
    application_data: Dummy,

    const Self = @This();

    /// @param (Hash) is the type of hash function. It is used to decode handshake message.
    /// @param (writer) if not null, fragment is written to the writer (used for KeySchedule etc.)
    pub fn decode(reader: anytype, t: ContentType, allocator: std.mem.Allocator, Hash: ?type, writer: anytype) !Self {
        const proto_version = try reader.readIntBig(u16);
        if (proto_version != 0x0303) {
            // TODO: return error
        }

        const len = try reader.readIntBig(u16);

        // read the fragment
        var fragment: []u8 = try allocator.alloc(u8, len);
        defer allocator.free(fragment);

        _ = try reader.readAll(fragment);
        var fragmentStream = io.fixedBufferStream(fragment);
        var res: Self = undefined;
        switch (t) {
            ContentType.change_cipher_spec => res = Self{ .change_cipher_spec = try ChangeCipherSpec.decode(fragmentStream.reader(), len) },
            ContentType.handshake => res = Self{ .handshake = try Handshake.decode(fragmentStream.reader(), allocator, Hash) },
            else => unreachable,
        }

        // check the entire of fragment has been decoded
        if ((try fragmentStream.getPos()) != (try fragmentStream.getEndPos())) {
            return DecodeError.NotAllDecoded;
        }

        if (@TypeOf(writer) != @TypeOf(null)) {
            try writer.writeAll(fragment);
        }

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u8, @enumToInt(self));
        len += @sizeOf(u8);

        try writer.writeIntBig(u16, 0x0303);
        len += @sizeOf(u16);

        len += @sizeOf(u16);
        try writer.writeIntBig(u16, @intCast(u16, self.length() - len));

        switch (self) {
            ContentType.handshake => |e| len += try e.encode(writer),
            else => unreachable,
        }

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // content_type
        len += @sizeOf(u16); // protocol_version
        len += @sizeOf(u16); // length
        switch (self) {
            ContentType.handshake => |e| len += e.length(),
            else => unreachable,
        }

        return len;
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            ContentType.change_cipher_spec => |e| e.deinit(),
            ContentType.handshake => |e| e.deinit(),
            else => unreachable,
        }
    }
};

pub const ChangeCipherSpec = struct {
    const Self = @This();

    pub fn decode(reader: anytype, length: usize) !Self {
        var i: usize = 0;
        while (i < length) : (i += 1) {
            _ = try reader.readByte();
        }

        return Self{};
    }

    pub fn deinit(self: Self) void {
        _ = self;
    }
};

pub const TLSCipherText = struct {
    record: []u8 = undefined,
    allocator: std.mem.Allocator = undefined,

    const Self = @This();

    const Error = error{
        InvalidContentType,
        InvalidProtocolVersion,
    };

    pub fn init(len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .record = try allocator.alloc(u8, len),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.record);
    }

    pub fn decode(reader: anytype, t: ContentType, allocator: std.mem.Allocator) !Self {
        if (t != .application_data) {
            return Error.InvalidContentType;
        }

        const proto_version = try reader.readIntBig(u16);
        if (proto_version != 0x0303) {
            return Error.InvalidProtocolVersion;
        }

        const len = try reader.readIntBig(u16);
        var res = try Self.init(len, allocator);
        errdefer res.deinit();

        try reader.readNoEof(res.record);

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = try self.writeHeader(writer);

        try writer.writeAll(self.record);
        len += self.record.len;

        return len;
    }

    pub fn writeHeader(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u8, @enumToInt(ContentType.application_data));
        len += @sizeOf(u8);

        try writer.writeIntBig(u16, 0x0303); //protocol_version
        len += @sizeOf(u16);

        try writer.writeIntBig(u16, @intCast(u16, self.record.len)); //record length
        len += @sizeOf(u16);

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // ContentType
        len += @sizeOf(u16); // protocol_version
        len += @sizeOf(u16); // record length
        len += self.record.len; // record

        return len;
    }
};

pub const TLSInnerPlainText = struct {
    content: []u8 = undefined,
    content_type: ContentType = undefined,
    zero_pad_length: usize = 0,

    allocator: std.mem.Allocator = undefined,

    const Self = @This();

    const Error = error{
        InvalidData,
    };

    pub fn init(len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .content = try allocator.alloc(u8, len),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.content);
    }

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

        var res = try Self.init(content_len, allocator);
        errdefer res.deinit();

        res.content_type = @intToEnum(ContentType, m[content_len]);
        res.zero_pad_length = zero_pad_length;
        std.mem.copy(u8, res.content, m[0..content_len]);

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeAll(self.content);
        len += self.content.len;

        try writer.writeByte(@enumToInt(self.content_type));
        len += @sizeOf(u8);

        // TODO: more efficient way to zero filling
        var i: usize = 0;
        while (i < self.zero_pad_length) : (i += 1) {
            try writer.writeByte(0x00);
            len += @sizeOf(u8);
        }

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += self.content.len;
        len += @sizeOf(u8); // ContentType
        len += self.zero_pad_length;

        return len;
    }
};

pub const RecordPayloadProtector = struct {
    aead: crypto.Aead,

    const Self = @This();

    pub fn init(aead: crypto.Aead) !Self {
        return Self{ .aead = aead };
    }

    pub fn encrypt(self: Self, mt: TLSInnerPlainText, n: []const u8, k: []const u8, allocator: std.mem.Allocator) !TLSCipherText {
        var mt_bytes = try allocator.alloc(u8, mt.length());
        defer allocator.free(mt_bytes);
        _ = try mt.encode(io.fixedBufferStream(mt_bytes).writer());

        const tag_length = self.aead.tag_length;
        var ct = try TLSCipherText.init(mt.length() + tag_length, allocator);
        var header: [5]u8 = undefined;
        _ = try ct.writeHeader(io.fixedBufferStream(&header).writer());

        // RFC 8446 5.2 Record Payload Protection(p. 81)
        // additional_data = TLSCiphertext.opaque_tyoe ||
        //                   TLSCiphertext.legacy_record_version ||
        //                   TLSCiphertext.length
        self.aead.encrypt(ct.record[0..(ct.record.len - tag_length)], ct.record[(ct.record.len - tag_length)..], mt_bytes, &header, n, k);
        return ct;
    }

    pub fn encryptFromPlainBytes(self: Self, m: []const u8, content_type: ContentType, n: []const u8, k: []const u8, allocator: std.mem.Allocator) !TLSCipherText {
        var mt = try TLSInnerPlainText.init(m.len, allocator);
        defer mt.deinit();
        mt.content_type = content_type;
        std.mem.copy(u8, mt.content, m);

        return try self.encrypt(mt, n, k, allocator);
    }

    pub fn decrypt(self: Self, c: TLSCipherText, n: []const u8, k: []const u8, allocator: std.mem.Allocator) !TLSInnerPlainText {
        const tag_length = self.aead.tag_length;
        var mt_bytes = try allocator.alloc(u8, c.record.len - tag_length);
        defer allocator.free(mt_bytes);

        var header: [5]u8 = undefined;
        _ = try c.writeHeader(io.fixedBufferStream(&header).writer());
        try self.aead.decrypt(mt_bytes, c.record[0 .. c.record.len - tag_length], c.record[(c.record.len - tag_length)..], &header, n, k);

        return try TLSInnerPlainText.decode(mt_bytes, allocator);
    }

    pub fn decryptFromCipherBytes(self: Self, c: []const u8, n: []const u8, k: []const u8, allocator: std.mem.Allocator) !TLSInnerPlainText {
        var reader = io.fixedBufferStream(c).reader();
        const t = @intToEnum(ContentType, try reader.readIntBig(u8));
        const ct = try TLSCipherText.decode(reader, t, allocator);
        defer ct.deinit();

        return try self.decrypt(ct, n, k, allocator);
    }
};

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "TLSPlainText ClientHello decode" {
    const recv_data = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x94, 0x01, 0x00, 0x00, 0x90, 0x03, 0x03, 0xf0, 0x5d, 0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4, 0x24, 0x9d, 0x4a, 0x69, 0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec, 0xc7, 0x8f, 0xd0, 0x25, 0xc6, 0xeb, 0xe1, 0x33, 0x20, 0x67, 0x7e, 0xb6, 0x52, 0xad, 0x12, 0x51, 0xda, 0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf, 0xca, 0xa8, 0xc5, 0xfe, 0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83, 0x35, 0xae, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00, 0x45, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51, 0x50, 0xa9, 0x0a, 0x47, 0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc, 0xf0, 0xce, 0x0d, 0xee, 0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7, 0xd3, 0x93, 0x64, 0x2f, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07 };
    var readStream = io.fixedBufferStream(&recv_data);

    const t = @intToEnum(ContentType, try readStream.reader().readIntBig(u8));
    const res = try TLSPlainText.decode(readStream.reader(), t, std.testing.allocator, null, null);
    defer res.deinit();

    try expect(res == .handshake);
    try expect(res.handshake == .client_hello);
}

test "TLSCipherText decode" {
    const recv_data = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    var readStream = io.fixedBufferStream(&recv_data);

    const t = @intToEnum(ContentType, try readStream.reader().readIntBig(u8));
    const res = try TLSCipherText.decode(readStream.reader(), t, std.testing.allocator);
    defer res.deinit();

    try expectError(error.EndOfStream, readStream.reader().readByte());

    const record_ans = [_]u8{ 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    try expect(std.mem.eql(u8, res.record, &record_ans));
}

test "TLSCipherText encode" {
    const record = [_]u8{ 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };

    var ct = try TLSCipherText.init(record.len, std.testing.allocator);
    defer ct.deinit();
    std.mem.copy(u8, ct.record, &record);

    var send_data: [1000]u8 = undefined;
    var sendStream = io.fixedBufferStream(&send_data);
    const write_len = try ct.encode(sendStream.writer());
    try expect(write_len == try sendStream.getPos());

    const send_data_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    try expect(std.mem.eql(u8, send_data[0..write_len], &send_data_ans));
}

test "TLSInnerPlainText decode" {
    const recv_data = [_]u8{ 0x01, 0x00, 0x15, 0x00, 0x00, 0x00 }; // ContentType alert

    const pt = try TLSInnerPlainText.decode(&recv_data, std.testing.allocator);
    defer pt.deinit();

    const content_ans = [_]u8{ 0x01, 0x00 };
    try expect(std.mem.eql(u8, pt.content, &content_ans));
    try expect(pt.content_type == .alert);
    try expect(pt.zero_pad_length == 3);
}

test "TLSInnerPlainText encode" {
    const content = [_]u8{ 0x01, 0x00 };

    var pt = try TLSInnerPlainText.init(content.len, std.testing.allocator);
    defer pt.deinit();

    std.mem.copy(u8, pt.content, &content);
    pt.content_type = .alert;
    pt.zero_pad_length = 2;

    var send_data: [1000]u8 = undefined;
    var sendStream = io.fixedBufferStream(&send_data);
    const write_len = try pt.encode(sendStream.writer());
    try expect(write_len == try sendStream.getPos());

    const send_data_ans = [_]u8{ 0x01, 0x00, 0x15, 0x00, 0x00 };
    try expect(std.mem.eql(u8, send_data[0..write_len], &send_data_ans));
}

test "RecordPayloadProtector encrypt" {
    const key = [_]u8{ 0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f, 0x50, 0x51 };
    const iv = [_]u8{ 0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9 };
    var nonce = [_]u8{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 };
    var i: usize = 0;
    while (i < iv.len) : (i += 1) {
        nonce[i] = iv[i] ^ nonce[i];
    }

    var mt = try TLSInnerPlainText.init(2, std.testing.allocator);
    defer mt.deinit();
    mt.content[0] = 0x1;
    mt.content[1] = 0x0;
    mt.content_type = .alert;

    const protector = try RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead);
    const ct = try protector.encrypt(mt, &nonce, &key, std.testing.allocator);
    defer ct.deinit();

    const c_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xC9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xB7, 0x4D, 0x7F, 0xF1, 0x15, 0x3E, 0xFD, 0x6D, 0xB6, 0xD0, 0xB0, 0xE3 };
    var c: [1000]u8 = undefined;
    const write_len = try ct.encode(io.fixedBufferStream(&c).writer());
    try expect(std.mem.eql(u8, c[0..write_len], &c_ans));
}

test "RecordPayloadProtector decrypt" {
    const key = [_]u8{ 0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56 };
    const iv = [_]u8{ 0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84 };
    var nonce = [_]u8{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2 }; // increment nonce counter
    var i: usize = 0;
    while (i < iv.len) : (i += 1) {
        nonce[i] = iv[i] ^ nonce[i];
    }
    const s_alert = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    var stream = io.fixedBufferStream(&s_alert);
    const t = @intToEnum(ContentType, try stream.reader().readIntBig(u8));
    const ct = try TLSCipherText.decode(stream.reader(), t, std.testing.allocator);
    defer ct.deinit();

    const protector = try RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead);
    const mt = try protector.decrypt(ct, &nonce, &key, std.testing.allocator);
    defer mt.deinit();

    const mt_content_ans = [_]u8{ 0x01, 0x00 };
    try expect(mt.content_type == .alert);
    try expect(std.mem.eql(u8, mt.content, &mt_content_ans));
}

test "RecordPayloadProtector encryptFromPlainBytes" {
    const key = [_]u8{ 0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f, 0x50, 0x51 };
    const iv = [_]u8{ 0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9 };
    var nonce = [_]u8{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1 };
    var i: usize = 0;
    while (i < iv.len) : (i += 1) {
        nonce[i] = iv[i] ^ nonce[i];
    }

    const content = [_]u8{ 0x01, 0x00 };

    const protector = try RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead);
    const ct = try protector.encryptFromPlainBytes(&content, .alert, &nonce, &key, std.testing.allocator);
    defer ct.deinit();

    const c_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xC9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xB7, 0x4D, 0x7F, 0xF1, 0x15, 0x3E, 0xFD, 0x6D, 0xB6, 0xD0, 0xB0, 0xE3 };
    var c: [1000]u8 = undefined;
    const write_len = try ct.encode(io.fixedBufferStream(&c).writer());
    try expect(std.mem.eql(u8, c[0..write_len], &c_ans));
}

test "RecordPayloadProtector decryptFromBytes" {
    const key = [_]u8{ 0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56 };
    const iv = [_]u8{ 0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84 };
    var nonce = [_]u8{ 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2 }; // increment nonce counter
    var i: usize = 0;
    while (i < iv.len) : (i += 1) {
        nonce[i] = iv[i] ^ nonce[i];
    }
    const s_alert = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };

    const protector = try RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead);
    const mt = try protector.decryptFromCipherBytes(&s_alert, &nonce, &key, std.testing.allocator);
    defer mt.deinit();

    const mt_content_ans = [_]u8{ 0x01, 0x00 };
    try expect(mt.content_type == .alert);
    try expect(std.mem.eql(u8, mt.content, &mt_content_ans));
}
