const std = @import("std");
const io = std.io;
const Handshake = @import("msg.zig").Handshake;
const DecodeError = @import("msg.zig").DecodeError;

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
    change_cipher_spec: Dummy,
    alert: Dummy,
    handshake: Handshake,
    application_data: Dummy,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator, Hash: ?type) !Self {
        const t = @intToEnum(ContentType, try reader.readIntBig(u8));
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
            ContentType.handshake => res = Self{ .handshake = try Handshake.decode(fragmentStream.reader(), allocator, Hash) },
            else => unreachable,
        }

        // check the entire of fragment has been decoded
        if ((try fragmentStream.getPos()) != (try fragmentStream.getEndPos())) {
            return DecodeError.NotAllDecoded;
        }

        return res;
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            ContentType.handshake => |e| e.deinit(),
            else => unreachable,
        }
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

    pub fn init(len: u16, allocator: std.mem.Allocator) !Self {
        return Self{
            .record = try allocator.alloc(u8, len),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.record);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(ContentType, try reader.readIntBig(u8));
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
};

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "TLSPlainText ClientHello decode" {
    const recv_data = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x94, 0x01, 0x00, 0x00, 0x90, 0x03, 0x03, 0xf0, 0x5d, 0x41, 0x2d, 0x24, 0x35, 0x27, 0xfd, 0x90, 0xb5, 0xb4, 0x24, 0x9d, 0x4a, 0x69, 0xf8, 0x97, 0xb5, 0xcf, 0xfe, 0xe3, 0x8d, 0x4c, 0xec, 0xc7, 0x8f, 0xd0, 0x25, 0xc6, 0xeb, 0xe1, 0x33, 0x20, 0x67, 0x7e, 0xb6, 0x52, 0xad, 0x12, 0x51, 0xda, 0x7a, 0xe4, 0x5d, 0x3f, 0x19, 0x2c, 0xd1, 0xbf, 0xaf, 0xca, 0xa8, 0xc5, 0xfe, 0x59, 0x2f, 0x1b, 0x2f, 0x2a, 0x96, 0x1e, 0x12, 0x83, 0x35, 0xae, 0x00, 0x02, 0x13, 0x02, 0x01, 0x00, 0x00, 0x45, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x51, 0x50, 0xa9, 0x0a, 0x47, 0x82, 0xfe, 0xa7, 0x47, 0xf5, 0xcb, 0x55, 0x19, 0xdc, 0xf0, 0xce, 0x0d, 0xee, 0x9c, 0xdc, 0x04, 0x93, 0xbd, 0x84, 0x9e, 0xea, 0xf7, 0xd3, 0x93, 0x64, 0x2f, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try TLSPlainText.decode(readStream.reader(), std.testing.allocator, null);
    defer res.deinit();

    try expect(res == .handshake);
    try expect(res.handshake == .client_hello);
}

test "TLSCipherText Alert decode" {
    const recv_data = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try TLSCipherText.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expectError(error.EndOfStream, readStream.reader().readByte());

    const record_ans = [_]u8{ 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    try expect(std.mem.eql(u8, res.record, &record_ans));
}
