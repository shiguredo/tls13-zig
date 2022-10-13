const std = @import("std");
const ArrayList = std.ArrayList;
const HandshakeType = @import("handshake.zig").HandshakeType;

pub const PreSharedKey = struct {
    msg_type: HandshakeType,
    offeredPsks: OfferedPsks = undefined,
    selected_identify: u16 = undefined,

    const Self = @This();

    pub fn deinit(self: Self) void {
        switch (self.msg_type) {
            .client_hello => self.offeredPsks.deinit(),
            .server_hello => {},
            else => unreachable,
        }
    }

    pub fn decode(reader: anytype, msg_type: HandshakeType, allocator: std.mem.Allocator) !PreSharedKey {
        switch (msg_type) {
            .client_hello => return .{
                .msg_type = msg_type,
                .offeredPsks = try OfferedPsks.decode(reader, allocator),
            },
            .server_hello => return .{
                .msg_type = msg_type,
                .selected_identify = try reader.readIntBig(u16),
            },
            else => unreachable,
        }
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        switch (self.msg_type) {
            .client_hello => return try self.offeredPsks.encode(writer),
            .server_hello => {
                try writer.writeIntBig(u16, self.selected_identify);
                return @sizeOf(u16);
            },
            else => unreachable,
        }
    }

    pub fn length(self: Self) usize {
        switch (self.msg_type) {
            .client_hello => return self.offeredPsks.length(),
            .server_hello => return @sizeOf(u16),
            else => unreachable,
        }
    }
};

pub const OfferedPsks = struct {
    identities: ArrayList(PskIdentity),
    binders: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();
    pub fn init(b_len: usize, allocator: std.mem.Allocator) !Self {
        return .{
            .identities = ArrayList(PskIdentity).init(allocator),
            .binders = try allocator.alloc(u8, b_len),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        for (self.identities.items) |i| {
            i.deinit();
        }
        self.identities.deinit();
        self.allocator.free(self.binders);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !OfferedPsks {
        var ids = ArrayList(PskIdentity).init(allocator);
        errdefer ids.deinit();

        const id_len = try reader.readIntBig(u16);
        var i: usize = 0;
        while (i < id_len) {
            const psk_id = try PskIdentity.decode(reader, allocator);
            errdefer psk_id.deinit();
            try ids.append(psk_id);
            i += psk_id.length();
        }

        const b_len = try reader.readIntBig(u16);
        var binders = try allocator.alloc(u8, b_len);
        errdefer allocator.free(binders);
        try reader.readNoEof(binders);

        return .{
            .identities = ids,
            .binders = binders,
            .allocator = allocator,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        var id_len: usize = 0;
        for (self.identities.items) |i| {
            id_len += i.length();
        }
        try writer.writeIntBig(u16, @intCast(u16, id_len));
        len += @sizeOf(u16);
        for (self.identities.items) |i| {
            len += try i.encode(writer);
        }

        try writer.writeIntBig(u16, @intCast(u16, self.binders.len));
        len += @sizeOf(u16);
        try writer.writeAll(self.binders);
        len += self.binders.len;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16);
        for (self.identities.items) |i| {
            len += i.length();
        }

        len += @sizeOf(u16);
        len += self.binders.len;

        return len;
    }
};

pub const PskIdentity = struct {
    identity: []u8,
    obfuscated_ticket_age: u32,

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, id_len: usize) !Self {
        return .{
            .identity = try allocator.alloc(u8, id_len),
            .obfuscated_ticket_age = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.identity);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const id_len = try reader.readIntBig(u16);
        var id = try allocator.alloc(u8, id_len);
        errdefer allocator.free(id);
        try reader.readNoEof(id);

        const ticket_age = try reader.readIntBig(u32);

        return .{
            .identity = id,
            .obfuscated_ticket_age = ticket_age,
            .allocator = allocator,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u16, @intCast(u16, self.identity.len));
        len += @sizeOf(u16);

        try writer.writeAll(self.identity);
        len += self.identity.len;

        try writer.writeIntBig(u32, self.obfuscated_ticket_age);
        len += @sizeOf(u32);

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // identity length
        len += self.identity.len;
        len += @sizeOf(u32);

        return len;
    }

    pub fn copy(self: Self, allocator: std.mem.Allocator) !Self {
        var res = try Self.init(allocator, self.identity.len);
        std.mem.copy(u8, res.identity, self.identity);
        res.obfuscated_ticket_age = self.obfuscated_ticket_age;

        return res;
    }
};

const io = std.io;
const expect = std.testing.expect;
const Extension = @import("extension.zig").Extension;

test "decode & encode" {
    // zig fmt: off
    const psk_bytes = [_]u8{
    0x00, 0x29, 0x00, 0xdd, 0x00, 0xb8, 0x00, 0xb2, 0x2c, 0x03, 0x5d, 0x82,
    0x93, 0x59, 0xee, 0x5f, 0xf7, 0xaf, 0x4e, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x26,
    0x2a, 0x64, 0x94, 0xdc, 0x48, 0x6d, 0x2c, 0x8a, 0x34, 0xcb, 0x33, 0xfa, 0x90,
    0xbf, 0x1b, 0x00, 0x70, 0xad, 0x3c, 0x49, 0x88, 0x83, 0xc9, 0x36, 0x7c, 0x09,
    0xa2, 0xbe, 0x78, 0x5a, 0xbc, 0x55, 0xcd, 0x22, 0x60, 0x97, 0xa3, 0xa9, 0x82,
    0x11, 0x72, 0x83, 0xf8, 0x2a, 0x03, 0xa1, 0x43, 0xef, 0xd3, 0xff, 0x5d, 0xd3,
    0x6d, 0x64, 0xe8, 0x61, 0xbe, 0x7f, 0xd6, 0x1d, 0x28, 0x27, 0xdb, 0x27, 0x9c,
    0xce, 0x14, 0x50, 0x77, 0xd4, 0x54, 0xa3, 0x66, 0x4d, 0x4e, 0x6d, 0xa4, 0xd2,
    0x9e, 0xe0, 0x37, 0x25, 0xa6, 0xa4, 0xda, 0xfc, 0xd0, 0xfc, 0x67, 0xd2, 0xae,
    0xa7, 0x05, 0x29, 0x51, 0x3e, 0x3d, 0xa2, 0x67, 0x7f, 0xa5, 0x90, 0x6c, 0x5b,
    0x3f, 0x7d, 0x8f, 0x92, 0xf2, 0x28, 0xbd, 0xa4, 0x0d, 0xda, 0x72, 0x14, 0x70,
    0xf9, 0xfb, 0xf2, 0x97, 0xb5, 0xae, 0xa6, 0x17, 0x64, 0x6f, 0xac, 0x5c, 0x03,
    0x27, 0x2e, 0x97, 0x07, 0x27, 0xc6, 0x21, 0xa7, 0x91, 0x41, 0xef, 0x5f, 0x7d,
    0xe6, 0x50, 0x5e, 0x5b, 0xfb, 0xc3, 0x88, 0xe9, 0x33, 0x43, 0x69, 0x40, 0x93,
    0x93, 0x4a, 0xe4, 0xd3, 0x57, 0xfa, 0xd6, 0xaa, 0xcb, 0x00, 0x21, 0x20, 0x3a,
    0xdd, 0x4f, 0xb2, 0xd8, 0xfd, 0xf8, 0x22, 0xa0, 0xca, 0x3c, 0xf7, 0x67, 0x8e,
    0xf5, 0xe8, 0x8d, 0xae, 0x99, 0x01, 0x41, 0xc5, 0x92, 0x4d, 0x57, 0xbb, 0x6f,
    0xa3, 0x1b, 0x9e, 0x5f, 0x9d
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&psk_bytes);
    const psk = try Extension.decode(stream.reader(), std.testing.allocator, .client_hello, false);
    defer psk.deinit();

    var psk_enc: [psk_bytes.len]u8 = undefined;
    var stream_enc = io.fixedBufferStream(&psk_enc);
    const write_len = try psk.encode(stream_enc.writer());
    try expect(std.mem.eql(u8, stream_enc.getWritten(), &psk_bytes));
    try expect(write_len == psk_bytes.len);
}
