const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const msg = @import("msg.zig");

pub const SupportedVersions = struct {
    version: u16 = 0x0304,

    ht: msg.HandshakeType = undefined,
    const Self = @This();

    pub fn init(ht: msg.HandshakeType) Self {
        return .{
            .ht = ht,
        };
    }

    pub fn decode(reader: anytype, ht: msg.HandshakeType) !Self {
        var res = Self.init(ht);

        // type is already read.
        var len = try reader.readIntBig(u16);
        switch (res.ht) {
            msg.HandshakeType.client_hello => {
                var supported_len = try reader.readIntBig(u8);
                assert(len == supported_len + 1);
                assert(supported_len % 2 == 0);

                //TODO: return error when the versions are not TLSv1.3
                assert(supported_len == 2); //only supports TLSv1.3
                var i: usize = 0;
                while (i < supported_len) : (i += 2) {
                    assert(res.version == try reader.readIntBig(u16)); //only suppoerts TLSv1.3
                }
            },
            msg.HandshakeType.server_hello => {
                assert(len == 2);
                res.version = try reader.readIntBig(u16);
            },
        }

        return res;
    }

    pub fn length(self: Self) usize {
        _ = self;
        var len: usize = 0;
        len += @sizeOf(u16); // type
        len += @sizeOf(u16); // length
        switch (self.ht) {
            msg.HandshakeType.client_hello => {
                len += @sizeOf(u8); // supported versions length
                len += @sizeOf(u16); // TLSv1.3 (0x0304)
            },
            msg.HandshakeType.server_hello => {
                len += @sizeOf(u16);
            },
        }
        return len;
    }

    pub fn print(self: Self) void {
        _ = self;
        log.debug("Extension: SupportedVersions({s})", .{@tagName(self.ht)});
        log.debug("- version = 0x{x:0>2}", .{self.version});
    }
};

const expect = std.testing.expect;

test "SupportedVersions decode" {
    const recv_data = [_]u8{ 0x00, 0x03, 0x02, 0x03, 0x04 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try SupportedVersions.decode(readStream.reader(), msg.HandshakeType.client_hello);
    try expect(res.ht == .client_hello);
    try expect(res.version == 0x0304);
}
