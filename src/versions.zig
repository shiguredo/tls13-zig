const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const msg = @import("msg.zig");
const ArrayList = std.ArrayList;

pub const SupportedVersions = struct {
    versions: ArrayList(u16) = undefined,
    ht: msg.HandshakeType = undefined,

    const Self = @This();

    const Error = error{
        InvalidVersionsLength,
    };

    pub fn init(ht: msg.HandshakeType, allocator: std.mem.Allocator) Self {
        return .{
            .versions = ArrayList(u16).init(allocator),
            .ht = ht,
        };
    }

    pub fn deinit(self: Self) void {
        self.versions.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator, ht: msg.HandshakeType) !Self {
        var res = Self.init(ht, allocator);
        errdefer res.deinit();

        switch (res.ht) {
            msg.HandshakeType.client_hello => {
                var supported_len = try reader.readIntBig(u8);

                if (supported_len % 2 != 0) {
                    return Error.InvalidVersionsLength;
                }

                var i: usize = 0;
                while (i < supported_len) : (i += 2) {
                    try res.versions.append(try reader.readIntBig(u16));
                }
            },
            msg.HandshakeType.server_hello => {
                try res.versions.append(try reader.readIntBig(u16));
            },
            else => unreachable,
        }

        return res;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        switch (self.ht) {
            msg.HandshakeType.client_hello => {
                len += @sizeOf(u8); // supported versions length
                len += self.versions.items.len * @sizeOf(u16);
            },
            msg.HandshakeType.server_hello => {
                len += @sizeOf(u16); // version
            },
            else => unreachable,
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
    const recv_data = [_]u8{ 0x02, 0x03, 0x04 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try SupportedVersions.decode(readStream.reader(), std.testing.allocator, .client_hello);
    defer res.deinit();
    try expect(res.ht == .client_hello);
    try expect(res.versions.items[0] == 0x0304);
}
