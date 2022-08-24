const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const NamedGroup = @import("msg.zig").NamedGroup;

pub const SupportedGroups = struct {
    groups: ArrayList(NamedGroup) = undefined,

    const Self = @This();

    const Error = error {
        InvalidGroupLength,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .groups = ArrayList(NamedGroup).init(allocator),
        };
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        const group_len = try reader.readIntBig(u16);
        if (group_len % 2 != 0) {
            return Error.InvalidGroupLength;
        }

        var i: usize = 0;
        while (i < group_len) : (i += 2) {
            try res.groups.append(@intToEnum(NamedGroup, try reader.readIntBig(u16)));
        }

        return res;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // supported groups length
        len += self.groups.items.len * @sizeOf(NamedGroup);
        return len;
    }

    pub fn deinit(self: Self) void {
        self.groups.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("Extension: SupportedGroups", .{});
        for (self.groups.items) |group| {
            log.debug("- {s}(0x{x:0>4})", .{ @tagName(group), @enumToInt(group) });
        }
    }
};

const expect = std.testing.expect;

test "SupportedGroups decode" {
    const recv_data = [_]u8{0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try SupportedGroups.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.groups.items.len == 5);
    try expect(res.groups.items[0] == .x25519);
    try expect(res.groups.items[1] == .secp256r1);
    try expect(res.groups.items[2] == .x448);
    try expect(res.groups.items[3] == .secp521r1);
    try expect(res.groups.items[4] == .secp384r1);
}
