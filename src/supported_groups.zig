const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;

/// RFC8446 Section 4.2.7 Supported Groups
///
/// enum {
///
///     /* Elliptic Curve Groups (ECDHE) */
///     secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
///     x25519(0x001D), x448(0x001E),
///
///     /* Finite Field Groups (DHE) */
///     ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
///     ffdhe6144(0x0103), ffdhe8192(0x0104),
///
///     /* Reserved Code Points */
///     ffdhe_private_use(0x01FC..0x01FF),
///     ecdhe_private_use(0xFE00..0xFEFF),
///     (0xFFFF)
/// } NamedGroup;
///
pub const NamedGroup = enum(u16) {
    x25519 = 0x001D,
    x448 = 0x001e,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,

    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,

    none = 0xfff,
};

/// RFC8446 Section 4.2.7 Supported Groups
///
/// struct {
///     NamedGroup named_group_list<2..2^16-1>;
/// } NamedGroupList;
///
pub const NamedGroupList = struct {
    groups: ArrayList(NamedGroup) = undefined,
    grease_length: usize = 0,

    const Self = @This();

    const Error = error{
        InvalidGroupLength,
    };

    /// initialize NamedGroupList.
    /// @param allocator allocator to allocate ArrayList.
    /// @return initialized NamedGroupList.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .groups = ArrayList(NamedGroup).init(allocator),
        };
    }

    /// decode NamedGroupList reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator to initialize NamedGroupList.
    /// @return decoded NamedGroupList.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        // Decoding NamedGroups.
        const group_len = try reader.readIntBig(u16);
        if (group_len % 2 != 0) {
            return Error.InvalidGroupLength;
        }
        var i: usize = 0;
        while (i < group_len) : (i += 2) {
            const ng = reader.readEnum(NamedGroup, .Big) catch {
                // if the value is not NamedGroup, it may be GREASE.
                res.grease_length += 2;
                continue;
            };
            try res.groups.append(ng);
        }

        return res;
    }

    /// encode NamedGroupList writing to io.Writer.
    /// @param self   NamedGroupList to be encoded.
    /// @param writer io.Writer to write encoded NamedGroupList.
    /// @return length of encoded NamedGroupList.
    pub fn encode(self: Self, writer: anytype) !usize {
        // Encoding NamedGroups.
        var len: usize = 0;
        try writer.writeIntBig(u16, @intCast(u16, self.groups.items.len * @sizeOf(NamedGroup)));
        len += @sizeOf(u16);
        for (self.groups.items) |e| {
            try writer.writeIntBig(u16, @enumToInt(e));
            len += @sizeOf(NamedGroup);
        }

        return len;
    }

    /// get the length of encoded NamedGroupList.
    /// @param self the target NamedGroupList.
    /// @return length of encoded NamedGroupList.
    pub fn length(self: Self) usize {
        var len: usize = self.grease_length;
        len += @sizeOf(u16); // supported groups length
        len += self.groups.items.len * @sizeOf(NamedGroup);
        return len;
    }

    /// deinitialize NamedGroupList.
    /// @param self NamedGroupList to be deinitialized.
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

test "NamedGroupList decode" {
    const recv_data = [_]u8{ 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try NamedGroupList.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.groups.items.len == 5);
    try expect(res.groups.items[0] == .x25519);
    try expect(res.groups.items[1] == .secp256r1);
    try expect(res.groups.items[2] == .x448);
    try expect(res.groups.items[3] == .secp521r1);
    try expect(res.groups.items[4] == .secp384r1);
}

test "NamedGroupList encode" {
    var res = NamedGroupList.init(std.testing.allocator);
    defer res.deinit();

    try res.groups.append(.x25519);
    try res.groups.append(.secp256r1);
    try res.groups.append(.x448);
    try res.groups.append(.secp521r1);
    try res.groups.append(.secp384r1);

    const groups_ans = [_]u8{ 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18 };
    var send_bytes: [100]u8 = undefined;

    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &groups_ans));
}
