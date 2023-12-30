const std = @import("std");
const ArrayList = std.ArrayList;
const Extension = @import("extension.zig").Extension;

/// RFC6066 Section 3 Server Name Indication
///
/// enum {
///     host_name(0), (255)
/// } NameType;
///
pub const NameType = enum(u8) {
    host_name = 0,
};

/// RFC6066 Section 3 Server Name Indication
///
/// opaque HostName<1..2^16-1>;
///
/// struct {
///     NameType name_type;
///     select (name_type) {
///         case host_name: HostName;
///     } name;
/// } ServerName;
///
pub const ServerName = struct {
    name_type: NameType,
    host_name: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();

    const Error = error{
        UnsupportedNameType,
    };

    /// decode ServerName reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator to allocate host_name.
    /// @return decoded ServerName.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // Decoding name_type.
        const nt = @as(NameType, @enumFromInt(try reader.readByte()));
        if (nt != .host_name) {
            return Error.UnsupportedNameType;
        }

        // Decoding host_name.
        const name_len = try reader.readInt(u16, .big);
        const host_name = try allocator.alloc(u8, name_len);
        errdefer allocator.free(host_name);
        try reader.readNoEof(host_name);

        return Self{
            .name_type = nt,
            .host_name = host_name,
            .allocator = allocator,
        };
    }

    /// encode ServerName writing to io.Writer.
    /// @param self   ServerName to be encoded.
    /// @param writer io.Writer to write encoded ServerName.
    /// @return the length of encoded ServerName.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding name_type.
        try writer.writeInt(u8, @intFromEnum(self.name_type), .big);
        len += @sizeOf(NameType);

        // Encoding server_name_list.
        try writer.writeInt(u16, @as(u16, @intCast(self.host_name.len)), .big);
        len += @sizeOf(u16);
        try writer.writeAll(self.host_name);
        len += self.host_name.len;

        return len;
    }

    /// get the length of encoded ServerName.
    /// @param self ServerName to get the encoded length.
    /// @return the length of encoded ServerName.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(NameType);
        len += @sizeOf(u16); // length of host_name
        len += self.host_name.len;

        return len;
    }

    /// create ServerName from hostname string.
    /// @param host_name string for hostname.
    /// @param allocator allocator to allocate host_name.
    /// @return created ServerName.
    pub fn fromHostName(host_name: []const u8, allocator: std.mem.Allocator) !Self {
        const res = Self{
            .name_type = .host_name,
            .host_name = try allocator.alloc(u8, host_name.len),
            .allocator = allocator,
        };

        @memcpy(res.host_name, host_name);

        return res;
    }

    /// deinitialize ServerName.
    /// @param self ServerName to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.host_name);
    }

    pub fn print(self: Self) void {
        _ = self;
    }
};

/// RFC6066 Section 3 Server Name Indication
///
/// The "extension_data" field of this extension SHALL contain "ServerNameList".
/// struct {
///     ServerName server_name_list<1..2^16-1>
/// } ServerNameList;
///
pub const ServerNameList = struct {
    nothing: bool = false, // sometimes ServerNameList does not have contents.
    server_name_list: ArrayList(ServerName),

    const Self = @This();

    const Error = error{
        InvalidServerNameListLength,
    };

    /// initialize ServerNameList.
    /// @param allocator allocator to allocate ArrayList.
    /// @return initialized ServerNameList.
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .server_name_list = ArrayList(ServerName).init(allocator),
        };
    }

    /// deinitialize ServerNameList.
    /// @param self ServerNameList to be deinitialized.
    pub fn deinit(self: Self) void {
        for (self.server_name_list.items) |n| {
            n.deinit();
        }
        self.server_name_list.deinit();
    }

    /// decode ServerNameList reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param snl_len   the length of ServerNameList.
    /// @param allocator allocator to initialize ServerNameList.
    /// @return decoded ServerNameList.
    pub fn decode(reader: anytype, snl_len: usize, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        if (snl_len == 0) {
            res.nothing = true;
            return res;
        }

        // Decoding server_name_list.
        const len = try reader.readInt(u16, .big);
        var i: usize = 0;
        while (i < len) {
            const name = try ServerName.decode(reader, allocator);
            errdefer name.deinit();
            try res.server_name_list.append(name);
            i += name.length();
        }

        if (i != len) {
            return Error.InvalidServerNameListLength;
        }

        return res;
    }

    /// encode ServerNameList writing to io.Writer.
    /// @param self   ServerNameList to be encoded.
    /// @param writer io.Writer to write encoded ServerNameList.
    /// @return the length of encoded ServerNameList.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeInt(u16, @as(u16, @intCast(self.length() - @sizeOf(u16))), .big);
        len += @sizeOf(u16);
        for (self.server_name_list.items) |n| {
            len += try n.encode(writer);
        }

        return len;
    }

    /// get the length of encoded ServerNameList.
    /// @param self ServerNameList to get the encoded length.
    /// @return the length encoded ServerNameList.
    pub fn length(self: Self) usize {
        if (self.nothing) {
            return 0;
        }

        var len: usize = 0;
        len += @sizeOf(u16);
        for (self.server_name_list.items) |n| {
            len += n.length();
        }

        return len;
    }
};

const io = std.io;
const expect = std.testing.expect;

test "Extension ServerNameList decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e,
    0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Extension.decode(readStream.reader(), std.testing.allocator, .server_hello, false);
    defer res.deinit();
    try expect(res == .server_name);
    const snl = res.server_name;

    try expect(snl.server_name_list.items.len == 1);
    const sn = snl.server_name_list.items[0];
    try expect(std.mem.eql(u8, sn.host_name, "www.google.com"));
}

test "Extension ServerNameList encode" {
    const sn = try ServerName.fromHostName("www.google.com", std.testing.allocator);
    var snl = ServerNameList.init(std.testing.allocator);
    try snl.server_name_list.append(sn);
    const ext = Extension{ .server_name = snl };
    defer ext.deinit();

    // zig fmt: off
    const sn_ans = [_]u8{
    0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e,
    0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    };
    // zig fmt: on

    var send_bytes: [100]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try ext.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &sn_ans));
}
