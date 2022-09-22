const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const msg = @import("msg.zig");
const ArrayList = std.ArrayList;
const NamedGroup = @import("supported_groups.zig").NamedGroup;
const HandshakeType = @import("handshake.zig").HandshakeType;
const Extension = @import("extension.zig").Extension;

/// RFC8446 Section 4.2.8 Key Share
///
/// struct {
///     KeyShareEntry client_shares<0..2^16-1>;
/// } KeyShareClientHello;
///
/// struct {
///     NamedGroup selected_group;
/// } KeyShareHelloRetryRequest;
///
/// struct {
///     KeyShareEntry server_share;
/// } KeyShareServerHello;
///
pub const KeyShare = struct {
    entries: ArrayList(KeyShareEntry), // for ClientHello, ServerHello
    selected: NamedGroup = .x25519, // for HelloRetryRequest
    grease_length: usize = 0,

    ht: HandshakeType = undefined,
    is_hello_retry_request: bool = false,
    const Self = @This();

    const Error = error{
        InvalidKeyShareLength,
    };

    /// initialize KeyShare.
    /// @param allocator   allocator to allocate ArrayList.
    /// @param ht          HandshakeType.
    /// @param hello_retry is KeyShare contained in HelloRetryRequest.
    /// @return initialized KeyShare.
    pub fn init(allocator: std.mem.Allocator, ht: HandshakeType, hello_retry: bool) Self {
        return .{
            .entries = ArrayList(KeyShareEntry).init(allocator),
            .ht = ht,
            .is_hello_retry_request = hello_retry,
        };
    }

    /// decode KeyShare reading from io.Reader.
    /// @param reader      io.Reader to read messages.
    /// @param allocator   allocator to initialize KeyShare.
    /// @param ht          HandshakeType.
    /// @param hello_retry is KeyShare contained in HelloRetryRequest.
    /// @return decoded KeyShare.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator, ht: HandshakeType, hello_retry: bool) !Self {
        var res = Self.init(allocator, ht, hello_retry);
        errdefer res.deinit();

        // Structure of KeyShare varies based on HandshakeType.
        switch (res.ht) {
            HandshakeType.client_hello => {
                // Decoding KeyShareEntries.
                const ks_len = try reader.readIntBig(u16);
                var i: usize = 0;
                while (i < ks_len) {
                    const kse = try KeyShareEntry.decode(reader, allocator);
                    errdefer kse.deinit();
                    if (kse.group != .none) {
                        try res.entries.append(kse);
                    } else {
                        // if the KeyShareEntry is meaningless, it may be GREASE.
                        res.grease_length += kse.length();
                    }
                    i += kse.length();
                }

                // Checking all data has been decoded.
                if (i != ks_len) {
                    return Error.InvalidKeyShareLength;
                }
            },
            HandshakeType.server_hello => {
                if (res.is_hello_retry_request) {
                    // Decoding NamedGroup.
                    res.selected = @intToEnum(NamedGroup, try reader.readIntBig(u16));
                } else {
                    // Decoding a KeyShareEntry
                    const kse = try KeyShareEntry.decode(reader, allocator);
                    errdefer kse.deinit();
                    try res.entries.append(kse);
                }
            },
            else => unreachable,
        }

        return res;
    }

    // encode KeyShare writing to io.Writer.
    // @param self   KeyShare to be encoded.
    // @param writer io.Writer to write encoded KeyShare.
    // @return length of encoded KeyShare.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Structure of KeyShare varies based on HandshakeType.
        switch (self.ht) {
            HandshakeType.client_hello => {
                // Encoding KeyShareEntries.
                try writer.writeIntBig(u16, @intCast(u16, self.length() - @sizeOf(u16))); // entire length - sizeOf(field:'len')
                len += @sizeOf(u16);
                for (self.entries.items) |entry| {
                    len += try entry.encode(writer);
                }
            },
            HandshakeType.server_hello => {
                if (self.is_hello_retry_request) {
                    // Encoding NamedGroup.
                    try writer.writeIntBig(u16, @enumToInt(self.selected));
                    len += @sizeOf(NamedGroup);
                } else {
                    // Encoding KeyShareEntry.
                    len += try self.entries.items[0].encode(writer);
                }
            },
            else => unreachable,
        }

        return len;
    }

    /// get the length of encoded KeyShare.
    /// @param self the target KeyShare.
    /// @return length of encoded KeyShare.
    pub fn length(self: Self) usize {
        var len: usize = self.grease_length;
        // Structure of KeyShare varies based on HandshakeType.
        switch (self.ht) {
            HandshakeType.client_hello => {
                len += @sizeOf(u16); // entries length
                for (self.entries.items) |entry| {
                    len += entry.length();
                }
            },
            HandshakeType.server_hello => {
                if (self.is_hello_retry_request) {
                    // NamedGroup
                    len += @sizeOf(u16);
                } else {
                    // KeyShareEntry
                    len += self.entries.items[0].length();
                }
            },
            else => unreachable,
        }
        return len;
    }

    /// deinitailize KeyShare.
    /// @param self KeyShare to be deinitialized.
    pub fn deinit(self: Self) void {
        for (self.entries.items) |e| {
            e.deinit();
        }
        self.entries.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("Extension: KeyShare({s})", .{@tagName(self.ht)});
        if (self.is_hello_retry_request) {
            log.debug("- SelectedGroup = {s}(0x{x:0>4})", .{ @tagName(self.selected), @enumToInt(self.selected) });
        } else {
            for (self.entries.items) |e| {
                e.print();
            }
        }
    }
};

/// RFC8446 Section 4.2.8 Key Share
///
/// struct {
///     NamedGroup group;
///     opaque key_exchange<1..2^16-1>;
/// } KeyShareEntry;
///
pub const KeyShareEntry = struct {
    group: NamedGroup,
    key_exchange: []u8,

    allocator: std.mem.Allocator,

    const Self = @This();
    pub const Error = error{
        InvalidKeyExchangeLength,
    };

    /// initialize KeyShareentry.
    /// @param group     NamedGroup of key.
    /// @param key_len   key_exchange length.
    /// @param allocator allocator to allocate key_exchange.
    /// @return initialized KeyShareEntry.
    pub fn init(group: NamedGroup, key_len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .group = group,
            .key_exchange = try allocator.alloc(u8, key_len),
            .allocator = allocator,
        };
    }

    /// decode KeyShareEntry reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator to allocate key_exchange.
    /// @return decoded KeyShareEntry.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // Decoding group.
        // NamedGroup.none is for GREASE.
        const t = reader.readEnum(NamedGroup, .Big) catch NamedGroup.none;

        // Decoding key_exchange.
        const len = try reader.readIntBig(u16);
        var ke = try allocator.alloc(u8, len);
        errdefer allocator.free(ke);
        try reader.readNoEof(ke);

        return Self{
            .group = t,
            .key_exchange = ke,
            .allocator = allocator,
        };
    }

    /// encode KeyShareEntry writing to io.Writer.
    /// @param self   KeyShareEntry to be encoded.
    /// @param writer io.Writer to write encoded KeyShareEntry.
    /// @return length of encoded KeyShareEntry.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding group.
        try writer.writeIntBig(u16, @enumToInt(self.group));
        len += @sizeOf(u16);

        // Encoding key_exchange.
        try writer.writeIntBig(u16, @intCast(u16, self.key_exchange.len));
        len += @sizeOf(u16);
        try writer.writeAll(self.key_exchange);
        len += self.key_exchange.len;

        return len;
    }

    // get the length of encoded KeyShareEntry.
    // @param self the target KeyShareEntry.
    // @return length of encoded KeyShareEntry.
    pub fn length(self: Self) usize {
        var len: usize = @sizeOf(u16); // type
        len += @sizeOf(u16); // length
        len += self.key_exchange.len;
        return len;
    }

    // deinitialize KeyShareEntry.
    // @param self KeyShareEntry to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.key_exchange);
    }

    pub fn print(self: Self) void {
        log.debug("key = {}", .{std.fmt.fmtSliceHexLower(self.key_exchange)});
    }
};

const expect = std.testing.expect;

test "Extension KeyShare with EntryX25519 decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x6c, 0xc8,
    0x42, 0x40, 0x7f, 0x7e, 0x62, 0xad, 0x5c, 0xd3, 0x92, 0x97, 0xf7, 0x7f, 0xfc,
    0x6c, 0x72, 0x83, 0xba, 0xcb, 0x89, 0x4b, 0x58, 0x20, 0x16, 0x24, 0xae, 0x27,
    0xbe, 0x87, 0x2f
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const res = (try Extension.decode(readStream.reader(), std.testing.allocator, .client_hello, false)).key_share;
    defer res.deinit();
    try expect(res.entries.items.len == 1);
    const x25519 = res.entries.items[0];
    try expect(x25519.group == .x25519);

    // zig fmt: off
    const key_exchg_ans = [_]u8{
    0x49, 0x6c, 0xc8, 0x42, 0x40, 0x7f, 0x7e, 0x62, 0xad, 0x5c, 0xd3, 0x92, 0x97,
    0xf7, 0x7f, 0xfc, 0x6c, 0x72, 0x83, 0xba, 0xcb, 0x89, 0x4b, 0x58, 0x20, 0x16,
    0x24, 0xae, 0x27, 0xbe, 0x87, 0x2f
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, x25519.key_exchange, &key_exchg_ans));
}

test "Extension KeyShare with EntryX25519 encode" {
    var res = try KeyShareEntry.init(.x25519, 32, std.testing.allocator);

    // zig fmt: off
    const key = [_]u8{
    0x49, 0x6c, 0xc8, 0x42, 0x40, 0x7f, 0x7e, 0x62, 0xad, 0x5c, 0xd3, 0x92, 0x97,
    0xf7, 0x7f, 0xfc, 0x6c, 0x72, 0x83, 0xba, 0xcb, 0x89, 0x4b, 0x58, 0x20, 0x16,
    0x24, 0xae, 0x27, 0xbe, 0x87, 0x2f
    };
    // zig fmt: on

    std.mem.copy(u8, res.key_exchange, &key);
    var ext = Extension{ .key_share = KeyShare.init(std.testing.allocator, .client_hello, false) };
    defer ext.deinit();
    try ext.key_share.entries.append(res);

    var send_bytes: [100]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try ext.encode(stream.writer());

    // zig fmt: off
    const ext_ans = [_]u8{
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x49, 0x6c, 0xc8,
    0x42, 0x40, 0x7f, 0x7e, 0x62, 0xad, 0x5c, 0xd3, 0x92, 0x97, 0xf7, 0x7f, 0xfc,
    0x6c, 0x72, 0x83, 0xba, 0xcb, 0x89, 0x4b, 0x58, 0x20, 0x16, 0x24, 0xae, 0x27,
    0xbe, 0x87, 0x2f
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, send_bytes[0..write_len], &ext_ans));
}

test "EntrySecp256r1 decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x00, 0x17, 0x00, 0x41, 0x04, 0xf9, 0x38, 0x90, 0xa1, 0x01, 0x82, 0xe6, 0xe4,
    0xd9, 0x85, 0x60, 0x3a, 0x43, 0x35, 0xfa, 0x77, 0x68, 0x3f, 0x87, 0x69, 0x37,
    0xd5, 0xde, 0xda, 0x19, 0x35, 0x1a, 0x7b, 0xbe, 0x21, 0x93, 0x0e, 0x21, 0xf2,
    0xe5, 0xf4, 0x18, 0xa3, 0x9d, 0xc1, 0xfb, 0x2f, 0xab, 0xdd, 0x0a, 0xdb, 0x45,
    0x9d, 0x79, 0x7f, 0xb9, 0x59, 0x14, 0xb6, 0xe5, 0xda, 0x62, 0xf9, 0xdd, 0x93,
    0x20, 0xe7, 0x86, 0xf8
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const res = try KeyShareEntry.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.group == .secp256r1);

    // zig fmt: off
    const key_exchg_ans = [_]u8{
    0x04, 0xf9, 0x38, 0x90, 0xa1, 0x01, 0x82, 0xe6, 0xe4, 0xd9, 0x85, 0x60, 0x3a,
    0x43, 0x35, 0xfa, 0x77, 0x68, 0x3f, 0x87, 0x69, 0x37, 0xd5, 0xde, 0xda, 0x19,
    0x35, 0x1a, 0x7b, 0xbe, 0x21, 0x93, 0x0e, 0x21, 0xf2, 0xe5, 0xf4, 0x18, 0xa3,
    0x9d, 0xc1, 0xfb, 0x2f, 0xab, 0xdd, 0x0a, 0xdb, 0x45, 0x9d, 0x79, 0x7f, 0xb9,
    0x59, 0x14, 0xb6, 0xe5, 0xda, 0x62, 0xf9, 0xdd, 0x93, 0x20, 0xe7, 0x86, 0xf8
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, res.key_exchange, &key_exchg_ans));
}

test "EntrySecp256r1 encode" {
    // zig fmt: off
    const key = [_]u8{
    0x04, 0xf9, 0x38, 0x90, 0xa1, 0x01, 0x82, 0xe6, 0xe4, 0xd9, 0x85, 0x60, 0x3a,
    0x43, 0x35, 0xfa, 0x77, 0x68, 0x3f, 0x87, 0x69, 0x37, 0xd5, 0xde, 0xda, 0x19,
    0x35, 0x1a, 0x7b, 0xbe, 0x21, 0x93, 0x0e, 0x21, 0xf2, 0xe5, 0xf4, 0x18, 0xa3,
    0x9d, 0xc1, 0xfb, 0x2f, 0xab, 0xdd, 0x0a, 0xdb, 0x45, 0x9d, 0x79, 0x7f, 0xb9,
    0x59, 0x14, 0xb6, 0xe5, 0xda, 0x62, 0xf9, 0xdd, 0x93, 0x20, 0xe7, 0x86, 0xf8
    };
    // zig fmt: on

    var res = try KeyShareEntry.init(.secp256r1, key.len, std.testing.allocator);
    defer res.deinit();

    std.mem.copy(u8, res.key_exchange, &key);

    var send_bytes: [100]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());

    // zig fmt: off
    const secp256r1_ans = [_]u8{
    0x00, 0x17, 0x00, 0x41, 0x04, 0xf9, 0x38, 0x90, 0xa1, 0x01, 0x82, 0xe6, 0xe4,
    0xd9, 0x85, 0x60, 0x3a, 0x43, 0x35, 0xfa, 0x77, 0x68, 0x3f, 0x87, 0x69, 0x37,
    0xd5, 0xde, 0xda, 0x19, 0x35, 0x1a, 0x7b, 0xbe, 0x21, 0x93, 0x0e, 0x21, 0xf2,
    0xe5, 0xf4, 0x18, 0xa3, 0x9d, 0xc1, 0xfb, 0x2f, 0xab, 0xdd, 0x0a, 0xdb, 0x45,
    0x9d, 0x79, 0x7f, 0xb9, 0x59, 0x14, 0xb6, 0xe5, 0xda, 0x62, 0xf9, 0xdd, 0x93,
    0x20, 0xe7, 0x86, 0xf8
    };
    // zig fmt: on

    try expect(std.mem.eql(u8, send_bytes[0..write_len], &secp256r1_ans));
}
