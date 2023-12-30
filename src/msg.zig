const std = @import("std");
const log = @import("log.zig");
const assert = std.debug.assert;
const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;

const utils = @import("utils.zig");
const Extension = @import("extension.zig").Extension;
const ExtensionType = @import("extension.zig").ExtensionType;
const HandshakeType = @import("handshake.zig").HandshakeType;

pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff,
};

pub const SessionID = struct {
    const MAX_SESSIONID_LENGTH = 32;

    session_id: BoundedArray(u8, MAX_SESSIONID_LENGTH),

    const Self = @This();

    pub fn init(len: usize) !Self {
        return Self{
            .session_id = try BoundedArray(u8, 32).init(len),
        };
    }

    pub fn decode(reader: anytype) !Self {
        var res = try Self.init(try reader.readInt(u8, .big));
        _ = try reader.readAll(res.session_id.slice());

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeInt(u8, @as(u8, self.session_id.len), .big);
        len += @sizeOf(u8);

        try writer.writeAll(self.session_id.slice());
        len += self.session_id.len;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8);
        len += self.session_id.len;

        return len;
    }

    pub fn print(self: Self) void {
        log.debug("SessionID", .{});
        log.debug("- id = {}", .{std.fmt.fmtSliceHexLower(&self.session_id.slice())});
    }
};

pub fn decodeCipherSuites(reader: anytype, suites: *ArrayList(CipherSuite)) !void {
    const len: usize = try reader.readInt(u16, .big);
    assert(len % 2 == 0);

    var i: usize = 0;
    while (i < len) : (i += @sizeOf(u16)) {
        const cs_raw = try reader.readInt(u16, .big);
        const cs = utils.intToEnum(CipherSuite, cs_raw) catch {
            log.warn("Unknown CipherSuite 0x{x:0>4}", .{cs_raw});
            continue;
        };
        try suites.append(cs);
    }

    assert(i == len);
}

pub fn encodeCipherSuites(writer: anytype, suites: ArrayList(CipherSuite)) !usize {
    var len: usize = 0;
    try writer.writeInt(u16, @as(u16, @intCast(suites.items.len * @sizeOf(CipherSuite))), .big);
    len += @sizeOf(u16);

    for (suites.items) |suite| {
        try writer.writeInt(u16, @intFromEnum(suite), .big);
        len += @sizeOf(CipherSuite);
    }

    return len;
}

pub fn decodeExtensions(reader: anytype, allocator: std.mem.Allocator, extensions: *ArrayList(Extension), ht: HandshakeType, is_hello_retry: bool) !void {
    errdefer {
        for (extensions.items) |e| {
            e.deinit();
        }
    }
    const ext_len = try reader.readInt(u16, .big);
    var i: usize = 0;
    while (i < ext_len) {
        var ext = try Extension.decode(reader, allocator, ht, is_hello_retry);
        try extensions.append(ext);
        i += ext.length();
    }
    assert(i == ext_len);
}

pub fn encodeExtensions(writer: anytype, extensions: ArrayList(Extension)) !usize {
    var ext_len: usize = 0;
    for (extensions.items) |ext| {
        ext_len += ext.length();
    }

    var len: usize = 0;
    try writer.writeInt(u16, @as(u16, @intCast(ext_len)), .big);
    len += @sizeOf(u16);

    for (extensions.items) |ext| {
        len += try ext.encode(writer);
    }

    return len;
}

pub const ExtensionError = error{
    ExtensionNotFound,
};

pub const DecodeError = error{
    HashNotSpecified,
    NotAllDecoded,
};

pub fn getExtension(extensions: ArrayList(Extension), ext_type: ExtensionType) !Extension {
    for (extensions.items) |e| {
        if (e == ext_type) {
            return e;
        }
    }

    return ExtensionError.ExtensionNotFound;
}
