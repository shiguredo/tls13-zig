const std = @import("std");
const log = std.log;
const io = std.io;
const assert = std.debug.assert;
const hmac = std.crypto.auth.hmac;
const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;

const crypto = @import("crypto.zig");
const Extension = @import("extension.zig").Extension;
const ExtensionType = @import("extension.zig").ExtensionType;
const ServerHello = @import("server_hello.zig").ServerHello;
const ClientHello = @import("client_hello.zig").ClientHello;
const Finished = @import("finished.zig").Finished;
const Handshake = @import("handshake.zig").Handshake;
const HandshakeType = @import("handshake.zig").HandshakeType;

pub const CipherSuite = enum(u16) {
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_CCM_SHA256 = 0x1304,
    TLS_AES_128_CCM_8_SHA256 = 0x1305,

    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x0,
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
        var res = try Self.init(try reader.readIntBig(u8));
        _ = try reader.readAll(res.session_id.slice());

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u8, @intCast(u8, self.session_id.len));
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
    var len: usize = try reader.readIntBig(u16);
    assert(len % 2 == 0);

    var i: usize = 0;
    while (i < len) : (i += @sizeOf(u16)) {
        try suites.append(@intToEnum(CipherSuite, try reader.readIntBig(u16)));
    }

    assert(i == len);
}

pub fn encodeCipherSuites(writer: anytype, suites: ArrayList(CipherSuite)) !usize {
    var len: usize = 0;
    try writer.writeIntBig(u16, @intCast(u16, suites.items.len * @sizeOf(CipherSuite)));
    len += @sizeOf(u16);

    for (suites.items) |suite| {
        try writer.writeIntBig(u16, @enumToInt(suite));
        len += @sizeOf(CipherSuite);
    }

    return len;
}

pub fn decodeExtensions(reader: anytype, allocator: std.mem.Allocator, extensions: *ArrayList(Extension), ht: HandshakeType, is_hello_retry: bool) !void {
    const ext_len = try reader.readIntBig(u16);
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
    try writer.writeIntBig(u16, @intCast(u16, ext_len));
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
