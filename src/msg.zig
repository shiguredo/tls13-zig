const std = @import("std");

pub const HandshakeType = enum(u8) {
    client_hello = 0x1,
    server_hello = 0x2,
};