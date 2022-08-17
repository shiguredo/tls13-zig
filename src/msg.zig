const std = @import("std");

pub const HandshakeType = enum(u8) {
    client_hello = 0x1,
    server_hello = 0x2,
};

pub const NamedGroup = enum(u16) {
    x25519 = 0x001D,
    x448 = 0x001e,
    secp256r1 = 0x0017,
    secp521r1 = 0x0019,
    secp384r1 = 0x0018,
};
