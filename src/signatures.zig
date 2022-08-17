const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const ArrayList = std.ArrayList;

pub const SignatureAlgorithm = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
};

pub const SignatureAlgorithms = struct {
    algos:ArrayList(SignatureAlgorithm) = undefined,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .algos = ArrayList(SignatureAlgorithm).init(allocator),
        };
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);

        // type is already read
        const len = try reader.readIntBig(u16);
        const algos_len = try reader.readIntBig(u16);
        assert(len == algos_len + 2);
        assert(algos_len % 2 == 0);

        var i:usize = 0;
        while (i < algos_len) : (i += 2) {
            try res.algos.append(@intToEnum(SignatureAlgorithm, try reader.readIntBig(u16)));
        }

        return res;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // type
        len += @sizeOf(u16); // length
        len += @sizeOf(u16); // supported groups length
        len += self.algos.items.len * @sizeOf(SignatureAlgorithm);
        return len;
    }

    pub fn deinit(self: *Self) void {
        self.algos.deinit();
    }

    pub fn print(self: Self) void {
        log.debug("Extension: SignatureAlgrotihms", .{});
        for (self.algos.items) |algo| {
            log.debug("- {s}(0x{x:0>4})", .{@tagName(algo), @enumToInt(algo)});
        }
    }
};

const expect = std.testing.expect;

test "SignatureAlgorithms decode" {
    const recv_data = [_]u8{0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03,0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01};
    var readStream = io.fixedBufferStream(&recv_data);

    var res = try SignatureAlgorithms.decode(readStream.reader(), std.testing.allocator);
    defer res.deinit();

    try expect(res.algos.items.len == 14);
    try expect(res.algos.items[0] == .ecdsa_secp256r1_sha256);
    try expect(res.algos.items[1] == .ecdsa_secp384r1_sha384);
    try expect(res.algos.items[2] == .ecdsa_secp521r1_sha512);
    try expect(res.algos.items[3] == .ed25519);
    try expect(res.algos.items[4] == .ed448);
    try expect(res.algos.items[5] == .rsa_pss_pss_sha256);
    try expect(res.algos.items[6] == .rsa_pss_pss_sha384);
    try expect(res.algos.items[7] == .rsa_pss_pss_sha512);
    try expect(res.algos.items[8] == .rsa_pss_rsae_sha256);
    try expect(res.algos.items[9] == .rsa_pss_rsae_sha384);
    try expect(res.algos.items[10] == .rsa_pss_rsae_sha512);
    try expect(res.algos.items[11] == .rsa_pkcs1_sha256);
    try expect(res.algos.items[12] == .rsa_pkcs1_sha384);
    try expect(res.algos.items[13] == .rsa_pkcs1_sha512);
}