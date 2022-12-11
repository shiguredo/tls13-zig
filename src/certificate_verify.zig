const std = @import("std");
const io = std.io;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectError = std.testing.expectError;

const log = @import("log.zig");
const SignatureScheme = @import("signature_scheme.zig").SignatureScheme;

/// RFC8446 Section 4.4.3 Certificate Verify
///
/// struct {
///     SignatureScheme algorithm;
///     opaque signature<0..2^16-1>;
/// } CertificateVerify;
///
pub const CertificateVerify = struct {
    algorithm: SignatureScheme,
    signature: []u8 = &([_]u8{}),

    allocator: std.mem.Allocator,

    const Self = @This();

    /// initialize CertificateVerify.
    /// @param algo      algorithm used to sign.
    /// @param sig_len   the length of signature.
    /// @param allocator allocator to allocate CertificateVerify.
    /// @return initialized CertificateVerify.
    pub fn init(algo: SignatureScheme, sig_len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .algorithm = algo,
            .signature = try allocator.alloc(u8, sig_len),
            .allocator = allocator,
        };
    }

    /// decode CertificateVerify message reading from io.Reader
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator for each handshake mssage.
    /// @return the result of decoded CertificateVerify.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // Decoding SignatureAlgorithm.
        const algorithm = @intToEnum(SignatureScheme, try reader.readIntBig(u16));

        // Decoding signature.
        const sig_len = try reader.readIntBig(u16);
        var signature = try allocator.alloc(u8, sig_len);
        errdefer allocator.free(signature);
        try reader.readNoEof(signature);

        return Self{
            .algorithm = algorithm,
            .signature = signature,
            .allocator = allocator,
        };
    }

    /// encode CertificateVerify message writing to io.Writer.
    /// @param self   CertificateVerify to be encoded.
    /// @param writer io.Writer to write encoded CertificateVerify.
    /// @return the length of encoded CertificateVerify.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding algorithm.
        try writer.writeIntBig(u16, @enumToInt(self.algorithm));
        len += 2;

        // Encoding signature.
        try writer.writeIntBig(u16, @intCast(u16, self.signature.len));
        len += 2;
        try writer.writeAll(self.signature);
        len += self.signature.len;

        return len;
    }

    /// get length of encoded CertificateVerify.
    /// @param self the target CertificateVerify.
    /// @return length of encoded CertificateVerify.
    pub fn length(self: Self) usize {
        var len: usize = 0;

        len += @sizeOf(SignatureScheme); // signature algorithm
        len += @sizeOf(u16); // signature length
        len += self.signature.len;

        return len;
    }

    /// deinitialize CertificateVerify.
    /// @param self deinitialized CertificateVerify.
    pub fn deinit(self: Self) void {
        if (self.signature.len != 0) {
            self.allocator.free(self.signature);
        }
    }
};

test "CertificateVerify decode & encode" {
    const Handshake = @import("handshake.zig").Handshake;

    // zig fmt: off
    const recv_data = [_]u8{
    0x0F, 0x00, 0x00, 0x84, 0x08, 0x04, 0x00, 0x80, 0x5A, 0x74, 0x7C, 0x5D, 0x88,
    0xFA, 0x9B, 0xD2, 0xE5, 0x5A, 0xB0, 0x85, 0xA6, 0x10, 0x15, 0xB7, 0x21, 0x1F,
    0x82, 0x4C, 0xD4, 0x84, 0x14, 0x5A, 0xB3, 0xFF, 0x52, 0xF1, 0xFD, 0xA8, 0x47,
    0x7B, 0x0B, 0x7A, 0xBC, 0x90, 0xDB, 0x78, 0xE2, 0xD3, 0x3A, 0x5C, 0x14, 0x1A,
    0x07, 0x86, 0x53, 0xFA, 0x6B, 0xEF, 0x78, 0x0C, 0x5E, 0xA2, 0x48, 0xEE, 0xAA,
    0xA7, 0x85, 0xC4, 0xF3, 0x94, 0xCA, 0xB6, 0xD3, 0x0B, 0xBE, 0x8D, 0x48, 0x59,
    0xEE, 0x51, 0x1F, 0x60, 0x29, 0x57, 0xB1, 0x54, 0x11, 0xAC, 0x02, 0x76, 0x71,
    0x45, 0x9E, 0x46, 0x44, 0x5C, 0x9E, 0xA5, 0x8C, 0x18, 0x1E, 0x81, 0x8E, 0x95,
    0xB8, 0xC3, 0xFB, 0x0B, 0xF3, 0x27, 0x84, 0x09, 0xD3, 0xBE, 0x15, 0x2A, 0x3D,
    0xA5, 0x04, 0x3E, 0x06, 0x3D, 0xDA, 0x65, 0xCD, 0xF5, 0xAE, 0xA2, 0x0D, 0x53,
    0xDF, 0xAC, 0xD4, 0x2F, 0x74, 0xF3
    };
    // zig fmt: on
    var enc_data: [recv_data.len]u8 = undefined;
    var readStream = io.fixedBufferStream(&recv_data);
    var writeStream = io.fixedBufferStream(&enc_data);

    const res = try Handshake.decode(readStream.reader(), std.testing.allocator, null);
    defer res.deinit();

    // check all data was read.
    try expectError(error.EndOfStream, readStream.reader().readByte());

    try expect(res == .certificate_verify);

    _ = try res.encode(writeStream.writer());
    try expect(std.mem.eql(u8, &recv_data, &enc_data));
}
