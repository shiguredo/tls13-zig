const std = @import("std");
const io = std.io;
const crypto = @import("crypto.zig");
const Handshake = @import("handshake.zig").Handshake;
const Hkdf = crypto.Hkdf;
const DigestBoundedArray = crypto.DigestBoundedArray;

/// RFC8446 Section 4.4.4 Finished
///
/// struct {
///     opaque verify_data[Hash.length];
/// } Finished;
///
pub const Finished = struct {
    const MAX_DIGEST_LENGTH = Hkdf.MAX_DIGEST_LENGTH;

    hkdf: Hkdf,
    verify_data: DigestBoundedArray,

    const Self = @This();

    /// initialize Finished mesage.
    /// @param hkdf crypto.Hkdf for hash.
    /// @return initialized Finished.
    pub fn init(hkdf: Hkdf) !Self {
        return Self{
            .hkdf = hkdf,
            .verify_data = try DigestBoundedArray.init(hkdf.digest_length),
        };
    }

    /// decode Finished message reading from io.Reader.
    /// @param reader io.Reader to read messages.
    /// @param hkdf   crypto.Hkdf for hash.
    /// @return the result of decoded Finished.
    pub fn decode(reader: anytype, hkdf: Hkdf) !Self {
        var res = try Self.init(hkdf);
        try reader.readNoEof(res.verify_data.slice());

        return res;
    }

    /// encode Finished message writing to io.Reader.
    /// @param self   Finished to be encoded.
    /// @param writer io.Writer to be written encoded messages.
    /// @return encoded length.
    pub fn encode(self: Self, writer: anytype) !usize {
        try writer.writeAll(self.verify_data.slice());
        return self.verify_data.len;
    }

    /// get length of encoded Finished.
    /// @param self the target Finished.
    pub fn length(self: Self) usize {
        return self.verify_data.len;
    }

    /// create Finished from message bytes.
    /// @param m      messages to be hashed.
    /// @param secret secret(finished_key).
    /// @return created Finished.
    pub fn fromMessageBytes(m: []const u8, secret: []const u8, hkdf: Hkdf) !Self {
        var res = try Self.init(hkdf);
        var hash: [MAX_DIGEST_LENGTH]u8 = undefined;
        var digest: [MAX_DIGEST_LENGTH]u8 = undefined;

        // verify_data =
        //   HMAC(finished_key,
        //        Transcript-Hash(Handshake Context,
        //                        Certificate*, CertificateVerify*))
        hkdf.hash(&hash, m);
        hkdf.create(&digest, hash[0..hkdf.digest_length], secret);
        std.mem.copy(u8, res.verify_data.slice(), digest[0..hkdf.digest_length]);

        return res;
    }

    /// verify Finished with message bytes.
    /// @param self   Finished to be verified.
    /// @param m      messages used to verify data.
    /// @param secret secret(finished_key).
    /// @return verified result.
    pub fn verify(self: Self, m: []const u8, secret: []const u8) bool {
        var hash: [MAX_DIGEST_LENGTH]u8 = undefined;
        var digest: [MAX_DIGEST_LENGTH]u8 = undefined;

        // verify_data =
        //   HMAC(finished_key,
        //        Transcript-Hash(Handshake Context,
        //                        Certificate*, CertificateVerify*))
        self.hkdf.hash(&hash, m);
        self.hkdf.create(&digest, hash[0..self.hkdf.digest_length], secret);

        // Checking the computed verify_data is equal to Finished one.
        return std.mem.eql(u8, digest[0..self.hkdf.digest_length], self.verify_data.slice());
    }
};

const expect = std.testing.expect;
const expectError = std.testing.expectError;

test "Finished decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2,
    0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72,
    0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18
    };
    // zig fmt: on
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Handshake.decode(readStream.reader(), std.testing.allocator, Hkdf.Sha256.hkdf);
    defer res.deinit();

    // check all data was read.
    try expectError(error.EndOfStream, readStream.reader().readByte());

    try expect(res == .finished);
}
