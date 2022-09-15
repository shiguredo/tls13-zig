const std = @import("std");
const io = std.io;
const crypto = @import("crypto.zig");

const expect = std.testing.expect;

const TLSInnerPlainText = @import("tls_cipher.zig").TLSInnerPlainText;
const TLSCipherText = @import("tls_cipher.zig").TLSCipherText;
const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;
const RecordKeys = @import("crypto.zig").Secret.RecordKeys;

/// RFC 8446 Section 5.2 Record Payload Protection
///
/// Since the ciphers might incorporate padding, the amount of overhead
/// could vary with different lengths of plaintext.  Symbolically,
///
///    AEADEncrypted =
///        AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
///
/// The encrypted_record field of TLSCiphertext is set to AEADEncrypted.
///
/// In order to decrypt and verify, the cipher takes as input the key,
/// nonce, additional data, and the AEADEncrypted value.  The output is
/// either the plaintext or an error indicating that the decryption
/// failed.  There is no separate integrity check.  Symbolically,
///
///    plaintext of encrypted_record =
///        AEAD-Decrypt(peer_write_key, nonce,
///                     additional_data, AEADEncrypted)
///
/// If the decryption fails, the receiver MUST terminate the connection
/// with a "bad_record_mac" alert.
///
/// An AEAD algorithm used in TLS 1.3 MUST NOT produce an expansion
/// greater than 255 octets.  An endpoint that receives a record from its
/// peer with TLSCiphertext.length larger than 2^14 + 256 octets MUST
/// terminate the connection with a "record_overflow" alert.  This limit
/// is derived from the maximum TLSInnerPlaintext length of 2^14 octets +
/// 1 octet for ContentType + the maximum AEAD expansion of 255 octets.
pub const RecordPayloadProtector = struct {
    aead: crypto.Aead,

    enc_keys: RecordKeys,
    enc_cnt: usize = 0,

    dec_keys: RecordKeys,
    dec_cnt: usize = 0,

    const Self = @This();

    const Error = error{
        EncodeFailed,
    };

    /// initialize RecordPayloadProtector.
    /// @param aead     Aead algrotihm to use encrypt or decrypt payload.
    /// @param enc_keys RecordKeys used to encrypt payload.
    /// @param dec_keys RecordKeys used to decrypt payload.
    /// @return initialized RecordPayloadProtector.
    pub fn init(aead: crypto.Aead, enc_keys: RecordKeys, dec_keys: RecordKeys) Self {
        return .{
            .aead = aead,
            .enc_keys = enc_keys,
            .dec_keys = dec_keys,
        };
    }

    /// encrypt TLSInnerPlainText into TLSCipherText.
    /// @param self      RecordPayloadProtector used to encrypt.
    /// @param mt        TLSInnerPlainText to be encrypted.
    /// @param allocator allocator to allocate temporary byte arrays.
    /// @return encrypted TLSCipherText.
    pub fn encrypt(self: *Self, mt: TLSInnerPlainText, allocator: std.mem.Allocator) !TLSCipherText {
        // Encoding TLSInnerPlainText.
        var mt_bytes = try allocator.alloc(u8, mt.length());
        defer allocator.free(mt_bytes);
        var stream = io.fixedBufferStream(mt_bytes);
        _ = try mt.encode(stream.writer());

        // Encoding header for aead tag.
        // additional_data = TLSCiphertext.opaque_tyoe ||
        //                   TLSCiphertext.legacy_record_version ||
        //                   TLSCiphertext.length
        const tag_length = self.aead.tag_length;
        var ct = try TLSCipherText.init(mt.length() + tag_length, allocator);
        var header: [5]u8 = undefined;
        stream = io.fixedBufferStream(&header);
        _ = try ct.writeHeader(stream.writer());

        const nonce = try self.generateNonce(self.enc_keys.iv.slice(), self.enc_cnt);
        self.aead.encrypt(ct.record[0..(ct.record.len - tag_length)], ct.record[(ct.record.len - tag_length)..], mt_bytes, &header, nonce.slice(), self.enc_keys.key.slice());

        // Incrementing counter.
        self.enc_cnt += 1;
        return ct;
    }

    /// encrypt Content into TLSCipherText.
    /// @param self      RecordPayloadProtector used to encrypt.
    /// @param c         Content to be encrypted.
    /// @param allocator allocator to allocate temporary byte arrays.
    /// @return encrypted TLSCipherText.
    pub fn encryptFromMessage(self: *Self, c: Content, allocator: std.mem.Allocator) !TLSCipherText {
        // Encoding Content into TLSInnerPlainText.
        const mt = try TLSInnerPlainText.initWithContent(c, allocator);
        defer mt.deinit();

        // Encrypting Content into TLSCipherText.
        return try self.encrypt(mt, allocator);
    }

    /// encrypt Content and write encrypted Content to io.Writer.
    /// @param self      RecordPayloadProtector used to encrypt.
    /// @param c         Content to be encrypted.
    /// @param allocator allocator to allocate temporary byte arrays.
    /// @param writer    io.Writer to write encrypted Content.
    /// @return the length of written message.
    pub fn encryptFromMessageAndWrite(self: *Self, c: Content, allocator: std.mem.Allocator, writer: anytype) !usize {
        // Encrypting Content into TLSCipherText.
        const et = try self.encryptFromMessage(c, allocator);
        defer et.deinit();

        // Encoding TLSCipherText and write to writer.
        return try et.encode(writer);
    }

    /// decrypt TLSCipherText into TLSInnerPlainText.
    /// @param self      RecordPayloadProtector used to decrypt.
    /// @param c         TLSCipherText to be decrypted.
    /// @param allocator allocator to allocate TLSInnerPlainText.
    /// @return decrypted TLSInnerPlainText.
    pub fn decrypt(self: *Self, c: TLSCipherText, allocator: std.mem.Allocator) !TLSInnerPlainText {
        // Allocate bytes array for decrypt message.
        const tag_length = self.aead.tag_length;
        var mt_bytes = try allocator.alloc(u8, c.record.len - tag_length);
        defer allocator.free(mt_bytes);

        // Encoding header for aead tag.
        // additional_data = TLSCiphertext.opaque_tyoe ||
        //                   TLSCiphertext.legacy_record_version ||
        //                   TLSCiphertext.length
        var header: [5]u8 = undefined;
        var stream = io.fixedBufferStream(&header);
        _ = try c.writeHeader(stream.writer());

        const nonce = try self.generateNonce(self.dec_keys.iv.slice(), self.dec_cnt);
        try self.aead.decrypt(mt_bytes, c.record[0 .. c.record.len - tag_length], c.record[(c.record.len - tag_length)..], &header, nonce.slice(), self.dec_keys.key.slice());
        const res = try TLSInnerPlainText.decode(mt_bytes, allocator);

        // Incrementing counter.
        self.dec_cnt += 1;
        return res;
    }

    /// decrypt TLSCipherText into TLSInnerPlainText.
    /// @param self      RecordPayloadProtector used to decrypt.
    /// @param c         bytes to be decrypted(encoded in TLSCipherText).
    /// @param allocator allocator to allocate TLSInnerPlainText.
    /// @return decrypted TLSInnerPlainText.
    pub fn decryptFromCipherBytes(self: *Self, c: []const u8, allocator: std.mem.Allocator) !TLSInnerPlainText {
        // Decoding TLSCipherText.
        var stream = io.fixedBufferStream(c);
        var reader = stream.reader();
        const t = try reader.readEnum(ContentType, .Big);
        const ct = try TLSCipherText.decode(reader, t, allocator);
        defer ct.deinit();

        // Decrypting TLSCipherText.
        return try self.decrypt(ct, allocator);
    }

    /// RFC8446 Section 5.3 Pre-Record Nonce
    fn generateNonce(self: Self, iv: []const u8, count: u64) !crypto.NonceBoundedArray {
        var nonce = try crypto.NonceBoundedArray.init(self.aead.nonce_length);
        var i: usize = 0;

        // BoundedArray must be 0-initialized.
        while (i < nonce.len) : (i += 1) {
            nonce.slice()[i] = 0;
        }

        i = 0;
        while (i < @sizeOf(u64)) : (i += 1) {
            nonce.slice()[nonce.len - i - 1] = @intCast(u8, count >> (@intCast(u6, i * 8)));
        }

        i = 0;
        while (i < nonce.len) : (i += 1) {
            nonce.slice()[i] = iv[i] ^ nonce.slice()[i];
        }

        return nonce;
    }
};

const Alert = @import("alert.zig").Alert;

test "RecordPayloadProtector encrypt" {
    const key = [_]u8{ 0x17, 0x42, 0x2d, 0xda, 0x59, 0x6e, 0xd5, 0xd9, 0xac, 0xd8, 0x90, 0xe3, 0xc6, 0x3f, 0x50, 0x51 };
    const iv = [_]u8{ 0x5b, 0x78, 0x92, 0x3d, 0xee, 0x08, 0x57, 0x90, 0x33, 0xe5, 0x23, 0xd9 };
    const keys = try RecordKeys.fromBytes(&key, &iv);
    var protector = RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead, keys, keys);
    protector.enc_cnt = 1;

    const alert = Content{ .alert = Alert{
        .level = .warning,
        .description = .close_notify,
    } };
    const mt = try TLSInnerPlainText.initWithContent(alert, std.testing.allocator);
    defer mt.deinit();
    const ct = try protector.encrypt(mt, std.testing.allocator);
    defer ct.deinit();

    // zig fmt: off
    const c_ans = [_]u8{
    0x17, 0x03, 0x03, 0x00, 0x13, 0xC9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xB7,
    0x4D, 0x7F, 0xF1, 0x15, 0x3E, 0xFD, 0x6D, 0xB6, 0xD0, 0xB0, 0xE3
    };
    // zig fmt: on

    var c: [1000]u8 = undefined;
    var stream = io.fixedBufferStream(&c);
    const write_len = try ct.encode(stream.writer());
    try expect(std.mem.eql(u8, c[0..write_len], &c_ans));
}

test "RecordPayloadProtector decryptToContent" {
    const key = [_]u8{ 0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56 };
    const iv = [_]u8{ 0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84 };
    const keys = try RecordKeys.fromBytes(&key, &iv);
    var protector = RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead, keys, keys);
    protector.dec_cnt = 2;

    // zig fmt: off
    const s_alert = [_]u8{
    0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99,
    0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&s_alert);
    const t = try stream.reader().readEnum(ContentType, .Big);
    const ct = try TLSCipherText.decode(stream.reader(), t, std.testing.allocator);
    defer ct.deinit();

    var mt = try protector.decrypt(ct, std.testing.allocator);
    defer mt.deinit();
    const content = try mt.decodeContent(std.testing.allocator, null);
    defer content.deinit();

    try expect(content == .alert);
    const alert = content.alert;
    try expect(alert.level == .warning);
    try expect(alert.description == .close_notify);
}

test "RecordPayloadProtector decryptFromBytes" {
    const key = [_]u8{ 0x9f, 0x02, 0x28, 0x3b, 0x6c, 0x9c, 0x07, 0xef, 0xc2, 0x6b, 0xb9, 0xf2, 0xac, 0x92, 0xe3, 0x56 };
    const iv = [_]u8{ 0xcf, 0x78, 0x2b, 0x88, 0xdd, 0x83, 0x54, 0x9a, 0xad, 0xf1, 0xe9, 0x84 };
    const keys = try RecordKeys.fromBytes(&key, &iv);
    var protector = RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead, keys, keys);
    protector.dec_cnt = 2;

    // zig fmt: off
    const s_alert = [_]u8{
    0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99,
    0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9
    };
    // zig fmt: on

    var mt = try protector.decryptFromCipherBytes(&s_alert, std.testing.allocator);
    defer mt.deinit();
    const content = try mt.decodeContent(std.testing.allocator, null);
    defer content.deinit();

    try expect(content == .alert);
    const alert = content.alert;
    try expect(alert.level == .warning);
    try expect(alert.description == .close_notify);
}
