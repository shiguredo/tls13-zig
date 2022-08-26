const std = @import("std");
const io = std.io;
const dh = std.crypto.dh;
const hmac = std.crypto.auth.hmac;
const hkdf = std.crypto.kdf.hkdf;
const expect = std.testing.expect;
const expectError = std.testing.expectError;

const msg = @import("msg.zig");
const key = @import("key.zig");
const record = @import("record.zig");
const extension = @import("extension.zig");
const certificate = @import("certificate.zig");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const TLSClient = struct {

    // message buffer for KeySchedule
    msgs_bytes: []u8 = undefined,
    msgs_stream: io.FixedBufferStream([]u8) = undefined,

    // state machine
    state: State = State.START,

    // X25519 DH keys
    x25519_priv_key: [32]u8 = undefined,
    x25519_pub_key: [32]u8 = undefined,

    // crypto scheme

    // payload protection
    ks: key.KeySchedulerImpl(Sha256, Aes128Gcm) = undefined,
    recv_count: usize = 0,
    send_count: usize = 0,

    // Misc
    allocator: std.mem.Allocator = undefined,

    const State = enum { START, WAIT_SH, WAIT_EE, WAIT_CERT_CR, WAIT_CERT, WAIT_CV, WAIT_FINISHED, CONNECTED };

    const Protector = record.RecordPayloadProtector(Aes128Gcm);

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        var res = Self{};
        res.allocator = allocator;
        res.msgs_bytes = try res.allocator.alloc(u8, 1024 * 32);
        res.msgs_stream = io.fixedBufferStream(res.msgs_bytes);

        return res;
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.msgs_bytes);
        self.ks.deinit();
    }

    pub fn configureX25519Keys(self: *Self, priv_key: [32]u8) !void {
        std.mem.copy(u8, &self.x25519_priv_key, &priv_key);
        self.x25519_pub_key = try dh.X25519.recoverPublicKey(self.x25519_priv_key);
    }

    pub fn start(self: *Self, reader: anytype, ch: []const u8) !void {
        _ = try self.msgs_stream.write(ch);

        // ClientHello is already sent.
        self.state = .WAIT_SH;
        while (self.state != .CONNECTED) {
            if (self.state == .WAIT_SH) {
                const recv_record = try record.TLSPlainText.decode(reader, self.allocator, null, self.msgs_stream.writer());
                defer recv_record.deinit();

                if (recv_record != .handshake) {
                    // TODO: Error
                    return;
                }
                if (recv_record.handshake != .server_hello) {
                    // TODO: Error
                    return;
                }

                try self.handleServerHello(recv_record.handshake.server_hello);
            } else {
                const recv_record = try record.TLSCipherText.decode(reader, self.allocator);
                defer recv_record.deinit();

                const plain_record = try Self.Protector.decrypt(recv_record, self.ks.generateNonce(self.ks.s_hs_iv, self.recv_count), self.ks.s_hs_key, self.allocator);
                defer plain_record.deinit();
                self.recv_count += 1;

                if (plain_record.content_type == .handshake) {
                    try self.handleHandshakeInnerPlaintext(plain_record);
                } else {
                    unreachable;
                }
            }
        }
    }

    fn handleServerHello(self: *Self, sh: msg.ServerHello) !void {
        // Only TLS_AES_128_GCM_SHA256 is allowed
        if (sh.cipher_suite != .TLS_AES_128_GCM_SHA256) {
            // TODO: Error
            return;
        }

        const key_share = (try msg.getExtension(sh.extensions, .key_share)).key_share;
        if (key_share.entries.items.len != 1) {
            // TODO: Error
            return;
        }

        const key_entry = key_share.entries.items[0];
        if (key_entry != .x25519) {
            // TODO: Error
            return;
        }

        const server_pubkey = key_entry.x25519.key_exchange;
        const shared_key = try dh.X25519.scalarmult(self.x25519_priv_key, server_pubkey);

        self.ks = try key.KeySchedulerImpl(Sha256, Aes128Gcm).init(&shared_key, &([_]u8{0} ** 32), self.allocator);
        try self.ks.generateHandshakeSecrets(self.msgs_stream.getWritten());

        // if everythig is ok, go to next state.
        self.state = .WAIT_EE;
    }

    fn handleHandshakeInnerPlaintext(self: *Self, t: record.TLSInnerPlainText) !void {
        var stream = io.fixedBufferStream(t.content);
        var i: usize = 0;
        while ((try stream.getPos()) != (try stream.getEndPos())) {
            const recv_msg = try msg.Handshake.decode(stream.reader(), self.allocator, Sha256);
            defer recv_msg.deinit();
            if (self.state == .WAIT_EE) {
                if (recv_msg != .encrypted_extensions) {
                    // TODO: Error
                    continue;
                }

                const e = recv_msg.encrypted_extensions;
                try self.handleEncryptedExtensions(e);
            } else if (self.state == .WAIT_CERT_CR) {
                // TODO: CertificateRequest
                if (recv_msg != .certificate) {
                    // TODO: Error
                    continue;
                }

                const e = recv_msg.certificate;
                try self.handleCertificate(e);
            } else if (self.state == .WAIT_CV) {
                if (recv_msg != .certificate_verify) {
                    // TODO: Error
                    continue;
                }

                const e = recv_msg.certificate_verify;
                try self.handleCertificateVerify(e);
            } else if (self.state == .WAIT_FINISHED) {
                if (recv_msg != .finished) {
                    // TODO: Error
                    continue;
                }

                const e = recv_msg.finished;
                try self.handleFinished(e);
            }
            const content_len = recv_msg.length();
            _ = try self.msgs_stream.write(t.content[i..(i + content_len)]);
            i += content_len;
        }

        // done
    }

    fn handleEncryptedExtensions(self: *Self, ee: msg.EncryptedExtensions) !void {
        _ = self;
        _ = ee;
        // TODO: what to do?

        self.state = .WAIT_CERT_CR;
    }

    fn handleCertificate(self: *Self, cert: certificate.Certificate) !void {
        _ = self;
        _ = cert;
        // TODO: parse certificate

        self.state = .WAIT_CV;
    }

    fn handleCertificateVerify(self: *Self, cert_verify: certificate.CertificateVerify) !void {
        _ = self;
        _ = cert_verify;
        // TODO: verify certificate

        self.state = .WAIT_FINISHED;
    }

    fn handleFinished(self: *Self, finished: msg.Finished) !void {
        var hashed: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(self.msgs_stream.getWritten(), &hashed, .{});
        var verify: [Sha256.digest_length]u8 = undefined;
        hmac.Hmac(Sha256).create(&verify, &hashed, &self.ks.s_hs_finished_secret);

        if (!std.mem.eql(u8, &verify, finished.verify_data.slice())) {
            // TODO: Error
            return;
        }

        try self.ks.generateApplicationSecrets(self.msgs_stream.getWritten());
        self.state = .CONNECTED;
    }
};

test "TLSClient with RFC8448" {
    const client_privkey = [_]u8{ 0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05 };
    const ch_bytes = [_]u8{ 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };

    const recv_bytes = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x17, 0x03, 0x03, 0x02, 0xA2, 0xD1, 0xFF, 0x33, 0x4A, 0x56, 0xF5, 0xBF, 0xF6, 0x59, 0x4A, 0x07, 0xCC, 0x87, 0xB5, 0x80, 0x23, 0x3F, 0x50, 0x0F, 0x45, 0xE4, 0x89, 0xE7, 0xF3, 0x3A, 0xF3, 0x5E, 0xDF, 0x78, 0x69, 0xFC, 0xF4, 0x0A, 0xA4, 0x0A, 0xA2, 0xB8, 0xEA, 0x73, 0xF8, 0x48, 0xA7, 0xCA, 0x07, 0x61, 0x2E, 0xF9, 0xF9, 0x45, 0xCB, 0x96, 0x0B, 0x40, 0x68, 0x90, 0x51, 0x23, 0xEA, 0x78, 0xB1, 0x11, 0xB4, 0x29, 0xBA, 0x91, 0x91, 0xCD, 0x05, 0xD2, 0xA3, 0x89, 0x28, 0x0F, 0x52, 0x61, 0x34, 0xAA, 0xDC, 0x7F, 0xC7, 0x8C, 0x4B, 0x72, 0x9D, 0xF8, 0x28, 0xB5, 0xEC, 0xF7, 0xB1, 0x3B, 0xD9, 0xAE, 0xFB, 0x0E, 0x57, 0xF2, 0x71, 0x58, 0x5B, 0x8E, 0xA9, 0xBB, 0x35, 0x5C, 0x7C, 0x79, 0x02, 0x07, 0x16, 0xCF, 0xB9, 0xB1, 0x18, 0x3E, 0xF3, 0xAB, 0x20, 0xE3, 0x7D, 0x57, 0xA6, 0xB9, 0xD7, 0x47, 0x76, 0x09, 0xAE, 0xE6, 0xE1, 0x22, 0xA4, 0xCF, 0x51, 0x42, 0x73, 0x25, 0x25, 0x0C, 0x7D, 0x0E, 0x50, 0x92, 0x89, 0x44, 0x4C, 0x9B, 0x3A, 0x64, 0x8F, 0x1D, 0x71, 0x03, 0x5D, 0x2E, 0xD6, 0x5B, 0x0E, 0x3C, 0xDD, 0x0C, 0xBA, 0xE8, 0xBF, 0x2D, 0x0B, 0x22, 0x78, 0x12, 0xCB, 0xB3, 0x60, 0x98, 0x72, 0x55, 0xCC, 0x74, 0x41, 0x10, 0xC4, 0x53, 0xBA, 0xA4, 0xFC, 0xD6, 0x10, 0x92, 0x8D, 0x80, 0x98, 0x10, 0xE4, 0xB7, 0xED, 0x1A, 0x8F, 0xD9, 0x91, 0xF0, 0x6A, 0xA6, 0x24, 0x82, 0x04, 0x79, 0x7E, 0x36, 0xA6, 0xA7, 0x3B, 0x70, 0xA2, 0x55, 0x9C, 0x09, 0xEA, 0xD6, 0x86, 0x94, 0x5B, 0xA2, 0x46, 0xAB, 0x66, 0xE5, 0xED, 0xD8, 0x04, 0x4B, 0x4C, 0x6D, 0xE3, 0xFC, 0xF2, 0xA8, 0x94, 0x41, 0xAC, 0x66, 0x27, 0x2F, 0xD8, 0xFB, 0x33, 0x0E, 0xF8, 0x19, 0x05, 0x79, 0xB3, 0x68, 0x45, 0x96, 0xC9, 0x60, 0xBD, 0x59, 0x6E, 0xEA, 0x52, 0x0A, 0x56, 0xA8, 0xD6, 0x50, 0xF5, 0x63, 0xAA, 0xD2, 0x74, 0x09, 0x96, 0x0D, 0xCA, 0x63, 0xD3, 0xE6, 0x88, 0x61, 0x1E, 0xA5, 0xE2, 0x2F, 0x44, 0x15, 0xCF, 0x95, 0x38, 0xD5, 0x1A, 0x20, 0x0C, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8A, 0x26, 0x4E, 0xD6, 0x54, 0x0C, 0x84, 0x83, 0x8D, 0x89, 0xF7, 0x2C, 0x24, 0x46, 0x1A, 0xAD, 0x6D, 0x26, 0xF5, 0x9E, 0xCA, 0xBA, 0x9A, 0xCB, 0xBB, 0x31, 0x7B, 0x66, 0xD9, 0x02, 0xF4, 0xF2, 0x92, 0xA3, 0x6A, 0xC1, 0xB6, 0x39, 0xC6, 0x37, 0xCE, 0x34, 0x31, 0x17, 0xB6, 0x59, 0x62, 0x22, 0x45, 0x31, 0x7B, 0x49, 0xEE, 0xDA, 0x0C, 0x62, 0x58, 0xF1, 0x00, 0xD7, 0xD9, 0x61, 0xFF, 0xB1, 0x38, 0x64, 0x7E, 0x92, 0xEA, 0x33, 0x0F, 0xAE, 0xEA, 0x6D, 0xFA, 0x31, 0xC7, 0xA8, 0x4D, 0xC3, 0xBD, 0x7E, 0x1B, 0x7A, 0x6C, 0x71, 0x78, 0xAF, 0x36, 0x87, 0x90, 0x18, 0xE3, 0xF2, 0x52, 0x10, 0x7F, 0x24, 0x3D, 0x24, 0x3D, 0xC7, 0x33, 0x9D, 0x56, 0x84, 0xC8, 0xB0, 0x37, 0x8B, 0xF3, 0x02, 0x44, 0xDA, 0x8C, 0x87, 0xC8, 0x43, 0xF5, 0xE5, 0x6E, 0xB4, 0xC5, 0xE8, 0x28, 0x0A, 0x2B, 0x48, 0x05, 0x2C, 0xF9, 0x3B, 0x16, 0x49, 0x9A, 0x66, 0xDB, 0x7C, 0xCA, 0x71, 0xE4, 0x59, 0x94, 0x26, 0xF7, 0xD4, 0x61, 0xE6, 0x6F, 0x99, 0x88, 0x2B, 0xD8, 0x9F, 0xC5, 0x08, 0x00, 0xBE, 0xCC, 0xA6, 0x2D, 0x6C, 0x74, 0x11, 0x6D, 0xBD, 0x29, 0x72, 0xFD, 0xA1, 0xFA, 0x80, 0xF8, 0x5D, 0xF8, 0x81, 0xED, 0xBE, 0x5A, 0x37, 0x66, 0x89, 0x36, 0xB3, 0x35, 0x58, 0x3B, 0x59, 0x91, 0x86, 0xDC, 0x5C, 0x69, 0x18, 0xA3, 0x96, 0xFA, 0x48, 0xA1, 0x81, 0xD6, 0xB6, 0xFA, 0x4F, 0x9D, 0x62, 0xD5, 0x13, 0xAF, 0xBB, 0x99, 0x2F, 0x2B, 0x99, 0x2F, 0x67, 0xF8, 0xAF, 0xE6, 0x7F, 0x76, 0x91, 0x3F, 0xA3, 0x88, 0xCB, 0x56, 0x30, 0xC8, 0xCA, 0x01, 0xE0, 0xC6, 0x5D, 0x11, 0xC6, 0x6A, 0x1E, 0x2A, 0xC4, 0xC8, 0x59, 0x77, 0xB7, 0xC7, 0xA6, 0x99, 0x9B, 0xBF, 0x10, 0xDC, 0x35, 0xAE, 0x69, 0xF5, 0x51, 0x56, 0x14, 0x63, 0x6C, 0x0B, 0x9B, 0x68, 0xC1, 0x9E, 0xD2, 0xE3, 0x1C, 0x0B, 0x3B, 0x66, 0x76, 0x30, 0x38, 0xEB, 0xBA, 0x42, 0xF3, 0xB3, 0x8E, 0xDC, 0x03, 0x99, 0xF3, 0xA9, 0xF2, 0x3F, 0xAA, 0x63, 0x97, 0x8C, 0x31, 0x7F, 0xC9, 0xFA, 0x66, 0xA7, 0x3F, 0x60, 0xF0, 0x50, 0x4D, 0xE9, 0x3B, 0x5B, 0x84, 0x5E, 0x27, 0x55, 0x92, 0xC1, 0x23, 0x35, 0xEE, 0x34, 0x0B, 0xBC, 0x4F, 0xDD, 0xD5, 0x02, 0x78, 0x40, 0x16, 0xE4, 0xB3, 0xBE, 0x7E, 0xF0, 0x4D, 0xDA, 0x49, 0xF4, 0xB4, 0x40, 0xA3, 0x0C, 0xB5, 0xD2, 0xAF, 0x93, 0x98, 0x28, 0xFD, 0x4A, 0xE3, 0x79, 0x4E, 0x44, 0xF9, 0x4D, 0xF5, 0xA6, 0x31, 0xED, 0xE4, 0x2C, 0x17, 0x19, 0xBF, 0xDA, 0xBF, 0x02, 0x53, 0xFE, 0x51, 0x75, 0xBE, 0x89, 0x8E, 0x75, 0x0E, 0xDC, 0x53, 0x37, 0x0D, 0x2B };

    var client = try TLSClient.init(std.testing.allocator);
    defer client.deinit();
    try client.configureX25519Keys(client_privkey);
    try client.start(io.fixedBufferStream(&recv_bytes).reader(), &ch_bytes);
    try expect(client.state == .CONNECTED);
}

test "client test with RFC8448" {
    var msgs_bytes = [_]u8{0} ** (1024 * 32);
    var msgs_stream = io.fixedBufferStream(&msgs_bytes);

    // STATE = START

    const client_privkey = [_]u8{ 0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05 };
    const client_pubkey_ans = [_]u8{ 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c };
    const client_pubkey = try dh.X25519.recoverPublicKey(client_privkey);
    try expect(std.mem.eql(u8, &client_pubkey, &client_pubkey_ans));

    const client_hello_bytes = [_]u8{ 0x01, 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };
    _ = try msgs_stream.write(&client_hello_bytes);

    // STATE = WAIT_SH

    const server_hello_bytes = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12, 0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb, 0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95, 0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d, 0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
    const handshake = (try record.TLSPlainText.decode(io.fixedBufferStream(&server_hello_bytes).reader(), std.testing.allocator, null, msgs_stream.writer())).handshake;
    try expect(handshake == .server_hello);

    const server_hello = handshake.server_hello;
    defer server_hello.deinit();

    try expect(server_hello.cipher_suite == .TLS_AES_128_GCM_SHA256);
    const key_share = (try msg.getExtension(server_hello.extensions, .key_share)).key_share;
    try expect(key_share.entries.items.len == 1);
    try expect(key_share.entries.items[0] == .x25519);

    const server_pubkey = key_share.entries.items[0].x25519.key_exchange;

    const Protector = record.RecordPayloadProtector(Aes128Gcm);

    const dhe_shared_key_ans = [_]u8{ 0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };
    const dhe_shared_key = try dh.X25519.scalarmult(client_privkey, server_pubkey);
    try expect(std.mem.eql(u8, &dhe_shared_key, &dhe_shared_key_ans));

    var ks = try key.KeySchedulerImpl(Sha256, Aes128Gcm).init(&dhe_shared_key, &([_]u8{0} ** 32), std.testing.allocator);
    defer ks.deinit();
    try ks.generateHandshakeSecrets(msgs_stream.getWritten());

    // STATE = WAIT_EE

    // RFC 8446 Section 5.2 Record Payload Protection
    const enc_data = [_]u8{ 0x17, 0x03, 0x03, 0x02, 0xA2, 0xD1, 0xFF, 0x33, 0x4A, 0x56, 0xF5, 0xBF, 0xF6, 0x59, 0x4A, 0x07, 0xCC, 0x87, 0xB5, 0x80, 0x23, 0x3F, 0x50, 0x0F, 0x45, 0xE4, 0x89, 0xE7, 0xF3, 0x3A, 0xF3, 0x5E, 0xDF, 0x78, 0x69, 0xFC, 0xF4, 0x0A, 0xA4, 0x0A, 0xA2, 0xB8, 0xEA, 0x73, 0xF8, 0x48, 0xA7, 0xCA, 0x07, 0x61, 0x2E, 0xF9, 0xF9, 0x45, 0xCB, 0x96, 0x0B, 0x40, 0x68, 0x90, 0x51, 0x23, 0xEA, 0x78, 0xB1, 0x11, 0xB4, 0x29, 0xBA, 0x91, 0x91, 0xCD, 0x05, 0xD2, 0xA3, 0x89, 0x28, 0x0F, 0x52, 0x61, 0x34, 0xAA, 0xDC, 0x7F, 0xC7, 0x8C, 0x4B, 0x72, 0x9D, 0xF8, 0x28, 0xB5, 0xEC, 0xF7, 0xB1, 0x3B, 0xD9, 0xAE, 0xFB, 0x0E, 0x57, 0xF2, 0x71, 0x58, 0x5B, 0x8E, 0xA9, 0xBB, 0x35, 0x5C, 0x7C, 0x79, 0x02, 0x07, 0x16, 0xCF, 0xB9, 0xB1, 0x18, 0x3E, 0xF3, 0xAB, 0x20, 0xE3, 0x7D, 0x57, 0xA6, 0xB9, 0xD7, 0x47, 0x76, 0x09, 0xAE, 0xE6, 0xE1, 0x22, 0xA4, 0xCF, 0x51, 0x42, 0x73, 0x25, 0x25, 0x0C, 0x7D, 0x0E, 0x50, 0x92, 0x89, 0x44, 0x4C, 0x9B, 0x3A, 0x64, 0x8F, 0x1D, 0x71, 0x03, 0x5D, 0x2E, 0xD6, 0x5B, 0x0E, 0x3C, 0xDD, 0x0C, 0xBA, 0xE8, 0xBF, 0x2D, 0x0B, 0x22, 0x78, 0x12, 0xCB, 0xB3, 0x60, 0x98, 0x72, 0x55, 0xCC, 0x74, 0x41, 0x10, 0xC4, 0x53, 0xBA, 0xA4, 0xFC, 0xD6, 0x10, 0x92, 0x8D, 0x80, 0x98, 0x10, 0xE4, 0xB7, 0xED, 0x1A, 0x8F, 0xD9, 0x91, 0xF0, 0x6A, 0xA6, 0x24, 0x82, 0x04, 0x79, 0x7E, 0x36, 0xA6, 0xA7, 0x3B, 0x70, 0xA2, 0x55, 0x9C, 0x09, 0xEA, 0xD6, 0x86, 0x94, 0x5B, 0xA2, 0x46, 0xAB, 0x66, 0xE5, 0xED, 0xD8, 0x04, 0x4B, 0x4C, 0x6D, 0xE3, 0xFC, 0xF2, 0xA8, 0x94, 0x41, 0xAC, 0x66, 0x27, 0x2F, 0xD8, 0xFB, 0x33, 0x0E, 0xF8, 0x19, 0x05, 0x79, 0xB3, 0x68, 0x45, 0x96, 0xC9, 0x60, 0xBD, 0x59, 0x6E, 0xEA, 0x52, 0x0A, 0x56, 0xA8, 0xD6, 0x50, 0xF5, 0x63, 0xAA, 0xD2, 0x74, 0x09, 0x96, 0x0D, 0xCA, 0x63, 0xD3, 0xE6, 0x88, 0x61, 0x1E, 0xA5, 0xE2, 0x2F, 0x44, 0x15, 0xCF, 0x95, 0x38, 0xD5, 0x1A, 0x20, 0x0C, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8A, 0x26, 0x4E, 0xD6, 0x54, 0x0C, 0x84, 0x83, 0x8D, 0x89, 0xF7, 0x2C, 0x24, 0x46, 0x1A, 0xAD, 0x6D, 0x26, 0xF5, 0x9E, 0xCA, 0xBA, 0x9A, 0xCB, 0xBB, 0x31, 0x7B, 0x66, 0xD9, 0x02, 0xF4, 0xF2, 0x92, 0xA3, 0x6A, 0xC1, 0xB6, 0x39, 0xC6, 0x37, 0xCE, 0x34, 0x31, 0x17, 0xB6, 0x59, 0x62, 0x22, 0x45, 0x31, 0x7B, 0x49, 0xEE, 0xDA, 0x0C, 0x62, 0x58, 0xF1, 0x00, 0xD7, 0xD9, 0x61, 0xFF, 0xB1, 0x38, 0x64, 0x7E, 0x92, 0xEA, 0x33, 0x0F, 0xAE, 0xEA, 0x6D, 0xFA, 0x31, 0xC7, 0xA8, 0x4D, 0xC3, 0xBD, 0x7E, 0x1B, 0x7A, 0x6C, 0x71, 0x78, 0xAF, 0x36, 0x87, 0x90, 0x18, 0xE3, 0xF2, 0x52, 0x10, 0x7F, 0x24, 0x3D, 0x24, 0x3D, 0xC7, 0x33, 0x9D, 0x56, 0x84, 0xC8, 0xB0, 0x37, 0x8B, 0xF3, 0x02, 0x44, 0xDA, 0x8C, 0x87, 0xC8, 0x43, 0xF5, 0xE5, 0x6E, 0xB4, 0xC5, 0xE8, 0x28, 0x0A, 0x2B, 0x48, 0x05, 0x2C, 0xF9, 0x3B, 0x16, 0x49, 0x9A, 0x66, 0xDB, 0x7C, 0xCA, 0x71, 0xE4, 0x59, 0x94, 0x26, 0xF7, 0xD4, 0x61, 0xE6, 0x6F, 0x99, 0x88, 0x2B, 0xD8, 0x9F, 0xC5, 0x08, 0x00, 0xBE, 0xCC, 0xA6, 0x2D, 0x6C, 0x74, 0x11, 0x6D, 0xBD, 0x29, 0x72, 0xFD, 0xA1, 0xFA, 0x80, 0xF8, 0x5D, 0xF8, 0x81, 0xED, 0xBE, 0x5A, 0x37, 0x66, 0x89, 0x36, 0xB3, 0x35, 0x58, 0x3B, 0x59, 0x91, 0x86, 0xDC, 0x5C, 0x69, 0x18, 0xA3, 0x96, 0xFA, 0x48, 0xA1, 0x81, 0xD6, 0xB6, 0xFA, 0x4F, 0x9D, 0x62, 0xD5, 0x13, 0xAF, 0xBB, 0x99, 0x2F, 0x2B, 0x99, 0x2F, 0x67, 0xF8, 0xAF, 0xE6, 0x7F, 0x76, 0x91, 0x3F, 0xA3, 0x88, 0xCB, 0x56, 0x30, 0xC8, 0xCA, 0x01, 0xE0, 0xC6, 0x5D, 0x11, 0xC6, 0x6A, 0x1E, 0x2A, 0xC4, 0xC8, 0x59, 0x77, 0xB7, 0xC7, 0xA6, 0x99, 0x9B, 0xBF, 0x10, 0xDC, 0x35, 0xAE, 0x69, 0xF5, 0x51, 0x56, 0x14, 0x63, 0x6C, 0x0B, 0x9B, 0x68, 0xC1, 0x9E, 0xD2, 0xE3, 0x1C, 0x0B, 0x3B, 0x66, 0x76, 0x30, 0x38, 0xEB, 0xBA, 0x42, 0xF3, 0xB3, 0x8E, 0xDC, 0x03, 0x99, 0xF3, 0xA9, 0xF2, 0x3F, 0xAA, 0x63, 0x97, 0x8C, 0x31, 0x7F, 0xC9, 0xFA, 0x66, 0xA7, 0x3F, 0x60, 0xF0, 0x50, 0x4D, 0xE9, 0x3B, 0x5B, 0x84, 0x5E, 0x27, 0x55, 0x92, 0xC1, 0x23, 0x35, 0xEE, 0x34, 0x0B, 0xBC, 0x4F, 0xDD, 0xD5, 0x02, 0x78, 0x40, 0x16, 0xE4, 0xB3, 0xBE, 0x7E, 0xF0, 0x4D, 0xDA, 0x49, 0xF4, 0xB4, 0x40, 0xA3, 0x0C, 0xB5, 0xD2, 0xAF, 0x93, 0x98, 0x28, 0xFD, 0x4A, 0xE3, 0x79, 0x4E, 0x44, 0xF9, 0x4D, 0xF5, 0xA6, 0x31, 0xED, 0xE4, 0x2C, 0x17, 0x19, 0xBF, 0xDA, 0xBF, 0x02, 0x53, 0xFE, 0x51, 0x75, 0xBE, 0x89, 0x8E, 0x75, 0x0E, 0xDC, 0x53, 0x37, 0x0D, 0x2B };
    const pt_misc = try Protector.decryptFromCipherBytes(&enc_data, ks.generateNonce(ks.s_hs_iv, 0), ks.s_hs_key, std.testing.allocator);
    defer pt_misc.deinit();
    try expect(pt_misc.content_type == .handshake);

    // decode EncryptedExtensions
    var readStream2 = io.fixedBufferStream(pt_misc.content);
    const hs_enc_ext = try msg.Handshake.decode(readStream2.reader(), std.testing.allocator, null);
    defer hs_enc_ext.deinit();
    const enc_ext = hs_enc_ext.encrypted_extensions;

    var msgs_idx: usize = 0;
    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_enc_ext.length())]);
    msgs_idx += hs_enc_ext.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(enc_ext.extensions.items.len == 3);
    try expect(enc_ext.extensions.items[0] == .supported_groups);
    try expect(enc_ext.extensions.items[1] == .record_size_limit);
    try expect(enc_ext.extensions.items[2] == .server_name);

    // STATE = WAIT_CERT_CR

    // decode Certificate
    const hs_cert = (try msg.Handshake.decode(readStream2.reader(), std.testing.allocator, null));
    defer hs_cert.deinit();
    const cert = hs_cert.certificate;

    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_cert.length())]);
    msgs_idx += hs_cert.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(cert.cert_req_ctx.len == 0);
    try expect(cert.cert_list.items.len == 1);
    try expect(cert.cert_list.items[0].cert_data.items.len == 432);
    try expect(cert.cert_list.items[0].extensions.items.len == 0);

    // WAIT_CV

    // decode CertificateVerify
    const hs_cert_verify = (try msg.Handshake.decode(readStream2.reader(), std.testing.allocator, null));
    defer hs_cert_verify.deinit();
    const cert_verify = hs_cert_verify.certificate_verify;

    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_cert_verify.length())]);
    msgs_idx += hs_cert_verify.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(cert_verify.algorithm == .rsa_pss_rsae_sha256);

    // STATE = WAIT_FINISHED

    // decode Finished
    const hs_s_hs_finished = (try msg.Handshake.decode(readStream2.reader(), std.testing.allocator, Sha256));
    defer hs_s_hs_finished.deinit();
    const s_hs_finished = hs_s_hs_finished.finished;

    // check all data was read.
    try expectError(error.EndOfStream, readStream2.reader().readByte());

    // validate "finished"
    var s_hs_finished_digest: [Sha256.digest_length]u8 = undefined;
    var s_hs_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(msgs_stream.getWritten(), &s_hs_hash, .{});
    hmac.Hmac(Sha256).create(&s_hs_finished_digest, &s_hs_hash, &ks.s_hs_finished_secret);
    try expect(std.mem.eql(u8, &s_hs_finished_digest, s_hs_finished.verify_data.slice()));

    // add "finished"
    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_s_hs_finished.length())]);
    msgs_idx += hs_s_hs_finished.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try ks.generateApplicationSecrets(msgs_stream.getWritten());

    // Construct client finised message
    var c_hs_finished_digest: [Sha256.digest_length]u8 = undefined;
    var c_hs_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(msgs_stream.getWritten(), &c_hs_hash, .{});
    hmac.Hmac(Sha256).create(&c_hs_finished_digest, &c_hs_hash, &ks.c_hs_finished_secret);

    var c_finished = try msg.Finished.init(Sha256);
    std.mem.copy(u8, c_finished.verify_data.slice(), &c_hs_finished_digest);
    const hs_c_finished = msg.Handshake{ .finished = c_finished };

    const c_finished_ans = [_]u8{ 0x14, 0x0, 0x0, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2, 0xed, 0xd5, 0xce, 0x61 };
    var c_finished_inner = try record.TLSInnerPlainText.init(hs_c_finished.length(), std.testing.allocator);
    c_finished_inner.content_type = .handshake;
    defer c_finished_inner.deinit();
    _ = try hs_c_finished.encode(io.fixedBufferStream(c_finished_inner.content).writer());
    try expect(std.mem.eql(u8, c_finished_inner.content, &c_finished_ans));

    const c_record_finished_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xEC, 0x4D, 0xC2, 0x38, 0xCC, 0xE6, 0x0B, 0x29, 0x80, 0x44, 0xA7, 0x1E, 0x21, 0x9C, 0x56, 0xCC, 0x77, 0xB0, 0x51, 0x7F, 0xE9, 0xB9, 0x3C, 0x7A, 0x4B, 0xFC, 0x44, 0xD8, 0x7F, 0x38, 0xF8, 0x03, 0x38, 0xAC, 0x98, 0xFC, 0x46, 0xDE, 0xB3, 0x84, 0xBD, 0x1C, 0xAE, 0xAC, 0xAB, 0x68, 0x67, 0xD7, 0x26, 0xC4, 0x05, 0x46 };
    var c_record_finished_bytes: [1000]u8 = undefined;
    const c_record_finished = try Protector.encrypt(c_finished_inner, ks.generateNonce(ks.c_hs_iv, 0), ks.c_hs_key, std.testing.allocator);
    defer c_record_finished.deinit();
    const c_finished_write_len = try c_record_finished.encode(io.fixedBufferStream(&c_record_finished_bytes).writer());
    try expect(std.mem.eql(u8, c_record_finished_bytes[0..c_finished_write_len], &c_record_finished_ans));

    // STATE = CONNECTED

    _ = try msgs_stream.write(c_record_finished_bytes[0..c_finished_write_len]);
    try ks.generateResumptionMasterSecret(msgs_stream.getWritten());

    // decode NewSessionTicket
    const s_ticket_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0xDE, 0x3A, 0x6B, 0x8F, 0x90, 0x41, 0x4A, 0x97, 0xD6, 0x95, 0x9C, 0x34, 0x87, 0x68, 0x0D, 0xE5, 0x13, 0x4A, 0x2B, 0x24, 0x0E, 0x6C, 0xFF, 0xAC, 0x11, 0x6E, 0x95, 0xD4, 0x1D, 0x6A, 0xF8, 0xF6, 0xB5, 0x80, 0xDC, 0xF3, 0xD1, 0x1D, 0x63, 0xC7, 0x58, 0xDB, 0x28, 0x9A, 0x01, 0x59, 0x40, 0x25, 0x2F, 0x55, 0x71, 0x3E, 0x06, 0x1D, 0xC1, 0x3E, 0x07, 0x88, 0x91, 0xA3, 0x8E, 0xFB, 0xCF, 0x57, 0x53, 0xAD, 0x8E, 0xF1, 0x70, 0xAD, 0x3C, 0x73, 0x53, 0xD1, 0x6D, 0x9D, 0xA7, 0x73, 0xB9, 0xCA, 0x7F, 0x2B, 0x9F, 0xA1, 0xB6, 0xC0, 0xD4, 0xA3, 0xD0, 0x3F, 0x75, 0xE0, 0x9C, 0x30, 0xBA, 0x1E, 0x62, 0x97, 0x2A, 0xC4, 0x6F, 0x75, 0xF7, 0xB9, 0x81, 0xBE, 0x63, 0x43, 0x9B, 0x29, 0x99, 0xCE, 0x13, 0x06, 0x46, 0x15, 0x13, 0x98, 0x91, 0xD5, 0xE4, 0xC5, 0xB4, 0x06, 0xF1, 0x6E, 0x3F, 0xC1, 0x81, 0xA7, 0x7C, 0xA4, 0x75, 0x84, 0x00, 0x25, 0xDB, 0x2F, 0x0A, 0x77, 0xF8, 0x1B, 0x5A, 0xB0, 0x5B, 0x94, 0xC0, 0x13, 0x46, 0x75, 0x5F, 0x69, 0x23, 0x2C, 0x86, 0x51, 0x9D, 0x86, 0xCB, 0xEE, 0xAC, 0x87, 0xAA, 0xC3, 0x47, 0xD1, 0x43, 0xF9, 0x60, 0x5D, 0x64, 0xF6, 0x50, 0xDB, 0x4D, 0x02, 0x3E, 0x70, 0xE9, 0x52, 0xCA, 0x49, 0xFE, 0x51, 0x37, 0x12, 0x1C, 0x74, 0xBC, 0x26, 0x97, 0x68, 0x7E, 0x24, 0x87, 0x46, 0xD6, 0xDF, 0x35, 0x30, 0x05, 0xF3, 0xBC, 0xE1, 0x86, 0x96, 0x12, 0x9C, 0x81, 0x53, 0x55, 0x6B, 0x3B, 0x6C, 0x67, 0x79, 0xB3, 0x7B, 0xF1, 0x59, 0x85, 0x68, 0x4F };
    const pt_s_ticket = try Protector.decryptFromCipherBytes(&s_ticket_enc, ks.generateNonce(ks.s_ap_iv, 0), ks.s_ap_key, std.testing.allocator);
    defer pt_s_ticket.deinit();
    try expect(pt_s_ticket.content_type == .handshake);

    // send application_data
    var c_app_data: [50]u8 = undefined;
    for (c_app_data) |*value, app_i| {
        value.* = @intCast(u8, app_i);
    }

    const c_app_record_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x43, 0xA2, 0x3F, 0x70, 0x54, 0xB6, 0x2C, 0x94, 0xD0, 0xAF, 0xFA, 0xFE, 0x82, 0x28, 0xBA, 0x55, 0xCB, 0xEF, 0xAC, 0xEA, 0x42, 0xF9, 0x14, 0xAA, 0x66, 0xBC, 0xAB, 0x3F, 0x2B, 0x98, 0x19, 0xA8, 0xA5, 0xB4, 0x6B, 0x39, 0x5B, 0xD5, 0x4A, 0x9A, 0x20, 0x44, 0x1E, 0x2B, 0x62, 0x97, 0x4E, 0x1F, 0x5A, 0x62, 0x92, 0xA2, 0x97, 0x70, 0x14, 0xBD, 0x1E, 0x3D, 0xEA, 0xE6, 0x3A, 0xEE, 0xBB, 0x21, 0x69, 0x49, 0x15, 0xE4 };
    const c_app_record = try Protector.encryptFromPlainBytes(&c_app_data, .application_data, ks.generateNonce(ks.c_ap_iv, 0), ks.c_ap_key, std.testing.allocator);
    defer c_app_record.deinit();
    var c_app: [1000]u8 = undefined;
    const c_app_len = try c_app_record.encode(io.fixedBufferStream(&c_app).writer());
    try expect(std.mem.eql(u8, c_app[0..c_app_len], &c_app_record_ans));

    // recv application_data
    const s_app_record_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x43, 0x2E, 0x93, 0x7E, 0x11, 0xEF, 0x4A, 0xC7, 0x40, 0xE5, 0x38, 0xAD, 0x36, 0x00, 0x5F, 0xC4, 0xA4, 0x69, 0x32, 0xFC, 0x32, 0x25, 0xD0, 0x5F, 0x82, 0xAA, 0x1B, 0x36, 0xE3, 0x0E, 0xFA, 0xF9, 0x7D, 0x90, 0xE6, 0xDF, 0xFC, 0x60, 0x2D, 0xCB, 0x50, 0x1A, 0x59, 0xA8, 0xFC, 0xC4, 0x9C, 0x4B, 0xF2, 0xE5, 0xF0, 0xA2, 0x1C, 0x00, 0x47, 0xC2, 0xAB, 0xF3, 0x32, 0x54, 0x0D, 0xD0, 0x32, 0xE1, 0x67, 0xC2, 0x95, 0x5D };
    const pt_recv_ap = try Protector.decryptFromCipherBytes(&s_app_record_enc, ks.generateNonce(ks.s_ap_iv, 1), ks.s_ap_key, std.testing.allocator);
    defer pt_recv_ap.deinit();
    try expect(pt_recv_ap.content_type == .application_data);

    // send alert
    const c_alert_data = [_]u8{ 0x01, 0x00 }; // ContentType alert
    const c_alert_record = try Protector.encryptFromPlainBytes(&c_alert_data, .alert, ks.generateNonce(ks.c_ap_iv, 1), ks.c_ap_key, std.testing.allocator);
    defer c_alert_record.deinit();
    const c_alert_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xC9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xB7, 0x4D, 0x7F, 0xF1, 0x15, 0x3E, 0xFD, 0x6D, 0xB6, 0xD0, 0xB0, 0xE3 };
    var c_alert: [1000]u8 = undefined;
    const c_alert_len = try c_alert_record.encode(io.fixedBufferStream(&c_alert).writer());
    try expect(std.mem.eql(u8, c_alert[0..c_alert_len], &c_alert_ans));

    // recv alert
    const s_alert_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    const pt_recv_alert = try Protector.decryptFromCipherBytes(&s_alert_enc, ks.generateNonce(ks.s_ap_iv, 2), ks.s_ap_key, std.testing.allocator);
    defer pt_recv_alert.deinit();
    try expect(pt_recv_alert.content_type == .alert);

    // End of connection
}
