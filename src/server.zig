const std = @import("std");
const io = std.io;
const os = std.os;
const net = std.net;
const dh = std.crypto.dh;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
const random = std.crypto.random;
const ArrayList = std.ArrayList;

const msg = @import("msg.zig");
const key = @import("key.zig");
const extension = @import("extension.zig");
const certificate = @import("certificate.zig");
const key_share = @import("key_share.zig");
const SupportedVersions = @import("supported_versions.zig").SupportedVersions;
const signature_scheme = @import("signature_scheme.zig");
const server_name = @import("server_name.zig");
const crypto = @import("crypto.zig");
const x509 = @import("x509.zig");
const ServerHello = @import("server_hello.zig").ServerHello;
const ClientHello = @import("client_hello.zig").ClientHello;
const Handshake = @import("handshake.zig").Handshake;
const EncryptedExtensions = @import("encrypted_extensions.zig").EncryptedExtensions;
const Finished = @import("finished.zig").Finished;
const Alert = @import("alert.zig").Alert;
const ApplicationData = @import("application_data.zig").ApplicationData;
const CertificateVerify = @import("certificate_verify.zig").CertificateVerify;
const NamedGroup = @import("supported_groups.zig").NamedGroup;
const NamedGroupList = @import("supported_groups.zig").NamedGroupList;
const RecordPayloadProtector = @import("protector.zig").RecordPayloadProtector;
const TLSPlainText = @import("tls_plain.zig").TLSPlainText;
const TLSCipherText = @import("tls_cipher.zig").TLSCipherText;

const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const rsa = @import("rsa.zig");

pub const TLSServerTCP = TLSServerImpl(net.Stream.Reader, net.Stream.Writer, true);

pub fn TLSServerImpl(comptime ReaderType: type, comptime WriterType: type, comptime is_tcp: bool) type {
    return struct {
        // io
        tcp_server: net.StreamServer = undefined,

        // host
        host: []u8 = &([_]u8{}),

        // certificate
        cert: certificate.CertificateEntry,
        cert_key: x509.PrivateKey,

        ca_cert: ?certificate.CertificateEntry = null,

        // Misc
        allocator: std.mem.Allocator,

        // print
        print_keys: bool = false,

        const Self = @This();

        const Error = error{
            UnsupportedPrivateKey,
        };

        pub fn init(key_path: []const u8, key_type: x509.PrivateKeyType, cert_path: []const u8, ca_path: ?[]const u8, host: ?[]const u8, allocator: std.mem.Allocator) !Self {
            // ignore SIGPIPE
            var act = os.Sigaction{
                .handler = .{ .handler = os.SIG.IGN },
                .mask = os.empty_sigset,
                .flags = (os.SA.SIGINFO | os.SA.RESTART | os.SA.RESETHAND),
            };
            try os.sigaction(os.SIG.PIPE, &act, null);

            var private_key: x509.PrivateKey = undefined;
            switch (key_type) {
                .rsa => {
                    const cert_keys = try x509.RSAPrivateKey.fromDer(key_path, allocator);
                    private_key = .{ .rsa = cert_keys };
                },
                .ec => {
                    const cert_keys = try x509.ECPrivateKey.fromDer(key_path, allocator);
                    if (cert_keys.namedCurve) |n| {
                        if (!std.mem.eql(u8, n.id, "1.2.840.10045.3.1.7")) {
                            // currently, only accepts secp256r1.
                            return Error.UnsupportedPrivateKey;
                        }
                    } else {
                        return Error.UnsupportedPrivateKey;
                    }

                    private_key = .{ .ec = cert_keys };
                },
            }

            var res = Self{
                .cert = try certificate.CertificateEntry.fromDerFile(cert_path, allocator),
                .cert_key = private_key,

                .allocator = allocator,
            };

            if (ca_path) |p| {
                res.ca_cert = try certificate.CertificateEntry.fromDerFile(p, allocator);
            }

            if (host) |h| {
                res.host = try allocator.alloc(u8, h.len);
                std.mem.copy(u8, res.host, h);
            }

            return res;
        }

        pub fn deinit(self: Self) void {
            if (self.host.len != 0) {
                self.allocator.free(self.host);
            }
            self.cert.deinit();
            if (self.ca_cert) |c| {
                c.deinit();
            }
        }

        pub fn listen(self: *Self, port: u16) !void {
            if (is_tcp) {
                self.tcp_server = net.StreamServer.init(.{
                    .reuse_address = true,
                });
                const addr = try net.Address.parseIp("0.0.0.0", port);
                try self.tcp_server.listen(addr);
            }
        }

        pub fn accept(self: *Self) !TLSStreamImpl(ReaderType, WriterType, is_tcp) {
            var conn = try self.tcp_server.accept();
            std.log.info("accept remote_addr={}", .{conn.address});
            var stream = try TLSStreamImpl(ReaderType, WriterType, is_tcp).init(self.*, conn, self.allocator);
            return stream;
        }
    };
}

pub const TLSStreamTCP = TLSStreamImpl(net.Stream.Reader, net.Stream.Writer, true);

pub fn TLSStreamImpl(comptime ReaderType: type, comptime WriterType: type, comptime is_tcp: bool) type {
    return struct {
        // server
        const TLSServer = TLSServerImpl(ReaderType, WriterType, is_tcp);
        tls_server: TLSServer,

        // io
        reader: ReaderType,
        writer: WriterType,
        write_buffer: io.BufferedWriter(4096, WriterType),
        tcp_conn: ?net.StreamServer.Connection = null,

        // session related
        random: [32]u8,
        session_id: msg.SessionID,

        // message buffer for KeySchedule
        msgs_bytes: []u8,
        msgs_stream: io.FixedBufferStream([]u8),

        // key_share
        key_share: NamedGroup = .x25519,

        // X25519 DH keys
        x25519_priv_key: [32]u8 = [_]u8{0} ** 32,
        x25519_pub_key: [32]u8 = [_]u8{0} ** 32,

        // secp256r1 DH keys
        secp256r1_key: P256.KeyPair = undefined,

        // payload protection
        cipher_suite: msg.CipherSuite,
        ks: key.KeyScheduler,
        hs_protector: RecordPayloadProtector,
        ap_protector: RecordPayloadProtector,

        // misc
        allocator: std.mem.Allocator,

        const Self = @This();

        const Error = error{
            IllegalParameter,
            UnexpectedMessage,
            IoNotConfigured,
            InvalidServerHello,
            InvalidFinished,
            UnsupportedProtocolVersion,
            UnsupportedCertificateAlgorithm,
            UnsupportedCipherSuite,
            UnsupportedKeyShareAlgorithm,
            UnsupportedSignatureScheme,
            CertificateNotFound,
            FailedToConnect,
            UnsupportedPrivateKey,
            UnknownServerName,
        };

        pub fn init(server: TLSServer, tcp_conn: net.StreamServer.Connection, allocator: std.mem.Allocator) !Self {
            if (!is_tcp) {
                return Error.NotTCP;
            }

            var rand: [32]u8 = undefined;
            random.bytes(&rand);

            var msgs_bytes = try allocator.alloc(u8, 1024 * 32);
            errdefer allocator.free(msgs_bytes);

            var secp256r1_priv_key: [P256.SecretKey.encoded_length]u8 = undefined;
            random.bytes(secp256r1_priv_key[0..]);

            var res = Self{
                .tls_server = server,
                .reader = tcp_conn.stream.reader(),
                .writer = tcp_conn.stream.writer(),
                .write_buffer = io.bufferedWriter(tcp_conn.stream.writer()),
                .tcp_conn = tcp_conn,
                .random = rand,
                .session_id = undefined,
                .msgs_bytes = msgs_bytes,
                .msgs_stream = io.fixedBufferStream(msgs_bytes),
                .secp256r1_key = try P256.KeyPair.fromSecretKey(try P256.SecretKey.fromBytes(secp256r1_priv_key)),
                .cipher_suite = undefined,
                .ks = undefined,
                .hs_protector = undefined,
                .ap_protector = undefined,
                .allocator = allocator,
            };

            random.bytes(&res.x25519_priv_key);
            res.x25519_pub_key = try dh.X25519.recoverPublicKey(res.x25519_priv_key);

            return res;
        }

        pub fn deinit(self: Self) void {
            if (self.tcp_conn) |c| {
                c.stream.close();
            }
            self.allocator.free(self.msgs_bytes);
        }

        fn createServerHello(self: Self) !ServerHello {
            var server_hello = ServerHello.init(self.random, self.session_id, self.cipher_suite, self.allocator);

            // Extension SupportedVresions
            var sv = try SupportedVersions.init(.server_hello);
            try sv.versions.append(0x0304); //TLSv1.3
            try server_hello.extensions.append(.{ .supported_versions = sv });

            // Extension KeyShare
            var ks = key_share.KeyShare.init(self.allocator, .server_hello, false);
            switch (self.key_share) {
                .x25519 => {
                    var entry_x25519 = try key_share.KeyShareEntry.init(.x25519, 32, self.allocator);
                    std.mem.copy(u8, entry_x25519.key_exchange, &self.x25519_pub_key);
                    try ks.entries.append(entry_x25519);
                },
                .secp256r1 => {
                    var entry_secp256r1 = try key_share.KeyShareEntry.init(.secp256r1, P256.PublicKey.uncompressed_sec1_encoded_length, self.allocator);
                    std.mem.copy(u8, entry_secp256r1.key_exchange, &self.secp256r1_key.public_key.toUncompressedSec1());
                    try ks.entries.append(entry_secp256r1);
                },
                else => unreachable,
            }
            try server_hello.extensions.append(.{ .key_share = ks });

            return server_hello;
        }

        pub fn handshake(self: *Self) !void {
            std.log.info("handshake started", .{});
            var t = try self.reader.readEnum(ContentType, .Big);
            const ch_record = try TLSPlainText.decode(self.reader, t, self.allocator, null, self.msgs_stream.writer());
            defer ch_record.deinit();
            if (ch_record.content != .handshake) {
                return Error.UnexpectedMessage;
            }
            const hs = ch_record.content.handshake;
            if (hs != .client_hello) {
                return Error.UnexpectedMessage;
            }
            const ch = hs.client_hello;
            try self.handleClientHello(ch);
            try self.sendServerHello();

            try self.ks.generateHandshakeSecrets(self.msgs_stream.getWritten());
            std.log.debug("generated handshake secrets", .{});
            self.hs_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.s_hs_keys, self.ks.secret.c_hs_keys);

            try self.sendEncryptedExtensions();
            try self.sendCertificate();
            try self.sendCertificateVerify();
            try self.sendFinished();

            try self.write_buffer.flush();
            std.log.debug("sent all contents in write buffer", .{});

            try self.ks.generateApplicationSecrets(self.msgs_stream.getWritten());
            self.ap_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.s_ap_keys, self.ks.secret.c_ap_keys);
            std.log.debug("generated application secrets", .{});

            if (self.tls_server.print_keys) {
                self.ks.printKeys(&self.random);
            }

            // wait for Finished.
            var finished_ok = false;
            while (!finished_ok) {
                t = try self.reader.readEnum(ContentType, .Big);
                if (t == .change_cipher_spec) {
                    const r = try TLSPlainText.decode(self.reader, t, self.allocator, null, null);
                    defer r.deinit();
                } else if (t == .alert) {
                    const r = try TLSPlainText.decode(self.reader, t, self.allocator, null, null);
                    defer r.deinit();
                    const alert = r.content.alert;
                    std.log.err("alert = {}", .{alert});
                } else if (t == .application_data) {
                    const c_record = try TLSCipherText.decode(self.reader, t, self.allocator);
                    defer c_record.deinit();

                    var p_record = try self.hs_protector.decrypt(c_record, self.allocator);
                    defer p_record.deinit();
                    if (p_record.content_type == .alert) {
                        const alert = (try p_record.decodeContent(self.allocator, null)).alert;
                        std.log.err("alert = {}", .{alert});
                        continue;
                    }

                    if (p_record.content_type != .handshake) {
                        std.log.warn("unexpected message type={s}", .{@tagName(p_record.content_type)});
                        continue;
                    }

                    const hss = try p_record.decodeContents(self.allocator, self.ks.hkdf);
                    for (hss.items) |h| {
                        if (h.handshake != .finished) {
                            std.log.warn("unexpected message type={s}", .{@tagName(h.handshake)});
                            continue;
                        }
                        try self.handleFinished(h.handshake.finished);
                        finished_ok = true;
                    }
                } else {
                    std.log.err("unexpected message type={s}", .{@tagName(t)});
                }
            }

            std.log.info("handshake done", .{});
        }

        pub fn send(self: *Self, b: []const u8) !usize {
            const app_c = Content{ .application_data = try ApplicationData.initAsView(b) };
            defer app_c.deinit();

            _ = try self.ap_protector.encryptFromMessageAndWrite(app_c, self.allocator, self.write_buffer.writer());
            try self.write_buffer.flush();

            return b.len;
        }

        pub fn recv(self: *Self, b: []u8) !usize {
            var ap_recv = false;
            var msg_stream = io.fixedBufferStream(b);
            while (!ap_recv) {
                const t = try self.reader.readEnum(ContentType, .Big);
                if (t != .application_data) {
                    // TODO: error
                    std.log.warn("unexpected message type={s}", .{@tagName(t)});
                    continue;
                }
                const recv_record = try TLSCipherText.decode(self.reader, t, self.allocator);
                defer recv_record.deinit();

                const plain_record = try self.ap_protector.decrypt(recv_record, self.allocator);
                defer plain_record.deinit();

                if (plain_record.content_type != .application_data) {
                    continue;
                }

                const content = try plain_record.decodeContent(self.allocator, self.ks.hkdf);
                defer content.deinit();
                // TODO: handle oversized content
                _ = try msg_stream.write(content.application_data.content);
                ap_recv = true;
            }

            return msg_stream.getWritten().len;
        }

        pub fn close(self: *Self) void {
            defer {
                if (self.tcp_conn) |c| {
                    c.stream.close();
                    self.tcp_conn = null;
                    std.log.debug("tcp connection closed", .{});
                }
            }

            const close_notify = Content{ .alert = Alert{ .level = .warning, .description = .close_notify } };
            _ = self.ap_protector.encryptFromMessageAndWrite(
                close_notify,
                self.allocator,
                self.write_buffer.writer(),
            ) catch {
                return;
            };

            self.write_buffer.flush() catch {
                // TCP connection may be closed.
                return;
            };
        }

        fn handleClientHello(self: *Self, ch: ClientHello) !void {
            std.log.debug("received ClientHello", .{});
            self.session_id = ch.legacy_session_id;

            // Checking TLS version.
            const sv = (try msg.getExtension(ch.extensions, .supported_versions)).supported_versions;
            var version_ok = false;
            for (sv.versions.slice()) |v| {
                if (v == 0x0304) {
                    // TLS1.3
                    version_ok = true;
                }
            }
            if (!version_ok) {
                return Error.UnsupportedProtocolVersion;
            }

            // Selecting CiperSuite
            var cs_ok = ch.cipher_suites.items.len != 0;
            var hkdf: crypto.Hkdf = undefined;
            var aead: crypto.Aead = undefined;
            for (ch.cipher_suites.items) |cs| {
                self.cipher_suite = cs;
                switch (cs) {
                    .TLS_AES_128_GCM_SHA256 => {
                        hkdf = crypto.Hkdf.Sha256.hkdf;
                        aead = crypto.Aead.Aes128Gcm.aead;
                        cs_ok = true;
                        break;
                    },
                    .TLS_AES_256_GCM_SHA384 => {
                        hkdf = crypto.Hkdf.Sha384.hkdf;
                        aead = crypto.Aead.Aes256Gcm.aead;
                        cs_ok = true;
                        break;
                    },
                    .TLS_CHACHA20_POLY1305_SHA256 => {
                        hkdf = crypto.Hkdf.Sha256.hkdf;
                        aead = crypto.Aead.ChaCha20Poly1305.aead;
                        cs_ok = true;
                        break;
                    },
                    else => cs_ok = false,
                }
            }
            if (!cs_ok) {
                return Error.UnsupportedCipherSuite;
            }
            self.ks = try key.KeyScheduler.init(hkdf, aead);
            std.log.debug("selected cipher_suite={s}", .{@tagName(self.cipher_suite)});

            // Selecting KeyShare and deriving shared secret.
            const ks = (try msg.getExtension(ch.extensions, .key_share)).key_share;
            var key_share_ok = ks.entries.items.len != 0;
            const zero_bytes = &([_]u8{0} ** 64);
            for (ks.entries.items) |ke| {
                switch (ke.group) {
                    .x25519 => |k| {
                        self.key_share = k;
                        key_share_ok = true;

                        const shared_key = try dh.X25519.scalarmult(self.x25519_priv_key, ke.key_exchange[0..32].*);
                        try self.ks.generateEarlySecrets(&shared_key, zero_bytes[0..self.ks.hkdf.digest_length]);
                    },
                    .secp256r1 => |k| {
                        self.key_share = k;
                        key_share_ok = true;

                        const pubkey = try P256.PublicKey.fromSec1(ke.key_exchange);
                        const mul = try pubkey.p.mulPublic(self.secp256r1_key.secret_key.bytes, .Big);
                        const shared_key = mul.affineCoordinates().x.toBytes(.Big);
                        try self.ks.generateEarlySecrets(&shared_key, zero_bytes[0..self.ks.hkdf.digest_length]);
                    },
                    else => key_share_ok = false,
                }
            }
            if (!key_share_ok) {
                return Error.UnsupportedKeyShareAlgorithm;
            }
            std.log.debug("selected key_share={s}", .{@tagName(self.key_share)});

            var sn_ok = true;
            if (self.tls_server.host.len != 0) {
                sn_ok = false;
                const snl = (try msg.getExtension(ch.extensions, .server_name)).server_name;
                for (snl.server_name_list.items) |sn| {
                    if (std.mem.eql(u8, sn.host_name, self.tls_server.host)) {
                        sn_ok = true;
                        std.log.debug("server_name={s}", .{self.tls_server.host});
                        break;
                    }
                }
            }
            if (!sn_ok) {
                return Error.UnknownServerName;
            }
        }

        fn sendServerHello(self: *Self) !void {
            const sh = try self.createServerHello();
            const hs_sh = Handshake{ .server_hello = sh };
            _ = try hs_sh.encode(self.msgs_stream.writer());

            const record_sh = TLSPlainText{ .content = Content{ .handshake = hs_sh } };
            defer record_sh.deinit();
            _ = try record_sh.encode(self.write_buffer.writer());

            std.log.debug("ServerHello has been written to send buffer", .{});
        }

        fn sendEncryptedExtensions(self: *Self) !void {
            const ee = EncryptedExtensions.init(self.allocator);
            const cont_ee = Content{ .handshake = .{ .encrypted_extensions = ee } };
            defer cont_ee.deinit();
            _ = try cont_ee.encode(self.msgs_stream.writer());

            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_ee, self.allocator, self.write_buffer.writer());

            std.log.debug("EncryptedExtensions has been written to send buffer", .{});
        }

        fn sendCertificate(self: *Self) !void {
            var c = try certificate.Certificate.init(0, self.allocator);
            defer {
                // remove certs not to deinit them.
                // TODO: FIX THIS.
                _ = c.cert_list.popOrNull();
                _ = c.cert_list.popOrNull();
                _ = c.cert_list.popOrNull();
                c.deinit();
            }
            try c.cert_list.append(self.tls_server.cert);
            if (self.tls_server.ca_cert) |ca| {
                try c.cert_list.append(ca);
            }
            var cont_c = Content{ .handshake = .{ .certificate = c } };
            _ = try cont_c.encode(self.msgs_stream.writer());
            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_c, self.allocator, self.write_buffer.writer());

            std.log.debug("Certificate has been written to send buffer", .{});
        }

        fn sendCertificateVerify(self: *Self) !void {
            var hash_out: [crypto.Hkdf.MAX_DIGEST_LENGTH]u8 = undefined;
            self.ks.hkdf.hash(&hash_out, self.msgs_stream.getWritten());

            // TODO: fix not to allocate large buffer.
            var verify_bytes: [1000]u8 = undefined;
            var verify_stream = io.fixedBufferStream(&verify_bytes);
            _ = try verify_stream.write(&([_]u8{0x20} ** 64));
            _ = try verify_stream.write("TLS 1.3, server CertificateVerify");
            _ = try verify_stream.write(&([_]u8{0x00}));
            _ = try verify_stream.write(hash_out[0..self.ks.hkdf.digest_length]);

            var cv: CertificateVerify = undefined;
            switch (self.tls_server.cert_key) {
                .rsa => |k| {
                    var modulus_len = k.modulus.len;
                    var i: usize = 0;
                    while (i < modulus_len) : (i += 1) {
                        if (k.modulus[i] != 0) {
                            break;
                        }
                        modulus_len -= 1;
                    }
                    const modulus = k.modulus[i..];
                    const modulus_bits = modulus.len * 8;
                    if (modulus_bits == 2048) {
                        var p_key = try rsa.Rsa2048.SecretKey.fromBytes(k.privateExponent, modulus, self.allocator);
                        defer p_key.deinit();

                        const sig = try rsa.Rsa2048.PSSSignature.sign(verify_stream.getWritten(), p_key, std.crypto.hash.sha2.Sha256, self.allocator);
                        _ = sig;
                    } else if (modulus_bits == 4096) {
                        var p_key = try rsa.Rsa4096.SecretKey.fromBytes(k.privateExponent, modulus, self.allocator);
                        defer p_key.deinit();
                        var pub_key = try rsa.Rsa4096.PublicKey.fromBytes(k.publicExponent, modulus, self.allocator);
                        defer pub_key.deinit();

                        const sig = try rsa.Rsa4096.PSSSignature.sign(verify_stream.getWritten(), p_key, std.crypto.hash.sha2.Sha256, self.allocator);
                        try sig.verify(verify_stream.getWritten(), pub_key, std.crypto.hash.sha2.Sha256, self.allocator);
                        cv = try CertificateVerify.init(.rsa_pss_rsae_sha256, sig.signature.len, self.allocator);
                        std.mem.copy(u8, cv.signature, &sig.signature);
                    } else {
                        std.log.err("unsupported modulus length: {d} bits", .{modulus_bits});
                        return Error.UnsupportedSignatureScheme;
                    }
                },
                .ec => |k| {
                    const skey = try P256.SecretKey.fromBytes(k.privateKey[0..P256.SecretKey.encoded_length].*);
                    const kp = try P256.KeyPair.fromSecretKey(skey);
                    const verify_sig = try kp.sign(verify_stream.getWritten(), null);
                    var sig_buf: [P256.Signature.der_encoded_max_length]u8 = undefined;
                    const sig_bytes = verify_sig.toDer(&sig_buf);
                    cv = try CertificateVerify.init(.ecdsa_secp256r1_sha256, sig_bytes.len, self.allocator);
                    std.mem.copy(u8, cv.signature, sig_bytes);
                },
            }
            const cont_cv = Content{ .handshake = .{ .certificate_verify = cv } };
            defer cont_cv.deinit();
            _ = try cont_cv.encode(self.msgs_stream.writer());
            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_cv, self.allocator, self.write_buffer.writer());

            std.log.debug("CertificateVerify has been written to send buffer", .{});
        }

        fn sendFinished(self: *Self) !void {
            const fin = try Finished.fromMessageBytes(self.msgs_stream.getWritten(), self.ks.secret.s_hs_finished_secret.slice(), self.ks.hkdf);
            const cont_fin = Content{ .handshake = Handshake{ .finished = fin } };
            defer cont_fin.deinit();
            _ = try cont_fin.encode(self.msgs_stream.writer());

            _ = try self.hs_protector.encryptFromMessageAndWrite(cont_fin, self.allocator, self.write_buffer.writer());

            std.log.debug("Finished has been written to send buffer", .{});
        }

        fn handleFinished(self: *Self, fin: Finished) !void {
            std.log.debug("receieved Finished", .{});
            if (!fin.verify(self.msgs_stream.getWritten(), self.ks.secret.c_hs_finished_secret.slice())) {
                return Error.InvalidFinished;
            }
            std.log.debug("Finished verify done", .{});
        }
    };
}
