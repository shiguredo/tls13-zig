const std = @import("std");
const io = std.io;
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
const common = @import("common.zig");
const ServerHello = @import("server_hello.zig").ServerHello;
const ClientHello = @import("client_hello.zig").ClientHello;
const HandshakeType = @import("handshake.zig").HandshakeType;
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
const TLSInnerPlainText = @import("tls_cipher.zig").TLSInnerPlainText;
const NewSessionTicket = @import("new_session_ticket.zig").NewSessionTicket;
const MessageHash = @import("message_hash.zig").MessageHash;
const pre_shared_key = @import("pre_shared_key.zig");
const PskKeyExchangeModes = @import("psk_key_exchange_modes.zig").PskKeyExchangeModes;
const EarlyData = @import("early_data.zig").EarlyData;
const KeyUpdate = @import("key_update.zig").KeyUpdate;
const RecordSizeLimit = @import("record_size_limit.zig").RecordSizeLimit;

const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

const rsa = @import("rsa.zig");

const Client = std.x.net.tcp.Client;

pub fn ErrorSetOf(comptime Function: anytype) type {
    return @typeInfo(@typeInfo(@TypeOf(Function)).Fn.return_type.?).ErrorUnion.error_set;
}

pub const TLSClientTCP = TLSClientImpl(io.Reader(Client.Reader, ErrorSetOf(Client.Reader.read), Client.Reader.read), io.Writer(Client.Writer, ErrorSetOf(Client.Writer.write), Client.Writer.write), true);

pub fn TLSClientImpl(comptime ReaderType: type, comptime WriterType: type, comptime is_tcp: bool) type {
    return struct {
        // io
        io_init: bool = false,
        reader: ReaderType = undefined,
        writer: WriterType = undefined,
        write_buffer: io.BufferedWriter(4096, WriterType) = undefined,
        tcp_client: ?std.x.net.tcp.Client = null,

        // session related
        random: [32]u8,
        session_id: msg.SessionID,
        host: []u8 = &([_]u8{}),

        // engines
        write_engine: common.WriteEngine(io.BufferedWriter(4096, WriterType), .client) = undefined,
        read_engine: ?common.ReadEngine(Self, .client) = null,

        // message buffer for KeySchedule
        msgs_bytes: []u8,
        msgs_stream: io.FixedBufferStream([]u8),

        // state machine
        state: State = State.START,
        already_recv_hrr: bool = false,

        // key_share
        supported_groups: ArrayList(NamedGroup),
        key_shares: ArrayList(NamedGroup),

        // X25519 DH keys
        x25519_priv_key: [32]u8 = [_]u8{0} ** 32,
        x25519_pub_key: [32]u8 = [_]u8{0} ** 32,

        // secp256r1 DH keys
        secp256r1_key: P256.KeyPair = undefined,

        // new session tickets
        session_ticket: ?NewSessionTicket = null,
        resume_accepted: bool = false,
        early_data: []const u8 = &([_]u8{}), // this array is not managed by TLSClient.
        early_data_ok: bool = false,
        early_protector: RecordPayloadProtector = undefined,

        // psk
        pre_shared_key: ?pre_shared_key.PskIdentity = null,
        res_secret: ?crypto.DigestBoundedArray = null,

        // payload protection
        cipher_suites: ArrayList(msg.CipherSuite),
        ks: key.KeyScheduler,
        hs_protector: RecordPayloadProtector,
        ap_protector: RecordPayloadProtector,

        // certificate
        signature_schems: ArrayList(signature_scheme.SignatureScheme),
        cert_pubkeys: ArrayList(x509.PublicKey),

        // record size limitation
        // RFC 8449 Section 4.  The "record_size_limit" Extension
        // An endpoint that supports all record sizes can include any limit up
        // to the protocol-defined limit for maximum record size.  For TLS 1.2
        // and earlier, that limit is 2^14 octets.  TLS 1.3 uses a limit of
        // 2^14+1 octets.
        record_size_limit: u16 = 2 << 13,

        // Misc
        allocator: std.mem.Allocator,

        // logoutput
        print_keys: bool = false,

        const State = enum { START, SEND_CH, WAIT_SH, WAIT_EE, WAIT_CERT_CR, WAIT_CERT, WAIT_CV, WAIT_FINISHED, SEND_FINISHED, CONNECTED };

        const Self = @This();

        const Error = error{
            IllegalParameter,
            UnexpectedMessage,
            IoNotConfigured,
            InvalidServerHello,
            UnsupportedCertificateAlgorithm,
            UnsupportedCipherSuite,
            UnsupportedKeyShareAlgorithm,
            UnsupportedSignatureScheme,
            CertificateNotFound,
            FailedToConnect,
            CannotSendEarlyData,
        };

        // io.Reader, Writer
        pub const ReadError = ErrorSetOf(Self.recv);
        pub const WriteError = ErrorSetOf(Self.send);

        pub const Reader = io.Reader(*Self, ReadError, recv);
        pub const Writer = io.Writer(*Self, WriteError, send);

        pub fn tlsReader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn tlsWriter(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn init(allocator: std.mem.Allocator) !Self {
            var session_id = try msg.SessionID.init(32);
            var msgs_bytes = try allocator.alloc(u8, 1024 * 32);
            errdefer allocator.free(msgs_bytes);

            var rand: [32]u8 = undefined;
            random.bytes(&rand);
            random.bytes(session_id.session_id.slice());

            var res = Self{
                .random = rand,
                .session_id = session_id,
                .msgs_bytes = msgs_bytes,
                .msgs_stream = io.fixedBufferStream(msgs_bytes),
                .supported_groups = ArrayList(NamedGroup).init(allocator),
                .key_shares = ArrayList(NamedGroup).init(allocator),
                .cipher_suites = ArrayList(msg.CipherSuite).init(allocator),
                .ks = undefined,
                .hs_protector = undefined,
                .ap_protector = undefined,
                .signature_schems = ArrayList(signature_scheme.SignatureScheme).init(allocator),
                .cert_pubkeys = ArrayList(x509.PublicKey).init(allocator),

                .allocator = allocator,
            };

            random.bytes(&res.x25519_priv_key);
            res.x25519_pub_key = try dh.X25519.recoverPublicKey(res.x25519_priv_key);

            var skey_bytes: [P256.SecretKey.encoded_length]u8 = undefined;
            random.bytes(skey_bytes[0..]);
            var skey = try P256.SecretKey.fromBytes(skey_bytes);
            res.secp256r1_key = try P256.KeyPair.fromSecretKey(skey);

            try res.supported_groups.append(.x25519);
            try res.supported_groups.append(.secp256r1);

            try res.key_shares.append(.x25519);
            //try res.key_shares.append(.secp256r1);

            try res.cipher_suites.append(.TLS_AES_128_GCM_SHA256);
            try res.cipher_suites.append(.TLS_AES_256_GCM_SHA384);
            try res.cipher_suites.append(.TLS_CHACHA20_POLY1305_SHA256);

            try res.signature_schems.append(.ecdsa_secp256r1_sha256);
            try res.signature_schems.append(.ecdsa_secp384r1_sha384);
            try res.signature_schems.append(.rsa_pss_rsae_sha256);

            return res;
        }

        pub fn initWithIo(reader: ReaderType, writer: WriterType, allocator: std.mem.Allocator) !Self {
            var res = try Self.init(allocator);
            res.io_init = true;
            res.reader = reader;
            res.writer = writer;

            return res;
        }

        pub fn deinit(self: Self) void {
            self.allocator.free(self.msgs_bytes);
            if (self.read_engine) |re| {
                re.deinit();
            }
            for (self.cert_pubkeys.items) |c| {
                c.deinit();
            }
            if (self.host.len != 0) {
                self.allocator.free(self.host);
            }
            self.cert_pubkeys.deinit();
            self.supported_groups.deinit();
            self.key_shares.deinit();
            if (self.session_ticket) |st| {
                st.deinit();
            }
            self.cipher_suites.deinit();
            self.ks.deinit();
            self.signature_schems.deinit();
            if (self.pre_shared_key) |p| {
                p.deinit();
            }
            if (self.tcp_client) |tc| {
                tc.deinit();
            }
        }

        pub fn configureX25519Keys(self: *Self, priv_key: [32]u8) !void {
            std.mem.copy(u8, &self.x25519_priv_key, &priv_key);
            self.x25519_pub_key = try dh.X25519.recoverPublicKey(self.x25519_priv_key);
        }

        fn createClientHello(self: *Self, host: []const u8) !ClientHello {
            var client_hello = ClientHello.init(self.random, self.session_id, self.allocator);

            // CipherSuite
            for (self.cipher_suites.items) |ch| {
                try client_hello.cipher_suites.append(ch);
            }

            // Extension SupportedVresions
            var sv = try SupportedVersions.init(.client_hello);
            try sv.versions.append(0x0304); //TLSv1.3
            try client_hello.extensions.append(.{ .supported_versions = sv });

            // Extension SupportedGroups
            var sg = NamedGroupList.init(self.allocator);
            for (self.supported_groups.items) |n| {
                try sg.groups.append(n);
            }
            try client_hello.extensions.append(.{ .supported_groups = sg });

            // Extension KeyShare
            var ks = key_share.KeyShare.init(self.allocator, .client_hello, false);
            for (self.key_shares.items) |k| {
                switch (k) {
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
            }
            try client_hello.extensions.append(.{ .key_share = ks });

            // Extension Signature Algorithms
            var sa = signature_scheme.SignatureSchemeList.init(self.allocator);
            for (self.signature_schems.items) |sc| {
                try sa.algos.append(sc);
            }
            try client_hello.extensions.append(.{ .signature_algorithms = sa });

            // Extension Server Name
            const sn = try server_name.ServerName.fromHostName(host, self.allocator);
            var snl = server_name.ServerNameList.init(self.allocator);
            try snl.server_name_list.append(sn);
            try client_hello.extensions.append(.{ .server_name = snl });

            // Extension Early Data
            if (self.early_data.len != 0 and self.pre_shared_key != null and !self.already_recv_hrr) {
                const ed = EarlyData{ .msg_type = .client_hello };
                try client_hello.extensions.append(.{ .early_data = ed });
            }

            // Extension Pre Shared Key
            // Caution!!: This extension must be appended last of createClientHello
            //            because of binder key derivation.
            if (self.pre_shared_key) |psk| {
                var pkem = PskKeyExchangeModes.init(self.allocator);
                try pkem.modes.append(.psk_dhe_ke);
                try client_hello.extensions.append(.{ .psk_key_exchange_modes = pkem });

                var opsk = try pre_shared_key.OfferedPsks.init(self.ks.hkdf.digest_length + 1, self.allocator);
                errdefer opsk.deinit();
                try opsk.identities.append(try psk.copy(self.allocator));
                var ext_psk = pre_shared_key.PreSharedKey{
                    .msg_type = .client_hello,
                    .offeredPsks = opsk,
                };
                try client_hello.extensions.append(.{ .pre_shared_key = ext_psk });

                try self.ks.generateEarlySecrets1(self.res_secret.?.slice());
                var prk = try crypto.DigestBoundedArray.init(self.ks.hkdf.digest_length);
                try self.ks.hkdf.deriveSecret(prk.slice(), self.ks.secret.early_secret.slice(), "res binder", "");
                var fin_secret = try crypto.DigestBoundedArray.init(self.ks.hkdf.digest_length);
                try self.ks.hkdf.hkdfExpandLabel(fin_secret.slice(), prk.slice(), "finished", "", self.ks.hkdf.digest_length);

                var hs_ch = Handshake{ .client_hello = client_hello };
                var ch_tmp = try self.allocator.alloc(u8, hs_ch.length());
                defer self.allocator.free(ch_tmp);
                var ch_stream = io.fixedBufferStream(ch_tmp);
                _ = try hs_ch.encode(ch_stream.writer());
                const last_chb_idx = hs_ch.length() - opsk.binders.len - 2;

                var binder_bytes: [1024 * 4]u8 = undefined;
                var binder_stream = io.fixedBufferStream(&binder_bytes);
                _ = try binder_stream.write(self.msgs_stream.getWritten());
                _ = try binder_stream.write(ch_stream.getWritten()[0..last_chb_idx]);

                const fin = try Finished.fromMessageBytes(binder_stream.getWritten(), fin_secret.slice(), self.ks.hkdf);
                opsk.binders[0] = @intCast(u8, self.ks.hkdf.digest_length);
                std.mem.copy(u8, opsk.binders[1..], fin.verify_data.slice());
            }

            return client_hello;
        }

        fn connectToHost(client: *std.x.net.tcp.Client, allocator: std.mem.Allocator, name: []const u8, port: u16) !void {
            const list = try net.getAddressList(allocator, name, port);
            defer list.deinit();

            if (list.addrs.len == 0) return error.UnknownHostName;

            for (list.addrs) |addr| {
                if (addr.any.family != std.os.AF.INET) {
                    continue;
                }
                // TODO: ipv6
                const bytes = @ptrCast(*const [4]u8, &addr.in.sa.addr);
                var ipv4_addr = std.x.os.IPv4{
                    .octets = [_]u8{ bytes[0], bytes[1], bytes[2], bytes[3] },
                };

                client.connect(std.x.net.ip.Address.initIPv4(ipv4_addr, port)) catch |err| switch (err) {
                    error.ConnectionRefused => {
                        continue;
                    },
                    else => return err,
                };

                return;
            }
            return std.os.ConnectError.ConnectionRefused;
        }

        pub fn connect(self: *Self, host: []const u8, port: u16) !void {
            if (is_tcp) {
                var tcp_client = try std.x.net.tcp.Client.init(.ip, .{});
                errdefer tcp_client.deinit();

                try tcp_client.setReadTimeout(500);
                // establish tcp connection.
                try connectToHost(&tcp_client, self.allocator, host, port);
                self.reader = tcp_client.reader(0);
                self.writer = tcp_client.writer(0); //TODO: handle SIGPIPE
                self.tcp_client = tcp_client;
                self.io_init = true;
            }

            self.host = try self.allocator.alloc(u8, host.len);
            std.mem.copy(u8, self.host, host);

            if (!self.io_init) {
                return Error.IoNotConfigured;
            }

            self.write_buffer = io.bufferedWriter(self.writer);

            self.state = .SEND_CH;
            self.msgs_stream.reset();

            if (self.early_data.len != 0 and self.pre_shared_key == null) {
                return Error.CannotSendEarlyData;
            }

            while (self.state != .CONNECTED) {
                if (self.state == .SEND_CH) {
                    // Sending ClientHello.
                    const ch = try self.createClientHello(host);
                    const hs_ch = Handshake{ .client_hello = ch };
                    _ = try hs_ch.encode(self.msgs_stream.writer());

                    const record_ch = TLSPlainText{ .content = Content{ .handshake = hs_ch } };
                    defer record_ch.deinit();
                    _ = try record_ch.encode(self.write_buffer.writer());

                    // Sending EarlyData if this is first flight.(not received HRR)
                    if (self.early_data.len != 0 and !self.already_recv_hrr) {
                        try self.ks.generateEarlySecrets2(self.msgs_stream.getWritten());
                        self.early_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.c_early_ap_keys, self.ks.secret.c_early_ap_keys);
                        const app_c = Content{ .application_data = try ApplicationData.initAsView(self.early_data) };
                        defer app_c.deinit();

                        _ = try self.early_protector.encryptFromMessageAndWrite(app_c, self.allocator, self.write_buffer.writer());
                        if (self.print_keys) {
                            std.debug.print("CLIENT_EARLY_TRAFFIC_SECRET {} {}\n", .{ std.fmt.fmtSliceHexLower(&self.random), &std.fmt.fmtSliceHexLower(self.ks.secret.c_early_ap_secret.slice()) });
                        }
                    }

                    self.state = .WAIT_SH;
                } else {
                    const t = try self.reader.readEnum(ContentType, .Big);
                    if (t == .change_cipher_spec) {
                        const recv_record = (try TLSPlainText.decode(self.reader, t, self.allocator, null, null));
                        defer recv_record.deinit();
                    } else if (t == .handshake and self.state == .WAIT_SH) {
                        var sh_bytes: [1024 * 2]u8 = undefined;
                        var sh_stream = io.fixedBufferStream(&sh_bytes);
                        const recv_record = (try TLSPlainText.decode(self.reader, t, self.allocator, null, sh_stream.writer())).content;
                        defer recv_record.deinit();
                        if (self.state == .WAIT_SH) {
                            if (recv_record != .handshake) {
                                // TODO: Error
                                return;
                            }
                            if (recv_record.handshake != .server_hello) {
                                // TODO: Error
                                return;
                            }

                            try self.handleServerHello(recv_record.handshake.server_hello, &sh_stream);
                            std.log.debug("hhr_hash={}", .{std.fmt.fmtSliceHexLower(self.msgs_stream.getWritten())});
                        }
                    } else {
                        const recv_record = try TLSCipherText.decode(self.reader, t, self.allocator);
                        defer recv_record.deinit();

                        var plain_record = try self.hs_protector.decrypt(recv_record, self.allocator);
                        defer plain_record.deinit();

                        if (plain_record.content_type == .alert) {
                            const alert = (try plain_record.decodeContent(self.allocator, null)).alert;
                            std.log.err("alert = {}", .{alert});
                            return Error.FailedToConnect;
                        }

                        if (plain_record.content_type == .handshake) {
                            try self.handleHandshakeInnerPlaintext(plain_record, self.write_buffer.writer());
                        } else {
                            unreachable;
                        }
                    }
                }

                try self.write_buffer.flush();
            }

            if (self.print_keys) {
                self.ks.printKeys(&self.random);
            }

            self.write_engine = .{
                .protector = &self.ap_protector,
                .ks = &self.ks,
                .write_buffer = &self.write_buffer,
                .allocator = self.allocator,
                .record_size_limit = self.record_size_limit,
            };

            self.read_engine = .{
                .entity = self,
            };

            // if early_data is not accepted, send early_data after connected.
            // TODO: Is this ok?
            if (self.early_data.len != 0 and !self.early_data_ok) {
                _ = try self.send(self.early_data);
                std.log.info("sent early_data as application data.", .{});
            }

            std.log.info("connected\n", .{});
        }

        pub fn send(self: *Self, b: []const u8) !usize {
            return try self.write_engine.write(b);
        }

        pub fn recv(self: *Self, b: []u8) !usize {
            return try self.read_engine.?.read(b);
        }

        pub fn close(self: *Self) !void {
            defer {
                if (self.tcp_client) |tc| {
                    tc.shutdown(.both) catch {
                        //TODO Error handle
                    };
                }
            }

            // close connection
            const close_notify = Content{ .alert = Alert{ .level = .warning, .description = .close_notify } };
            _ = try self.ap_protector.encryptFromMessageAndWrite(
                close_notify,
                self.allocator,
                self.write_buffer.writer(),
            );
            try self.write_buffer.flush();

            var close_recv = false;
            while (!close_recv) {
                const t = self.reader.readEnum(ContentType, .Big) catch |err| {
                    switch (err) {
                        // sometimes the tcp connection is closed after sending close_notify.
                        error.EndOfStream => return,
                        error.WouldBlock => return,
                        else => return err,
                    }
                };
                const recv_record = try TLSCipherText.decode(self.reader, t, self.allocator);
                defer recv_record.deinit();

                const plain_record = try self.ap_protector.decrypt(recv_record, self.allocator);
                defer plain_record.deinit();

                if (plain_record.content_type != .alert) {
                    // TODO: handle messages.
                    continue;
                }

                const content = try plain_record.decodeContent(self.allocator, self.ks.hkdf);
                defer content.deinit();

                if (content != .alert) {
                    // the message is broken.
                    continue;
                }

                const alert = content.alert;

                if (alert.level != .warning or alert.description != .close_notify) {
                    std.log.warn("invalid close_notify, level={} description={}", .{ alert.level, alert.description });
                    return;
                }
                close_recv = true;
            }

            std.log.info("connection closed", .{});
        }

        fn handleServerHello(self: *Self, sh: ServerHello, sh_stream: *io.FixedBufferStream([]u8)) !void {
            defer sh_stream.reset();

            if (msg.getExtension(sh.extensions, .supported_versions)) |sv_raw| {
                const sv = sv_raw.supported_versions;
                if (sv.versions.len != 1) {
                    return Error.IllegalParameter;
                }
                if (sv.versions.slice()[0] != 0x0304) {
                    return Error.IllegalParameter;
                }
            } else |_| {
                return Error.IllegalParameter;
            }

            const ks_tmp = try key.KeyScheduler.fromCipherSuite(sh.cipher_suite);

            // Checking is the PSK for resumption accepted.
            if (self.pre_shared_key != null) {
                if (msg.getExtension(sh.extensions, .pre_shared_key)) |psk_raw| {
                    const psk = psk_raw.pre_shared_key;
                    if (psk.selected_identify != 0) {
                        return Error.IllegalParameter;
                    }
                    self.resume_accepted = true;
                } else |_| {
                    self.resume_accepted = false;
                }
            }

            if (self.pre_shared_key != null or self.already_recv_hrr) {
                // check CipherSuites is same as first flight or previous session's ServerHello.
                if (self.ks.aead.aead_type != ks_tmp.aead.aead_type or self.ks.hkdf.hash_type != ks_tmp.hkdf.hash_type) {
                    return Error.IllegalParameter;
                }
            } else {
                self.ks = ks_tmp;
                const zero_bytes = &([_]u8{0} ** 64);
                try self.ks.generateEarlySecrets1(zero_bytes[0..self.ks.hkdf.digest_length]);
            }

            if (sh.is_hello_retry_request) {
                // RFC8446 Section 4.1.4 Hello Retry Request
                //
                // If a client receives a second
                // HelloRetryRequest in the same connection (i.e., where the ClientHello
                // was itself in response to a HelloRetryRequest), it MUST abort the
                // handshake with an "unexpected_message" alert.
                if (self.already_recv_hrr) {
                    return Error.UnexpectedMessage;
                }
                self.already_recv_hrr = true;

                const ks = (try msg.getExtension(sh.extensions, .key_share)).key_share;
                self.key_shares.clearAndFree();
                switch (ks.selected) {
                    .x25519 => {},
                    .secp256r1 => {},
                    else => return Error.UnsupportedKeyShareAlgorithm,
                }
                try self.key_shares.append(ks.selected);

                // RFC8446 Section 4.4.1 The Transcript Hash
                //  As an exception to this general rule, when the server responds to a
                //  ClientHello with a HelloRetryRequest, the value of ClientHello1 is
                //  replaced with a special synthetic handshake message of handshake type
                //  "message_hash" containing Hash(ClientHello1).  I.e.,
                //
                // Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
                //     Hash(message_hash ||        /* Handshake type */
                //          00 00 Hash.length  ||  /* Handshake message length (bytes) */
                //          Hash(ClientHello1) ||  /* Hash of ClientHello1 */
                //          HelloRetryRequest  || ... || Mn)
                const hs_hash = Handshake{ .message_hash = try MessageHash.fromClientHello(self.msgs_stream.getWritten(), self.ks.hkdf) };
                self.msgs_stream.reset();
                _ = try hs_hash.encode(self.msgs_stream.writer());

                self.state = .SEND_CH;
                _ = try self.msgs_stream.write(sh_stream.getWritten());
                return;
            } else {
                _ = try self.msgs_stream.write(sh_stream.getWritten());
            }

            const ks = (try msg.getExtension(sh.extensions, .key_share)).key_share;
            if (ks.entries.items.len != 1) {
                return Error.InvalidServerHello;
            }

            const key_entry = ks.entries.items[0];
            if (key_entry.group != .x25519 and key_entry.group != .secp256r1) {
                return Error.UnsupportedKeyShareAlgorithm;
            }

            const server_pubkey = key_entry.key_exchange;
            switch (key_entry.group) {
                .x25519 => {
                    const shared_key = try dh.X25519.scalarmult(self.x25519_priv_key, server_pubkey[0..32].*);
                    try self.ks.generateHandshakeSecrets1(&shared_key);
                },
                .secp256r1 => {
                    const pubkey = try P256.PublicKey.fromSec1(server_pubkey);
                    const mul = try pubkey.p.mulPublic(self.secp256r1_key.secret_key.bytes, .Big);
                    const shared_key = mul.affineCoordinates().x.toBytes(.Big);
                    try self.ks.generateHandshakeSecrets1(&shared_key);
                },
                else => unreachable,
            }
            try self.ks.generateHandshakeSecrets2(self.msgs_stream.getWritten());

            self.hs_protector = RecordPayloadProtector.init(self.ks.aead, self.ks.secret.c_hs_keys, self.ks.secret.s_hs_keys);

            // if everythig is ok, go to next state.
            self.state = .WAIT_EE;
        }

        fn handleHandshakeInnerPlaintext(self: *Self, t: TLSInnerPlainText, writer: anytype) !void {
            var contents = try t.decodeContents(self.allocator, self.ks.hkdf);
            defer {
                for (contents.items) |c| {
                    c.deinit();
                }
                contents.deinit();
            }

            var i: usize = 0;
            for (contents.items) |c| {
                const recv_msg = c.handshake;
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

                if (self.state == .SEND_FINISHED) {
                    // generate keys
                    try self.ks.generateApplicationSecrets(self.msgs_stream.getWritten());
                    self.ap_protector = RecordPayloadProtector.init(self.hs_protector.aead, self.ks.secret.c_ap_keys, self.ks.secret.s_ap_keys);

                    if (self.early_data_ok) {
                        const eoed = Content{ .handshake = Handshake{ .end_of_early_data = [0]u8{} } };
                        defer eoed.deinit();
                        // End Of Early Data is also included in Handshake Context.
                        _ = try eoed.encode(self.msgs_stream.writer());

                        _ = try self.early_protector.encryptFromMessageAndWrite(eoed, self.allocator, writer);
                    }

                    // construct client finished message
                    const c_finished = try Finished.fromMessageBytes(self.msgs_stream.getWritten(), self.ks.secret.c_hs_finished_secret.slice(), self.ks.hkdf);
                    const hs_c_finished = Content{ .handshake = Handshake{ .finished = c_finished } };
                    defer hs_c_finished.deinit();
                    _ = try hs_c_finished.encode(self.msgs_stream.writer());

                    _ = try self.hs_protector.encryptFromMessageAndWrite(hs_c_finished, self.allocator, writer);

                    self.state = .CONNECTED;
                }
            }

            // done
        }

        fn handleEncryptedExtensions(self: *Self, ee: EncryptedExtensions) !void {
            if (self.pre_shared_key != null and self.resume_accepted) {
                self.state = .WAIT_FINISHED;
                if (self.early_data.len != 0) {
                    if (msg.getExtension(ee.extensions, .early_data)) |ed| {
                        if (ed == .early_data) {
                            self.early_data_ok = true;
                        }
                    } else |_| {
                        self.early_data_ok = false;
                    }
                }
            } else {
                self.state = .WAIT_CERT_CR;
            }

            if (msg.getExtension(ee.extensions, .record_size_limit)) |rsl| {
                const r = rsl.record_size_limit;
                if (r.record_size_limit < 64) {
                    return Error.IllegalParameter;
                }
                self.record_size_limit = r.record_size_limit;
                std.log.info("recv record_size_limit={}", .{r.record_size_limit});
            } else |_| {}
        }

        fn handleCertificate(self: *Self, cert: certificate.Certificate) !void {
            for (cert.cert_list.items) |c| {
                // find certificate for host
                var cert_host = true;
                const cn_oid = (try x509.OIDMap.getEntryByName("CN")).oid;
                for (c.cert.tbs_certificate.subject.rdn_sequence.items) |rs| {
                    for (rs.attrs.items) |attr| {
                        if (!std.mem.eql(u8, attr.attr_type.id, cn_oid)) {
                            continue;
                        }
                        if (!certHostMatches(attr.attr_value, self.host)) {
                            cert_host = false;
                        }
                    }
                }

                if (!cert_host) {
                    continue;
                }

                const pubkey = c.cert.tbs_certificate.subjectPublicKeyInfo.publicKey;
                if (pubkey == .secp256r1 or pubkey == .secp384r1 or pubkey == .rsa) {
                    try self.cert_pubkeys.append(try pubkey.copy(self.allocator));
                } else {
                    return Error.UnsupportedCertificateAlgorithm;
                }
            }

            self.state = .WAIT_CV;
        }

        fn getPublicKey(self: Self, t: x509.PublicKeyType) !x509.PublicKey {
            for (self.cert_pubkeys.items) |cp| {
                if (cp == t) {
                    return cp;
                }
            }
            return Error.CertificateNotFound;
        }

        fn handleCertificateVerify(self: *Self, cert_verify: CertificateVerify) !void {
            var hash_out: [crypto.Hkdf.MAX_DIGEST_LENGTH]u8 = undefined;
            self.ks.hkdf.hash(&hash_out, self.msgs_stream.getWritten());

            var verify_bytes: [1000]u8 = undefined;
            var verify_stream = io.fixedBufferStream(&verify_bytes);
            _ = try verify_stream.write(&([_]u8{0x20} ** 64));
            _ = try verify_stream.write("TLS 1.3, server CertificateVerify");
            _ = try verify_stream.write(&([_]u8{0x00}));
            _ = try verify_stream.write(hash_out[0..self.ks.hkdf.digest_length]);

            switch (cert_verify.algorithm) {
                .ecdsa_secp256r1_sha256 => {
                    const pk = (try self.getPublicKey(.secp256r1)).secp256r1;
                    const sig = try P256.Signature.fromDer(cert_verify.signature);
                    try sig.verify(verify_stream.getWritten(), pk.key);
                },
                .ecdsa_secp384r1_sha384 => {
                    const pk = (try self.getPublicKey(.secp384r1)).secp384r1;
                    const sig = try P384.Signature.fromDer(cert_verify.signature);
                    try sig.verify(verify_stream.getWritten(), pk.key);
                },
                .rsa_pss_rsae_sha256 => {
                    const pk = (try self.getPublicKey(.rsa)).rsa;
                    var modulus_len = pk.modulus.len;
                    var i: usize = 0;
                    while (i < modulus_len) : (i += 1) {
                        if (pk.modulus[i] != 0) {
                            break;
                        }
                        modulus_len -= 1;
                    }
                    const modulus = pk.modulus[i..];
                    const modulus_bits = modulus.len * 8;
                    if (modulus_bits == 2048) {
                        var p_key = try rsa.Rsa2048.PublicKey.fromBytes(pk.publicExponent, modulus, self.allocator);
                        defer p_key.deinit();

                        const sig = rsa.Rsa2048.PSSSignature.fromBytes(cert_verify.signature);
                        try sig.verify(verify_stream.getWritten(), p_key, Sha256, self.allocator);
                    } else if (modulus_bits == 4096) {
                        std.log.info("RSA-4096", .{});
                        unreachable;
                    } else {
                        std.log.err("unsupported modulus length: {d} bits", .{modulus_bits});
                        return Error.UnsupportedSignatureScheme;
                    }
                },
                else => return Error.UnsupportedSignatureScheme,
            }

            self.state = .WAIT_FINISHED;
        }

        fn handleFinished(self: *Self, finished: Finished) !void {
            if (!finished.verify(self.msgs_stream.getWritten(), self.ks.secret.s_hs_finished_secret.slice())) {
                // TODO: Error
                return;
            }

            self.state = .SEND_FINISHED;
        }

        pub fn handleNewSessionTicket(self: *Self, nst: NewSessionTicket) !void {
            if (self.session_ticket) |st| {
                st.deinit();
            }
            self.session_ticket = nst;
            try self.ks.generateResumptionMasterSecret(self.msgs_stream.getWritten(), nst.ticket_nonce.slice());
        }

        pub fn handleKeyUpdate(self: *Self, ku: KeyUpdate) !void {
            // update decoding key(server key)
            try self.ks.updateServerSecrets();
            self.ap_protector.dec_keys = self.ks.secret.s_ap_keys;
            self.ap_protector.dec_cnt = 0;

            switch (ku.request_update) {
                .update_not_requested => {
                    std.log.debug("received key update update_not_requested", .{});
                },
                .update_requested => {
                    std.log.debug("received key update update_requested", .{});
                    const update = Content{ .handshake = .{ .key_update = .{ .request_update = .update_not_requested } } };
                    defer update.deinit();

                    _ = try self.ap_protector.encryptFromMessageAndWrite(update, self.allocator, self.write_buffer.writer());
                    try self.write_buffer.flush();

                    // update encoding key(clieny key)
                    try self.ks.updateClientSecrets();
                    self.ap_protector.enc_keys = self.ks.secret.c_ap_keys;
                    self.ap_protector.enc_cnt = 0;
                },
            }
        }
    };
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
    var stream = io.fixedBufferStream(&server_hello_bytes);
    var sh_reader = stream.reader();
    var t = try sh_reader.readEnum(ContentType, .Big);
    const handshake = (try TLSPlainText.decode(sh_reader, t, std.testing.allocator, null, msgs_stream.writer())).content.handshake;
    try expect(handshake == .server_hello);

    const server_hello = handshake.server_hello;
    defer server_hello.deinit();

    try expect(server_hello.cipher_suite == .TLS_AES_128_GCM_SHA256);
    const k_s = (try msg.getExtension(server_hello.extensions, .key_share)).key_share;
    try expect(k_s.entries.items.len == 1);
    try expect(k_s.entries.items[0].group == .x25519);

    const server_pubkey = k_s.entries.items[0].key_exchange;

    const dhe_shared_key_ans = [_]u8{ 0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };
    const dhe_shared_key = try dh.X25519.scalarmult(client_privkey, server_pubkey[0..32].*);
    try expect(std.mem.eql(u8, &dhe_shared_key, &dhe_shared_key_ans));

    var ks = try key.KeyScheduler.init(crypto.Hkdf.Sha256.hkdf, crypto.Aead.Aes128Gcm.aead);
    defer ks.deinit();
    try ks.generateEarlySecrets1(&([_]u8{0} ** 32));
    try ks.generateHandshakeSecrets1(&dhe_shared_key);
    try ks.generateHandshakeSecrets2(msgs_stream.getWritten());

    var hs_protector = RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead, ks.secret.c_hs_keys, ks.secret.s_hs_keys);

    // STATE = WAIT_EE

    // RFC 8446 Section 5.2 Record Payload Protection
    const enc_data = [_]u8{ 0x17, 0x03, 0x03, 0x02, 0xA2, 0xD1, 0xFF, 0x33, 0x4A, 0x56, 0xF5, 0xBF, 0xF6, 0x59, 0x4A, 0x07, 0xCC, 0x87, 0xB5, 0x80, 0x23, 0x3F, 0x50, 0x0F, 0x45, 0xE4, 0x89, 0xE7, 0xF3, 0x3A, 0xF3, 0x5E, 0xDF, 0x78, 0x69, 0xFC, 0xF4, 0x0A, 0xA4, 0x0A, 0xA2, 0xB8, 0xEA, 0x73, 0xF8, 0x48, 0xA7, 0xCA, 0x07, 0x61, 0x2E, 0xF9, 0xF9, 0x45, 0xCB, 0x96, 0x0B, 0x40, 0x68, 0x90, 0x51, 0x23, 0xEA, 0x78, 0xB1, 0x11, 0xB4, 0x29, 0xBA, 0x91, 0x91, 0xCD, 0x05, 0xD2, 0xA3, 0x89, 0x28, 0x0F, 0x52, 0x61, 0x34, 0xAA, 0xDC, 0x7F, 0xC7, 0x8C, 0x4B, 0x72, 0x9D, 0xF8, 0x28, 0xB5, 0xEC, 0xF7, 0xB1, 0x3B, 0xD9, 0xAE, 0xFB, 0x0E, 0x57, 0xF2, 0x71, 0x58, 0x5B, 0x8E, 0xA9, 0xBB, 0x35, 0x5C, 0x7C, 0x79, 0x02, 0x07, 0x16, 0xCF, 0xB9, 0xB1, 0x18, 0x3E, 0xF3, 0xAB, 0x20, 0xE3, 0x7D, 0x57, 0xA6, 0xB9, 0xD7, 0x47, 0x76, 0x09, 0xAE, 0xE6, 0xE1, 0x22, 0xA4, 0xCF, 0x51, 0x42, 0x73, 0x25, 0x25, 0x0C, 0x7D, 0x0E, 0x50, 0x92, 0x89, 0x44, 0x4C, 0x9B, 0x3A, 0x64, 0x8F, 0x1D, 0x71, 0x03, 0x5D, 0x2E, 0xD6, 0x5B, 0x0E, 0x3C, 0xDD, 0x0C, 0xBA, 0xE8, 0xBF, 0x2D, 0x0B, 0x22, 0x78, 0x12, 0xCB, 0xB3, 0x60, 0x98, 0x72, 0x55, 0xCC, 0x74, 0x41, 0x10, 0xC4, 0x53, 0xBA, 0xA4, 0xFC, 0xD6, 0x10, 0x92, 0x8D, 0x80, 0x98, 0x10, 0xE4, 0xB7, 0xED, 0x1A, 0x8F, 0xD9, 0x91, 0xF0, 0x6A, 0xA6, 0x24, 0x82, 0x04, 0x79, 0x7E, 0x36, 0xA6, 0xA7, 0x3B, 0x70, 0xA2, 0x55, 0x9C, 0x09, 0xEA, 0xD6, 0x86, 0x94, 0x5B, 0xA2, 0x46, 0xAB, 0x66, 0xE5, 0xED, 0xD8, 0x04, 0x4B, 0x4C, 0x6D, 0xE3, 0xFC, 0xF2, 0xA8, 0x94, 0x41, 0xAC, 0x66, 0x27, 0x2F, 0xD8, 0xFB, 0x33, 0x0E, 0xF8, 0x19, 0x05, 0x79, 0xB3, 0x68, 0x45, 0x96, 0xC9, 0x60, 0xBD, 0x59, 0x6E, 0xEA, 0x52, 0x0A, 0x56, 0xA8, 0xD6, 0x50, 0xF5, 0x63, 0xAA, 0xD2, 0x74, 0x09, 0x96, 0x0D, 0xCA, 0x63, 0xD3, 0xE6, 0x88, 0x61, 0x1E, 0xA5, 0xE2, 0x2F, 0x44, 0x15, 0xCF, 0x95, 0x38, 0xD5, 0x1A, 0x20, 0x0C, 0x27, 0x03, 0x42, 0x72, 0x96, 0x8A, 0x26, 0x4E, 0xD6, 0x54, 0x0C, 0x84, 0x83, 0x8D, 0x89, 0xF7, 0x2C, 0x24, 0x46, 0x1A, 0xAD, 0x6D, 0x26, 0xF5, 0x9E, 0xCA, 0xBA, 0x9A, 0xCB, 0xBB, 0x31, 0x7B, 0x66, 0xD9, 0x02, 0xF4, 0xF2, 0x92, 0xA3, 0x6A, 0xC1, 0xB6, 0x39, 0xC6, 0x37, 0xCE, 0x34, 0x31, 0x17, 0xB6, 0x59, 0x62, 0x22, 0x45, 0x31, 0x7B, 0x49, 0xEE, 0xDA, 0x0C, 0x62, 0x58, 0xF1, 0x00, 0xD7, 0xD9, 0x61, 0xFF, 0xB1, 0x38, 0x64, 0x7E, 0x92, 0xEA, 0x33, 0x0F, 0xAE, 0xEA, 0x6D, 0xFA, 0x31, 0xC7, 0xA8, 0x4D, 0xC3, 0xBD, 0x7E, 0x1B, 0x7A, 0x6C, 0x71, 0x78, 0xAF, 0x36, 0x87, 0x90, 0x18, 0xE3, 0xF2, 0x52, 0x10, 0x7F, 0x24, 0x3D, 0x24, 0x3D, 0xC7, 0x33, 0x9D, 0x56, 0x84, 0xC8, 0xB0, 0x37, 0x8B, 0xF3, 0x02, 0x44, 0xDA, 0x8C, 0x87, 0xC8, 0x43, 0xF5, 0xE5, 0x6E, 0xB4, 0xC5, 0xE8, 0x28, 0x0A, 0x2B, 0x48, 0x05, 0x2C, 0xF9, 0x3B, 0x16, 0x49, 0x9A, 0x66, 0xDB, 0x7C, 0xCA, 0x71, 0xE4, 0x59, 0x94, 0x26, 0xF7, 0xD4, 0x61, 0xE6, 0x6F, 0x99, 0x88, 0x2B, 0xD8, 0x9F, 0xC5, 0x08, 0x00, 0xBE, 0xCC, 0xA6, 0x2D, 0x6C, 0x74, 0x11, 0x6D, 0xBD, 0x29, 0x72, 0xFD, 0xA1, 0xFA, 0x80, 0xF8, 0x5D, 0xF8, 0x81, 0xED, 0xBE, 0x5A, 0x37, 0x66, 0x89, 0x36, 0xB3, 0x35, 0x58, 0x3B, 0x59, 0x91, 0x86, 0xDC, 0x5C, 0x69, 0x18, 0xA3, 0x96, 0xFA, 0x48, 0xA1, 0x81, 0xD6, 0xB6, 0xFA, 0x4F, 0x9D, 0x62, 0xD5, 0x13, 0xAF, 0xBB, 0x99, 0x2F, 0x2B, 0x99, 0x2F, 0x67, 0xF8, 0xAF, 0xE6, 0x7F, 0x76, 0x91, 0x3F, 0xA3, 0x88, 0xCB, 0x56, 0x30, 0xC8, 0xCA, 0x01, 0xE0, 0xC6, 0x5D, 0x11, 0xC6, 0x6A, 0x1E, 0x2A, 0xC4, 0xC8, 0x59, 0x77, 0xB7, 0xC7, 0xA6, 0x99, 0x9B, 0xBF, 0x10, 0xDC, 0x35, 0xAE, 0x69, 0xF5, 0x51, 0x56, 0x14, 0x63, 0x6C, 0x0B, 0x9B, 0x68, 0xC1, 0x9E, 0xD2, 0xE3, 0x1C, 0x0B, 0x3B, 0x66, 0x76, 0x30, 0x38, 0xEB, 0xBA, 0x42, 0xF3, 0xB3, 0x8E, 0xDC, 0x03, 0x99, 0xF3, 0xA9, 0xF2, 0x3F, 0xAA, 0x63, 0x97, 0x8C, 0x31, 0x7F, 0xC9, 0xFA, 0x66, 0xA7, 0x3F, 0x60, 0xF0, 0x50, 0x4D, 0xE9, 0x3B, 0x5B, 0x84, 0x5E, 0x27, 0x55, 0x92, 0xC1, 0x23, 0x35, 0xEE, 0x34, 0x0B, 0xBC, 0x4F, 0xDD, 0xD5, 0x02, 0x78, 0x40, 0x16, 0xE4, 0xB3, 0xBE, 0x7E, 0xF0, 0x4D, 0xDA, 0x49, 0xF4, 0xB4, 0x40, 0xA3, 0x0C, 0xB5, 0xD2, 0xAF, 0x93, 0x98, 0x28, 0xFD, 0x4A, 0xE3, 0x79, 0x4E, 0x44, 0xF9, 0x4D, 0xF5, 0xA6, 0x31, 0xED, 0xE4, 0x2C, 0x17, 0x19, 0xBF, 0xDA, 0xBF, 0x02, 0x53, 0xFE, 0x51, 0x75, 0xBE, 0x89, 0x8E, 0x75, 0x0E, 0xDC, 0x53, 0x37, 0x0D, 0x2B };
    const pt_misc = try hs_protector.decryptFromCipherBytes(&enc_data, std.testing.allocator);
    defer pt_misc.deinit();
    try expect(pt_misc.content_type == .handshake);

    // decode EncryptedExtensions
    var readStream2 = io.fixedBufferStream(pt_misc.content);
    const hs_enc_ext = try Handshake.decode(readStream2.reader(), std.testing.allocator, null);
    defer hs_enc_ext.deinit();
    const enc_ext = hs_enc_ext.encrypted_extensions;

    var msgs_idx: usize = 0;
    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_enc_ext.length())]);
    msgs_idx += hs_enc_ext.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(enc_ext.extensions.items.len == 3);
    try expect(enc_ext.extensions.items[0] == .supported_groups);
    try expect(enc_ext.extensions.items[1] == .record_size_limit);
    try expect(enc_ext.extensions.items[2] == .server_name); //server name

    // STATE = WAIT_CERT_CR

    // decode Certificate
    const hs_cert = (try Handshake.decode(readStream2.reader(), std.testing.allocator, null));
    defer hs_cert.deinit();
    const cert = hs_cert.certificate;

    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_cert.length())]);
    msgs_idx += hs_cert.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(cert.cert_req_ctx.len == 0);
    try expect(cert.cert_list.items.len == 1);
    //try expect(cert.cert_list.items[0].cert_data.items.len == 432);
    //try expect(cert.cert_list.items[0].extensions.items.len == 0);

    // WAIT_CV

    // decode CertificateVerify
    const hs_cert_verify = (try Handshake.decode(readStream2.reader(), std.testing.allocator, null));
    defer hs_cert_verify.deinit();
    const cert_verify = hs_cert_verify.certificate_verify;

    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_cert_verify.length())]);
    msgs_idx += hs_cert_verify.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    try expect(cert_verify.algorithm == .rsa_pss_rsae_sha256);

    // STATE = WAIT_FINISHED

    // decode Finished
    const hs_s_hs_finished = (try Handshake.decode(readStream2.reader(), std.testing.allocator, crypto.Hkdf.Sha256.hkdf));
    defer hs_s_hs_finished.deinit();
    const s_hs_finished = hs_s_hs_finished.finished;

    // check all data was read.
    try expectError(error.EndOfStream, readStream2.reader().readByte());

    // validate "finished"
    try expect(s_hs_finished.verify(msgs_stream.getWritten(), ks.secret.s_hs_finished_secret.slice()));

    // add "finished"
    _ = try msgs_stream.write(pt_misc.content[msgs_idx..(msgs_idx + hs_s_hs_finished.length())]);
    msgs_idx += hs_s_hs_finished.length();
    try expect(msgs_idx == (try readStream2.getPos()));

    // Construct client finised message
    const c_finished = try Finished.fromMessageBytes(msgs_stream.getWritten(), ks.secret.c_hs_finished_secret.slice(), crypto.Hkdf.Sha256.hkdf);
    const hs_c_finished = Handshake{ .finished = c_finished };

    const c_finished_ans = [_]u8{ 0x14, 0x0, 0x0, 0x20, 0xa8, 0xec, 0x43, 0x6d, 0x67, 0x76, 0x34, 0xae, 0x52, 0x5a, 0xc1, 0xfc, 0xeb, 0xe1, 0x1a, 0x03, 0x9e, 0xc1, 0x76, 0x94, 0xfa, 0xc6, 0xe9, 0x85, 0x27, 0xb6, 0x42, 0xf2, 0xed, 0xd5, 0xce, 0x61 };
    var c_finished_inner = try TLSInnerPlainText.init(hs_c_finished.length(), .handshake, std.testing.allocator);
    c_finished_inner.content_type = .handshake;
    defer c_finished_inner.deinit();
    var inner_stream = io.fixedBufferStream(c_finished_inner.content);
    _ = try hs_c_finished.encode(inner_stream.writer());
    try expect(std.mem.eql(u8, c_finished_inner.content, &c_finished_ans));

    const c_record_finished_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x35, 0x75, 0xEC, 0x4D, 0xC2, 0x38, 0xCC, 0xE6, 0x0B, 0x29, 0x80, 0x44, 0xA7, 0x1E, 0x21, 0x9C, 0x56, 0xCC, 0x77, 0xB0, 0x51, 0x7F, 0xE9, 0xB9, 0x3C, 0x7A, 0x4B, 0xFC, 0x44, 0xD8, 0x7F, 0x38, 0xF8, 0x03, 0x38, 0xAC, 0x98, 0xFC, 0x46, 0xDE, 0xB3, 0x84, 0xBD, 0x1C, 0xAE, 0xAC, 0xAB, 0x68, 0x67, 0xD7, 0x26, 0xC4, 0x05, 0x46 };
    var c_record_finished_bytes: [1000]u8 = undefined;
    const c_record_finished = try hs_protector.encrypt(c_finished_inner, std.testing.allocator);
    defer c_record_finished.deinit();
    var c_record_finished_stream = io.fixedBufferStream(&c_record_finished_bytes);
    const c_finished_write_len = try c_record_finished.encode(c_record_finished_stream.writer());
    try expect(std.mem.eql(u8, c_record_finished_bytes[0..c_finished_write_len], &c_record_finished_ans));

    // STATE = CONNECTED
    try ks.generateApplicationSecrets(msgs_stream.getWritten());
    var ap_protector = RecordPayloadProtector.init(crypto.Aead.Aes128Gcm.aead, ks.secret.c_ap_keys, ks.secret.s_ap_keys);

    _ = try msgs_stream.write(c_finished_inner.content);

    // decode NewSessionTicket
    const s_ticket_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0xDE, 0x3A, 0x6B, 0x8F, 0x90, 0x41, 0x4A, 0x97, 0xD6, 0x95, 0x9C, 0x34, 0x87, 0x68, 0x0D, 0xE5, 0x13, 0x4A, 0x2B, 0x24, 0x0E, 0x6C, 0xFF, 0xAC, 0x11, 0x6E, 0x95, 0xD4, 0x1D, 0x6A, 0xF8, 0xF6, 0xB5, 0x80, 0xDC, 0xF3, 0xD1, 0x1D, 0x63, 0xC7, 0x58, 0xDB, 0x28, 0x9A, 0x01, 0x59, 0x40, 0x25, 0x2F, 0x55, 0x71, 0x3E, 0x06, 0x1D, 0xC1, 0x3E, 0x07, 0x88, 0x91, 0xA3, 0x8E, 0xFB, 0xCF, 0x57, 0x53, 0xAD, 0x8E, 0xF1, 0x70, 0xAD, 0x3C, 0x73, 0x53, 0xD1, 0x6D, 0x9D, 0xA7, 0x73, 0xB9, 0xCA, 0x7F, 0x2B, 0x9F, 0xA1, 0xB6, 0xC0, 0xD4, 0xA3, 0xD0, 0x3F, 0x75, 0xE0, 0x9C, 0x30, 0xBA, 0x1E, 0x62, 0x97, 0x2A, 0xC4, 0x6F, 0x75, 0xF7, 0xB9, 0x81, 0xBE, 0x63, 0x43, 0x9B, 0x29, 0x99, 0xCE, 0x13, 0x06, 0x46, 0x15, 0x13, 0x98, 0x91, 0xD5, 0xE4, 0xC5, 0xB4, 0x06, 0xF1, 0x6E, 0x3F, 0xC1, 0x81, 0xA7, 0x7C, 0xA4, 0x75, 0x84, 0x00, 0x25, 0xDB, 0x2F, 0x0A, 0x77, 0xF8, 0x1B, 0x5A, 0xB0, 0x5B, 0x94, 0xC0, 0x13, 0x46, 0x75, 0x5F, 0x69, 0x23, 0x2C, 0x86, 0x51, 0x9D, 0x86, 0xCB, 0xEE, 0xAC, 0x87, 0xAA, 0xC3, 0x47, 0xD1, 0x43, 0xF9, 0x60, 0x5D, 0x64, 0xF6, 0x50, 0xDB, 0x4D, 0x02, 0x3E, 0x70, 0xE9, 0x52, 0xCA, 0x49, 0xFE, 0x51, 0x37, 0x12, 0x1C, 0x74, 0xBC, 0x26, 0x97, 0x68, 0x7E, 0x24, 0x87, 0x46, 0xD6, 0xDF, 0x35, 0x30, 0x05, 0xF3, 0xBC, 0xE1, 0x86, 0x96, 0x12, 0x9C, 0x81, 0x53, 0x55, 0x6B, 0x3B, 0x6C, 0x67, 0x79, 0xB3, 0x7B, 0xF1, 0x59, 0x85, 0x68, 0x4F };
    const pt_s_ticket = try ap_protector.decryptFromCipherBytes(&s_ticket_enc, std.testing.allocator);
    defer pt_s_ticket.deinit();
    try expect(pt_s_ticket.content_type == .handshake);
    const nst = (try pt_s_ticket.decodeContent(std.testing.allocator, crypto.Hkdf.Sha256.hkdf)).handshake.new_session_ticket;
    defer nst.deinit();

    try ks.generateResumptionMasterSecret(msgs_stream.getWritten(), nst.ticket_nonce.slice());
    // zig fmt: off
    const res_master_ans = [_]u8{
    0x7d, 0xf2, 0x35, 0xf2, 0x03, 0x1d, 0x2a, 0x05, 0x12, 0x87, 0xd0, 0x2b, 0x02,
    0x41, 0xb0, 0xbf, 0xda, 0xf8, 0x6c, 0xc8, 0x56, 0x23, 0x1f, 0x2d, 0x5a, 0xba,
    0x46, 0xc4, 0x34, 0xec, 0x19, 0x6c
    };
    const res_secret_ans = [_]u8{
    0x4e, 0xcd, 0x0e, 0xb6, 0xec, 0x3b, 0x4d, 0x87, 0xf5, 0xd6, 0x02, 0x8f, 0x92,
    0x2c, 0xa4, 0xc5, 0x85, 0x1a, 0x27, 0x7f, 0xd4, 0x13, 0x11, 0xc9, 0xe6, 0x2d,
    0x2c, 0x94, 0x92, 0xe1, 0xc4, 0xf3
    };
    // zig fmt: on
    try expect(std.mem.eql(u8, ks.secret.res_master_secret.slice(), &res_master_ans));
    try expect(std.mem.eql(u8, ks.secret.res_secret.slice(), &res_secret_ans));

    // send application_data
    var c_app_data: [50]u8 = undefined;
    for (c_app_data) |*value, app_i| {
        value.* = @intCast(u8, app_i);
    }

    const c_app_record_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x43, 0xA2, 0x3F, 0x70, 0x54, 0xB6, 0x2C, 0x94, 0xD0, 0xAF, 0xFA, 0xFE, 0x82, 0x28, 0xBA, 0x55, 0xCB, 0xEF, 0xAC, 0xEA, 0x42, 0xF9, 0x14, 0xAA, 0x66, 0xBC, 0xAB, 0x3F, 0x2B, 0x98, 0x19, 0xA8, 0xA5, 0xB4, 0x6B, 0x39, 0x5B, 0xD5, 0x4A, 0x9A, 0x20, 0x44, 0x1E, 0x2B, 0x62, 0x97, 0x4E, 0x1F, 0x5A, 0x62, 0x92, 0xA2, 0x97, 0x70, 0x14, 0xBD, 0x1E, 0x3D, 0xEA, 0xE6, 0x3A, 0xEE, 0xBB, 0x21, 0x69, 0x49, 0x15, 0xE4 };
    const c_app_data_view = Content{ .application_data = try ApplicationData.initAsView(&c_app_data) };
    const c_app_record = try ap_protector.encryptFromMessage(c_app_data_view, std.testing.allocator);
    defer c_app_record.deinit();
    var c_app: [1000]u8 = undefined;
    var c_app_stream = io.fixedBufferStream(&c_app);
    const c_app_len = try c_app_record.encode(c_app_stream.writer());
    try expect(std.mem.eql(u8, c_app[0..c_app_len], &c_app_record_ans));

    // recv application_data
    const s_app_record_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x43, 0x2E, 0x93, 0x7E, 0x11, 0xEF, 0x4A, 0xC7, 0x40, 0xE5, 0x38, 0xAD, 0x36, 0x00, 0x5F, 0xC4, 0xA4, 0x69, 0x32, 0xFC, 0x32, 0x25, 0xD0, 0x5F, 0x82, 0xAA, 0x1B, 0x36, 0xE3, 0x0E, 0xFA, 0xF9, 0x7D, 0x90, 0xE6, 0xDF, 0xFC, 0x60, 0x2D, 0xCB, 0x50, 0x1A, 0x59, 0xA8, 0xFC, 0xC4, 0x9C, 0x4B, 0xF2, 0xE5, 0xF0, 0xA2, 0x1C, 0x00, 0x47, 0xC2, 0xAB, 0xF3, 0x32, 0x54, 0x0D, 0xD0, 0x32, 0xE1, 0x67, 0xC2, 0x95, 0x5D };
    const pt_recv_ap = try ap_protector.decryptFromCipherBytes(&s_app_record_enc, std.testing.allocator);
    defer pt_recv_ap.deinit();
    try expect(pt_recv_ap.content_type == .application_data);

    // send alert
    const c_alert_plain = Content{ .alert = Alert{
        .level = .warning,
        .description = .close_notify,
    } };
    const c_alert_record = try ap_protector.encryptFromMessage(c_alert_plain, std.testing.allocator);
    defer c_alert_record.deinit();
    const c_alert_ans = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xC9, 0x87, 0x27, 0x60, 0x65, 0x56, 0x66, 0xB7, 0x4D, 0x7F, 0xF1, 0x15, 0x3E, 0xFD, 0x6D, 0xB6, 0xD0, 0xB0, 0xE3 };
    var c_alert: [1000]u8 = undefined;
    var c_alert_stream = io.fixedBufferStream(&c_alert);
    const c_alert_len = try c_alert_record.encode(c_alert_stream.writer());
    try expect(std.mem.eql(u8, c_alert[0..c_alert_len], &c_alert_ans));

    // recv alert
    const s_alert_enc = [_]u8{ 0x17, 0x03, 0x03, 0x00, 0x13, 0xB5, 0x8F, 0xD6, 0x71, 0x66, 0xEB, 0xF5, 0x99, 0xD2, 0x47, 0x20, 0xCF, 0xBE, 0x7E, 0xFA, 0x7A, 0x88, 0x64, 0xA9 };
    const pt_recv_alert = try ap_protector.decryptFromCipherBytes(&s_alert_enc, std.testing.allocator);
    defer pt_recv_alert.deinit();
    try expect(pt_recv_alert.content_type == .alert);

    // End of connection
}

test "connect e2e with x25519" {
    // ClientHello + Finished
    // zig fmt: off
    const client_ans = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0xa4, 0x01, 0x00, 0x00, 0xa0, 0x03, 0x03, 0x01, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x00, 0x02,
    0x13, 0x01, 0x01, 0x00, 0x00, 0x55, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d, 0x00, 0x33, 0x00, 0x26, 0x00,
    0x24, 0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43,
    0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1,
    0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x0d,
    0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04, 0x00, 0x00, 0x00, 0x0e, 0x00,
    0x0c, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74,
    0x17, 0x03, 0x03, 0x00, 0x35, 0x30, 0xa3, 0x70, 0x73, 0xfc, 0x60, 0xcd, 0xc7,
    0x16, 0xf9, 0x5a, 0x0a, 0x1c, 0x80, 0x19, 0xce, 0x4c, 0x34, 0x2b, 0x08, 0xea,
    0xad, 0x0c, 0x4a, 0xf5, 0xd8, 0x6e, 0xf7, 0xf4, 0x6d, 0x33, 0x54, 0xf5, 0xa8,
    0x54, 0xfd, 0x0f, 0x99, 0x4e, 0x76, 0x04, 0xde, 0x19, 0xf7, 0xd9, 0x27, 0x3d,
    0x0d, 0xa8, 0x4b, 0xfe, 0xa0, 0x2c,
    };
    // zig fmt: on

    // ServerHello + ChangeCipherSpec + EncryptedExtensions +
    // Certificate + Certificate Verify + Finished.
    // zig fmt: off
    const server_msgs = [_]u8{
    0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0xf7, 0x01,
    0x42, 0x32, 0x5b, 0x56, 0x50, 0xb7, 0x1b, 0x68, 0xc3, 0x6c, 0x56, 0xdc, 0x64,
    0x64, 0x7c, 0x8c, 0x4e, 0xeb, 0x66, 0xab, 0xd7, 0x54, 0x8e, 0xaa, 0x0c, 0x10,
    0x12, 0x34, 0xc2, 0x43, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x13, 0x01,
    0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24,
    0x00, 0x1d, 0x00, 0x20, 0x67, 0x07, 0xf8, 0xa3, 0x8d, 0xdb, 0xec, 0xf3, 0xaa,
    0xc3, 0x7e, 0x01, 0xd8, 0x40, 0x18, 0xb5, 0xab, 0x87, 0xaf, 0x62, 0x0a, 0xb2,
    0x64, 0x3e, 0xdd, 0xc2, 0x81, 0xcc, 0x8e, 0xbf, 0x78, 0x31, 0x14, 0x03, 0x03,
    0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x17, 0x52, 0x94, 0xa6, 0x97, 0x6b,
    0xd6, 0xd9, 0x6d, 0xc0, 0x3e, 0xc5, 0xc8, 0xb2, 0xec, 0xac, 0x22, 0xa3, 0x25,
    0x71, 0x7b, 0xaf, 0xa6, 0xab, 0x17, 0x03, 0x03, 0x01, 0xf9, 0x91, 0xaf, 0x2d,
    0xde, 0x79, 0xb9, 0xc9, 0x2a, 0x60, 0x87, 0x82, 0x18, 0x9c, 0x31, 0xa2, 0xf7,
    0x46, 0xd1, 0x23, 0x5f, 0x64, 0xf3, 0xa3, 0xfd, 0x28, 0xbb, 0x4e, 0xa5, 0x1e,
    0xd0, 0xb5, 0xa4, 0x5c, 0xd6, 0x78, 0x34, 0x2c, 0x9f, 0xd1, 0xab, 0x31, 0x2c,
    0x73, 0x5d, 0x0b, 0x31, 0x6b, 0x04, 0xc4, 0xc6, 0x0d, 0x0b, 0x9f, 0x9e, 0x15,
    0x41, 0x45, 0xe9, 0xb3, 0xe4, 0x04, 0x0d, 0x4c, 0x7f, 0xc0, 0xfa, 0x55, 0x14,
    0x37, 0xe9, 0xe0, 0xd2, 0xc5, 0x17, 0x02, 0x9f, 0x16, 0xb7, 0xb3, 0x34, 0x9f,
    0x2f, 0xc2, 0x6b, 0x5d, 0xb3, 0x53, 0x28, 0xeb, 0xef, 0xc7, 0x7c, 0x51, 0x6b,
    0x01, 0xdc, 0x28, 0x93, 0x9f, 0xc9, 0x7a, 0x86, 0x40, 0xd6, 0xef, 0x22, 0x9d,
    0xa7, 0xb6, 0xdc, 0x04, 0x96, 0x74, 0xcb, 0x8b, 0x41, 0xe1, 0xc2, 0x73, 0xaf,
    0xd6, 0xc4, 0x3a, 0xde, 0x5b, 0xe9, 0x60, 0x77, 0xd5, 0xeb, 0x8d, 0x01, 0xb5,
    0x28, 0x12, 0x37, 0x12, 0x82, 0x8c, 0x42, 0xa5, 0x36, 0xd6, 0x97, 0x49, 0x2b,
    0xbe, 0x65, 0x51, 0x1f, 0xa4, 0xd1, 0xcb, 0x26, 0x55, 0x18, 0xf9, 0x59, 0x92,
    0x7a, 0x18, 0x5d, 0x7c, 0x15, 0x50, 0xb4, 0x62, 0xb7, 0x1e, 0x69, 0x53, 0x0f,
    0xf3, 0x01, 0xf7, 0x7b, 0x96, 0xfa, 0xad, 0x81, 0x4f, 0x61, 0x7a, 0x41, 0xcf,
    0x83, 0x7d, 0x71, 0x14, 0x95, 0x8b, 0xd5, 0xc6, 0x04, 0x3b, 0x0c, 0xc8, 0x1d,
    0xb3, 0x47, 0xc2, 0xf4, 0x79, 0x1b, 0x9f, 0x28, 0x67, 0xcd, 0xb5, 0x73, 0x60,
    0x35, 0xcc, 0x73, 0x40, 0x4b, 0xfb, 0x54, 0xf9, 0x74, 0xa4, 0x77, 0x1a, 0x07,
    0x46, 0xcb, 0x65, 0x55, 0x81, 0x5f, 0xe0, 0xa1, 0x2e, 0xa7, 0x30, 0xac, 0x1b,
    0x99, 0xd1, 0x8e, 0xfc, 0x8c, 0x8b, 0x03, 0x8c, 0x72, 0x24, 0xc4, 0x0f, 0x57,
    0x18, 0x07, 0x8d, 0x9d, 0xf2, 0xf1, 0xcd, 0x6c, 0xab, 0xdf, 0xee, 0xd4, 0xef,
    0xb6, 0x51, 0xbe, 0x17, 0xa6, 0x95, 0x45, 0xfa, 0xff, 0x22, 0x36, 0x0c, 0xe3,
    0xae, 0x6d, 0xfa, 0x6e, 0xaa, 0x5b, 0x17, 0xe9, 0x29, 0x74, 0xf5, 0x2a, 0xd5,
    0xb5, 0x86, 0xb2, 0xec, 0x2f, 0x87, 0x99, 0xf1, 0xe4, 0x68, 0x61, 0xa6, 0x09,
    0xde, 0x7d, 0xb6, 0xcd, 0x4e, 0x0c, 0x55, 0xae, 0x9b, 0xfa, 0x74, 0x0e, 0xf8,
    0xfb, 0x78, 0xae, 0x6c, 0x8e, 0xb9, 0xe3, 0x2c, 0x81, 0x06, 0x84, 0x3d, 0x02,
    0x45, 0x8a, 0x09, 0x8d, 0x23, 0x58, 0x23, 0x3d, 0x5a, 0x38, 0x8d, 0x40, 0x3d,
    0x9c, 0x5d, 0x0a, 0x11, 0xba, 0xf3, 0x80, 0xaa, 0x7e, 0x14, 0x59, 0x86, 0xbe,
    0xb8, 0xf0, 0xe0, 0x97, 0xe9, 0x3c, 0x6d, 0xc9, 0x73, 0x8d, 0xc9, 0x81, 0x28,
    0x9a, 0x6c, 0x96, 0x48, 0x4e, 0x38, 0xa1, 0xd9, 0x9c, 0x46, 0x68, 0xd9, 0x47,
    0xb4, 0xb6, 0xa8, 0x02, 0x40, 0xa0, 0x7b, 0x09, 0x83, 0xed, 0x48, 0x55, 0x2b,
    0xc6, 0xdf, 0x10, 0xc1, 0x10, 0x07, 0xc0, 0x70, 0x2a, 0xf6, 0xe3, 0x1f, 0xe6,
    0x98, 0xb9, 0xd3, 0xa1, 0x6a, 0xfb, 0xa9, 0x11, 0x60, 0xbb, 0x7f, 0x5c, 0xb6,
    0x62, 0x66, 0x5a, 0xd5, 0x7a, 0x0e, 0x66, 0x90, 0xcf, 0x0f, 0xc9, 0x2b, 0x60,
    0x5c, 0x2d, 0xa0, 0x08, 0x97, 0xd8, 0xcc, 0xef, 0x0c, 0x42, 0x03, 0x7b, 0x38,
    0x00, 0x0a, 0x50, 0xfd, 0x9b, 0xdb, 0xeb, 0x3a, 0x84, 0x2c, 0xc6, 0x38, 0x1b,
    0xf6, 0x2d, 0xa3, 0x75, 0x60, 0xa4, 0x17, 0xa1, 0xa9, 0xa7, 0xb9, 0xcf, 0x77,
    0x5a, 0xb0, 0x61, 0xca, 0x4f, 0xba, 0xac, 0x6e, 0x90, 0x6f, 0x9a, 0x43, 0xf8,
    0x93, 0x78, 0xef, 0x2c, 0x1e, 0xaf, 0x53, 0xf1, 0xd1, 0x87, 0x8e, 0xf2, 0x75,
    0x36, 0x71, 0x45, 0xab, 0x60, 0x96, 0xe0, 0x2b, 0x17, 0x03, 0x03, 0x00, 0x60,
    0xe4, 0xb6, 0xf3, 0xd4, 0x28, 0xde, 0x14, 0x85, 0x2b, 0x67, 0xb4, 0x01, 0xd3,
    0xf9, 0xe8, 0xd4, 0xef, 0xdb, 0x29, 0xe3, 0x86, 0x60, 0x78, 0x4b, 0x1c, 0xfe,
    0x1d, 0x57, 0x3f, 0x79, 0xbf, 0x07, 0x95, 0x3d, 0x10, 0xd7, 0x1e, 0x5f, 0x64,
    0x53, 0x6e, 0x69, 0xb6, 0x71, 0xeb, 0xa3, 0x32, 0x85, 0xb9, 0x29, 0x1e, 0x55,
    0xb7, 0x60, 0x48, 0x8d, 0xd7, 0xa4, 0xaf, 0x0f, 0xbe, 0xac, 0x62, 0xd6, 0x96,
    0x5b, 0xbe, 0xf1, 0xa3, 0x1f, 0xbe, 0x54, 0x38, 0x50, 0x48, 0x77, 0x4a, 0x5f,
    0x59, 0xa6, 0xb3, 0xaa, 0xc5, 0x3a, 0x67, 0xb2, 0xe9, 0xaf, 0x82, 0x0e, 0x63,
    0x9b, 0xc4, 0x0b, 0xa3, 0x94, 0x17, 0x03, 0x03, 0x00, 0x35, 0x67, 0xd3, 0xdd,
    0x9b, 0x77, 0x47, 0xbd, 0x4e, 0xf5, 0x6c, 0xbb, 0xc5, 0x87, 0xc6, 0x48, 0x8b,
    0x2a, 0xb8, 0x57, 0x8a, 0xe8, 0xb8, 0x5f, 0xe4, 0x24, 0x55, 0x04, 0xe8, 0xe9,
    0xfe, 0xe9, 0xe9, 0xd7, 0xb5, 0x4e, 0x4a, 0xfc, 0xf4, 0x66, 0x4b, 0xdb, 0x06,
    0xfe, 0xcb, 0x6f, 0x2b, 0x77, 0xde, 0x8b, 0x0d, 0x30, 0xc4, 0x7b,
    };
    // zig fmt: on

    var test_send_bytes: [2000]u8 = undefined;
    var test_send_stream = io.fixedBufferStream(&test_send_bytes);

    var test_recv_stream = io.fixedBufferStream(&server_msgs);

    const ReaderType = @TypeOf(test_recv_stream.reader());
    const WriterType = @TypeOf(test_send_stream.writer());
    const TLSClient = TLSClientImpl(ReaderType, WriterType, false);
    var tls_client = try TLSClient.initWithIo(test_recv_stream.reader(), test_send_stream.writer(), std.testing.allocator);
    defer tls_client.deinit();
    // zig fmt: off
    const client_privkey = [_]u8{
    0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78,
    0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63,
    0x45, 0x40, 0xe7, 0xea, 0x50, 0x05
    };
    // zig fmt: on
    try tls_client.configureX25519Keys(client_privkey);

    // zig fmt: off
    const dummy = [_]u8{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    // zig fmt: on

    tls_client.random = dummy;
    std.mem.copy(u8, tls_client.session_id.session_id.slice(), &dummy);

    tls_client.cipher_suites.clearAndFree();
    try tls_client.cipher_suites.append(.TLS_AES_128_GCM_SHA256);

    tls_client.supported_groups.clearAndFree();
    try tls_client.supported_groups.append(.x25519);

    tls_client.key_shares.clearAndFree();
    try tls_client.key_shares.append(.x25519);

    tls_client.signature_schems.clearAndFree();
    try tls_client.signature_schems.append(.ecdsa_secp256r1_sha256);
    try tls_client.signature_schems.append(.rsa_pss_rsae_sha256);

    try tls_client.connect("localhost", 443);
    try expect(std.mem.eql(u8, &client_ans, test_send_stream.getWritten()));
}

test "connect to www.google.com" {
    var tls_client = try TLSClientTCP.init(std.testing.allocator);
    defer tls_client.deinit();

    try tls_client.connect("www.google.com", 443);

    const http_req = "GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: tls13-zig\r\nAccept: */*\r\n\r\n";
    _ = try tls_client.send(http_req);

    var recv_bytes: [4096]u8 = undefined;
    _ = try tls_client.recv(&recv_bytes);

    const ans_bytes = "HTTP/1.1 200 OK";
    try expect(std.mem.eql(u8, recv_bytes[0..ans_bytes.len], ans_bytes));

    try tls_client.close();

    return;
}

test "RFC8448 Section 5. HelloRetryRequest" {
    // zig fmt: off
    const ch_bytes = [_]u8{
    0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x1b, 0xc3, 0xce, 0xb6, 0xbb, 0xe3, 0x9c,
    0xff, 0x93, 0x83, 0x55, 0xb5, 0xa5, 0x0a, 0xdb, 0x6d, 0xb2, 0x1b, 0x7a, 0x6a,
    0xf6, 0x49, 0xd7, 0xb4, 0xbc, 0x41, 0x9d, 0x78, 0x76, 0x48, 0x7d, 0x95, 0x00,
    0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0x01, 0x00, 0x01, 0xcd, 0x00,
    0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
    0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00,
    0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
    0x01, 0x03, 0x01, 0x04, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
    0x20, 0xe4, 0xff, 0xb6, 0x8a, 0xc0, 0x5f, 0x8d, 0x96, 0xc9, 0x9d, 0xa2, 0x66,
    0x98, 0x34, 0x6c, 0x6b, 0xe1, 0x64, 0x82, 0xba, 0xdd, 0xda, 0xfe, 0x05, 0x1a,
    0x66, 0xb4, 0xf1, 0x8d, 0x66, 0x8f, 0x0b, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x2b,
    0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
    0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,
    0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02,
    0x02, 0x02, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40,
    0x01, 0x00, 0x15, 0x00, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x29, 0x00, 0xdd, 0x00, 0xb8, 0x00, 0xb2, 0x2c, 0x03, 0x5d, 0x82,
    0x93, 0x59, 0xee, 0x5f, 0xf7, 0xaf, 0x4e, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x26,
    0x2a, 0x64, 0x94, 0xdc, 0x48, 0x6d, 0x2c, 0x8a, 0x34, 0xcb, 0x33, 0xfa, 0x90,
    0xbf, 0x1b, 0x00, 0x70, 0xad, 0x3c, 0x49, 0x88, 0x83, 0xc9, 0x36, 0x7c, 0x09,
    0xa2, 0xbe, 0x78, 0x5a, 0xbc, 0x55, 0xcd, 0x22, 0x60, 0x97, 0xa3, 0xa9, 0x82,
    0x11, 0x72, 0x83, 0xf8, 0x2a, 0x03, 0xa1, 0x43, 0xef, 0xd3, 0xff, 0x5d, 0xd3,
    0x6d, 0x64, 0xe8, 0x61, 0xbe, 0x7f, 0xd6, 0x1d, 0x28, 0x27, 0xdb, 0x27, 0x9c,
    0xce, 0x14, 0x50, 0x77, 0xd4, 0x54, 0xa3, 0x66, 0x4d, 0x4e, 0x6d, 0xa4, 0xd2,
    0x9e, 0xe0, 0x37, 0x25, 0xa6, 0xa4, 0xda, 0xfc, 0xd0, 0xfc, 0x67, 0xd2, 0xae,
    0xa7, 0x05, 0x29, 0x51, 0x3e, 0x3d, 0xa2, 0x67, 0x7f, 0xa5, 0x90, 0x6c, 0x5b,
    0x3f, 0x7d, 0x8f, 0x92, 0xf2, 0x28, 0xbd, 0xa4, 0x0d, 0xda, 0x72, 0x14, 0x70,
    0xf9, 0xfb, 0xf2, 0x97, 0xb5, 0xae, 0xa6, 0x17, 0x64, 0x6f, 0xac, 0x5c, 0x03,
    0x27, 0x2e, 0x97, 0x07, 0x27, 0xc6, 0x21, 0xa7, 0x91, 0x41, 0xef, 0x5f, 0x7d,
    0xe6, 0x50, 0x5e, 0x5b, 0xfb, 0xc3, 0x88, 0xe9, 0x33, 0x43, 0x69, 0x40, 0x93,
    0x93, 0x4a, 0xe4, 0xd3, 0x57, 0xfa, 0xd6, 0xaa, 0xcb, 0x00, 0x21, 0x20, 0x3a,
    0xdd, 0x4f, 0xb2, 0xd8, 0xfd, 0xf8, 0x22, 0xa0, 0xca, 0x3c, 0xf7, 0x67, 0x8e,
    0xf5, 0xe8, 0x8d, 0xae, 0x99, 0x01, 0x41, 0xc5, 0x92, 0x4d, 0x57, 0xbb, 0x6f,
    0xa3, 0x1b, 0x9e, 0x5f, 0x9d
    };
    // zig fmt: on

    var stream = io.fixedBufferStream(&ch_bytes);
    const ch = try Handshake.decode(stream.reader(), std.testing.allocator, null);
    defer ch.deinit();

    var hkdf = crypto.Hkdf.Sha256.hkdf;
    var hash: [crypto.Hkdf.MAX_DIGEST_LENGTH]u8 = undefined;

    const binder_hash_ans = [_]u8{
        0x63, 0x22, 0x4b, 0x2e, 0x45, 0x73, 0xf2, 0xd3, 0x45, 0x4c, 0xa8, 0x4b, 0x9d,
        0x00, 0x9a, 0x04, 0xf6, 0xbe, 0x9e, 0x05, 0x71, 0x1a, 0x83, 0x96, 0x47, 0x3a,
        0xef, 0xa0, 0x1e, 0x92, 0x4a, 0x14,
    };
    const psk = (try msg.getExtension(ch.client_hello.extensions, .pre_shared_key)).pre_shared_key;
    const last_chb_idx = ch.length() - psk.offeredPsks.binders.len - 2;
    hkdf.hash(&hash, ch_bytes[0..last_chb_idx]);
    try expect(std.mem.eql(u8, hash[0..hkdf.digest_length], &binder_hash_ans));

    const early_secret = [_]u8{ 0x9b, 0x21, 0x88, 0xe9, 0xb2, 0xfc, 0x6d, 0x64, 0xd7, 0x1d, 0xc3, 0x29, 0x90, 0x0e, 0x20, 0xbb, 0x41, 0x91, 0x50, 0x00, 0xf6, 0x78, 0xaa, 0x83, 0x9c, 0xbb, 0x79, 0x7c, 0xb7, 0xd8, 0x33, 0x2c };

    const prk_ans = [_]u8{ 0x69, 0xfe, 0x13, 0x1a, 0x3b, 0xba, 0xd5, 0xd6, 0x3c, 0x64, 0xee, 0xbc, 0xc3, 0x0e, 0x39, 0x5b, 0x9d, 0x81, 0x07, 0x72, 0x6a, 0x13, 0xd0, 0x74, 0xe3, 0x89, 0xdb, 0xc8, 0xa4, 0xe4, 0x72, 0x56 };

    var prk: [32]u8 = undefined;
    try hkdf.deriveSecret(&prk, &early_secret, "res binder", "");
    try expect(std.mem.eql(u8, &prk, &prk_ans));

    var c_early_ap: [32]u8 = undefined;
    try hkdf.deriveSecret(&c_early_ap, &early_secret, "c e traffic", &ch_bytes);
    const c_early_ap_ans = [_]u8{ 0x3f, 0xbb, 0xe6, 0xa6, 0x0d, 0xeb, 0x66, 0xc3, 0x0a, 0x32, 0x79, 0x5a, 0xba, 0x0e, 0xff, 0x7e, 0xaa, 0x10, 0x10, 0x55, 0x86, 0xe7, 0xbe, 0x5c, 0x09, 0x67, 0x8d, 0x63, 0xb6, 0xca, 0xab, 0x62 };
    try expect(std.mem.eql(u8, &c_early_ap, &c_early_ap_ans));

    const expand_ans = [_]u8{ 0x55, 0x88, 0x67, 0x3e, 0x72, 0xcb, 0x59, 0xc8, 0x7d, 0x22, 0x0c, 0xaf, 0xfe, 0x94, 0xf2, 0xde, 0xa9, 0xa3, 0xb1, 0x60, 0x9f, 0x7d, 0x50, 0xe9, 0x0a, 0x48, 0x22, 0x7d, 0xb9, 0xed, 0x7e, 0xaa };
    var out: [32]u8 = undefined;
    try hkdf.hkdfExpandLabel(&out, &prk, "finished", "", 32);
    try expect(std.mem.eql(u8, &out, &expand_ans));

    const fin = try Finished.fromMessageBytes(ch_bytes[0..last_chb_idx], &out, hkdf);
    std.log.warn("FIN={}", .{std.fmt.fmtSliceHexLower(fin.verify_data.slice())});
}

// whether certificate hostname with possible star certificate
// matches hostname
fn certHostMatches(cert: []const u8, host: []const u8) bool {
    if (std.mem.startsWith(u8, cert, "*.")) {
        // handle star certificate
        if (std.mem.indexOf(u8, host, ".")) |pos| {
            return std.mem.eql(u8, host[pos + 1 ..], cert[2..]);
        }
    }
    return std.mem.eql(u8, cert, host);
}

test "matches host" {
    try std.testing.expect(certHostMatches("*.google.com", "www.google.com"));
    try std.testing.expect(certHostMatches("*.google.com", "anything.google.com"));

    try std.testing.expect(!certHostMatches("*.google.com", "www."));
    try std.testing.expect(!certHostMatches("*.", "www.google.com"));
}
