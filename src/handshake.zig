const std = @import("std");

const msg = @import("msg.zig");
const ClientHello = @import("client_hello.zig").ClientHello;
const ServerHello = @import("server_hello.zig").ServerHello;
const EncryptedExtensions = @import("encrypted_extensions.zig").EncryptedExtensions;
const Certificate = @import("certificate.zig").Certificate;
const CertificateVerify = @import("certificate_verify.zig").CertificateVerify;
const Finished = @import("finished.zig").Finished;
const NewSessionTicket = @import("new_session_ticket.zig").NewSessionTicket;
const KeyUpdate = @import("key_update.zig").KeyUpdate;
const MessageHash = @import("message_hash.zig").MessageHash;
const Hkdf = @import("crypto.zig").Hkdf;

/// RFC8446 Secion 4 Handshake Protocol
///
/// enum {
///     client_hello(1),
///     server_hello(2),
///     new_session_ticket(4),
///     end_of_early_data(5),
///     encrypted_extensions(8),
///     certificate(11),
///     certificate_request(13),
///     certificate_verify(15),
///     finished(20),
///     key_update(24),
///     message_hash(254),
///     (255)
/// } HandshakeType;
///
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    // certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
};

/// RFC8446 Section 4 Handshake Protocol
///
/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* remaining bytes in message */
///     select (Handshake.msg_type) {
///         case client_hello:          ClientHello;
///         case server_hello:          ServerHello;
///         case end_of_early_data:     EndOfEarlyData;
///         case encrypted_extensions:  EncryptedExtensions;
///         case certificate_request:   CertificateRequest;
///         case certificate:           Certificate;
///         case certificate_verify:    CertificateVerify;
///         case finished:              Finished;
///         case new_session_ticket:    NewSessionTicket;
///         case key_update:            KeyUpdate;
///     };
/// } Handshake;
///
pub const Handshake = union(HandshakeType) {
    client_hello: ClientHello,
    server_hello: ServerHello,
    new_session_ticket: NewSessionTicket,
    end_of_early_data: [0]u8,
    encrypted_extensions: EncryptedExtensions,
    certificate: Certificate,
    certificate_verify: CertificateVerify,
    finished: Finished,
    key_update: KeyUpdate,
    message_hash: MessageHash,

    const Self = @This();

    const Error = error{
        HkdfNotSpecified,
    };

    /// decode Handshake message reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator for each hahdshake message.
    /// @param hkdf      HKDF algorithm used to decode 'Finished'.
    /// @return the result of decoded Handshake.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator, hkdf: ?Hkdf) !Self {
        // Decoding HandshakeType
        const t = @intToEnum(HandshakeType, try reader.readIntBig(u8));
        const len = try reader.readIntBig(u24);
        _ = len; // TODO: check the length is less than readable size.

        // Decoding Handshake payload.
        switch (t) {
            .client_hello => return Self{ .client_hello = try ClientHello.decode(reader, allocator) },
            .server_hello => return Self{ .server_hello = try ServerHello.decode(reader, allocator) },
            .new_session_ticket => return Self{ .new_session_ticket = try NewSessionTicket.decode(reader, allocator) },
            .end_of_early_data => return Self{ .end_of_early_data = [0]u8{} },
            .encrypted_extensions => return Self{ .encrypted_extensions = try EncryptedExtensions.decode(reader, allocator) },
            .certificate => return Self{ .certificate = try Certificate.decode(reader, allocator) },
            .certificate_verify => return Self{ .certificate_verify = try CertificateVerify.decode(reader, allocator) },
            .finished => if (hkdf) |h| {
                return Self{ .finished = try Finished.decode(reader, h) };
            } else {
                return Error.HkdfNotSpecified;
            },
            .key_update => return Self{ .key_update = try KeyUpdate.decode(reader) },
            else => unreachable,
        }
    }

    /// encode Handshake message writing to io.Writer.
    /// @param self   Handshake to be encoded.
    /// @param writer io.Writer to be written encoded messages.
    /// @return encoded length.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding HandshakeType.
        try writer.writeIntBig(u8, @enumToInt(self));
        len += @sizeOf(HandshakeType);

        // Encoding length of payload.
        try writer.writeIntBig(u24, @intCast(u24, self.length() - (@sizeOf(u8) + 3)));
        len += 3;

        // Encoding payload.
        switch (self) {
            .end_of_early_data => {},
            inline else => |case| len += try case.encode(writer),
        }

        return len;
    }

    /// get length of encoded Handshake.
    /// @param self the target Handshake.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u8); // type
        len += 3; // length, @sizeOf(u24) = 4, so that the length is directly specified;
        switch (self) {
            .end_of_early_data => {},
            inline else => |case| len += case.length(),
        }

        return len;
    }

    /// deinitialize Handshake.
    /// @param self Handshake to be deinitialized.
    pub fn deinit(self: Self) void {
        switch (self) {
            .end_of_early_data => {},
            .finished => {},
            .key_update => {},
            .message_hash => {},
            inline else => |case| case.deinit(),
        }
    }
};
