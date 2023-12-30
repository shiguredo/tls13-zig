const std = @import("std");

/// RFC8446 Section 6 Alert Protocol
///
/// enum { warning(1), fatal(2), (255) } AlertLevel;
///
pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
};

/// RFC8446 Section 6 Alert Protocol
///
/// enum {
///     close_notify(0),
///     unexpected_message(10),
///     bad_record_mac(20),
///     record_overflow(22),
///     handshake_failure(40),
///     bad_certificate(42),
///     unsupported_certificate(43),
///     certificate_revoked(44),
///     certificate_expired(45),
///     certificate_unknown(46),
///     illegal_parameter(47),
///     unknown_ca(48),
///     access_denied(49),
///     decode_error(50),
///     decrypt_error(51),
///     protocol_version(70),
///     insufficient_security(71),
///     internal_error(80),
///     inappropriate_fallback(86),
///     user_canceled(90),
///     missing_extension(109),
///     unsupported_extension(110),
///     unrecognized_name(112),
///     bad_certificate_status_response(113),
///     unknown_psk_identity(115),
///     certificate_required(116),
///     no_application_protocol(120),
///     (255)
/// } AlertDescription;
///
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

/// RFC8446 Section 6 Alert Protocol
///
/// struct {
///     AlertLevel level;
///     AlertDescription description;
/// } Alert;
///
pub const Alert = struct {
    level: AlertLevel,
    description: AlertDescription,

    const Self = @This();

    /// decode Alert reading from io.Reader.
    /// @param reader io.Reader to read messages.
    /// @return decoded Alert.
    pub fn decode(reader: anytype) !Self {
        // Decoding level.
        const level = @as(AlertLevel, @enumFromInt(try reader.readByte()));

        // Decoding description.
        const description = @as(AlertDescription, @enumFromInt(try reader.readByte()));

        return Self{
            .level = level,
            .description = description,
        };
    }

    /// encode Alert writing to io.Writer.
    /// @param self   Alert to be encoded.
    /// @param writer io.Writer to be written.
    /// @return the length of encoded Alert.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding level.
        try writer.writeByte(@intFromEnum(self.level));
        len += @sizeOf(u8);

        // Encoding description.
        try writer.writeByte(@intFromEnum(self.description));
        len += @sizeOf(u8);

        return len;
    }

    /// get the length of encoded Alert.
    /// @param self Alert to get the length.
    /// @return the length of encoded Alert.
    pub fn length(self: Self) usize {
        _ = self;
        var len: usize = 0;
        len += @sizeOf(u8); // level
        len += @sizeOf(u8); // description

        return len;
    }
};
