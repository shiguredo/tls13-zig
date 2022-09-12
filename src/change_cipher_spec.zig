/// RFC5246 7.1. Change Cipher Spec Protocol
///
/// struct {
///     enum { change_cipher_spec(1), (255) } type;
/// } ChangeCipherSpec;
///
pub const ChangeCipherSpec = struct {
    const Self = @This();

    const Error = error {
        InvalidFormat,
        InvalidValue,
    };

    /// decode ChangeCipherSpec reading from io.Reader.
    /// @param reader io.Reader to read messages.
    /// @param length length in bytes of readable messages.
    /// @return decoded ChangeCipherSpec.
    pub fn decode(reader: anytype, length: usize) !Self {
        // ChangeCipherSpec must have one byte 'type'.
        if (length != 1) {
            return Error.InvalidFormat;
        }

        // Type must be change_cipher_spec(1),
        const t = try reader.readByte();
        if (t != 1) {
            return Error.InvalidValue;
        }

        return Self{};
    }

};