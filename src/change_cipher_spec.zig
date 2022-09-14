/// RFC5246 7.1. Change Cipher Spec Protocol
///
/// struct {
///     enum { change_cipher_spec(1), (255) } type;
/// } ChangeCipherSpec;
///
pub const ChangeCipherSpec = struct {
    const Self = @This();

    const Error = error{
        InvalidFormat,
        InvalidValue,
    };

    /// decode ChangeCipherSpec reading from io.Reader.
    /// @param reader io.Reader to read messages.
    /// @return decoded ChangeCipherSpec.
    pub fn decode(reader: anytype) !Self {
        // Type must be change_cipher_spec(1),
        const t = try reader.readByte();
        if (t != 1) {
            return Error.InvalidValue;
        }

        return Self{};
    }

    /// encode ChangeCipherSpec writing to io.Writer.
    /// @param self   ChangeCipherSpec to be encoded.
    /// @param writer io.Writer to write encoded ChangeCipherSpec.
    /// @return the length of encoded ChangeCipherSpec.
    pub fn encode(self: Self, writer: anytype) !usize {
        _ = self;

        try writer.writeByte(1);

        return 1;
    }

    /// get the length of encoded ChangeCipherSpec.
    /// @param self ChangeCipherSpec to get the encoded length.
    /// @return the length of encoded ChangeCipherSpec.
    pub fn length(self: Self) usize {
        _ = self;
        return 1;
    }
};
