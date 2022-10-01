const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const expect = std.testing.expect;
const ArrayList = std.ArrayList;

const msg = @import("msg.zig");
const Extension = @import("extension.zig").Extension;

/// RFC8446 Section 4.3.1
///
/// struct {
///     Extension extensions<0..2^16-1>;
/// } EncryptedExtensions;
///
pub const EncryptedExtensions = struct {
    extensions: ArrayList(Extension),

    const Self = @This();

    /// initialize EncryptedExtensions.
    /// @param allocator allocator to allocate ArrayList.
    /// @return initialized EncryptedExtensions.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    /// deinitialize EncryptedExtensions.
    /// @param self EncryptedExtensions to be deinitialized.
    pub fn deinit(self: Self) void {
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }

    /// decode EncryptedExtensions messsage reading from io.Reader.
    /// @param reader    io.Reader to reade messages.
    /// @param allocator allocator to initialize EncryptedExtensions.
    /// @return the result of decoded EncryptedExtensions.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // Initializing EncryptedExtensions.
        var res = Self.init(allocator);
        errdefer res.deinit();

        // Decoding Extensions.
        try msg.decodeExtensions(reader, allocator, &res.extensions, .encrypted_extensions, false);
        return res;
    }

    /// encode EncryptedExtensions writing to io.Writer.
    /// @param self   EncryptedExtensions to be encoded.
    /// @param writer io.Writer to write enocded EncryptedExntensions.
    /// @return the length of encoded EncryptedExntensions.
    pub fn encode(self: Self, writer: anytype) !usize {
        return try msg.encodeExtensions(writer, self.extensions);
    }

    /// get length of encoded EncryptedExtensions.
    /// @param self the target EncryptedExntensions.
    /// @return length of encoded EncryptedExtensions.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // extensions length
        for (self.extensions.items) |e| {
            len += e.length();
        }

        return len;
    }
};

test "EncryptedExtensions decode" {
    // zig fmt: off
    const recv_data = [_]u8{
    0x08, 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00,
    0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
    0x01, 0x03, 0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00,
    0x00
    };
    // zig fmt: on

    var readStream = io.fixedBufferStream(&recv_data);

    const Handshake = @import("handshake.zig").Handshake;
    const res = try Handshake.decode(readStream.reader(), std.testing.allocator, null);
    defer res.deinit();
}
