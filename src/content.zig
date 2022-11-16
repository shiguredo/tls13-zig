const std = @import("std");

const Hkdf = @import("crypto.zig").Hkdf;
const Handshake = @import("handshake.zig").Handshake;
const ChangeCipherSpec = @import("change_cipher_spec.zig").ChangeCipherSpec;
const Alert = @import("alert.zig").Alert;
const ApplicationData = @import("application_data.zig").ApplicationData;

/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
///
/// value      Description  DTLS-OK Reference
///  20	   change_cipher_spec	Y	[RFC8446]
///  21	   alert	            Y	[RFC8446]
///  22	   handshake	        Y	[RFC8446]
///  23	   application_data	    Y	[RFC8446]
///  24	   heartbeat	        Y	[RFC6520]
///  25	   tls12_cid	        Y	[RFC9146]
///  26	   ACK	                Y	[RFC9147]
pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

pub const Content = union(ContentType) {
    invalid: Dummy,
    change_cipher_spec: ChangeCipherSpec,
    alert: Alert,
    handshake: Handshake,
    application_data: ApplicationData,

    const Self = @This();

    const Error = error{
        InvalidLength,
    };

    /// decode Content reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param t         ContentType to be decoded.
    /// @param len       the length of bytes readable from reader.
    ///                  if the length is unknown, the value can be 0 exceptiing application_data.
    /// @param allocator allocator to allocate Content.
    /// @param hkdf      HKDF used to decode Content. the value is nullable.
    /// @return decoded Content.
    pub fn decode(reader: anytype, t: ContentType, len: usize, allocator: std.mem.Allocator, hkdf: ?Hkdf) !Self {
        if (t == .application_data and len == 0) {
            return Error.InvalidLength;
        }
        switch (t) {
            .invalid => unreachable,
            .change_cipher_spec => return Self{ .change_cipher_spec = try ChangeCipherSpec.decode(reader) },
            .alert => return Self{ .alert = try Alert.decode(reader) },
            .handshake => return Self{ .handshake = try Handshake.decode(reader, allocator, hkdf) },
            .application_data => return Self{ .application_data = try ApplicationData.decode(reader, len, allocator) },
        }
    }

    /// encode Content writing to io.Writer.
    /// @param self   Content to be encoded.
    /// @param writer io.Writer to write encoded Content.
    /// @return the length of encoded Content.
    pub fn encode(self: Self, writer: anytype) !usize {
        switch (self) {
            .invalid => unreachable,
            inline else => |case| return try case.encode(writer),
        }
    }

    /// get the length of Content.
    /// @param self Content to get the length.
    /// @return the length of encoded Content.
    pub fn length(self: Self) usize {
        switch (self) {
            .invalid => unreachable,
            inline else => |case| return case.length(),
        }
    }

    /// deinitialize Content.
    /// @param self Content to be deinitialized.
    pub fn deinit(self: Self) void {
        switch (self) {
            .invalid => unreachable,
            .change_cipher_spec => {},
            .alert => {},
            .handshake => |e| e.deinit(),
            .application_data => |e| e.deinit(),
        }
    }
};

const Dummy = struct {};
