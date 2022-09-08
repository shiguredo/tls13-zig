const std = @import("std");
const io = std.io;
const log = std.log;
const assert = std.debug.assert;
const msg = @import("msg.zig");
const BoundedArray = std.BoundedArray;
const HandshakeType = @import("handshake.zig").HandshakeType;

/// RFC8446 Section 4.2.1 Supported Versions
///
/// struct {
///     select (Handshake.msg_type) {
///         case client_hello:
///              ProtocolVersion versions<2..254>;

///         case server_hello: /* and HelloRetryRequest */
///              ProtocolVersion selected_version;
///     };
/// } SupportedVersions;
///
pub const SupportedVersions = struct {
    const MAX_VERSIONS_LENGTH: usize = 127;
    versions: BoundedArray(u16, MAX_VERSIONS_LENGTH),
    ht: HandshakeType,

    const Self = @This();

    const Error = error{
        InvalidVersionsLength,
    };

    /// initialize SupportedVersions.
    /// @param ht HandshakeType to specify structure of Supportedversions.
    /// @return initialized SupportedVersions.
    pub fn init(ht: HandshakeType) !Self{
        return Self{
            .versions = try BoundedArray(u16, MAX_VERSIONS_LENGTH).init(0),
            .ht = ht,
        };
    }

    /// decode SupportedVersions extension reading from io.Reader.
    /// @param reader io.Reader to read messages.
    /// @param ht     HandshakeType to specify structure of SupportedVersions.
    /// @return the result of decoded SupportedVersions.
    pub fn decode(reader: anytype, ht: HandshakeType) !Self {
        var res = try Self.init(ht);

        // Structure of SupportedVersions varies based on HandshakeType.
        switch (ht) {
            .client_hello => {
                // Decoding versions
                var supported_len = try reader.readIntBig(u8);
                if (supported_len % 2 != 0) {
                    return Error.InvalidVersionsLength;
                }

                var i: usize = 0;
                while (i < supported_len) : (i += 2) {
                    try res.versions.append(try reader.readIntBig(u16));
                }
            },
            .server_hello => {
                try res.versions.append(try reader.readIntBig(u16));
            },
            else => unreachable,
        }

        return res;
    }

    /// encode SupportedVersions writing to io.Writer.
    /// @param self   SupportedVersions to be encoded.
    /// @param writer io.Writer to write encoded SuppoertedVersions.
    /// @return length of encoded SupportedVersions.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Structure of SupportedVersions varies based on HandshakeType.
        switch (self.ht) {
            .client_hello => {
                // Encoding versions.
                try writer.writeIntBig(u8, @intCast(u8, self.versions.len * @sizeOf(u16)));
                len += @sizeOf(u8);

                for (self.versions.slice()) |version| {
                    try writer.writeIntBig(u16, version);
                    len += @sizeOf(u16);
                }
            },
            .server_hello => {
                try writer.writeIntBig(u16, self.versions.slice()[0]);
                len += @sizeOf(u16);
            },
            else => unreachable,
        }

        return len;
    }

    /// get the length of encoded SupportedVersions.
    /// @param self the target SupportedVersions.
    /// @return length of encoded SupportedVersions.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        switch (self.ht) {
            .client_hello => {
                len += @sizeOf(u8); // supported versions length
                len += self.versions.len * @sizeOf(u16);
            },
            .server_hello => {
                len += @sizeOf(u16); // version.cli
            },
            else => unreachable,
        }
        return len;
    }

    pub fn print(self: Self) void {
        _ = self;
        log.debug("Extension: SupportedVersions({s})", .{@tagName(self.ht)});
        log.debug("- version = 0x{x:0>2}", .{self.version});
    }
};

const expect = std.testing.expect;

test "SupportedVersions decode" {
    const recv_data = [_]u8{ 0x02, 0x03, 0x04 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try SupportedVersions.decode(readStream.reader(), .client_hello);
    try expect(res.ht == .client_hello);
    try expect(res.versions.get(0) == 0x0304);
}

test "SuppoertedVersions encode" {
    var res = try SupportedVersions.init(.client_hello);

    try res.versions.append(0x0304);

    const versions_ans = [_]u8{ 0x02, 0x03, 0x04 };
    var send_bytes: [100]u8 = undefined;

    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try res.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &versions_ans));
}
