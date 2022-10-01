const std = @import("std");
const HandshakeType = @import("handshake.zig").HandshakeType;

/// RFC8446 Section 4.2.10 Early Data Indication
///
///struct {} Empty;
///
///struct {
///    select (Handshake.msg_type) {
///        case new_session_ticket:   uint32 max_early_data_size;
///        case client_hello:         Empty;
///        case encrypted_extensions: Empty;
///    };
///} EarlyDataIndication;
///
pub const EarlyData = struct {
    msg_type: HandshakeType,
    max_early_data_size: u32 = 0,

    const Self = @This();
    pub fn decode(reader: anytype, ht: HandshakeType) !Self {
        switch (ht) {
            .new_session_ticket => return .{ .msg_type = ht, .max_early_data_size = try reader.readIntBig(u32) },
            .client_hello => return .{
                .msg_type = ht,
            },
            .encrypted_extensions => return .{
                .msg_type = ht,
            },
            else => unreachable,
        }
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;
        switch (self.msg_type) {
            .new_session_ticket => {
                try writer.writeIntBig(u32, self.max_early_data_size);
                len += @sizeOf(u32);
            },
            .client_hello => {},
            .encrypted_extensions => {},
            else => unreachable,
        }

        return len;
    }

    pub fn length(self: Self) usize {
        switch (self.msg_type) {
            .new_session_ticket => return @sizeOf(u32),
            .client_hello => return 0,
            .encrypted_extensions => return 0,
            else => unreachable,
        }
    }
};
