const std = @import("std");

/// RFC8446 Section 4.6.3.  Key and Initialization Vector Update
/// enum {
///     update_not_requested(0), update_requested(1), (255)
/// } KeyUpdateRequest;
//
/// struct {
///     KeyUpdateRequest request_update;
/// } KeyUpdate;
pub const KeyUpdateRequest = enum(u8) {
    update_not_requested = 0,
    update_requested = 1,
};

pub const KeyUpdate = struct {
    request_update: KeyUpdateRequest,

    const Self = @This();

    pub fn decode(reader: anytype) !Self {
        return .{
            .request_update = try reader.readEnum(KeyUpdateRequest, .big),
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        try writer.writeByte(@intFromEnum(self.request_update));

        return @sizeOf(u8);
    }

    pub fn length(self: Self) usize {
        _ = self;

        return @sizeOf(u8);
    }
};
