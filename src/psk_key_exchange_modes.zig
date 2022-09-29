const std = @import("std");
const ArrayList = std.ArrayList;

pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
};

pub const PskKeyExchangeModes = struct {
    modes: ArrayList(PskKeyExchangeMode),

    const Self = @This();
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .modes = ArrayList(PskKeyExchangeMode).init(allocator),
        };
    }

    pub fn deinit(self: Self) void {
        self.modes.deinit();
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var res = Self.init(allocator);
        errdefer res.deinit();

        const len = try reader.readByte();
        var i: usize = 0;
        while (i < len) : (i += 1) {
            const mode = try reader.readEnum(PskKeyExchangeMode, .Big);
            try res.modes.append(mode);
        }

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        const m_len = self.modes.items.len;
        try writer.writeIntBig(u8, @intCast(u8, m_len));
        len += @sizeOf(u8);

        for (self.modes.items) |m| {
            try writer.writeByte(@enumToInt(m));
            len += @sizeOf(u8);
        }

        return len;
    }

    pub fn length(self: Self) usize {
        return @sizeOf(u8) + self.modes.items.len;
    }
};
