const std = @import("std");

pub const ApplicationData = struct {
    content: []u8,

    view_c: []const u8 = undefined,
    view: bool = false,

    allocator: std.mem.Allocator,

    const Self = @This();

    const Error = error{
        InvalidFormat,
        InvalidValue,
    };

    pub fn init(len: usize, allocator: std.mem.Allocator) !Self {
        return Self{
            .content = try allocator.alloc(u8, len),
            .allocator = allocator,
        };
    }

    pub fn initAsView(v: []const u8) !Self {
        return Self{
            .content = undefined,
            .view_c = v,
            .view = true,
            .allocator = undefined,
        };
    }

    pub fn deinit(self: Self) void {
        if (!self.view) {
            self.allocator.free(self.content);
        }
    }

    /// decode ApplicationData reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param len       the length of readable bytes.
    /// @param allocator allocator to initialize ApplicationData.
    /// @return decoded ApplicationData.
    pub fn decode(reader: anytype, len: usize, allocator: std.mem.Allocator) !Self {
        var res = try Self.init(len, allocator);

        try reader.readNoEof(res.content);

        return res;
    }

    /// encode ApplicationData writing to io.Writer.
    /// @param self   ApplicationData to be encoded.
    /// @param writer io.Writer to write encoded ApplicationData.
    /// @return the length of encoded ApplicationData.
    pub fn encode(self: Self, writer: anytype) !usize {
        if (self.view) {
            try writer.writeAll(self.view_c);
        } else {
            try writer.writeAll(self.content);
        }

        return self.length();
    }

    /// get the length of encoded ApplicationData.
    /// @param self ApplicationData to get the encoded length.
    /// @return the length of encoded ApplicationData.
    pub fn length(self: Self) usize {
        if (self.view) {
            return self.view_c.len;
        } else {
            return self.content.len;
        }
    }
};
