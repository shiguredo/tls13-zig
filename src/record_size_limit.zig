const std = @import("std");
const io = std.io;

const Extension = @import("extension.zig").Extension;
const expect = std.testing.expect;

/// RFC8449 Section 4  The "record_size_limit" Extension
//
/// The ExtensionData of the "record_size_limit" extension is
/// RecordSizeLimit:
///
///    uint16 RecordSizeLimit;
///
pub const RecordSizeLimit = struct {
    record_size_limit: u16 = 0,

    const Self = @This();

    /// decode RecordSizeLimit.
    /// @param reader io.Reader to read messages.
    /// @return decoded RecordSizeLimit.
    pub fn decode(reader: anytype) !Self {
        const record_size_limit = try reader.readInt(u16, .big);

        return Self{
            .record_size_limit = record_size_limit,
        };
    }

    /// encode RecordSizeLimit.
    /// @param self   RecordSizeLimit to be encoded.
    /// @param writer io.Writer to write encoded RecordSizeLimit.
    /// @return length of encoded RecordSizeLimit.
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeInt(u16, self.record_size_limit, .big);
        len += @sizeOf(u16);

        return len;
    }

    /// get the length of encoded RecordSizeLimit.
    /// @param self RecordSizeLimit to get length.
    /// @return the length of encoded RecordSizeLimit.
    pub fn length(self: Self) usize {
        _ = self;
        var len: usize = 0;
        len += @sizeOf(u16); // size limit
        return len;
    }

    pub fn print(self: Self) void {
        _ = self;
    }
};

test "Extension RecordSizeLimit decode" {
    const recv_data = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Extension.decode(readStream.reader(), std.testing.allocator, .server_hello, false);
    try expect(res == .record_size_limit);

    const rsl = res.record_size_limit;
    try expect(rsl.record_size_limit == 16385);
}

test "Extension RecordSizeLimit encode" {
    const res = RecordSizeLimit{
        .record_size_limit = 16385,
    };
    const ext = Extension{ .record_size_limit = res };

    const rsl_ans = [_]u8{ 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01 };
    var send_bytes: [100]u8 = undefined;
    var stream = io.fixedBufferStream(&send_bytes);
    const write_len = try ext.encode(stream.writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &rsl_ans));
}
