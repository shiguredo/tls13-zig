const std = @import("std");
const expect = std.testing.expect;

pub fn intToEnum(comptime T: type, value: @typeInfo(T).Enum.tag_type) !T {
    const E = error{
        /// An integer was read, but it did not match any of the tags in the supplied enum.
        InvalidValue,
    };

    inline for (std.meta.fields(T)) |field| {
        if (value == field.value) {
            return @field(T, field.name);
        }
    }

    return E.InvalidValue;
}

test "intToEnum" {
    const TestEnum = enum(u8) {
        A = 1,
        B = 2,
    };

    const e = try intToEnum(TestEnum, 2);
    try expect(e == .B);
}

pub fn setReadTimeout(self: std.net.Stream, milliseconds: usize) !void {
    const timeout = std.os.timeval{
        .tv_sec = @as(i32, @intCast(milliseconds / std.time.ms_per_s)),
        .tv_usec = @as(i32, @intCast((milliseconds % std.time.ms_per_s) * std.time.us_per_ms)),
    };

    return std.os.setsockopt(self.handle, std.os.SOL.SOCKET, std.os.SO.RCVTIMEO, std.mem.asBytes(&timeout));
}
