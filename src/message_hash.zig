const std = @import("std");
const crypto = @import("crypto.zig");
const DigestBoundedArray = crypto.DigestBoundedArray;

pub const MessageHash = struct {
    hash: DigestBoundedArray,

    const Self = @This();

    pub fn encode(self: Self, writer: anytype) !usize {
        _ = try writer.write(self.hash.slice());

        return self.hash.len;
    }

    pub fn length(self: Self) usize {
        return self.hash.len;
    }

    pub fn fromClientHello(msg: []const u8, hkdf: crypto.Hkdf) !Self {
        var res = Self{
            .hash = try DigestBoundedArray.init(hkdf.digest_length),
        };
        hkdf.hash(res.hash.slice(), msg);

        return res;
    }
};
