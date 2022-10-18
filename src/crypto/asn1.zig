const std = @import("std");
const io = std.io;

const expect = std.testing.expect;

pub const Stream = io.FixedBufferStream([]u8);

pub const Tag = enum(u8) {
    BOOLEAN = 0x01,
    INTEGER = 0x02,
    BIT_STRING = 0x03,
    OCTET_STRING = 0x04,
    NULL = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    SEQUENCE = 0x30, // SEQUENCE OF
    SET = 0x31, // SET OF
};

pub const Decoder = struct {
    pub const Error = error{
        InvalidType,
        InvalidLength,
        InvalidFormat,
        TooLarge,
        NotAllDecoded,
    };

    pub fn decodeLength(reader: anytype) !u64 {
        const len = try reader.readByte();

        // Short form
        if (len & 0x80 == 0) {
            return len;
        }

        // Long form
        const len_size = len & 0x7F;

        // length field larger than u64 is ignored
        if (len_size > 8) {
            return Error.TooLarge;
        }

        var i: usize = 0;
        var res: u64 = 0;
        while (i < len_size) : (i += 1) {
            res = (res << 8) | (try reader.readByte());
        }

        return res;
    }

    pub fn getLengthSize(len: u64) usize {
        if (len < 0x80) {
            return 1;
        }

        var res: usize = 1;
        var cur = len;
        while (cur > 0) {
            cur = cur >> 8;
            res += 1;
        }

        return res;
    }

    pub fn decodeOID(out: []u8, id: []const u8) usize {
        var start_idx: usize = 0;
        var cur_idx: usize = 0;
        var out_idx: usize = 0;
        while (start_idx < id.len) {
            if (start_idx == 0) {
                out[out_idx] = (id[0] / 40) + '0';
                out_idx += 1;
                out[out_idx] = '.';
                out_idx += 1;
                out[out_idx] = (id[0] % 40) + '0';
                out_idx += 1;
                start_idx += 1;
            } else {
                cur_idx = start_idx;
                while (id[cur_idx] > 0x80) {
                    cur_idx += 1;
                }
                cur_idx += 1;

                const code = decodeOIDInt(id[start_idx..cur_idx]);
                start_idx = cur_idx;

                const s = std.fmt.bufPrintIntToSlice(out[out_idx..], code, 10, .lower, .{});
                out_idx += s.len;
            }

            if (start_idx != id.len) {
                out[out_idx] = '.';
                out_idx += 1;
            }
        }

        return out_idx;
    }

    fn decodeOIDInt(bytes: []const u8) usize {
        var res: usize = 0;
        for (bytes) |b, i| {
            res *= 128;
            if (i == bytes.len - 1) {
                res += b;
            } else {
                res += (b - 0x80);
            }
        }

        return res;
    }

    pub fn decodeSEQUENCE(reader: anytype, allocator: std.mem.Allocator, comptime DecodeType: type) !DecodeType {
        const t = @intToEnum(Tag, try reader.readByte());
        if (t != .SEQUENCE) {
            return Error.InvalidType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        defer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        var stream = io.fixedBufferStream(content);
        const res = try DecodeType.decodeContent(&stream, allocator);
        errdefer res.deinit();

        if ((try stream.getPos()) != (try stream.getEndPos())) {
            return Error.NotAllDecoded;
        }

        return res;
    }

    pub fn decodeINTEGER(reader: anytype, allocator: std.mem.Allocator) ![]u8 {
        const t = @intToEnum(Tag, try reader.readByte());
        if (t != .INTEGER) {
            return Error.InvalidType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        errdefer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        return content;
    }

    pub fn decodeOCTETSTRING(reader: anytype, allocator: std.mem.Allocator) ![]u8 {
        const t = @intToEnum(Tag, try reader.readByte());
        if (t != .OCTET_STRING) {
            return Error.InvalidType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        errdefer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        return content;
    }
};

pub const ObjectIdentifier = struct {
    id: []u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.id);
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        const t = @intToEnum(Tag, try reader.readByte());
        if (t != .OBJECT_IDENTIFIER) {
            return Decoder.Error.InvalidType;
        }
        const len = try Decoder.decodeLength(reader);
        var id_bin = try allocator.alloc(u8, len);
        defer allocator.free(id_bin);

        try reader.readNoEof(id_bin);

        // TODO: calculate buffer size
        var id_tmp: [100]u8 = undefined;
        const id_len = Decoder.decodeOID(&id_tmp, id_bin);
        var id = try allocator.alloc(u8, id_len);
        errdefer allocator.free(id);
        std.mem.copy(u8, id, id_tmp[0..id_len]);

        return Self{
            .id = id,
            .allocator = allocator,
        };
    }
};

pub const Encoder = struct {
    const Error = error{
        SomethingWrong,
    };

    pub fn encodeLength(len: u64, writer: anytype) !usize {
        if (len < 0x80) {
            try writer.writeByte(@intCast(u8, len));
            return 1;
        }

        var tmp = len;
        var end_idx: usize = 0;
        var res: [8]u8 = undefined;
        while (tmp > 0) {
            if (end_idx >= res.len) {
                return Error.SomethingWrong;
            }

            res[end_idx] = @intCast(u8, tmp & 0xFF);
            tmp = tmp >> 8;
            end_idx += 1;
        }

        const len_len = end_idx + 1;
        try writer.writeByte(@intCast(u8, (end_idx & 0x7F) | 0x80));
        while (end_idx > 0) {
            end_idx -= 1;
            try writer.writeByte(res[end_idx]);
        }

        return len_len;
    }

    // https://docs.microsoft.com/ja-jp/windows/win32/seccertenroll/about-object-identifier
    fn encodeOID(out: []u8, id: []const u8) !usize {
        var count: usize = 0;
        var out_idx: usize = 0;
        var start_idx: usize = 0;
        for (id) |c, i| {
            if (i != (id.len - 1) and c != '.') {
                continue;
            }
            var end_idx = i;
            if (i == (id.len - 1)) {
                end_idx = id.len;
            }

            const code = try std.fmt.parseInt(usize, id[start_idx..end_idx], 10);
            if (count == 0) {
                out[out_idx] = @intCast(u8, code);
                count += 1;
            } else if (count == 1) {
                out[out_idx] = @intCast(u8, out[out_idx] * 40 + code);
                out_idx += 1;
                count += 1;
            } else {
                out_idx += encodeOIDInt(out[out_idx..], code);
            }
            start_idx = i + 1;
        }

        return out_idx;
    }

    fn encodeOIDInt(out: []u8, i: usize) usize {
        var tmp: [100]u8 = undefined;
        var idx: usize = 0;
        var cur = i;
        while (cur > 0) {
            tmp[idx] = @intCast(u8, cur % 128);
            if (idx > 0) {
                tmp[idx] += 0x80;
            }
            cur = cur / 128;
            idx += 1;
        }

        var rev_i: usize = 0;
        while (rev_i < idx) : (rev_i += 1) {
            out[rev_i] = tmp[idx - rev_i - 1];
        }

        return idx;
    }
};

test "encodeOIDInt & decodeOIDInt 1" {
    var res: [100]u8 = undefined;
    const len = Encoder.encodeOIDInt(&res, 311);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x82, 0x37 })));
    try expect(Decoder.decodeOIDInt(res[0..len]) == 311);
}

test "encodeOIDInt & decodeOIDInt 2" {
    var res: [100]u8 = undefined;
    const len = Encoder.encodeOIDInt(&res, 56789);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x83, 0xbb, 0x55 })));
    try expect(Decoder.decodeOIDInt(res[0..len]) == 56789);
}

test "encodeOIDInt & decodeOIDInt 3" {
    var res: [100]u8 = undefined;
    const len = Encoder.encodeOIDInt(&res, 113549);
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x86, 0xf7, 0x0d })));
    try expect(Decoder.decodeOIDInt(res[0..len]) == 113549);
}

test "encodeOID" {
    var res: [100]u8 = undefined;
    const len = try Encoder.encodeOID(&res, "1.3.6.1.4.1.311.21.20");
    try expect(std.mem.eql(u8, res[0..len], &([_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14 })));
}

test "decodeOID" {
    var res: [100]u8 = undefined;
    const len = Decoder.decodeOID(&res, &([_]u8{ 0x2b, 0x06, 0x1, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14 }));
    try expect(std.mem.eql(u8, res[0..len], "1.3.6.1.4.1.311.21.20"));
}

test "decodeSEQUENCE" {
    const Test = struct {
        content: [1]u8,
        const Self = @This();

        pub fn decodeContent(stream: *Stream, allocator: std.mem.Allocator) !Self {
            _ = allocator;
            const c = try stream.reader().readByte();
            return Self{
                .content = [_]u8{c},
            };
        }

        pub fn deinit(self: Self) void {
            _ = self;
        }
    };

    const b = [_]u8{ 0x30, 0x01, 0xaa };
    var stream = io.fixedBufferStream(&b);

    const res = try Decoder.decodeSEQUENCE(stream.reader(), std.testing.allocator, Test);
    try expect(res.content[0] == 0xaa);
}
