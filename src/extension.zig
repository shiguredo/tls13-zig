const std = @import("std");
const SupportedGroups = @import("groups.zig").SupportedGroups;
const SupportedVersions = @import("versions.zig").SupportedVersions;
const SignatureAlgorithms = @import("signatures.zig").SignatureAlgorithms;
const KeyShare = @import("key_share.zig").KeyShare;
const HandshakeType = @import("msg.zig").HandshakeType;

pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    record_size_limit = 28,
    supported_versions = 43,
    key_share = 51,
};

pub const Extension = union(ExtensionType) {
    server_name: ServerName,
    supported_groups: SupportedGroups,
    signature_algorithms: SignatureAlgorithms,
    record_size_limit: RecordSizeLimit,
    supported_versions: SupportedVersions,
    key_share: KeyShare,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator, ht: HandshakeType, hello_retry: bool) !Self {
        const t = @intToEnum(ExtensionType, try reader.readIntBig(u16));
        const len = try reader.readIntBig(u16); // TODO: check readable length of reader
        if (len == 0) {
            switch (t) {
                ExtensionType.server_name => return Self { .server_name = .{} },
                else => unreachable,
            }
        } else {
            switch (t) {
                ExtensionType.server_name => return Self{ .server_name = try ServerName.decode(reader) },
                ExtensionType.supported_groups => return Self{ .supported_groups = try SupportedGroups.decode(reader, allocator) },
                ExtensionType.signature_algorithms => return Self{ .signature_algorithms = try SignatureAlgorithms.decode(reader, allocator) },
                ExtensionType.record_size_limit => return Self{ .record_size_limit = try RecordSizeLimit.decode(reader) },
                ExtensionType.supported_versions => return Self{ .supported_versions = try SupportedVersions.decode(reader, allocator, ht) },
                ExtensionType.key_share => return Self{ .key_share = try KeyShare.decode(reader, allocator, ht, hello_retry) },
            }
        }
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;
        len += @sizeOf(ExtensionType); // type
        len += @sizeOf(u16); // length
        switch (self) {
            ExtensionType.server_name => unreachable,
            ExtensionType.supported_groups => |e| return (try e.encode(writer)) + len,
            ExtensionType.signature_algorithms => |e| return (try e.encode(writer)) + len,
            ExtensionType.record_size_limit => |e| {
                try writer.writeIntBig(u16, @enumToInt(ExtensionType.record_size_limit));
                try writer.writeIntBig(u16, @intCast(u16, e.length()));
                len += try e.encode(writer);
            },
            ExtensionType.supported_versions => |e| return (try e.encode(writer)) + len,
            ExtensionType.key_share => unreachable,
        }

        return len;
    }

    pub fn print(self: Self) void {
        switch (self) {
            ExtensionType.server_name => |e| e.print(),
            ExtensionType.supported_groups => |e| e.print(),
            ExtensionType.signature_algorithms => |e| e.print(),
            ExtensionType.record_size_limit => |e| e.print(),
            ExtensionType.supported_versions => |e| e.print(),
            ExtensionType.key_share => |e| e.print(),
        }
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // type
        len += @sizeOf(u16); // length
        switch (self) {
            ExtensionType.server_name => |e| return e.length() + len,
            ExtensionType.supported_groups => |e| return e.length() + len,
            ExtensionType.signature_algorithms => |e| return e.length() + len,
            ExtensionType.record_size_limit => |e| return e.length() + len,
            ExtensionType.supported_versions => |e| return e.length() + len,
            ExtensionType.key_share => |e| return e.length() + len,
        }
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            ExtensionType.supported_groups => |e| e.deinit(),
            ExtensionType.signature_algorithms => |e| e.deinit(),
            ExtensionType.supported_versions => |e| e.deinit(),
            ExtensionType.key_share => |e| e.deinit(),
            else => {},
        }
    }
};

//RFC8449 Record Size Limit Extension for TLS
pub const RecordSizeLimit = struct {
    record_size_limit: u16 = undefined,

    const Self = @This();

    pub fn init() Self {
        return .{};
    }

    pub fn decode(reader: anytype) !Self {
        var res = Self.init();

        res.record_size_limit = try reader.readIntBig(u16);

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeIntBig(u16, self.record_size_limit);
        len += @sizeOf(u16);

        return len;
    }

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

//RFC6066 Transport Layer Security (TLS) Extensions: Extension Definitions
pub const ServerName = struct {
    init: bool = false,

    const Self = @This();

    pub fn init() Self {
        return .{
            .init = true,
        };
    }

    pub fn decode(reader: anytype) !Self {
        _ = reader;
        unreachable;
    }

    pub fn length(self: Self) usize {
        if (!self.init) {
            return 0;
        }

        unreachable;
    }

    pub fn print(self: Self) void {
        _ = self;
    }
};

const io = std.io;
const expect = std.testing.expect;

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
    const write_len = try ext.encode(io.fixedBufferStream(&send_bytes).writer());
    try expect(std.mem.eql(u8, send_bytes[0..write_len], &rsl_ans));
}

test "Extension ServerName decode" {
    const recv_data = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    var readStream = io.fixedBufferStream(&recv_data);

    const res = try Extension.decode(readStream.reader(), std.testing.allocator, .server_hello, false);
    try expect(res == .server_name);
}
