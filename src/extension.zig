const std = @import("std");
const SupportedGroups = @import("groups.zig").SupportedGroups;
const SupportedVersions = @import("versions.zig").SupportedVersions;
const SignatureAlgorithms = @import("signatures.zig").SignatureAlgorithms;
const KeyShare = @import("key_share.zig").KeyShare;
const HandshakeType = @import("msg.zig").HandshakeType;

pub const ExtensionType = enum(u16) {
    supported_groups = 10,
    signature_algorithms = 13,
    supported_versions = 43,
    key_share = 51,
};

pub const Extension = union(ExtensionType) {
    supported_groups: SupportedGroups,
    signature_algorithms: SignatureAlgorithms,
    supported_versions: SupportedVersions,
    key_share: KeyShare,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: std.mem.Allocator, ht: HandshakeType, hello_retry: bool) !Self {
        const t = @intToEnum(ExtensionType, try reader.readIntBig(u16));
        switch (t) {
            ExtensionType.supported_groups => return Self{ .supported_groups = try SupportedGroups.decode(reader, allocator) },
            ExtensionType.signature_algorithms => return Self{ .signature_algorithms = try SignatureAlgorithms.decode(reader, allocator) },
            ExtensionType.supported_versions => return Self{ .supported_versions = try SupportedVersions.decode(reader, ht) },
            ExtensionType.key_share => return Self{ .key_share = try KeyShare.decode(reader, allocator, ht, hello_retry) },
        }
    }

    pub fn print(self: Self) void {
        switch (self) {
            ExtensionType.supported_groups => |e| e.print(),
            ExtensionType.signature_algorithms => |e| e.print(),
            ExtensionType.supported_versions => |e| e.print(),
            ExtensionType.key_share => |e| e.print(),
        }
    }

    pub fn length(self: Self) usize {
        switch (self) {
            ExtensionType.supported_groups => |e| return e.length(),
            ExtensionType.signature_algorithms => |e| return e.length(),
            ExtensionType.supported_versions => |e| return e.length(),
            ExtensionType.key_share => |e| return e.length(),
        }
    }

    pub fn deinit(self: *Self) void {
        switch (self.*) {
            ExtensionType.supported_groups => |*e| e.deinit(),
            ExtensionType.signature_algorithms => |*e| e.deinit(),
            ExtensionType.key_share => |*e| e.deinit(),
            else => {},
        }
    }
};
