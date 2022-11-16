const std = @import("std");
const utils = @import("utils.zig");
const NamedGroupList = @import("supported_groups.zig").NamedGroupList;
const SupportedVersions = @import("supported_versions.zig").SupportedVersions;
const SignatureSchemeList = @import("signature_scheme.zig").SignatureSchemeList;
const KeyShare = @import("key_share.zig").KeyShare;
const RecordSizeLimit = @import("record_size_limit.zig").RecordSizeLimit;
const ServerNameList = @import("server_name.zig").ServerNameList;
const HandshakeType = @import("handshake.zig").HandshakeType;
const PreSharedKey = @import("pre_shared_key.zig").PreSharedKey;
const PskKeyExchangeModes = @import("psk_key_exchange_modes.zig").PskKeyExchangeModes;
const EarlyData = @import("early_data.zig").EarlyData;

/// RFC8446 Section 4.2 Extensions
///
/// enum {
///     server_name(0),                             /* RFC 6066 */
///     max_fragment_length(1),                     /* RFC 6066 */
///     status_request(5),                          /* RFC 6066 */
///     supported_groups(10),                       /* RFC 8422, 7919 */
///     signature_algorithms(13),                   /* RFC 8446 */
///     use_srtp(14),                               /* RFC 5764 */
///     heartbeat(15),                              /* RFC 6520 */
///     application_layer_protocol_negotiation(16), /* RFC 7301 */
///     signed_certificate_timestamp(18),           /* RFC 6962 */
///     client_certificate_type(19),                /* RFC 7250 */
///     server_certificate_type(20),                /* RFC 7250 */
///     padding(21),                                /* RFC 7685 */
///     pre_shared_key(41),                         /* RFC 8446 */
///     early_data(42),                             /* RFC 8446 */
///     supported_versions(43),                     /* RFC 8446 */
///     cookie(44),                                 /* RFC 8446 */
///     psk_key_exchange_modes(45),                 /* RFC 8446 */
///     certificate_authorities(47),                /* RFC 8446 */
///     oid_filters(48),                            /* RFC 8446 */
///     post_handshake_auth(49),                    /* RFC 8446 */
///     signature_algorithms_cert(50),              /* RFC 8446 */
///     key_share(51),                              /* RFC 8446 */
///     (65535)
/// } ExtensionType;
///
pub const ExtensionType = enum(u16) {
    server_name = 0,
    // max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    // user_srtp = 14,
    // heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    // client_certificate_type = 19,
    // server_certificate_type = 20,
    // padding = 21,
    record_size_limit = 28,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    // cookie = 44,
    psk_key_exchange_modes = 45,
    // certificate_authorities = 47,
    // oid_filters = 48,
    post_handshake_auth = 49,
    // signature_algorithms_cert = 50,
    key_share = 51,
    none = 65535,

    ec_points_format = 11,
    next_protocol_negotiation = 13172,
    encrypt_then_mac = 22,
    extended_master_secret = 23,
    padding = 21,
    session_ticket = 35,
    compress_certificate = 27,
    application_settings = 17513,
};

/// RFC8446 Section 4.2 Extensions
///
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
///
pub const Extension = union(ExtensionType) {
    server_name: ServerNameList,
    supported_groups: NamedGroupList,
    signature_algorithms: SignatureSchemeList,
    record_size_limit: RecordSizeLimit,
    supported_versions: SupportedVersions,
    key_share: KeyShare,
    none: Dummy,
    application_layer_protocol_negotiation: Dummy,
    psk_key_exchange_modes: PskKeyExchangeModes,
    post_handshake_auth: Dummy,
    ec_points_format: Dummy,
    next_protocol_negotiation: Dummy,
    encrypt_then_mac: Dummy,
    extended_master_secret: Dummy,
    padding: Dummy,
    status_request: Dummy,
    signed_certificate_timestamp: Dummy,
    session_ticket: Dummy,
    compress_certificate: Dummy,
    application_settings: Dummy,
    pre_shared_key: PreSharedKey,
    early_data: EarlyData,

    const Self = @This();
    pub const HEADER_LENGTH = @sizeOf(u16) + @sizeOf(u16);

    /// decode Extension reading from io.Reader.
    /// @param reader      io.Reader to read messages.
    /// @param allocator   allocator to allocate each Extension.
    /// @param ht          HandshakeType.
    /// @param hello_retry specify the extension is contained in HelloRetryRequest.
    /// @return decoded Extension.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator, ht: HandshakeType, hello_retry: bool) !Self {
        // Decoding ExtensionType.
        // none is for GREASE.
        const t_raw = try reader.readIntBig(u16);
        var t = utils.intToEnum(ExtensionType, t_raw) catch blk: {
            std.log.warn("Unknown ExtensionType 0x{x:0>4}", .{t_raw});
            break :blk .none;
        };

        // Decoding extension_data.
        const len = try reader.readIntBig(u16); // TODO: check readable length of reader

        switch (t) {
            .server_name => return Self{ .server_name = try ServerNameList.decode(reader, len, allocator) },
            .supported_groups => return Self{ .supported_groups = try NamedGroupList.decode(reader, allocator) },
            .signature_algorithms => return Self{ .signature_algorithms = try SignatureSchemeList.decode(reader, allocator) },
            .record_size_limit => return Self{ .record_size_limit = try RecordSizeLimit.decode(reader) },
            .supported_versions => return Self{ .supported_versions = try SupportedVersions.decode(reader, ht) },
            .key_share => return Self{ .key_share = try KeyShare.decode(reader, allocator, ht, hello_retry) },
            .none => return Self{ .none = try Dummy.decode(reader, len) },
            .application_layer_protocol_negotiation => return Self{ .application_layer_protocol_negotiation = try Dummy.decode(reader, len) },
            .psk_key_exchange_modes => return Self{ .psk_key_exchange_modes = try PskKeyExchangeModes.decode(reader, allocator) },
            .post_handshake_auth => return Self{ .post_handshake_auth = try Dummy.decode(reader, len) },
            .ec_points_format => return Self{ .ec_points_format = try Dummy.decode(reader, len) },
            .next_protocol_negotiation => return Self{ .next_protocol_negotiation = try Dummy.decode(reader, len) },
            .encrypt_then_mac => return Self{ .encrypt_then_mac = try Dummy.decode(reader, len) },
            .extended_master_secret => return Self{ .extended_master_secret = try Dummy.decode(reader, len) },
            .padding => return Self{ .padding = try Dummy.decode(reader, len) },
            .status_request => return Self{ .status_request = try Dummy.decode(reader, len) },
            .signed_certificate_timestamp => return Self{ .signed_certificate_timestamp = try Dummy.decode(reader, len) },
            .session_ticket => return Self{ .session_ticket = try Dummy.decode(reader, len) },
            .compress_certificate => return Self{ .compress_certificate = try Dummy.decode(reader, len) },
            .application_settings => return Self{ .application_settings = try Dummy.decode(reader, len) },
            .pre_shared_key => return Self{ .pre_shared_key = try PreSharedKey.decode(reader, ht, allocator) },
            .early_data => return Self{ .early_data = try EarlyData.decode(reader, ht) },
        }
    }

    /// encode Extension writing to io.Writer.
    /// @param self   Extension to be encoded.
    /// @param writer io.Writer to write encoded Extension.
    /// @return length of encoded Extension.
    pub fn encode(self: Self, writer: anytype) !usize {
        if (self == .none) {
            // do not encode 'none'.
            unreachable;
        }

        var len: usize = 0;

        // Encoding ExtensionType.
        try writer.writeIntBig(u16, @enumToInt(self));
        len += @sizeOf(ExtensionType); // type

        // Encoding extension_data.
        try writer.writeIntBig(u16, @intCast(u16, self.length() - (@sizeOf(u16) + @sizeOf(u16))));
        len += @sizeOf(u16); // length
        switch (self) {
            .server_name => |e| len += try e.encode(writer),
            .supported_groups => |e| len += try e.encode(writer),
            .signature_algorithms => |e| len += try e.encode(writer),
            .record_size_limit => |e| len += try e.encode(writer),
            .supported_versions => |e| len += try e.encode(writer),
            .key_share => |e| len += try e.encode(writer),
            .pre_shared_key => |e| len += try e.encode(writer),
            .psk_key_exchange_modes => |e| len += try e.encode(writer),
            .early_data => |e| len += try e.encode(writer),
            .none => unreachable,
            else => unreachable,
        }

        return len;
    }

    // get the length of encoded Extension.
    // @param self the target Extension.
    // @return length of encoded Extension.
    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // type
        len += @sizeOf(u16); // length
        switch (self) {
            inline else => |case| return case.length() + len,
        }
    }

    /// deinitialize Extension.
    /// @param self Extension to be deinitialized.
    pub fn deinit(self: Self) void {
        switch (self) {
            .server_name => |e| e.deinit(),
            .supported_groups => |e| e.deinit(),
            .signature_algorithms => |e| e.deinit(),
            .supported_versions => {},
            .key_share => |e| e.deinit(),
            .pre_shared_key => |e| e.deinit(),
            .psk_key_exchange_modes => |e| e.deinit(),
            else => {},
        }
    }

    pub fn print(self: Self) void {
        switch (self) {
            .server_name => |e| e.print(),
            .supported_groups => |e| e.print(),
            .signature_algorithms => |e| e.print(),
            .record_size_limit => |e| e.print(),
            .supported_versions => |e| e.print(),
            .key_share => |e| e.print(),
            else => unreachable,
        }
    }
};

pub const Dummy = struct {
    len: usize,

    const Self = @This();

    pub fn decode(reader: anytype, len: usize) !Self {
        var i: usize = 0;
        while (i < len) : (i += 1) {
            _ = try reader.readByte();
        }

        return .{ .len = len };
    }

    pub fn length(self: Self) usize {
        return self.len;
    }
};
