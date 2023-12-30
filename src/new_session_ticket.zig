const std = @import("std");
const io = std.io;
const msg = @import("msg.zig");

const crypto = @import("crypto.zig");
const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;
const Extension = @import("extension.zig").Extension;
const CipherSuite = @import("msg.zig").CipherSuite;

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// RFC8446 Section 4.6.1 NewSessionTicket
///
/// struct {
///     uint32 ticket_lifetime;
///     uint32 ticket_age_add;
///     opaque ticket_nonce<0..255>;
///     opaque ticket<1..2^16-1>;
///     Extension extensions<0..2^16-2>;
/// } NewSessionTicket;
///
pub const NewSessionTicket = struct {
    const MAX_TICKET_NONCE_LENGTH = 256;

    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: BoundedArray(u8, MAX_TICKET_NONCE_LENGTH),
    ticket: []u8,
    extensions: ArrayList(Extension),

    allocator: std.mem.Allocator,

    const Self = @This();

    /// decode NewSessionTicket reading from io.Reader.
    /// @param reader    io.Reader to read messages.
    /// @param allocator allocator for ArrayLists and []u8.
    /// @return the result of decoded NewSessionTicket.
    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        // Decoding ticket_lifetime.
        const ticket_lifetime = try reader.readInt(u32, .big);

        // Decoding ticket_age_add.
        const ticket_age_add = try reader.readInt(u32, .big);

        // Decoding ticket_nonce.
        const nonce_len = try reader.readInt(u8, .big);
        var ticket_nonce = try BoundedArray(u8, MAX_TICKET_NONCE_LENGTH).init(nonce_len);
        try reader.readNoEof(ticket_nonce.slice());

        // Decoding ticket.
        const ticket_len = try reader.readInt(u16, .big);
        const ticket = try allocator.alloc(u8, ticket_len);
        errdefer allocator.free(ticket);
        try reader.readNoEof(ticket);

        // Decoding Extensions.
        var exts = ArrayList(Extension).init(allocator);
        errdefer exts.deinit();
        try msg.decodeExtensions(reader, allocator, &exts, .new_session_ticket, false);

        return Self{
            .ticket_lifetime = ticket_lifetime,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = ticket_nonce,
            .ticket = ticket,
            .extensions = exts,
            .allocator = allocator,
        };
    }

    /// encode NewSessionTicket message writing to io.Writer.
    /// @param self NewSessionTicket to be encoded.
    /// @param writer io.Writer to be written encoded message.
    /// @return encoded length
    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        // Encoding ticket_lifetime.
        try writer.writeInt(u32, self.ticket_lifetime, .big);
        len += @sizeOf(u32);

        // Encoding ticket_age_add.
        try writer.writeInt(u32, self.ticket_age_add, .big);
        len += @sizeOf(u32);

        // Encoding ticket_nonce.
        try writer.writeByte(@as(u8, @intCast(self.ticket_nonce.len)));
        len += @sizeOf(u8);
        try writer.writeAll(self.ticket_nonce.slice());
        len += self.ticket_nonce.len;

        // Encoding ticket.
        try writer.writeInt(u16, @as(u16, @intCast(self.ticket.len)), .big);
        len += @sizeOf(u16);
        try writer.writeAll(self.ticket);
        len += self.ticket.len;

        // Encoding Extensions.
        len += try msg.encodeExtensions(writer, self.extensions);

        return len;
    }

    /// deinitialize NewSessionTicket.
    /// @param self NewSessionTicket to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.ticket);
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u32); // ticket_lifetime
        len += @sizeOf(u32); // ticket_age_add
        len += @sizeOf(u8); // ticket_nonce_len
        len += self.ticket_nonce.len; // ticket_nonce
        len += @sizeOf(u16); // ticket_len
        len += self.ticket.len; // ticket
        len += @sizeOf(u16); // extension len
        for (self.extensions.items) |e| {
            len += e.length(); // extension
        }

        return len;
    }

    /// creating NewSessionTicket from Ticket.
    /// @param ticket    ticket to be used.
    /// @param allocator allocator to allocate NewSessionTicket.
    pub fn fromTicket(ticket: Ticket, allocator: std.mem.Allocator) !Self {
        var res = Self{
            .ticket_lifetime = 3600, //TODO: specify via an argument
            .ticket_age_add = std.crypto.random.int(u32),
            .ticket_nonce = try BoundedArray(u8, MAX_TICKET_NONCE_LENGTH).init(ticket.nonce.len),
            .ticket = try allocator.alloc(u8, ticket.length()),
            .extensions = ArrayList(Extension).init(allocator),
            .allocator = allocator,
        };
        errdefer res.deinit();

        @memcpy(res.ticket_nonce.slice(), &ticket.nonce);

        var stream = io.fixedBufferStream(res.ticket);
        _ = try ticket.encode(stream.writer());

        return res;
    }
};

/// RFC 5077 4.  Recommended Ticket Construction
///
/// struct {
///     opaque key_name[16];
///     opaque iv[16];
///     opaque encrypted_state<0..2^16-1>;
///     opaque mac[32];
/// } ticket;
///
/// struct {
///     ProtocolVersion protocol_version;
///     CipherSuite cipher_suite;
///     CompressionMethod compression_method;
///     opaque master_secret[48];
///     ClientIdentity client_identity;
///     uint32 timestamp;
/// } StatePlaintext;
///
/// enum {
///    anonymous(0),
///    certificate_based(1),
///    psk(2)
/// } ClientAuthenticationType;
///
/// struct {
///     ClientAuthenticationType client_authentication_type;
///     select (ClientAuthenticationType) {
///         case anonymous: struct {};
///         case certificate_based:
///             ASN.1Cert certificate_list<0..2^24-1>;
///         case psk:
///             opaque psk_identity<0..2^16-1>;   /* from [RFC4279] */
///     };
/// } ClientIdentity;
pub const Ticket = struct {
    key_name: [16]u8 = undefined,
    nonce: [Aes128Gcm.nonce_length]u8 = undefined,
    encrypted_state: []u8 = &([_]u8{}),
    tag: [Aes128Gcm.tag_length]u8 = undefined,

    allocator: std.mem.Allocator,
    const Self = @This();

    pub fn deinit(self: Self) void {
        if (self.encrypted_state.len != 0) {
            self.allocator.free(self.encrypted_state);
        }
    }

    pub fn decode(reader: anytype, allocator: std.mem.Allocator) !Self {
        var key_name: [16]u8 = undefined;
        try reader.readNoEof(&key_name);
        var nonce: [Aes128Gcm.nonce_length]u8 = undefined;
        try reader.readNoEof(&nonce);

        const enc_len = try reader.readInt(u16, .big);
        const enc_state = try allocator.alloc(u8, enc_len);
        errdefer allocator.free(enc_state);
        try reader.readNoEof(enc_state);

        var tag: [Aes128Gcm.tag_length]u8 = undefined;
        try reader.readNoEof(&tag);

        return .{
            .key_name = key_name,
            .nonce = nonce,
            .encrypted_state = enc_state,
            .tag = tag,
            .allocator = allocator,
        };
    }

    pub fn decryptState(self: Self, key: [Aes128Gcm.key_length]u8) !StatePlaintext {
        const plain = try self.allocator.alloc(u8, self.encrypted_state.len);
        defer self.allocator.free(plain);

        try Aes128Gcm.decrypt(plain, self.encrypted_state, self.tag, &(self.key_name ++ self.nonce), self.nonce, key);
        var stream = io.fixedBufferStream(plain);
        return try StatePlaintext.decode(stream.reader());
    }

    pub fn fromStatePlaintext(key_name: [16]u8, key: [Aes128Gcm.key_length]u8, nonce: [Aes128Gcm.nonce_length]u8, state: StatePlaintext, allocator: std.mem.Allocator) !Self {
        var res = Self{
            .allocator = allocator,
        };
        errdefer res.deinit();
        res.key_name = key_name;
        res.nonce = nonce;

        const plain = try allocator.alloc(u8, state.length());
        defer allocator.free(plain);
        var stream = io.fixedBufferStream(plain);
        _ = try state.encode(stream.writer());

        res.encrypted_state = try res.allocator.alloc(u8, state.length());
        errdefer res.allocator.free(res.encrypted_state);

        Aes128Gcm.encrypt(res.encrypted_state, &res.tag, plain, &(res.key_name ++ res.nonce), res.nonce, key);

        return res;
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeAll(&self.key_name);
        len += self.key_name.len;

        try writer.writeAll(&self.nonce);
        len += self.nonce.len;

        try writer.writeInt(u16, @as(u16, @intCast(self.encrypted_state.len)), .big);
        len += 2;
        try writer.writeAll(self.encrypted_state);
        len += self.encrypted_state.len;

        try writer.writeAll(&self.tag);
        len += self.tag.len;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += self.key_name.len;
        len += self.nonce.len;
        len += @sizeOf(u16);
        len += self.encrypted_state.len;
        len += self.tag.len;

        return len;
    }
};

pub const StatePlaintext = struct {
    protocol_version: u16,
    cipher_suite: CipherSuite,
    compression_method: u8 = 0, // "null" compression methos
    master_secret: crypto.DigestBoundedArray,
    client_identity: ClientIdentity,
    timestamp: u64,

    const Self = @This();

    pub fn decode(reader: anytype) !Self {
        const proto_version = try reader.readInt(u16, .big);
        const cipher_suite = try reader.readEnum(CipherSuite, .big);
        const master_secret_len = try reader.readInt(u16, .big);
        var master_secret = try crypto.DigestBoundedArray.init(master_secret_len);
        try reader.readNoEof(master_secret.slice());
        const identity = try ClientIdentity.decode(reader);
        const timestamp = try reader.readInt(u64, .big);

        return Self{
            .protocol_version = proto_version,
            .cipher_suite = cipher_suite,
            .master_secret = master_secret,
            .client_identity = identity,
            .timestamp = timestamp,
        };
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;

        try writer.writeInt(u16, self.protocol_version, .big);
        len += 2;
        try writer.writeInt(u16, @intFromEnum(self.cipher_suite), .big);
        len += 2;
        try writer.writeInt(u16, @as(u16, @intCast(self.master_secret.len)), .big);
        len += 2;
        try writer.writeAll(self.master_secret.slice());
        len += self.master_secret.len;
        len += try self.client_identity.encode(writer);
        try writer.writeInt(u64, self.timestamp, .big);
        len += 8;

        return len;
    }

    pub fn length(self: Self) usize {
        var len: usize = 0;
        len += @sizeOf(u16); // prptocol_version
        len += @sizeOf(u16); // cipher_suite
        len += @sizeOf(u16); // master_secret.len
        len += self.master_secret.len;
        len += self.client_identity.length();
        len += @sizeOf(u64);

        return len;
    }
};

pub const ClientAuthenticationType = enum(u8) {
    anonymous = 0,
    certificate_based = 1,
    psk = 2,
};

pub const ClientIdentity = struct {
    client_authentication_type: ClientAuthenticationType,

    const Self = @This();

    pub fn decode(reader: anytype) !Self {
        const t = try reader.readEnum(ClientAuthenticationType, .big);
        switch (t) {
            .anonymous => return .{ .client_authentication_type = t },
            else => unreachable,
        }
    }

    pub fn encode(self: Self, writer: anytype) !usize {
        var len: usize = 0;
        try writer.writeByte(@intFromEnum(self.client_authentication_type));
        len += 1;
        switch (self.client_authentication_type) {
            .anonymous => return len,
            else => unreachable,
        }
    }

    pub fn length(self: Self) usize {
        const len: usize = 1;
        switch (self.client_authentication_type) {
            .anonymous => return len,
            else => unreachable,
        }
    }
};

const expect = std.testing.expect;

test "ticket encryption & decryption" {
    const state = StatePlaintext{
        .protocol_version = 0x0303,
        .cipher_suite = .TLS_AES_128_GCM_SHA256,
        .master_secret = try crypto.DigestBoundedArray.init(1),
        .client_identity = .{
            .client_authentication_type = .anonymous,
        },
        .timestamp = 0,
    };

    const key_name: [16]u8 = undefined;
    const key: [Aes128Gcm.key_length]u8 = undefined;
    const nonce: [Aes128Gcm.nonce_length]u8 = undefined;
    const ticket = try Ticket.fromStatePlaintext(key_name, key, nonce, state, std.testing.allocator);
    defer ticket.deinit();
    const state2 = try ticket.decryptState(key);

    try expect(state.protocol_version == state2.protocol_version);
}
