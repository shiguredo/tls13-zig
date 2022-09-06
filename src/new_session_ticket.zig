const std = @import("std");
const msg = @import("msg.zig");

const ArrayList = std.ArrayList;
const BoundedArray = std.BoundedArray;
const Extension = @import("extension.zig").Extension;

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
        const ticket_lifetime = try reader.readIntBig(u32);

        // Decoding ticket_age_add.
        const ticket_age_add = try reader.readIntBig(u32);

        // Decoding ticket_nonce.
        const nonce_len = try reader.readIntBig(u8);
        var ticket_nonce = try BoundedArray(u8, MAX_TICKET_NONCE_LENGTH).init(nonce_len);
        try reader.readNoEof(ticket_nonce.slice());

        // Decoding ticket.
        const ticket_len = try reader.readIntBig(u16);
        var ticket = try allocator.alloc(u8, ticket_len);
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

    /// deinitialize NewSessionTicket.
    /// @param self NewSessionTicket to be deinitialized.
    pub fn deinit(self: Self) void {
        self.allocator.free(self.ticket);
        for (self.extensions.items) |e| {
            e.deinit();
        }
        self.extensions.deinit();
    }
};
