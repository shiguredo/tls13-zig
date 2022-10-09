const std = @import("std");
const io = std.io;
const ArrayList = std.ArrayList;

const RecordPayloadProtector = @import("protector.zig").RecordPayloadProtector;
const KeyScheduler = @import("key.zig").KeyScheduler;
const Content = @import("content.zig").Content;
const ContentType = @import("content.zig").ContentType;
const ApplicationData = @import("application_data.zig").ApplicationData;
const TLSCipherText = @import("tls_cipher.zig").TLSCipherText;

pub const EntityType = enum(u8) {
    client,
    server,
};

pub fn checkAndUpdateKey(protector: *RecordPayloadProtector, ks: *KeyScheduler, write_buffer: anytype, allocator: std.mem.Allocator, et: EntityType) !bool {
    // RFC8446 Section 5.5.  Limits on Key Usage
    //
    // For AES-GCM, up to 2^24.5 full-size records (about 24 million) may be
    // encrypted on a given connection while keeping a safety margin of
    // approximately 2^-57 for Authenticated Encryption (AE) security.  For
    // ChaCha20/Poly1305, the record sequence number would wrap before the
    // safety limit is reached.

    const limit_cnt: usize = 2 << 23;
    if (protector.enc_cnt > limit_cnt or protector.dec_cnt > limit_cnt) {
        const update = Content{ .handshake = .{ .key_update = .{ .request_update = .update_requested } } };
        defer update.deinit();

        _ = try protector.encryptFromMessageAndWrite(update, allocator, write_buffer.writer());
        try write_buffer.flush();

        switch (et) {
            .client => {
                // update encoding key(clieny key)
                try ks.updateClientSecrets();
                protector.enc_keys = ks.secret.c_ap_keys;
            },
            .server => {
                // update encoding key(server key)
                try ks.updateServerSecrets();
                protector.enc_keys = ks.secret.s_ap_keys;
            },
        }
        protector.enc_cnt = 0;

        return true;
    }

    return false;
}

pub fn WriteEngine(comptime WriteBufferType: type, comptime et: EntityType) type {
    return struct {
        protector: *RecordPayloadProtector,
        ks: *KeyScheduler,
        write_buffer: *WriteBufferType,
        allocator: std.mem.Allocator,
        record_size_limit: u16,

        const Self = @This();

        pub fn write(self: *Self, b: []const u8) !usize {
            var cur_idx: usize = 0;
            while (cur_idx < b.len) {
                const updated = try checkAndUpdateKey(self.protector, self.ks, self.write_buffer, self.allocator, et);
                if (updated) {
                    std.log.debug("KeyUpdate updated_request has been sent", .{});
                }

                var end_idx = cur_idx + self.record_size_limit - self.protector.getHeaderSize();
                end_idx = if (end_idx >= b.len) b.len else end_idx;

                const app_c = Content{ .application_data = try ApplicationData.initAsView(b[cur_idx..end_idx]) };
                defer app_c.deinit();

                _ = try self.protector.encryptFromMessageAndWrite(app_c, self.allocator, self.write_buffer.writer());
                try self.write_buffer.flush();
                cur_idx = end_idx;
            }

            return b.len;
        }
    };
}

pub fn ReadEngine(comptime Entity: type, comptime et: EntityType) type {
    return struct {
        entity: *Entity,

        recv_contents: ?ArrayList(Content) = null,

        const Self = @This();

        pub fn deinit(self: Self) void {
            if (self.recv_contents) |cs| {
                for (cs.items) |c| {
                    c.deinit();
                }
                cs.deinit();
            }
        }

        pub fn read(self: *Self, b: []u8) !usize {
            var msg_stream = io.fixedBufferStream(b);

            while ((try msg_stream.getPos()) == 0) {
                // writing application_data contents into buffer/
                if (self.recv_contents) |*cs| {
                    while (cs.items.len != 0) {
                        var ap = cs.*.orderedRemove(0).application_data;
                        errdefer ap.deinit();
                        const read_size = ap.content.len - ap.read_idx;
                        const write_size = try msg_stream.getEndPos() - try msg_stream.getPos();
                        if (read_size >= write_size) {
                            _ = try msg_stream.write(ap.content[ap.read_idx..(ap.read_idx + write_size)]);
                            ap.read_idx += write_size;
                            if (read_size != write_size) {
                                try cs.*.insert(0, Content{ .application_data = ap });
                            } else {
                                ap.deinit();
                            }
                            return b.len;
                        } else {
                            _ = try msg_stream.write(ap.content[ap.read_idx..]);
                            ap.deinit();
                        }
                    }
                    cs.deinit();
                    self.recv_contents = null;
                }

                const updated = try checkAndUpdateKey(&self.entity.ap_protector, &self.entity.ks, &self.entity.write_buffer, self.entity.allocator, et);
                if (updated) {
                    std.log.debug("KeyUpdate updated_request has been sent", .{});
                }

                const t = self.entity.reader.readEnum(ContentType, .Big) catch |err| {
                    switch (err) {
                        error.WouldBlock => return msg_stream.getWritten().len,
                        else => return err,
                    }
                };
                if (t != .application_data) {
                    // TODO: error
                    std.log.err("ERROR!!!", .{});
                    continue;
                }
                const recv_record = try TLSCipherText.decode(self.entity.reader, t, self.entity.allocator);
                defer recv_record.deinit();

                const plain_record = try self.entity.ap_protector.decrypt(recv_record, self.entity.allocator);
                defer plain_record.deinit();

                if (plain_record.content_type != .application_data) {
                    if (plain_record.content_type == .handshake) {
                        const hs = (try plain_record.decodeContent(self.entity.allocator, self.entity.ks.hkdf)).handshake;
                        switch (hs) {
                            .new_session_ticket => |nst| {
                                switch (et) {
                                    .client => try self.entity.handleNewSessionTicket(nst),
                                    .server => unreachable,
                                }
                            },
                            .key_update => |ku| {
                                try self.entity.handleKeyUpdate(ku);
                            },
                            else => continue,
                        }
                    }
                    continue;
                }

                self.recv_contents = try plain_record.decodeContents(self.entity.allocator, self.entity.ks.hkdf);
            }
            return msg_stream.getWritten().len;
        }
    };
}
