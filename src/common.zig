const std = @import("std");
const io = std.io;

const RecordPayloadProtector = @import("protector.zig").RecordPayloadProtector;
const KeyScheduler = @import("key.zig").KeyScheduler;
const Content = @import("content.zig").Content;

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
