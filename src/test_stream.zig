const std = @import("std");
const log = std.log;
const allocator = std.heap.page_allocator;
const assert = std.debug.assert;

const client = @import("client.zig");

pub fn main() !void {
    log.info("started.", .{});
    var tls_client = try client.TLSClientTCP.init(allocator);
    defer tls_client.deinit();
    tls_client.print_keys = true;
    try tls_client.connect("localhost", 8443);

    var msg_len_bytes: [4]u8 = undefined;
    var recv_bytes: [16384]u8 = undefined;
    var size: u32 = 1;

    while (size < recv_bytes.len) : (size += 1) {
        if (size % 100 == 0) {
            std.log.debug("size = {}", .{size});
        }

        std.mem.writeIntBig(u32, &msg_len_bytes, size);
        _ = try tls_client.send(&msg_len_bytes);

        var recv_size = try tls_client.recv(recv_bytes[0..4]);
        const msg_len = std.mem.readIntSliceBig(u32, recv_bytes[0..4]);
        recv_size = try tls_client.recv(recv_bytes[0..size]);
        assert(msg_len == recv_size);
        var idx: usize = 0;
        while (idx < msg_len) : (idx += 1) {
            assert(idx & 0xFF == recv_bytes[idx]);
        }
    }

    try tls_client.close();

    return;
}
