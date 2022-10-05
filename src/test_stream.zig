const std = @import("std");
const log = std.log;
const allocator = std.heap.page_allocator;
const assert = std.debug.assert;

const client = @import("client.zig");

const Error = error{
    InvalidValue,
};

fn strlen(ptr: [*]const u8) usize {
    var count: usize = 0;
    while (ptr[count] != 0) : (count += 1) {}
    return count;
}

fn get_arg(idx: usize) !usize {
    const argv = std.os.argv[idx];
    const arg_n = argv[0..strlen(argv)];
    const n: usize = try std.fmt.parseInt(usize, arg_n, 10);

    return n;
}

pub fn main() !void {
    const start_n = try get_arg(1);
    const end_n = try get_arg(2);
    log.info("started. start={} end={}", .{ start_n, end_n });
    var tls_client = try client.TLSClientTCP.init(allocator);
    defer tls_client.deinit();
    tls_client.print_keys = true;
    try tls_client.connect("localhost", 8443);

    var msg_len_bytes: [8]u8 = undefined;
    var recv_bytes = try allocator.alloc(u8, end_n);
    defer allocator.free(recv_bytes);

    var size: u64 = @intCast(u64, start_n);
    var idx: usize = 0;

    while (size <= recv_bytes.len) : (size += 1) {
        if ((size - start_n) % 100 == 0) {
            std.log.info("size = {}", .{size});
        }

        idx = 0;
        while (idx < size) : (idx += 1) {
            recv_bytes[idx] = @intCast(u8, idx & 0xFF);
        }

        std.mem.writeIntBig(u64, &msg_len_bytes, size);
        _ = try tls_client.send(&msg_len_bytes);
        _ = try tls_client.send(recv_bytes[0..size]);

        var recv_size = try tls_client.recv(recv_bytes[0..8]);
        const msg_len = std.mem.readIntSliceBig(u64, recv_bytes[0..8]);
        recv_size = try tls_client.recv(recv_bytes[0..size]);
        if (msg_len != recv_size) {
            return Error.InvalidValue;
        }

        idx = 0;
        while (idx < msg_len) : (idx += 1) {
            if (idx & 0xFF != recv_bytes[idx]) {
                std.log.err("expected = {} actual = {}", .{ idx & 0xFF, recv_bytes[idx] });
                return Error.InvalidValue;
            }
        }
    }

    try tls_client.close();

    return;
}
