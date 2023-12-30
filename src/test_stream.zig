const std = @import("std");
const assert = std.debug.assert;

const log = @import("log.zig");
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
    try do(start_n, end_n, std.heap.page_allocator);
}

fn do(start_n: usize, end_n: usize, allocator: std.mem.Allocator) !void {
    log.info("started. start={} end={}", .{ start_n, end_n });
    var tls_client = try client.TLSClientTCP.init(allocator);
    defer tls_client.deinit();
    tls_client.print_keys = true;
    tls_client.allow_self_signed = true;
    try tls_client.connect("localhost", 8443);

    var recv_bytes = try allocator.alloc(u8, end_n);
    defer allocator.free(recv_bytes);

    var size: u64 = @as(u64, @intCast(start_n));
    var idx: usize = 0;

    const reader = tls_client.tlsReader();
    const writer = tls_client.tlsWriter();

    while (size <= recv_bytes.len) : (size += 1) {
        if ((size - start_n) % 100 == 0) {
            log.warn("size = {}", .{size});
        }

        idx = 0;
        while (idx < size) : (idx += 1) {
            recv_bytes[idx] = @as(u8, @intCast(idx & 0xFF));
        }

        try writer.writeInt(u64, size, .big);
        try writer.writeAll(recv_bytes[0..size]);

        const msg_len = try reader.readInt(u64, .big);
        const recv_size = try reader.readAll(recv_bytes[0..size]);
        if (msg_len != recv_size) {
            return Error.InvalidValue;
        }

        idx = 0;
        while (idx < msg_len) : (idx += 1) {
            if (idx & 0xFF != recv_bytes[idx]) {
                log.err("expected = {} actual = {}", .{ idx & 0xFF, recv_bytes[idx] });
                return Error.InvalidValue;
            }
        }
    }

    try tls_client.close();

    return;
}

test "stream" {
    try do(1048000, 1048576, std.testing.allocator);
}
