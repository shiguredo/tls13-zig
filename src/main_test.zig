const std = @import("std");
const log = std.log;
const allocator = std.heap.page_allocator;

const client = @import("client.zig");

pub fn main() !void {
    log.info("started.", .{});
    var tls_client = try client.TLSClientTCP.init(allocator);
    defer tls_client.deinit();
    tls_client.print_keys = true;
    try tls_client.connect("localhost", 8443);

    const http_req = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: tls13-zig\r\nAccept: */*\r\n\r\n";
    _ = try tls_client.send(http_req);

    var recv_bytes: [4096]u8 = undefined;
    const recv_size = try tls_client.recv(&recv_bytes);
    log.info("RECV=\n {s}", .{recv_bytes[0..recv_size]});

    try tls_client.close();
    log.info("finished.", .{});

    return;
}
