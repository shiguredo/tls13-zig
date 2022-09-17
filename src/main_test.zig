const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const allocator = std.heap.page_allocator;

const client = @import("client.zig");

pub fn main() !void {
    log.info("started.", .{});
    const endpoint = try net.Address.parseIp("127.0.0.1", 8443);
    var tls_client = try client.TLSClient.init(allocator);
    defer tls_client.deinit();
    tls_client.print_keys = true;

    var tcpStream = try net.tcpConnectToAddress(endpoint);

    try tls_client.connect(tcpStream.reader(), tcpStream.writer());

    const http_req = "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: tls13-zig\r\nAccept: */*\r\n\r\n";
    _ = try tls_client.send(http_req, tcpStream.writer());

    var recv_bytes: [4096]u8 = undefined;
    const recv_size = try tls_client.recv(&recv_bytes, tcpStream.reader());
    log.info("RECV=\n {s}", .{recv_bytes[0..recv_size]});

    try tls_client.close(tcpStream.reader(), tcpStream.writer());
    log.info("finished.", .{});

    return;
}
