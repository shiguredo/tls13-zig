const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const allocator = std.heap.page_allocator;

const client = @import("client.zig");

pub fn main() !void {
    log.info("started.", .{});
    const endpoint = try net.Address.parseIp("127.0.0.1", 8443);
    const client_privkey = [_]u8{ 0x49, 0xaf, 0x42, 0xba, 0x7f, 0x79, 0x94, 0x85, 0x2d, 0x71, 0x3e, 0xf2, 0x78, 0x4b, 0xcb, 0xca, 0xa7, 0x91, 0x1d, 0xe2, 0x6a, 0xdc, 0x56, 0x42, 0xcb, 0x63, 0x45, 0x40, 0xe7, 0xea, 0x50, 0x05 };
    var tls_client = try client.TLSClient.init(allocator);
    defer tls_client.deinit();
    try tls_client.configureX25519Keys(client_privkey);

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

test {
    std.testing.refAllDecls(@This());
}
