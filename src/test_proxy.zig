const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const allocator = std.heap.page_allocator;

const server = @import("server.zig");

pub fn main() !void {
    log.info("started.", .{});
    // key and certificate need to be der-formatted.
    // Especially, RSAPrivateKey need to be PKCS#1.
    // To convert PEM key, use 'openssl rsa -outform der -in key.pem -out key.der -traditional'
    // Currently, only one CA certificate is supported.
    var tls_server = try server.TLSServerTCP.init("./test-certs/key.der", .rsa, "./test-certs/cert.der", "./test-certs/chain.der", "tls13.pibvt.net", allocator);
    defer tls_server.deinit();
    tls_server.print_keys = true;
    try tls_server.listen(8443);
    while (true) {
        var con = try tls_server.accept();
        const fork_pid = std.os.fork() catch {
            std.log.err("fork failed", .{});
            return;
        };
        if (fork_pid != 0) {
            continue;
        }
        std.log.debug("forked", .{});

        defer {
            con.close();
            std.log.info("connection closed", .{});
        }
        try con.handshake();

        var conStream = try net.tcpConnectToHost(allocator, "localhost", 8080);
        defer conStream.close();

        var fds: [2]std.os.pollfd = undefined;
        fds[0] = .{
            .fd = con.tcp_conn.?.client.socket.fd,
            .events = std.os.POLL.IN,
            .revents = undefined,
        };
        fds[1] = .{
            .fd = conStream.handle,
            .events = std.os.POLL.IN,
            .revents = undefined,
        };

        while (true) {
            _ = try std.os.poll(&fds, -1);
            var recv_bytes: [16 * 1024]u8 = undefined;

            if ((fds[0].revents & std.os.POLL.IN) > 0) {
                const recv_size = con.recv(&recv_bytes) catch |err| {
                    switch (err) {
                        error.EndOfStream => return,
                        else => return err,
                    }
                };
                _ = try conStream.write(recv_bytes[0..recv_size]);
            } else if ((fds[1].revents & std.os.POLL.IN) > 0) {
                const recv_size = try conStream.read(&recv_bytes);
                _ = try con.send(recv_bytes[0..recv_size]);
            }
        }

        return;
    }

    return;
}
