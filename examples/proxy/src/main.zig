const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const os = std.os;
const allocator = std.heap.page_allocator;

const server = @import("tls13-server");

pub fn main() !void {
    // ignore SIGCHLD
    var act = os.Sigaction{
        .handler = .{ .handler = os.SIG.IGN },
        .mask = os.empty_sigset,
        .flags = (os.SA.SIGINFO | os.SA.RESTART | os.SA.RESETHAND),
    };
    try os.sigaction(os.SIG.CHLD, &act, null);

    const key_file = try getenvWithError("PROXY_TLS_KEYFILE");
    const cert_file = try getenvWithError("PROXY_TLS_CERTFILE");
    const ca_file = try getenvWithError("PROXY_TLS_CAFILE");
    const hostname = try getenvWithError("PROXY_TLS_HOSTNAME");
    const upstream_host = try getenvWithError("PROXY_UPSTREAM_HOST");
    const upstream_port_str = try getenvWithError("PROXY_UPSTREAM_PORT");
    const upstream_port = try std.fmt.parseInt(u16, upstream_port_str, 10);
    const bind_port_str = try getenvWithError("PROXY_BIND_PORT");
    const bind_port = try std.fmt.parseInt(u16, bind_port_str, 10);

    var tls_server = try server.TLSServerTCP.init(key_file, cert_file, ca_file, hostname, allocator);
    defer tls_server.deinit();
    tls_server.print_keys = true;
    try tls_server.listen(bind_port);
    log.info("started.", .{});
    while (true) {
        var con = try tls_server.accept();
        defer con.deinit();
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

        var conStream = try net.tcpConnectToHost(allocator, upstream_host, upstream_port);
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


fn getenvWithError(key: []const u8) ![]const u8{
    const res = std.os.getenv(key);
    if (res) |r| {
        return r;
    } else {
        return error.InvalidArguemnt;
    }

}