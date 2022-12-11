const std = @import("std");
const net = std.net;
const io = std.io;
const os = std.os;
const allocator = std.heap.page_allocator;

const log = @import("log");
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
            log.err("fork failed", .{});
            return;
        };
        if (fork_pid != 0) {
            continue;
        }
        log.info("forked", .{});
        defer log.info("exit", .{});
        log.info("connection accepted(remote_addr={})", .{con.tcp_conn.?.address});

        defer {
            con.close();
            log.info("TLS session closed(SessionID={})", .{std.fmt.fmtSliceHexLower(con.session_id.session_id.slice())});
        }
        try con.handshake();
        log.info("TLS session accepted(SessionID={})", .{std.fmt.fmtSliceHexLower(con.session_id.session_id.slice())});

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

        var req_on_proc = false;
        var req_done = false;
        var sendBuf = std.io.bufferedWriter(conStream.writer());
        while (true) {
            _ = try std.os.poll(&fds, -1);
            log.debug("poll done", .{});
            var recv_bytes: [16 * 1024]u8 = undefined;
            var tmp_buf: [16 * 1024]u8 = undefined;

            if ((fds[0].revents & std.os.POLL.IN) > 0) {
                while (true) {
                    const line = con.tlsReader().readUntilDelimiter(&tmp_buf, '\n') catch |err| {
                        log.err("failed to read({})", .{err});
                        return err;
                    };

                    if (line.len == 0) {
                        req_on_proc = false;
                        req_done = false;
                        log.err("invalid request {s}", .{sendBuf.buf[0..sendBuf.end]});
                        return;
                    }

                    if (line.len >= 3 and std.mem.eql(u8, line[0..3], "GET")) {
                        if (req_on_proc) {
                            log.err("invalid request", .{});
                            return;
                        }
                        req_on_proc = true;
                        log.debug("request is now on processing", .{});
                    } else if (line.len >= 1 and line[0] == '\r') {
                        try std.fmt.format(sendBuf.writer(), "X-Forwarded-For: {}\r\n", .{con.tcp_conn.?.address});
                        req_on_proc = false;
                        req_done = true;
                        log.debug("request processing is completed", .{});
                    }

                    _ = try sendBuf.write(line);
                    _ = try sendBuf.write("\n");

                    if (req_on_proc) {
                        continue;
                    }
                    break;
                }
                if (req_done) {
                    try sendBuf.flush();
                    req_done = false;
                }
            } else if ((fds[1].revents & std.os.POLL.IN) > 0) {
                const recv_size = try conStream.read(&recv_bytes);
                if (recv_size == 0) {
                    log.info("upstream connection closed", .{});
                    return;
                }
                _ = try con.send(recv_bytes[0..recv_size]);
            }
        }

        return;
    }

    return;
}

fn getenvWithError(key: []const u8) ![]const u8 {
    const res = std.os.getenv(key);
    if (res) |r| {
        return r;
    } else {
        return error.InvalidArguemnt;
    }
}
