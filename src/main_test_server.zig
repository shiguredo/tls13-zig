const std = @import("std");
const log = std.log;
const net = std.net;
const io = std.io;
const allocator = std.heap.page_allocator;

const server = @import("server.zig");

pub fn main() !void {
    log.info("started.", .{});
    var tls_server = try server.TLSServerTCP.init("./test/key.der", .ec, "./test/cert.der", null, "localhost", allocator);
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
        con.handshake() catch {
            std.log.err("failed to handshake", .{});
            continue;
        };

        var recv_bytes: [4096]u8 = undefined;
        const recv_size = try con.recv(&recv_bytes);
        log.info("RECV=\n{s}", .{recv_bytes[0..recv_size]});
        const get_req = "GET / ";
        if (std.mem.eql(u8, recv_bytes[0..get_req.len], get_req)) {
            std.log.info("HTTP GET received", .{});
            const http_res = "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n<HTML><BODY>tls13-zig</BODY></HTML>";
            _ = try con.send(http_res);
        }

        return;
    }

    return;
}
