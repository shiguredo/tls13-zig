const std = @import("std");
const x509 = @import("x509.zig");
const cert = @import("cert.zig");
const ArrayList = std.ArrayList;

const rootCAFiles = [_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt",
};

const rootCAPaths = [_][]const u8{
    "/etc/pki/tls/certs",
};

pub const RootCA = struct {
    rootCACerts: ArrayList(x509.Certificate),
    allocator: std.mem.Allocator,

    const Self = @This();

    const Error = error{
        NotFound,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .rootCACerts = ArrayList(x509.Certificate).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        for (self.rootCACerts.items) |c| {
            c.deinit();
        }
        self.rootCACerts.deinit();
    }

    pub fn loadCAFiles(self: *Self) !void {
        switch (@import("builtin").os.tag) {
            .linux => try self.loadCAFilesLinux(),
            .macos => try self.loadCAFilesMacOS(),
            else => unreachable,
        }
    }

    fn loadCAFilesLinux(self: *Self) !void {
        for (rootCAFiles) |ca| {
            std.log.debug("Loading RootCA certificate {s}", .{ca});
            const res = cert.readCertificatesFromFile(ca, self.allocator) catch |err| {
                switch (err) {
                    std.fs.File.OpenError.FileNotFound => continue,
                    else => return err,
                }
            };
            defer res.deinit();
            for (res.items) |c| {
                c.verify(null) catch |err| {
                    std.log.warn("Failed to verify certificate err={}", .{err});
                    c.deinit();
                    continue;
                };

                try self.rootCACerts.append(c);
            }
            std.log.debug("Loaded RootCA certificate {s}", .{ca});
        }

        for (rootCAPaths) |caPath| {
            var caDir = std.fs.openIterableDirAbsolute(caPath, .{}) catch |err| {
                switch (err) {
                    std.fs.File.OpenError.FileNotFound => continue,
                    else => return err,
                }
            };
            defer caDir.close();
            var walker = try caDir.walk(self.allocator);
            defer walker.deinit();
            var walking = try walker.next();
            while (walking != null) : (walking = try walker.next()) {
                if (walking.?.kind == .Directory) {
                    continue;
                }

                const path = try std.fs.path.join(self.allocator, &[_][]const u8{ caPath, walking.?.path });
                defer self.allocator.free(path);
                std.log.debug("Loading RootCA certificate {s}", .{path});

                const res = cert.readCertificatesFromFile(path, self.allocator) catch |err| {
                    std.log.warn("Failed to load RootCA certificate {s} err={}", .{ path, err });
                    continue;
                };
                if (res.items.len == 0) {
                    std.log.warn("No certificates found in {s}", .{path});
                    continue;
                }
                std.log.debug("Loaded RootCA certificate {s}", .{path});
                defer res.deinit();
                for (res.items) |c| {
                    c.verify(null) catch |err| {
                        std.log.warn("Failed to verify certificate err={}", .{err});
                        c.deinit();
                        continue;
                    };

                    try self.rootCACerts.append(c);
                }
            }
        }
    }

    fn loadCAFilesMacOS(self: *Self) !void {
        std.log.debug("Loading RootCA certificate", .{});

        const result = try std.ChildProcess.exec(.{
            .allocator = self.allocator,
            .argv = &[_][]const u8{ "/usr/bin/security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain" },
            .max_output_bytes = 1000 * 1024,
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        const res = try cert.readCertificatesFromPems(result.stdout, self.allocator);
        defer res.deinit();
        for (res.items) |c| {
            c.verify(null) catch |err| {
                std.log.warn("Failed to verify certificate err={}", .{err});
                c.deinit();
                continue;
            };

            try self.rootCACerts.append(c);
        }

        std.log.debug("Loaded RootCA certificate", .{});
    }

    pub fn getCertificateBySubject(self: Self, name: x509.Name) Error!x509.Certificate {
        for (self.rootCACerts.items) |c| {
            if (c.tbs_certificate.subject.eql(name)) {
                return c;
            }
        }

        return Error.NotFound;
    }
};

test "loading root CA" {
    var cas = RootCA.init(std.testing.allocator);
    defer cas.deinit();

    try cas.loadCAFiles();
}
