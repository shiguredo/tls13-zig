const std = @import("std");
const io = std.io;
const pkcs8 = @import("pkcs8.zig");
const private_key = @import("private_key.zig");
const PrivateKey = private_key.PrivateKey;

pub fn readContentsFromFile(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Get the path
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const path_abs = try std.fs.realpath(path, &path_buffer);

    // Open the file
    const file = try std.fs.openFileAbsolute(path_abs, .{});
    defer file.close();

    const fb = try file.readToEndAlloc(allocator, 10000);
    errdefer allocator.free(fb);

    return fb;
}

pub fn readPrivateKeyFromFile(key_path: []const u8, allocator: std.mem.Allocator) !PrivateKey {
    const key_content = try readContentsFromFile(key_path, allocator);
    defer allocator.free(key_content);

    return try decodePrivateKey(key_content, allocator);
}

/// RFC7468
fn isPEMFormatted(content: []const u8) bool {
    const BEGIN = "-----BEGIN ";
    if (content.len < BEGIN.len) {
        return false;
    }
    return std.mem.eql(u8, content[0..BEGIN.len], BEGIN);
}

pub const Error = error{
    UnsupportedPrivateKeyFormat,
};

pub fn decodePrivateKey(k: []const u8, allocator: std.mem.Allocator) !PrivateKey {
    if (isPEMFormatted(k)) {
        const pem_key = try pkcs8.OneAsymmetricKey.decodeFromPEM(k, allocator);
        defer pem_key.deinit();

        return try pem_key.decodePrivateKey();
    } else {
        var stream = io.fixedBufferStream(k);
        if (private_key.RSAPrivateKey.decode(stream.reader(), allocator)) |pk_rsa| {
            return .{ .rsa = pk_rsa };
        } else |_| {
            stream.reset();
            if (private_key.ECPrivateKey.decode(stream.reader(), allocator)) |pk_ec| {
                return .{ .ec = pk_ec };
            } else |_| {
                return Error.UnsupportedPrivateKeyFormat;
            }
        }
    }
}
