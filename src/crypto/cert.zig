const std = @import("std");
const io = std.io;
const base64 = std.base64;
const pkcs8 = @import("pkcs8.zig");
const x509 = @import("x509.zig");
const private_key = @import("private_key.zig");
const PrivateKey = private_key.PrivateKey;

fn readContentsFromFile(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
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

pub fn readCertificateFromFileToDer(cert_path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const cert_content = try readContentsFromFile(cert_path, allocator);
    errdefer allocator.free(cert_content);

    if (isPEMFormatted(cert_content)) {
        const der_content = try convertPEMToDER(cert_content, "CERTIFICATE", allocator);
        allocator.free(cert_content);
        return der_content;
    } else {
        return cert_content;
    }
}

pub fn readPrivateKeyFromFile(key_path: []const u8, allocator: std.mem.Allocator) !PrivateKey {
    const key_content = try readContentsFromFile(key_path, allocator);
    defer allocator.free(key_content);

    return try decodePrivateKey(key_content, allocator);
}

/// RFC7468
fn isPEMFormatted(content: []const u8) bool {
    const BEGIN = "-----BEGIN ";
    var begin_idx: usize = 0;
    while(begin_idx < content.len - BEGIN.len) : (begin_idx += 1) {
        if (std.mem.eql(u8, content[begin_idx..begin_idx + BEGIN.len], BEGIN)) {
            return true;
        }
    }

    return false;
}

pub const Error = error{
    InvalidFormat,
    UnsupportedPrivateKeyFormat,
};

pub fn decodePrivateKey(k: []const u8, allocator: std.mem.Allocator) !PrivateKey {
    if (isPEMFormatted(k)) {
        if (pkcs8.OneAsymmetricKey.decodeFromPEM(k, allocator)) |pem_key| {
            defer pem_key.deinit();
            return try pem_key.decodePrivateKey();
        } else |_| {
            if (private_key.RSAPrivateKey.decodeFromPEM(k, allocator)) |pk_rsa| {
                return .{ .rsa = pk_rsa };
            } else |_| {
                return Error.UnsupportedPrivateKeyFormat;
            }
        }
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

pub fn convertPEMToDER(pem: []const u8, comptime label: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const BEGIN_LABEL = "-----BEGIN " ++ label ++ "-----\n";
    const END_LABEL = "-----END " ++ label ++ "-----";

    // Searching for BEGIN_LABEL
    var begin_idx: usize = 0;
    var begin_ok = false;
    while (begin_idx < pem.len - BEGIN_LABEL.len and !begin_ok) : (begin_idx += 1) {
        begin_ok = std.mem.eql(u8, BEGIN_LABEL, pem[begin_idx .. begin_idx + BEGIN_LABEL.len]);
        if (begin_ok) {
            break;
        }
    }
    if (!begin_ok) {
        return Error.InvalidFormat;
    }

    // Searching for END_LABEL
    var end_idx = begin_idx + BEGIN_LABEL.len;
    var end_ok = false;
    while (end_idx < pem.len - END_LABEL.len and !end_ok) : (end_idx += 1) {
        end_ok = std.mem.eql(u8, END_LABEL, pem[end_idx + 1 .. end_idx + 1 + END_LABEL.len]);
    }
    if (!end_ok) {
        return Error.InvalidFormat;
    }

    var base64_decoder = base64.Base64Decoder.init(base64.standard_alphabet_chars, null);
    var decode_content = try allocator.alloc(u8, end_idx - BEGIN_LABEL.len - begin_idx);
    defer allocator.free(decode_content);

    const content = pem[begin_idx + BEGIN_LABEL.len .. end_idx];
    var stream_decode = io.fixedBufferStream(decode_content);
    var idx: usize = 0;
    var content_length: usize = 0;
    while (idx < content.len) : (idx += 1) {
        if (content[idx] == '\n' or content[idx] == '=') {
            continue;
        }
        _ = try stream_decode.write(&[_]u8{content[idx]});
        content_length += 1;
    }

    var decoded_content = try allocator.alloc(u8, try base64_decoder.calcSizeForSlice(stream_decode.getWritten()));
    errdefer allocator.free(decoded_content);

    try base64_decoder.decode(decoded_content, stream_decode.getWritten());

    return decoded_content;
}
