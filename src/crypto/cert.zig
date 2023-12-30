const std = @import("std");
const io = std.io;
const base64 = std.base64;
const ArrayList = std.ArrayList;
const log = @import("log.zig");
const pkcs8 = @import("pkcs8.zig");
const x509 = @import("x509.zig");
const key = @import("key.zig");
const PrivateKey = key.PrivateKey;
const errs = @import("errors.zig");

fn readContentsFromFile(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    // Get the path
    var path_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const path_abs = try std.fs.realpath(path, &path_buffer);

    // Open the file
    const file = try std.fs.openFileAbsolute(path_abs, .{});
    defer file.close();

    const fb = try file.readToEndAlloc(allocator, 1000000);
    errdefer allocator.free(fb);

    return fb;
}

pub fn readCertificateFromFileToDer(cert_path: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const cert_content = try readContentsFromFile(cert_path, allocator);
    errdefer allocator.free(cert_content);

    if (isPEMFormatted(cert_content)) {
        const certs = try convertPEMsToDERs(cert_content, "CERTIFICATE", allocator);
        defer {
            for (certs.items, 0..) |c, idx| {
                if (idx != 0) {
                    allocator.free(c);
                }
            }
            certs.deinit();
        }
        allocator.free(cert_content);
        if (certs.items.len == 0) {
            return errs.DecodingError.InvalidFormat;
        }
        return certs.items[0];
    } else {
        return cert_content;
    }
}

pub fn readCertificatesFromFile(cert_path: []const u8, allocator: std.mem.Allocator) !ArrayList(x509.Certificate) {
    const cert_content = try readContentsFromFile(cert_path, allocator);
    defer allocator.free(cert_content);

    return try readCertificatesFromPems(cert_content, allocator);
}

pub fn readCertificatesFromPems(pems: []const u8, allocator: std.mem.Allocator) !ArrayList(x509.Certificate) {
    const ders = try convertPEMsToDERs(pems, "CERTIFICATE", allocator);
    defer {
        for (ders.items) |d| {
            allocator.free(d);
        }
        ders.deinit();
    }

    var res = ArrayList(x509.Certificate).init(allocator);
    errdefer {
        for (res.items) |c| {
            c.deinit();
        }
        res.deinit();
    }
    for (ders.items) |d| {
        var stream = io.fixedBufferStream(d);
        const cert = try x509.Certificate.decode(stream.reader(), allocator);
        try res.append(cert);
    }

    return res;
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
    while (begin_idx < content.len - BEGIN.len) : (begin_idx += 1) {
        if (std.mem.eql(u8, content[begin_idx .. begin_idx + BEGIN.len], BEGIN)) {
            return true;
        }
    }

    return false;
}

fn splitPEM(src: []const u8, comptime label: []const u8, allocator: std.mem.Allocator) !ArrayList([]const u8) {
    const BEGIN_LABEL = "-----BEGIN " ++ label ++ "-----\n";
    const END_LABEL = "-----END " ++ label ++ "-----";
    var res = ArrayList([]const u8).init(allocator);
    errdefer res.deinit();
    var begin_idx: usize = 0;
    var end_idx: usize = 0;
    while (begin_idx < src.len) {
        if (src.len < BEGIN_LABEL.len) {
            return res;
        }
        var begin_ok = false;
        while (begin_idx < src.len - BEGIN_LABEL.len and !begin_ok) : (begin_idx += 1) {
            begin_ok = std.mem.eql(u8, BEGIN_LABEL, src[begin_idx .. begin_idx + BEGIN_LABEL.len]);
            if (begin_ok) {
                break;
            }
        }
        if (!begin_ok) {
            return res;
        }

        end_idx = begin_idx + BEGIN_LABEL.len;
        var end_ok = false;
        while (end_idx <= src.len - END_LABEL.len and !end_ok) : (end_idx += 1) {
            end_ok = std.mem.eql(u8, END_LABEL, src[end_idx .. end_idx + END_LABEL.len]);
            if (end_ok) {
                break;
            }
        }
        if (!end_ok) {
            return errs.DecodingError.InvalidFormat;
        }
        try res.append(src[begin_idx + BEGIN_LABEL.len .. end_idx]);
        begin_idx = end_idx + END_LABEL.len;
    }

    return res;
}

fn convertPEMToDER(pem: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var base64_decoder = base64.Base64Decoder.init(base64.standard_alphabet_chars, null);
    const decode_content = try allocator.alloc(u8, pem.len);
    defer allocator.free(decode_content);

    var stream_decode = io.fixedBufferStream(decode_content);
    var idx: usize = 0;
    var content_length: usize = 0;
    while (idx < pem.len) : (idx += 1) {
        if (pem[idx] == '\n' or pem[idx] == '=') {
            continue;
        }
        _ = try stream_decode.write(&[_]u8{pem[idx]});
        content_length += 1;
    }

    const decoded_content = try allocator.alloc(u8, try base64_decoder.calcSizeForSlice(stream_decode.getWritten()));
    errdefer allocator.free(decoded_content);

    try base64_decoder.decode(decoded_content, stream_decode.getWritten());

    return decoded_content;
}

pub fn decodePrivateKey(k: []const u8, allocator: std.mem.Allocator) !PrivateKey {
    if (isPEMFormatted(k)) {
        if (pkcs8.OneAsymmetricKey.decodeFromPEM(k, allocator)) |pem_key| {
            defer pem_key.deinit();
            return try pem_key.decodePrivateKey();
        } else |_| {
            if (key.RSAPrivateKey.decodeFromPEM(k, allocator)) |pk_rsa| {
                return .{ .rsa = pk_rsa };
            } else |_| {
                return errs.DecodingError.UnsupportedFormat;
            }
        }
    } else {
        var stream = io.fixedBufferStream(k);
        if (key.RSAPrivateKey.decode(stream.reader(), allocator)) |pk_rsa| {
            return .{ .rsa = pk_rsa };
        } else |_| {
            stream.reset();
            if (key.ECPrivateKey.decode(stream.reader(), allocator)) |pk_ec| {
                return .{ .ec = pk_ec };
            } else |_| {
                return errs.DecodingError.UnsupportedFormat;
            }
        }
    }
}

pub fn convertPEMsToDERs(pem: []const u8, comptime label: []const u8, allocator: std.mem.Allocator) !ArrayList([]const u8) {
    const pems = try splitPEM(pem, label, allocator);
    defer pems.deinit();

    var res = ArrayList([]const u8).init(allocator);
    errdefer res.deinit();

    for (pems.items) |p| {
        const der = try convertPEMToDER(p, allocator);
        try res.append(der);
    }

    return res;
}

test "split PEM" {
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIEYzCCA0ugAwIBAgIBATANBgkqhkiG9w0BAQsFADCB0jELMAkGA1UEBhMCVFIx
        \\GDAWBgNVBAcTD0dlYnplIC0gS29jYWVsaTFCMEAGA1UEChM5VHVya2l5ZSBCaWxp
        \\bXNlbCB2ZSBUZWtub2xvamlrIEFyYXN0aXJtYSBLdXJ1bXUgLSBUVUJJVEFLMS0w
        \\KwYDVQQLEyRLYW11IFNlcnRpZmlrYXN5b24gTWVya2V6aSAtIEthbXUgU00xNjA0
        \\BgNVBAMTLVRVQklUQUsgS2FtdSBTTSBTU0wgS29rIFNlcnRpZmlrYXNpIC0gU3Vy
        \\dW0gMTAeFw0xMzExMjUwODI1NTVaFw00MzEwMjUwODI1NTVaMIHSMQswCQYDVQQG
        \\EwJUUjEYMBYGA1UEBxMPR2ViemUgLSBLb2NhZWxpMUIwQAYDVQQKEzlUdXJraXll
        \\IEJpbGltc2VsIHZlIFRla25vbG9qaWsgQXJhc3Rpcm1hIEt1cnVtdSAtIFRVQklU
        \\QUsxLTArBgNVBAsTJEthbXUgU2VydGlmaWthc3lvbiBNZXJrZXppIC0gS2FtdSBT
        \\TTE2MDQGA1UEAxMtVFVCSVRBSyBLYW11IFNNIFNTTCBLb2sgU2VydGlmaWthc2kg
        \\LSBTdXJ1bSAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr3UwM6q7
        \\a9OZLBI3hNmNe5eA027n/5tQlT6QlVZC1xl8JoSNkvoBHToP4mQ4t4y86Ij5iySr
        \\LqP1N+RAjhgleYN1Hzv/bKjFxlb4tO2KRKOrbEz8HdDc72i9z+SqzvBV96I01INr
        \\N3wcwv61A+xXzry0tcXtAA9TNypN9E8Mg/uGz8v+jE69h/mniyFXnHrfA2eJLJ2X
        \\YacQuFWQfw4tJzh03+f92k4S400VIgLI4OD8D62K18lUUMw7D8oWgITQUVbDjlZ/
        \\iSIzL+aFCr2lqBs23tPcLG07xxO9WSMs5uWk99gL7eqQQESolbuT1dCANLZGeA4f
        \\AJNG4e7p+exPFwIDAQABo0IwQDAdBgNVHQ4EFgQUZT/HiobGPN08VFw1+DrtUgxH
        \\V8gwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
        \\BQADggEBACo/4fEyjq7hmFxLXs9rHmoJ0iKpEsdeV31zVmSAhHqT5Am5EM2fKifh
        \\AHe+SMg1qIGf5LgsyX8OsNJLN13qudULXjS99HMpw+0mFZx+CFOKWI3QSyjfwbPf
        \\IPP54+M638yclNhOT8NrF7f3cuitZjO1JVOr4PhMqZ398g26rrnZqsZr+ZO7rqu4
        \\lzwDGrpDxpa5RXI4s6ehlj2Re37AIVNMh+3yC1SVUZPVIqUNivGTDj5UDrDYyU7c
        \\8jEyVupk+eq1nRZmQnLzf9OxMUP8pI4X8W0jq5Rm+K37DwhuJi1/FwcJsoz7UMCf
        \\lo3Ptv0AnVoUmr8CRPXBwp8iXqIPoeM=
        \\-----END CERTIFICATE-----
        \\-----BEGIN CERTIFICATE-----
        \\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
        \\KwbQBM0=
        \\-----END CERTIFICATE-----
    ;
    const certs = try convertPEMsToDERs(cert_pem, "CERTIFICATE", std.testing.allocator);
    defer certs.deinit();
    for (certs.items) |cert| {
        //log.warn("{s}", .{cert});
        std.testing.allocator.free(cert);
    }
}

test "split PEM 2" {
    const cert_pem =
        \\-----BEGIN CERTIFICATE-----
        \\MIIB1zCCAX2gAwIBAgIUd15IMhkhVtUY+I6IKaX6/AfKxTowCgYIKoZIzj0EAwIw
        \\QTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBUt5b3RvMQ4wDAYDVQQHDAVLeW90bzES
        \\MBAGA1UEAwwJbG9jYWxob3N0MB4XDTIyMTAyNDA3MjgyMVoXDTIzMTAyNDA3Mjgy
        \\MVowQTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBUt5b3RvMQ4wDAYDVQQHDAVLeW90
        \\bzESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        \\idRm6Es+u4v1Ng/nArk7F7u+lkzG1tpKbdcsHGJ9I9iRXWkN18r26eajCF/UaHhy
        \\fuhGonTQT76OYEBDFOVgL6NTMFEwHQYDVR0OBBYEFAgmoQ1rUK+z9B+pzkJbdAXT
        \\Is3dMB8GA1UdIwQYMBaAFAgmoQ1rUK+z9B+pzkJbdAXTIs3dMA8GA1UdEwEB/wQF
        \\MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgcR+087vas0CVyG0jGHAXSWTebGIeCDbg
        \\dwZ12GwlZv0CIQC8/6Qe512S97xnN+Mm2UkBoy1bu6dn5MUkjMhe2QDdxw==
        \\-----END CERTIFICATE-----
    ;
    const certs = try convertPEMsToDERs(cert_pem, "CERTIFICATE", std.testing.allocator);
    defer certs.deinit();
    for (certs.items) |cert| {
        //log.warn("{s}", .{cert});
        std.testing.allocator.free(cert);
    }
}

//test "macos certs" {
//    const certs = try readCertificatesFromFile("./rootca-pems", std.testing.allocator);
//    defer {
//        for (certs.items) |c| {
//            c.deinit();
//        }
//        certs.deinit();
//    }
//}
