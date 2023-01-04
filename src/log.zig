const std = @import("std");
const builtin = @import("builtin");

pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, format, args);
}

pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, format, args);
}

pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, format, args);
}

pub fn log(
    comptime message_level: std.log.Level,
    comptime format: []const u8,
    args: anytype,
) void {
    if (@enumToInt(message_level) > @enumToInt(std.log.default_level)) {
        return;
    }
    if (builtin.os.tag == .freestanding)
        @compileError(
            \\freestanding targets do not have I/O configured;
            \\please provide at least an empty `log` function declaration
        );

    var buf = [_]u8{0} ** 20;
    const date_str = getDateTimeNowStr(&buf) catch |e| blk: {
        std.log.warn("failed to output log: {}", .{e});
        break :blk "";
    };

    const stderr = std.io.getStdErr().writer();
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    if (builtin.os.tag == .linux) {
        const pid = std.os.linux.getpid();
        nosuspend stderr.print(levelAsText(message_level) ++ " [{s} {}]: " ++ format ++ "\n", .{ date_str, pid } ++ args) catch return;
    } else {
        nosuspend stderr.print(levelAsText(message_level) ++ " [{s}]: " ++ format ++ "\n", .{date_str} ++ args) catch return;
    }
}

fn levelAsText(comptime self: std.log.Level) []const u8 {
    return switch (self) {
        .err => "\x1b[91mERROR\x1b[0m",
        .warn => "\x1b[93mWARN\x1b[0m ",
        .info => "\x1b[94mINFO\x1b[0m ",
        .debug => "DEBUG",
    };
}

fn getDateTimeNowStr(buf: []u8) ![]u8 {
    var buf_writer = std.io.fixedBufferStream(buf);

    const n = std.time.timestamp();
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(u64, n) };
    const ds = es.getDaySeconds();
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    try std.fmt.format(buf_writer.writer(), "{}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });

    return buf_writer.getWritten();
}
