const std = @import("std");

const stdout_file = std.io.getStdOut().writer();
var bw = std.io.bufferedWriter(stdout_file);
var stdout = bw.writer();

pub inline fn userMsg(fmt: []const u8, args: anytype) !void {
    try stdout.print(fmt, args);
    try bw.flush();
}
