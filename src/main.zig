const std = @import("std");
const mem = std.mem;
const kdf = @import("kdf.zig");
const enc = @import("encryptFile.zig");
const dec = @import("decryptFile.zig");
const utils = @import("utils.zig");

pub fn main() !void {
    const cwd = std.fs.cwd();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    // Skip the first argument (the program name)
    _ = args.next();

    const directive = args.next() orelse {
        try utils.userMsg("Usage: sec_files <enc|dec> <input_file> <password>\n", .{});
        return error.MissingArguments;
    };

    const path = args.next() orelse {
        try utils.userMsg("Usage: sec_files <enc|dec> <input_file> <password>\n", .{});
        return error.MissingArguments;
    };

    const password = args.next() orelse {
        try utils.userMsg("Usage: sec_files <enc|dec> <input_file> <password>\n", .{});
        return error.MissingArguments;
    };

    if (!mem.eql(u8, directive, "enc") and !mem.eql(u8, directive, "dec")) {
        return error.InvalidDirectiveArg;
    }

    const file = cwd.openFile(path, .{}) catch |err| {
        // If the file does not exist, return false
        if (err == error.FileNotFound) {
            return err;
        }
        // Propagate other errors
        try utils.userMsg("Error checking file: {}\n", .{err});
        return error.FileAccessError;
    };
    // If the file exists, close it and return true
    file.close();

    const stat = try cwd.statFile(path);

    if (stat.kind != .file) {
        try utils.userMsg("The input path is not a file.\n", .{});
        return error.InputNotFile;
    }

    const dir = std.fs.path.dirname(path) orelse {
        try utils.userMsg("No dir in given path\n", .{});
        return error.NoDirInPath;
    };
    const file_name = std.fs.path.basename(path);
    var outputFile: []u8 = "";

    if (mem.eql(u8, directive, "enc")) {
        const outputFileName = try std.mem.join(allocator, ".", &.{ file_name, "enc" });
        defer allocator.free(outputFileName);

        outputFile = try std.fs.path.join(allocator, &.{ dir, outputFileName });
        defer allocator.free(outputFile);

        const result = try kdf.getKey(allocator, password, null);

        const salt = result.salt;
        const key = result.key;

        try enc.encryptFile(allocator, path, outputFile, key, salt);
    } else if (mem.eql(u8, directive, "dec")) {
        if (!std.mem.endsWith(u8, path, ".enc")) {
            return error.InvalidExtension;
        }

        outputFile = try std.mem.replaceOwned(u8, allocator, path, ".enc", "");
        defer allocator.free(outputFile);

        try dec.decryptFile(allocator, path, outputFile, password);
    }
}
