const std = @import("std");
const utils = @import("utils.zig");

pub fn encryptFile(allocator: std.mem.Allocator, inputPath: []const u8, outputPath: []const u8, derivedKey: [32]u8, salt: [16]u8) !void {

    // Initialize chacha20poly1305 cipher
    const chacha20poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    // Open the input file
    const inputFile = try std.fs.cwd().openFile(inputPath, .{});
    defer inputFile.close();

    // Create the output file
    const outputFile = try std.fs.cwd().createFile(outputPath, .{});
    defer outputFile.close();

    // Generate a random nonce and key
    var nonce: [12]u8 = undefined;
    var dataEncKey: [32]u8 = undefined;
    std.crypto.random.bytes(&nonce);
    std.crypto.random.bytes(&dataEncKey);

    var encDataEncKey: [32]u8 = undefined;
    var rkTag: [16]u8 = undefined;

    chacha20poly1305.encrypt(
        encDataEncKey[0..],
        &rkTag,
        &dataEncKey,
        "",
        nonce,
        derivedKey,
    );

    // Write the nonce, salt, encrypted random key, random key tag to the output file
    _ = try outputFile.writeAll(&nonce);
    _ = try outputFile.writeAll(&salt);
    _ = try outputFile.writeAll(&encDataEncKey);
    _ = try outputFile.writeAll(&rkTag);

    // Define chunk size and create buffer
    const chunkSize = 64 * 1024; // 64 KB chunks
    const plaintextChunk = try allocator.alloc(u8, chunkSize);
    defer allocator.free(plaintextChunk);

    // Encrypted chunk buffer (plaintext chunk + 16 bytes for the tag)
    const ciphertextChunk = try allocator.alloc(u8, plaintextChunk.len + 16);
    defer allocator.free(ciphertextChunk);

    var totalBytesRead: usize = 0;

    while (true) {
        // Read a chunk of data from the input file
        const bytesRead = try inputFile.read(plaintextChunk);
        if (bytesRead == 0) break; // End of file

        // Tag for each encrypted chunk
        var tag: [16]u8 = undefined;

        // Encrypt chunk
        chacha20poly1305.encrypt(
            ciphertextChunk[0..bytesRead], // Ciphertext (same size as plaintext)
            &tag, // Tag
            plaintextChunk[0..bytesRead], // Plaintext
            "", // Additional data (empty)
            nonce, // Nonce
            dataEncKey, // Key
        );

        // Write the encrypted chunk and tag to the output file
        _ = try outputFile.writeAll(ciphertextChunk[0..bytesRead]);
        _ = try outputFile.writeAll(&tag);

        totalBytesRead += bytesRead;
    }

    try utils.userMsg("File encrypted successfully! Total bytes processed: {}\n", .{totalBytesRead});
}
