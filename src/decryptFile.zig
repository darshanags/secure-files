const std = @import("std");
const kdf = @import("kdf.zig");

pub fn decryptFile(allocator: std.mem.Allocator, inputPath: []const u8, outputPath: []const u8, password: []const u8) !void {

    // Initialize chacha20poly1305 cipher
    const chacha20poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    // Open the encrypted file
    const encryptedFile = try std.fs.cwd().openFile(inputPath, .{});
    defer encryptedFile.close();

    // Read the nonce (12 bytes)
    var nonce: [12]u8 = undefined;
    _ = try encryptedFile.readAll(&nonce);

    // Read the salt (16 bytes)
    var salt: [16]u8 = undefined;
    _ = try encryptedFile.readAll(&salt);

    // Read the encrypted data encryption key (32 bytes)
    var encryptedDataEncKey: [32]u8 = undefined;
    _ = try encryptedFile.readAll(&encryptedDataEncKey);

    // Read the tag for the data encryption key (16 bytes)
    var rkTag: [16]u8 = undefined;
    _ = try encryptedFile.readAll(&rkTag);

    var derivedKey: [32]u8 = undefined;
    var decryptedDataEncKey: [32]u8 = undefined;

    // Pass the password and salt to the KDF
    const result = try kdf.getKey(allocator, password, salt);

    derivedKey = result.key;

    // Decrypt the data encryption key - this will fail if the provided password is incorrect
    chacha20poly1305.decrypt(
        &decryptedDataEncKey, // Plaintext buffer
        &encryptedDataEncKey, // Ciphertext
        rkTag, // Tag
        "", // Additional data (empty)
        nonce, // Nonce
        derivedKey, // Key
    ) catch |err| {
        std.log.warn("The password that you entered is incorrect. Key Decryption failed: {}\n", .{err});
        return error.DecryptionFailed;
    };

    const fileStat = try encryptedFile.stat();
    const fileSize = fileStat.size;
    const nonceSize = 12;
    const saltSize = 16;
    const tagSize = 16;
    const dataEncKeySize = 32;

    // Check if file is large enough to contain a nonce, the salt, the encrypted data encryption key, its tag, and at least one tag
    const minFileSize = nonceSize + saltSize + dataEncKeySize + tagSize + tagSize;

    if (fileSize < minFileSize) {
        return error.InvalidFileFormat; // File is too small
    }

    // Create the output file
    const outputFile = try std.fs.cwd().createFile(outputPath, .{});
    defer outputFile.close();

    // Define chunk size and create buffer
    const chunkSize = 64 * 1024; // 64 KB chunks
    const ciphertextChunk = try allocator.alloc(u8, chunkSize);
    defer allocator.free(ciphertextChunk);

    // Decrypted chunk buffer (same size as ciphertext chunk)
    const plaintextChunk = try allocator.alloc(u8, chunkSize);
    defer allocator.free(plaintextChunk);

    var tag: [16]u8 = undefined;

    var totalBytesRead: usize = 0;

    while (true) {

        // Determine the remining bytes in the file
        const remainingBytes = fileSize - nonceSize - saltSize - dataEncKeySize - tagSize - totalBytesRead - tagSize;

        // Determine the size of the next ciphertext chunk
        const bytesToRead = if (remainingBytes > chunkSize) chunkSize else remainingBytes;

        // Read a chunk of ciphertext
        const bytesRead = try encryptedFile.read(ciphertextChunk[0..bytesToRead]);
        if (bytesRead == 0) break; // End of file

        // Read the tag for this chunk
        const tagBytesRead = try encryptedFile.readAll(&tag);
        if (tagBytesRead != 16) {
            return error.InvalidFileFormat; // Tag must be exactly 16 bytes
        }

        // Decrypt the chunk
        chacha20poly1305.decrypt(
            plaintextChunk[0..bytesRead], // Plaintext buffer
            ciphertextChunk[0..bytesRead], // Ciphertext
            tag, // Tag
            "", // Additional data (empty)
            nonce, // Nonce
            decryptedDataEncKey, // Key
        ) catch |err| {
            // Handle decryption error
            std.log.err("Decryption failed: {}\n", .{err});
            return error.DecryptionFailed;
        };

        // Write the decrypted chunk to the output file
        _ = try outputFile.writeAll(plaintextChunk[0..bytesRead]);

        totalBytesRead += bytesRead;
    }

    std.log.info("File decrypted successfully! Total bytes processed: {}\n", .{totalBytesRead});
}
