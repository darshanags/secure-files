const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

pub fn getKey(allocator: std.mem.Allocator, password: []const u8, exsalt: ?[16]u8) !struct { salt: [16]u8, key: [32]u8 } {
    // 16 byte / 128 bit salt
    var salt: [16]u8 = undefined;

    // Check if salt is provided. Use provided else generate random salt
    if (exsalt) |exsaltval| {
        if (exsaltval.len != 16) {
            return error.InvalidSaltLength;
        }
        std.mem.copyForwards(u8, &salt, &exsaltval);
    } else {
        std.crypto.random.bytes(&salt);
    }

    // Parameters for Argon2id

    // Argon2 KDF parameters
    // Steve Thomas's write up - https://tobtu.com/minimum-password-settings/
    // OWASP minimum recommendation - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    // Modern recommendation - https://guptadeepak.com/bcrypt-scrypt-and-argon2-choosing-the-right-password-hashing-algorithm/
    const opslimit = 4; // Number of iterations
    const memlimit = 1024 * 128; // Memory limit (128 MB) in bytes
    const parallelism = 4; // Degree of parallelism
    const params = argon2.Params{ .t = opslimit, .m = memlimit, .p = parallelism };
    const mode = argon2.Mode.argon2id;

    // Buffer to store the derived key
    var key: [32]u8 = undefined;

    // Derive the key using Argon2id
    try std.crypto.pwhash.argon2.kdf(
        allocator,
        key[0..], // Output buffer for the derived key
        password, // Password
        &salt, // Random salt
        params, // Argon2 parameters
        mode, // Use Argon2id mode
    );

    // Return salt and key
    return .{ .salt = salt, .key = key };
}
