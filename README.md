# Secure Files
A file encryption/decryption CLI program written using [Zig](https://ziglang.org/) **0.13.0**. This is an implementation of [RFC8439](https://datatracker.ietf.org/doc/html/rfc8439) which uses ChaCha20 as the cipher and Poly1305 for authentication, and [Argon2](https://datatracker.ietf.org/doc/html/rfc9106) for key derivation (KDF) from a given password.

**This is in no shape or form a well-polished program, so use at your own risk.**

## Usage:
**Encrypt a file:**

    secure-files enc <input_file> <password>
Encrypting a file will place the encrypted file in the same path as the input_file with an extension of .enc.

**Decrypt a file:**

    secure-files dec <input_file> <password>

