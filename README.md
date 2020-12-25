# AES Key Wrap for Rust

AES Key Wrap is a construction to encrypt secret keys using a master key.

This is an AES-KWP (NIST SP800-38F) implementation for Rust.

It is essentially a 5 round Feistel network using AES as the core function. One half of each AES block is used to encrypt the key, and the second half of the last permutation is used to compute a 64-bit MAC.

It doesn't require nonces, but still allows key reuse.

This is a NIST-blessed construction. Other than that, AES Key Wrap is inefficient and is generally not very useful.
