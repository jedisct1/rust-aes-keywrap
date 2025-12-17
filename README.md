# AES Key Wrap for Rust

AES Key Wrap is a construction to encrypt secret keys using a master key.

This library implements both AES-KW (RFC 3394) and AES-KWP (RFC 5649 / NIST SP800-38F).

It is essentially a 6 round Feistel network using AES as the core function. One half of each AES block is used to encrypt the key, and the second half of the last permutation is used to compute a 64-bit MAC.

It doesn't require nonces, but still allows key reuse.

This is a NIST-blessed construction. Other than that, AES Key Wrap is inefficient and is generally not very useful.

## Usage

### AES-KWP (arbitrary length input)

```rust
use aes_keywrap::Aes256KeyWrap;

let key = [0u8; 32];
let kw = Aes256KeyWrap::new(&key);

// Wrap a secret (any length)
let secret = b"my secret key";
let wrapped = kw.encapsulate(secret).unwrap();

// Unwrap (need to specify expected length for padding validation)
let unwrapped = kw.decapsulate(&wrapped, secret.len()).unwrap();
```

### AES-KW (8-byte aligned input)

```rust
use aes_keywrap::Aes256KeyWrapAligned;

let key = [0u8; 32];
let kw = Aes256KeyWrapAligned::new(&key);

// Wrap a secret (must be >= 16 bytes and multiple of 8)
let secret = b"16 byte secret!!";
let wrapped = kw.encapsulate(secret).unwrap();

// Unwrap
let unwrapped = kw.decapsulate(&wrapped).unwrap();
```

Both variants are available with 128-bit keys (`Aes128KeyWrap`, `Aes128KeyWrapAligned`).
