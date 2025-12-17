#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use byteorder::{BigEndian, ByteOrder};

const FEISTEL_ROUNDS: usize = 6;
const KW_IV: [u8; 8] = [0xa6u8; 8];

#[derive(Debug, Eq, PartialEq)]
pub enum KeywrapError {
    /// Input is too big.
    TooBig,
    /// Input is too small.
    TooSmall,
    /// Ciphertext has invalid padding.
    Unpadded,
    /// Input length is not a multiple of 8 bytes (required for AES-KW).
    NotAligned,
    /// The ciphertext is not valid for the expected length.
    InvalidExpectedLen,
    /// The ciphertext couldn't be authenticated.
    AuthenticationFailed,
}

impl Error for KeywrapError {}

impl fmt::Display for KeywrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            KeywrapError::TooBig => f.write_str("Input too big"),
            KeywrapError::TooSmall => f.write_str("Input too small"),
            KeywrapError::Unpadded => f.write_str("Padding error"),
            KeywrapError::NotAligned => f.write_str("Input length not a multiple of 8 bytes"),
            KeywrapError::InvalidExpectedLen => f.write_str("Invalid expected length"),
            KeywrapError::AuthenticationFailed => f.write_str("Authentication failed"),
        }
    }
}

#[derive(Debug)]
pub struct Aes256KeyWrap {
    aes: Aes256,
}

impl Aes256KeyWrap {
    pub const KEY_BYTES: usize = 32;
    pub const MAC_BYTES: usize = 8;

    pub fn new(key: &[u8; Self::KEY_BYTES]) -> Self {
        Aes256KeyWrap {
            aes: Aes256::new(key.into()),
        }
    }

    pub fn encapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if input.len() > u32::MAX as usize || input.len() as u64 >= u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], input.len() as u32);
        let mut block = Array([0u8; 16]);
        block[0..8].copy_from_slice(&aiv);

        if input.len() == 8 {
            block[8..16].copy_from_slice(input);
            self.aes.encrypt_block(&mut block);
            return Ok(block.to_vec());
        }

        let mut counter = 0u64;
        let mut counter_bin = [0u8; 8];
        let mut output = vec![0u8; ((input.len() + 7) & !7) + Self::MAC_BYTES];
        output[8..][..input.len()].copy_from_slice(input);
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = 8;
            while i <= (input.len() + 7) & !7 {
                block[8..16].copy_from_slice(&output[i..][0..8]);
                self.aes.encrypt_block(&mut block);
                counter += 1;
                BigEndian::write_u64(&mut counter_bin, counter);
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                output[i..i + 8].copy_from_slice(&block[8..16]);
                i += 8;
            }
        }
        output[0..8].copy_from_slice(&block[0..8]);
        Ok(output)
    }

    pub fn decapsulate(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::Unpadded);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len > u32::MAX as usize || output_len as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }
        if expected_len > output_len || (expected_len & !7) > output_len {
            return Err(KeywrapError::InvalidExpectedLen);
        }
        let mut output = vec![0u8; output_len];
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], expected_len as u32);

        let mut block = Array([0u8; 16]);

        if output.len() == 8 {
            block.copy_from_slice(input);
            self.aes.decrypt_block(&mut block);
            let c = block[0..8]
                .iter()
                .zip(aiv.iter())
                .fold(0, |acc, (a, b)| acc | (a ^ b));
            if c != 0 {
                return Err(KeywrapError::AuthenticationFailed);
            }
            output[0..8].copy_from_slice(&block[8..16]);
            return Ok(output);
        }

        output.copy_from_slice(&input[8..]);
        block[0..8].copy_from_slice(&input[0..8]);
        let mut counter = (FEISTEL_ROUNDS * output.len() / 8) as u64;
        let mut counter_bin = [0u8; 8];
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = output.len();
            while i >= 8 {
                i -= 8;
                block[8..16].copy_from_slice(&output[i..][0..8]);
                BigEndian::write_u64(&mut counter_bin, counter);
                counter -= 1;
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                self.aes.decrypt_block(&mut block);
                output[i..][0..8].copy_from_slice(&block[8..16]);
            }
        }
        let c = block[0..8]
            .iter()
            .zip(aiv.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b));
        if c != 0 {
            return Err(KeywrapError::AuthenticationFailed);
        }
        Ok(output)
    }
}

// --

#[derive(Debug)]
pub struct Aes128KeyWrap {
    aes: Aes128,
}

impl Aes128KeyWrap {
    pub const KEY_BYTES: usize = 16;
    pub const MAC_BYTES: usize = 8;

    pub fn new(key: &[u8; Self::KEY_BYTES]) -> Self {
        Aes128KeyWrap {
            aes: Aes128::new(key.into()),
        }
    }

    pub fn encapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if input.len() > u32::MAX as usize || input.len() as u64 >= u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], input.len() as u32);
        let mut block = Array([0u8; 16]);
        block[0..8].copy_from_slice(&aiv);

        if input.len() == 8 {
            block[8..16].copy_from_slice(input);
            self.aes.encrypt_block(&mut block);
            return Ok(block.to_vec());
        }

        let mut counter = 0u64;
        let mut counter_bin = [0u8; 8];
        let mut output = vec![0u8; ((input.len() + 7) & !7) + Self::MAC_BYTES];
        output[8..][..input.len()].copy_from_slice(input);
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = 8;
            while i <= (input.len() + 7) & !7 {
                block[8..16].copy_from_slice(&output[i..][0..8]);
                self.aes.encrypt_block(&mut block);
                counter += 1;
                BigEndian::write_u64(&mut counter_bin, counter);
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                output[i..i + 8].copy_from_slice(&block[8..16]);
                i += 8;
            }
        }
        output[0..8].copy_from_slice(&block[0..8]);
        Ok(output)
    }

    pub fn decapsulate(&self, input: &[u8], expected_len: usize) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::Unpadded);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len > u32::MAX as usize || output_len as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }
        if expected_len > output_len || (expected_len & !7) > output_len {
            return Err(KeywrapError::InvalidExpectedLen);
        }
        let mut output = vec![0u8; output_len];
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], expected_len as u32);

        let mut block = Array([0u8; 16]);

        if output.len() == 8 {
            block.copy_from_slice(input);
            self.aes.decrypt_block(&mut block);
            let c = block[0..8]
                .iter()
                .zip(aiv.iter())
                .fold(0, |acc, (a, b)| acc | (a ^ b));
            if c != 0 {
                return Err(KeywrapError::AuthenticationFailed);
            }
            output[0..8].copy_from_slice(&block[8..16]);
            return Ok(output);
        }

        output.copy_from_slice(&input[8..]);
        block[0..8].copy_from_slice(&input[0..8]);
        let mut counter = (FEISTEL_ROUNDS * output.len() / 8) as u64;
        let mut counter_bin = [0u8; 8];
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = output.len();
            while i >= 8 {
                i -= 8;
                block[8..16].copy_from_slice(&output[i..][0..8]);
                BigEndian::write_u64(&mut counter_bin, counter);
                counter -= 1;
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                self.aes.decrypt_block(&mut block);
                output[i..][0..8].copy_from_slice(&block[8..16]);
            }
        }
        let c = block[0..8]
            .iter()
            .zip(aiv.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b));
        if c != 0 {
            return Err(KeywrapError::AuthenticationFailed);
        }
        Ok(output)
    }
}

// -- AES-KW (RFC 3394) - requires 8-byte aligned input

#[derive(Debug)]
pub struct Aes256KeyWrapAligned {
    aes: Aes256,
}

impl Aes256KeyWrapAligned {
    pub const KEY_BYTES: usize = 32;
    pub const MAC_BYTES: usize = 8;

    pub fn new(key: &[u8; Self::KEY_BYTES]) -> Self {
        Aes256KeyWrapAligned {
            aes: Aes256::new(key.into()),
        }
    }

    pub fn encapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::NotAligned);
        }
        if input.len() < 16 {
            return Err(KeywrapError::TooSmall);
        }
        if input.len() as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }

        let mut block = Array([0u8; 16]);
        block[0..8].copy_from_slice(&KW_IV);

        let mut counter = 0u64;
        let mut counter_bin = [0u8; 8];
        let mut output = vec![0u8; input.len() + Self::MAC_BYTES];
        output[8..].copy_from_slice(input);
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = 8;
            while i < output.len() {
                block[8..16].copy_from_slice(&output[i..][0..8]);
                self.aes.encrypt_block(&mut block);
                counter += 1;
                BigEndian::write_u64(&mut counter_bin, counter);
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                output[i..i + 8].copy_from_slice(&block[8..16]);
                i += 8;
            }
        }
        output[0..8].copy_from_slice(&block[0..8]);
        Ok(output)
    }

    pub fn decapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::NotAligned);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len < 16 {
            return Err(KeywrapError::TooSmall);
        }
        if output_len as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }

        let mut output = vec![0u8; output_len];
        let mut block = Array([0u8; 16]);

        output.copy_from_slice(&input[8..]);
        block[0..8].copy_from_slice(&input[0..8]);
        let mut counter = (FEISTEL_ROUNDS * output.len() / 8) as u64;
        let mut counter_bin = [0u8; 8];
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = output.len();
            while i >= 8 {
                i -= 8;
                block[8..16].copy_from_slice(&output[i..][0..8]);
                BigEndian::write_u64(&mut counter_bin, counter);
                counter -= 1;
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                self.aes.decrypt_block(&mut block);
                output[i..][0..8].copy_from_slice(&block[8..16]);
            }
        }
        let c = block[0..8]
            .iter()
            .zip(KW_IV.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b));
        if c != 0 {
            return Err(KeywrapError::AuthenticationFailed);
        }
        Ok(output)
    }
}

#[derive(Debug)]
pub struct Aes128KeyWrapAligned {
    aes: Aes128,
}

impl Aes128KeyWrapAligned {
    pub const KEY_BYTES: usize = 16;
    pub const MAC_BYTES: usize = 8;

    pub fn new(key: &[u8; Self::KEY_BYTES]) -> Self {
        Aes128KeyWrapAligned {
            aes: Aes128::new(key.into()),
        }
    }

    pub fn encapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::NotAligned);
        }
        if input.len() < 16 {
            return Err(KeywrapError::TooSmall);
        }
        if input.len() as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }

        let mut block = Array([0u8; 16]);
        block[0..8].copy_from_slice(&KW_IV);

        let mut counter = 0u64;
        let mut counter_bin = [0u8; 8];
        let mut output = vec![0u8; input.len() + Self::MAC_BYTES];
        output[8..].copy_from_slice(input);
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = 8;
            while i < output.len() {
                block[8..16].copy_from_slice(&output[i..][0..8]);
                self.aes.encrypt_block(&mut block);
                counter += 1;
                BigEndian::write_u64(&mut counter_bin, counter);
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                output[i..i + 8].copy_from_slice(&block[8..16]);
                i += 8;
            }
        }
        output[0..8].copy_from_slice(&block[0..8]);
        Ok(output)
    }

    pub fn decapsulate(&self, input: &[u8]) -> Result<Vec<u8>, KeywrapError> {
        if !input.len().is_multiple_of(8) {
            return Err(KeywrapError::NotAligned);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len < 16 {
            return Err(KeywrapError::TooSmall);
        }
        if output_len as u64 >= u64::MAX / FEISTEL_ROUNDS as u64 {
            return Err(KeywrapError::TooBig);
        }

        let mut output = vec![0u8; output_len];
        let mut block = Array([0u8; 16]);

        output.copy_from_slice(&input[8..]);
        block[0..8].copy_from_slice(&input[0..8]);
        let mut counter = (FEISTEL_ROUNDS * output.len() / 8) as u64;
        let mut counter_bin = [0u8; 8];
        for _ in 0..FEISTEL_ROUNDS {
            let mut i = output.len();
            while i >= 8 {
                i -= 8;
                block[8..16].copy_from_slice(&output[i..][0..8]);
                BigEndian::write_u64(&mut counter_bin, counter);
                counter -= 1;
                block[0..8]
                    .iter_mut()
                    .zip(counter_bin.iter())
                    .for_each(|(a, b)| *a ^= b);
                self.aes.decrypt_block(&mut block);
                output[i..][0..8].copy_from_slice(&block[8..16]);
            }
        }
        let c = block[0..8]
            .iter()
            .zip(KW_IV.iter())
            .fold(0, |acc, (a, b)| acc | (a ^ b));
        if c != 0 {
            return Err(KeywrapError::AuthenticationFailed);
        }
        Ok(output)
    }
}

// --

#[test]
fn kw_aligned_roundtrip() {
    let secret = b"1234567812345678";
    let key = [42u8; 32];
    let kw = Aes256KeyWrapAligned::new(&key);
    let wrapped = kw.encapsulate(secret).unwrap();
    let unwrapped = kw.decapsulate(&wrapped).unwrap();
    assert_eq!(secret, unwrapped.as_slice());
}

#[test]
fn kw_aligned_rejects_unaligned() {
    let secret = b"12345678901234567"; // 17 bytes, not aligned
    let key = [42u8; 32];
    let kw = Aes256KeyWrapAligned::new(&key);
    assert_eq!(kw.encapsulate(secret), Err(KeywrapError::NotAligned));
}

#[test]
fn kw_aligned_rejects_small() {
    let secret = b"12345678"; // 8 bytes, too small (need 16)
    let key = [42u8; 32];
    let kw = Aes256KeyWrapAligned::new(&key);
    assert_eq!(kw.encapsulate(secret), Err(KeywrapError::TooSmall));
}

#[test]
fn kw_rfc3394_test_vector() {
    // RFC 3394 Section 4.1 - 128-bit KEK, 128-bit Key Data
    let kek = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    let key_data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let expected = [
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B,
        0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    ];

    let kw = Aes128KeyWrapAligned::new(&kek);
    let wrapped = kw.encapsulate(&key_data).unwrap();
    assert_eq!(wrapped, expected);

    let unwrapped = kw.decapsulate(&wrapped).unwrap();
    assert_eq!(unwrapped, key_data);
}

#[test]
fn aligned() {
    let secret = b"1234567812345678";
    let key = [42u8; 32];
    let kw = Aes256KeyWrap::new(&key);
    let wrapped = kw.encapsulate(secret).unwrap();
    let unwrapped = kw.decapsulate(&wrapped, secret.len()).unwrap();
    assert_eq!(secret, unwrapped.as_slice());
}

#[test]
fn not_aligned() {
    let secret = b"1234567812345";
    let key = [42u8; 32];
    let kw = Aes256KeyWrap::new(&key);
    let wrapped = kw.encapsulate(secret).unwrap();
    let unwrapped = kw.decapsulate(&wrapped, secret.len()).unwrap();
    assert_eq!(secret, &unwrapped.as_slice()[..secret.len()]);
}

#[test]
fn singleblock() {
    let secret = b"12345678";
    let key = [42u8; 32];
    let kw = Aes256KeyWrap::new(&key);
    let wrapped = kw.encapsulate(secret).unwrap();
    let unwrapped = kw.decapsulate(&wrapped, secret.len()).unwrap();
    assert_eq!(secret, unwrapped.as_slice());
}
