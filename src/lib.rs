#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

use aes::block_cipher::generic_array::GenericArray;
use aes::block_cipher::{BlockCipher, NewBlockCipher};
use aes::{Aes128, Aes256};
use byteorder::{BigEndian, ByteOrder};

const FEISTEL_ROUNDS: usize = 5;

#[derive(Debug, Eq, PartialEq)]
pub enum KeywrapError {
    /// Input is too big.
    TooBig,
    /// Input is too small.
    TooSmall,
    /// Ciphertext has invalid padding.
    Unpadded,
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
            KeywrapError::InvalidExpectedLen => f.write_str("Invalid expected lengthr"),
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
        if input.len() > std::u32::MAX as usize
            || input.len() as u64 >= std::u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], input.len() as u32);
        let mut block = [0u8; 16];
        let mut block = GenericArray::from_mut_slice(&mut block);
        block[0..8].copy_from_slice(&aiv);

        if input.len() == 8 {
            block[8..16].copy_from_slice(&input);
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
                block[8..16]
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
        if input.len() % 8 != 0 {
            return Err(KeywrapError::Unpadded);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len > std::u32::MAX as usize
            || output_len as u64 >= std::u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        if expected_len > output_len || (expected_len & !7) > output_len {
            return Err(KeywrapError::InvalidExpectedLen);
        }
        let mut output = vec![0u8; output_len];
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], expected_len as u32);

        let mut block = [0u8; 16];
        let mut block = GenericArray::from_mut_slice(&mut block);

        if output.len() == 8 {
            block.copy_from_slice(&input);
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
                block[8..16]
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
        if input.len() > std::u32::MAX as usize
            || input.len() as u64 >= std::u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], input.len() as u32);
        let mut block = [0u8; 16];
        let mut block = GenericArray::from_mut_slice(&mut block);
        block[0..8].copy_from_slice(&aiv);

        if input.len() == 8 {
            block[8..16].copy_from_slice(&input);
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
                block[8..16]
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
        if input.len() % 8 != 0 {
            return Err(KeywrapError::Unpadded);
        }
        let output_len = input
            .len()
            .checked_sub(Self::MAC_BYTES)
            .ok_or(KeywrapError::TooSmall)?;
        if output_len > std::u32::MAX as usize
            || output_len as u64 >= std::u64::MAX / FEISTEL_ROUNDS as u64
        {
            return Err(KeywrapError::TooBig);
        }
        if expected_len > output_len || (expected_len & !7) > output_len {
            return Err(KeywrapError::InvalidExpectedLen);
        }
        let mut output = vec![0u8; output_len];
        let mut aiv: [u8; 8] = [0xa6u8, 0x59, 0x59, 0xa6, 0, 0, 0, 0];
        BigEndian::write_u32(&mut aiv[4..8], expected_len as u32);

        let mut block = [0u8; 16];
        let mut block = GenericArray::from_mut_slice(&mut block);

        if output.len() == 8 {
            block.copy_from_slice(&input);
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
                block[8..16]
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
