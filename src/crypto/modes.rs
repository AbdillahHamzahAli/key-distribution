//! AES-128-CBC with random IVs and PKCS#7 padding.

use rand::RngCore;
use thiserror::Error;

use super::aes::{Aes128, AesError};
use super::codec::{
    CodecError, Hex, Key, ascii_to_bytes, bytes_to_ascii, hex_to_bytes, key_to_bytes,
};

#[derive(Debug, Error)]
pub enum ModeError {
    #[error("padded data must be a non-empty multiple of {block_size}, got {len}")]
    DataLength { len: usize, block_size: usize },
    #[error("data must be a non-empty multiple of 16 bytes (IV + ciphertext), got {0}")]
    CipherLength(usize),
    #[error("invalid padding value: {0}")]
    PaddingValue(u8),
    #[error("invalid padding bytes")]
    PaddingBytes,
    #[error(transparent)]
    Aes(#[from] AesError),
    #[error(transparent)]
    Codec(#[from] CodecError),
}

pub fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let pad_len = 16 - (data.len() % 16);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    out
}

pub fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, ModeError> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(ModeError::DataLength {
            len: data.len(),
            block_size: 16,
        });
    }

    let pad_len = *data.last().expect("non-empty") as usize;
    if !(1..=16).contains(&pad_len) {
        return Err(ModeError::PaddingValue(pad_len as u8));
    }
    if !data[data.len() - pad_len..]
        .iter()
        .all(|&byte| byte == pad_len as u8)
    {
        return Err(ModeError::PaddingBytes);
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, ModeError> {
    let aes = Aes128::new(key)?;
    let padded = pkcs7_pad(plaintext);

    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);

    let mut out = Vec::with_capacity(16 + padded.len());
    out.extend_from_slice(&iv);
    let mut previous = iv;

    for chunk in padded.as_chunks::<16>().0 {
        let mut block = [0u8; 16];
        for index in 0..16 {
            block[index] = chunk[index] ^ previous[index];
        }
        let encrypted = aes.encrypt_block(&block)?;
        out.extend_from_slice(&encrypted);
        previous = encrypted;
    }
    Ok(out)
}

pub fn cbc_decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ModeError> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(ModeError::CipherLength(data.len()));
    }

    let aes = Aes128::new(key)?;
    let mut previous = [0u8; 16];
    previous.copy_from_slice(&data[..16]);

    let mut out = Vec::with_capacity(data.len() - 16);
    for chunk in data[16..].as_chunks::<16>().0 {
        let plain = aes.decrypt_block(chunk)?;
        for index in 0..16 {
            out.push(plain[index] ^ previous[index]);
        }
        previous.copy_from_slice(chunk);
    }
    pkcs7_unpad(&out)
}

pub fn encrypt_text(key_ascii: &str, text_ascii: &str) -> Result<Hex, ModeError> {
    let key = key_to_bytes(key_ascii)?;
    let plaintext = ascii_to_bytes(text_ascii)?;
    Ok(Hex::from_bytes(&cbc_encrypt(&plaintext, &key)?))
}

pub fn decrypt_text(key_ascii: &str, hex_str: &str) -> Result<String, ModeError> {
    let key = key_to_bytes(key_ascii)?;
    let data = hex_to_bytes(hex_str)?;
    let plaintext = cbc_decrypt(&data, &key)?;
    Ok(bytes_to_ascii(&plaintext)?)
}

pub fn encrypt_with_key(key: &Key, text_ascii: &str) -> Result<Hex, ModeError> {
    let plaintext = ascii_to_bytes(text_ascii)?;
    Ok(Hex::from_bytes(&cbc_encrypt(&plaintext, key.as_bytes())?))
}

pub fn decrypt_with_key(key: &Key, hex: &Hex) -> Result<String, ModeError> {
    let data = hex_to_bytes(hex.as_str())?;
    let plaintext = cbc_decrypt(&data, key.as_bytes())?;
    Ok(bytes_to_ascii(&plaintext)?)
}
