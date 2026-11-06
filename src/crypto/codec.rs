//! ASCII, hex, and key conversions.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("input must be ASCII only: invalid character at index {0}")]
    Ascii(usize),
    #[error("data is not printable ASCII: invalid byte at index {0}")]
    NotAscii(usize),
    #[error("hex string must have an even number of digits, got {0}")]
    OddHex(usize),
    #[error("invalid hex characters: {0}")]
    InvalidHex(String),
    #[error("AES-128 key must be exactly 16 characters, got {0}")]
    KeyLength(usize),
}

pub fn ascii_to_bytes(text: &str) -> Result<Vec<u8>, CodecError> {
    if let Some((index, _)) = text.char_indices().find(|(_, ch)| !ch.is_ascii()) {
        return Err(CodecError::Ascii(index));
    }
    Ok(text.as_bytes().to_vec())
}

pub fn bytes_to_ascii(data: &[u8]) -> Result<String, CodecError> {
    if let Some(index) = data.iter().position(|&byte| !byte.is_ascii()) {
        return Err(CodecError::NotAscii(index));
    }
    Ok(data.iter().map(|&byte| byte as char).collect())
}

pub fn bytes_to_hex(data: &[u8]) -> String {
    use fmt::Write as _;

    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn hex_to_bytes(hexstr: &str) -> Result<Vec<u8>, CodecError> {
    let cleaned: Vec<u8> = hexstr
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();

    if !cleaned.len().is_multiple_of(2) {
        return Err(CodecError::OddHex(cleaned.len()));
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut invalid = BTreeSet::new();
    for pair in cleaned.as_chunks::<2>().0 {
        match (hex_value(pair[0]), hex_value(pair[1])) {
            (Some(high), Some(low)) => out.push((high << 4) | low),
            (high, low) => {
                if high.is_none() {
                    invalid.insert(pair[0] as char);
                }
                if low.is_none() {
                    invalid.insert(pair[1] as char);
                }
            }
        }
    }

    if !invalid.is_empty() {
        let chars: String = invalid.into_iter().collect();
        return Err(CodecError::InvalidHex(chars));
    }
    Ok(out)
}

pub fn key_to_bytes(key: &str) -> Result<[u8; 16], CodecError> {
    let data = ascii_to_bytes(key)?;
    if data.len() != 16 {
        return Err(CodecError::KeyLength(data.len()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&data);
    Ok(out)
}

/// A validated 16-character ASCII AES-128 key.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(String);

impl Key {
    pub fn new(value: &str) -> Result<Self, CodecError> {
        key_to_bytes(value)?;
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key(\"***\")")
    }
}

/// An even-length hex string, normalised to uppercase.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Hex(String);

impl Hex {
    pub fn new(value: &str) -> Result<Self, CodecError> {
        let bytes = hex_to_bytes(value)?;
        Ok(Self(bytes_to_hex(&bytes)))
    }

    pub fn from_bytes(data: &[u8]) -> Self {
        Self(bytes_to_hex(data))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for Hex {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Hex::new(&value).map_err(serde::de::Error::custom)
    }
}
