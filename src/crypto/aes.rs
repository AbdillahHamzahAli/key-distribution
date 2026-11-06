//! AES-128 block encryption and decryption, written from scratch.

use thiserror::Error;

use super::tables::{INV_SBOX, RCON, S_BOX, gmul};

#[derive(Debug, Error)]
pub enum AesError {
    #[error("block must be 16 bytes, got {0}")]
    BlockLength(usize),
    #[error("AES-128 key must be 16 bytes, got {0}")]
    KeyLength(usize),
}

pub type RoundKeys = [[u8; 16]; 11];

fn require_block(block: &[u8]) -> Result<(), AesError> {
    if block.len() == 16 {
        Ok(())
    } else {
        Err(AesError::BlockLength(block.len()))
    }
}

fn require_key(key: &[u8]) -> Result<(), AesError> {
    if key.len() == 16 {
        Ok(())
    } else {
        Err(AesError::KeyLength(key.len()))
    }
}

fn to_block(state: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block.copy_from_slice(&state[..16]);
    block
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        S_BOX[word[0] as usize],
        S_BOX[word[1] as usize],
        S_BOX[word[2] as usize],
        S_BOX[word[3] as usize],
    ]
}

/// Expand a 16-byte key into the eleven AES-128 round keys.
pub fn key_expansion(key: &[u8]) -> Result<RoundKeys, AesError> {
    require_key(key)?;

    let mut words = [[0u8; 4]; 44];
    for (i, word) in words.iter_mut().take(4).enumerate() {
        word.copy_from_slice(&key[4 * i..4 * i + 4]);
    }

    for i in 4..44 {
        let mut temp = words[i - 1];
        if i % 4 == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / 4 - 1];
        }
        for j in 0..4 {
            words[i][j] = words[i - 4][j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 11];
    for (round, round_key) in round_keys.iter_mut().enumerate() {
        for column in 0..4 {
            round_key[4 * column..4 * column + 4].copy_from_slice(&words[4 * round + column]);
        }
    }
    Ok(round_keys)
}

pub fn sub_bytes(state: &[u8]) -> Vec<u8> {
    state.iter().map(|&byte| S_BOX[byte as usize]).collect()
}

pub fn inv_sub_bytes(state: &[u8]) -> Vec<u8> {
    state.iter().map(|&byte| INV_SBOX[byte as usize]).collect()
}

pub fn shift_rows(state: &[u8]) -> Vec<u8> {
    debug_assert_eq!(state.len(), 16);
    let mut out = state.to_vec();
    for row in 0..4 {
        for column in 0..4 {
            out[row + 4 * column] = state[row + 4 * ((column + row) % 4)];
        }
    }
    out
}

pub fn inv_shift_rows(state: &[u8]) -> Vec<u8> {
    debug_assert_eq!(state.len(), 16);
    let mut out = state.to_vec();
    for row in 0..4 {
        for column in 0..4 {
            out[row + 4 * ((column + row) % 4)] = state[row + 4 * column];
        }
    }
    out
}

pub fn mix_columns(state: &[u8]) -> Vec<u8> {
    debug_assert_eq!(state.len(), 16);
    let mut out = state.to_vec();
    for column in 0..4 {
        let s = &state[4 * column..4 * column + 4];
        out[4 * column] = gmul(s[0], 0x02) ^ gmul(s[1], 0x03) ^ s[2] ^ s[3];
        out[4 * column + 1] = s[0] ^ gmul(s[1], 0x02) ^ gmul(s[2], 0x03) ^ s[3];
        out[4 * column + 2] = s[0] ^ s[1] ^ gmul(s[2], 0x02) ^ gmul(s[3], 0x03);
        out[4 * column + 3] = gmul(s[0], 0x03) ^ s[1] ^ s[2] ^ gmul(s[3], 0x02);
    }
    out
}

pub fn inv_mix_columns(state: &[u8]) -> Vec<u8> {
    debug_assert_eq!(state.len(), 16);
    let mut out = state.to_vec();
    for column in 0..4 {
        let s = &state[4 * column..4 * column + 4];
        out[4 * column] = gmul(s[0], 0x0E) ^ gmul(s[1], 0x0B) ^ gmul(s[2], 0x0D) ^ gmul(s[3], 0x09);
        out[4 * column + 1] =
            gmul(s[0], 0x09) ^ gmul(s[1], 0x0E) ^ gmul(s[2], 0x0B) ^ gmul(s[3], 0x0D);
        out[4 * column + 2] =
            gmul(s[0], 0x0D) ^ gmul(s[1], 0x09) ^ gmul(s[2], 0x0E) ^ gmul(s[3], 0x0B);
        out[4 * column + 3] =
            gmul(s[0], 0x0B) ^ gmul(s[1], 0x0D) ^ gmul(s[2], 0x09) ^ gmul(s[3], 0x0E);
    }
    out
}

pub fn add_round_key(state: &[u8], round_key: &[u8]) -> Vec<u8> {
    state
        .iter()
        .zip(round_key)
        .map(|(byte, key)| byte ^ key)
        .collect()
}

/// Cached AES-128 key schedule.
#[derive(Clone)]
pub struct Aes128 {
    round_keys: RoundKeys,
}

impl Aes128 {
    pub fn new(key: &[u8]) -> Result<Self, AesError> {
        Ok(Self {
            round_keys: key_expansion(key)?,
        })
    }

    pub fn encrypt_block(&self, block: &[u8]) -> Result<[u8; 16], AesError> {
        require_block(block)?;
        let mut state = add_round_key(block, &self.round_keys[0]);
        for round in 1..10 {
            state = sub_bytes(&state);
            state = shift_rows(&state);
            state = mix_columns(&state);
            state = add_round_key(&state, &self.round_keys[round]);
        }
        state = sub_bytes(&state);
        state = shift_rows(&state);
        state = add_round_key(&state, &self.round_keys[10]);
        Ok(to_block(&state))
    }

    pub fn decrypt_block(&self, block: &[u8]) -> Result<[u8; 16], AesError> {
        require_block(block)?;
        let mut state = add_round_key(block, &self.round_keys[10]);
        for round in (1..10).rev() {
            state = inv_shift_rows(&state);
            state = inv_sub_bytes(&state);
            state = add_round_key(&state, &self.round_keys[round]);
            state = inv_mix_columns(&state);
        }
        state = inv_shift_rows(&state);
        state = inv_sub_bytes(&state);
        state = add_round_key(&state, &self.round_keys[0]);
        Ok(to_block(&state))
    }
}

pub fn encrypt_block(block: &[u8], key: &[u8]) -> Result<[u8; 16], AesError> {
    require_block(block)?;
    Aes128::new(key)?.encrypt_block(block)
}

pub fn decrypt_block(block: &[u8], key: &[u8]) -> Result<[u8; 16], AesError> {
    require_block(block)?;
    Aes128::new(key)?.decrypt_block(block)
}
