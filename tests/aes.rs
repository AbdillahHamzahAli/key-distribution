use std::collections::HashSet;

use key_distribution::crypto::aes::{
    add_round_key, decrypt_block, encrypt_block, inv_mix_columns, inv_shift_rows, inv_sub_bytes,
    key_expansion, mix_columns, shift_rows, sub_bytes,
};
use key_distribution::crypto::codec::hex_to_bytes;

fn bytes(hex: &str) -> Vec<u8> {
    hex_to_bytes(hex).expect("valid hex")
}

const KEY_FIPS: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const BLOCK_FIPS: &str = "3243f6a8885a308d313198a2e0370734";
const CIPHER_FIPS: &str = "3925841d02dc09fbdc118597196a0b32";
const KEY_C1: &str = "000102030405060708090a0b0c0d0e0f";
const BLOCK_C1: &str = "00112233445566778899aabbccddeeff";
const CIPHER_C1: &str = "69c4e0d86a7b0430d8cdb78070b4c55a";

#[test]
fn key_expansion_returns_eleven_round_keys() {
    let round_keys = key_expansion(&bytes(KEY_FIPS)).expect("valid key");
    assert_eq!(round_keys.len(), 11);
    for round_key in round_keys {
        assert_eq!(round_key.len(), 16);
    }
}

#[test]
fn first_round_key_is_the_key() {
    let key = bytes(KEY_FIPS);
    let round_keys = key_expansion(&key).expect("valid key");
    assert_eq!(&round_keys[0][..], key.as_slice());
}

#[test]
fn last_round_key_matches_sp800() {
    let round_keys = key_expansion(&bytes(KEY_FIPS)).expect("valid key");
    assert_eq!(
        &round_keys[10][..],
        bytes("d014f9a8c9ee2589e13f0cc8b6630ca6").as_slice()
    );
}

#[test]
fn all_round_keys_are_distinct() {
    let round_keys = key_expansion(&bytes(KEY_C1)).expect("valid key");
    let unique: HashSet<[u8; 16]> = round_keys.iter().copied().collect();
    assert_eq!(unique.len(), 11);
}

#[test]
fn wrong_key_length_is_rejected() {
    assert!(key_expansion(b"short").is_err());
}

#[test]
fn sub_bytes_known() {
    assert_eq!(sub_bytes(&bytes("530001CA")), bytes("ED637C74"));
}

#[test]
fn sub_bytes_inverts() {
    let state: Vec<u8> = (0..16).collect();
    assert_eq!(inv_sub_bytes(&sub_bytes(&state)), state);
}

#[test]
fn shift_rows_known() {
    let state = bytes("00112233445566778899aabbccddeeff");
    assert_eq!(
        shift_rows(&state),
        bytes("0055aaff4499ee3388dd2277cc1166bb")
    );
}

#[test]
fn shift_rows_inverts() {
    let state: Vec<u8> = (0..16).collect();
    assert_eq!(inv_shift_rows(&shift_rows(&state)), state);
}

#[test]
fn mix_columns_inverts() {
    let state = bytes("00112233445566778899aabbccddeeff");
    assert_eq!(inv_mix_columns(&mix_columns(&state)), state);
}

#[test]
fn add_round_key_is_involutive() {
    let state = bytes("00112233445566778899aabbccddeeff");
    assert_eq!(add_round_key(&add_round_key(&state, &state), &state), state);
}

#[test]
fn encrypt_fips_appendix_b() {
    assert_eq!(
        encrypt_block(&bytes(BLOCK_FIPS), &bytes(KEY_FIPS)).expect("valid"),
        bytes(CIPHER_FIPS).as_slice()
    );
}

#[test]
fn encrypt_fips_appendix_c1() {
    assert_eq!(
        encrypt_block(&bytes(BLOCK_C1), &bytes(KEY_C1)).expect("valid"),
        bytes(CIPHER_C1).as_slice()
    );
}

#[test]
fn decrypt_fips_appendix_b() {
    assert_eq!(
        decrypt_block(&bytes(CIPHER_FIPS), &bytes(KEY_FIPS)).expect("valid"),
        bytes(BLOCK_FIPS).as_slice()
    );
}

#[test]
fn decrypt_fips_appendix_c1() {
    assert_eq!(
        decrypt_block(&bytes(CIPHER_C1), &bytes(KEY_C1)).expect("valid"),
        bytes(BLOCK_C1).as_slice()
    );
}

#[test]
fn random_roundtrips() {
    use rand::RngCore;

    let mut key = [0u8; 16];
    let mut block = [0u8; 16];
    for _ in 0..20 {
        rand::rng().fill_bytes(&mut key);
        rand::rng().fill_bytes(&mut block);
        let encrypted = encrypt_block(&block, &key).expect("valid");
        assert_eq!(decrypt_block(&encrypted, &key).expect("valid"), block);
    }
}

#[test]
fn wrong_block_length_is_rejected() {
    assert!(encrypt_block(b"tooshort", &bytes(KEY_FIPS)).is_err());
    assert!(decrypt_block(b"tooshort", &bytes(KEY_FIPS)).is_err());
}
