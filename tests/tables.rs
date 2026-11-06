use std::collections::HashSet;

use key_distribution::crypto::tables::{INV_SBOX, RCON, S_BOX, gmul};

#[test]
fn sbox_known_fips_values() {
    assert_eq!(S_BOX[0x00], 0x63);
    assert_eq!(S_BOX[0x01], 0x7C);
    assert_eq!(S_BOX[0x53], 0xED);
    assert_eq!(S_BOX[0xCA], 0x74);
}

#[test]
fn sbox_is_a_permutation() {
    let unique: HashSet<u8> = S_BOX.iter().copied().collect();
    assert_eq!(unique.len(), 256);
}

#[test]
fn sbox_first_row() {
    assert_eq!(
        &S_BOX[..16],
        &[
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
            0xAB, 0x76,
        ]
    );
}

#[test]
fn inv_sbox_known_values() {
    assert_eq!(INV_SBOX[0x63], 0x00);
    assert_eq!(INV_SBOX[0xED], 0x53);
}

#[test]
fn inv_sbox_inverts_sbox() {
    for index in 0..256usize {
        assert_eq!(INV_SBOX[S_BOX[index] as usize], index as u8);
    }
}

#[test]
fn inv_sbox_is_a_permutation() {
    let unique: HashSet<u8> = INV_SBOX.iter().copied().collect();
    assert_eq!(unique.len(), 256);
}

#[test]
fn rcon_known_values_and_length() {
    assert_eq!(RCON[0], 0x01);
    assert_eq!(RCON[1], 0x02);
    assert_eq!(RCON[9], 0x36);
    assert_eq!(RCON.len(), 15);
}

#[test]
fn gmul_known_products() {
    assert_eq!(gmul(0x57, 0x83), 0xC1);
    assert_eq!(gmul(0x53, 0xCA), 0x01);
}

#[test]
fn gmul_identity() {
    for value in [0x01u8, 0x53, 0xFF] {
        assert_eq!(gmul(value, 0x01), value);
    }
}
