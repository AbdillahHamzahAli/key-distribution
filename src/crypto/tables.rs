//! AES lookup tables, generated at compile time from GF(2^8) arithmetic.

/// Multiply two bytes in GF(2^8) modulo the AES polynomial 0x11B.
pub const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    while b != 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

const fn inverse(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut x: u16 = 1;
    while x < 256 {
        if gmul(a, x as u8) == 1 {
            return x as u8;
        }
        x += 1;
    }
    0
}

const fn affine(inv: u8) -> u8 {
    let mut out = 0u8;
    let mut i = 0u8;
    while i < 8 {
        let bit = ((inv >> i)
            ^ (inv >> ((i + 4) % 8))
            ^ (inv >> ((i + 5) % 8))
            ^ (inv >> ((i + 6) % 8))
            ^ (inv >> ((i + 7) % 8)))
            & 1;
        out |= (bit ^ ((0x63 >> i) & 1)) << i;
        i += 1;
    }
    out
}

const fn build_sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = affine(inverse(i as u8));
        i += 1;
    }
    table
}

const fn build_inv_sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        table[S_BOX[i] as usize] = i as u8;
        i += 1;
    }
    table
}

pub const S_BOX: [u8; 256] = build_sbox();
pub const INV_SBOX: [u8; 256] = build_inv_sbox();
pub const RCON: [u8; 15] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
];
