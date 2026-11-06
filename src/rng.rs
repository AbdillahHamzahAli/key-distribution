//! Randomness helpers backed by the OS-seeded thread RNG.

use rand::Rng;

/// Draw `len` characters uniformly from `alphabet`.
pub fn random_from_alphabet(alphabet: &[u8], len: usize) -> String {
    assert!(!alphabet.is_empty(), "alphabet must not be empty");
    let mut rng = rand::rng();
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        out.push(alphabet[rng.random_range(0..alphabet.len())] as char);
    }
    out
}
