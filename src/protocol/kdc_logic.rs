//! Pure KDC logic: validate a request and build the two encrypted replies.

use std::collections::BTreeMap;

use crate::crypto::codec::{Hex, Key};
use crate::crypto::modes::encrypt_text;
use crate::protocol::messages::{Id, MessageError, Nonce};
use crate::rng::random_from_alphabet;

/// Printable ASCII (0x21..=0x7E) without the `|` field separator.
pub const SESSION_ALPHABET: &str = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{}~";

/// Generate a fresh 16-character ASCII session key.
pub fn generate_session_key() -> Key {
    Key::new(&random_from_alphabet(SESSION_ALPHABET.as_bytes(), 16))
        .expect("session alphabet always yields a valid key")
}

/// Handle step 1: return the ciphertext for the initiator and the ticket for the responder.
pub fn handle_step1(
    keys: &BTreeMap<String, Key>,
    initiator: &Id,
    responder: &Id,
    nonce: &Nonce,
) -> Result<(Hex, Hex), MessageError> {
    if initiator == responder {
        return Err(MessageError::SameIdentity(initiator.as_str().to_string()));
    }

    let key_a = keys
        .get(initiator.as_str())
        .ok_or_else(|| MessageError::UnknownIdentity(initiator.as_str().to_string()))?;
    let key_b = keys
        .get(responder.as_str())
        .ok_or_else(|| MessageError::UnknownIdentity(responder.as_str().to_string()))?;

    let session_key = generate_session_key();
    let for_initiator = build_plaintext(&[
        session_key.as_str(),
        initiator.as_str(),
        responder.as_str(),
        nonce.as_str(),
    ]);
    let for_responder = build_plaintext(&[session_key.as_str(), initiator.as_str()]);

    Ok((
        encrypt_text(key_a.as_str(), &for_initiator)?,
        encrypt_text(key_b.as_str(), &for_responder)?,
    ))
}

/// Join plaintext fields with the `|` separator used inside encrypted payloads.
pub fn build_plaintext(fields: &[&str]) -> String {
    fields.join("|")
}
