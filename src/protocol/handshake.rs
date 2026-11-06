//! Nonces, ticket parsing, and the challenge-response exchange.

use crate::crypto::codec::{Hex, Key};
use crate::crypto::modes::{decrypt_text, encrypt_text};
use crate::protocol::messages::{Id, MessageError, Nonce};
use crate::rng::random_from_alphabet;

const NONCE_LENGTH: usize = 8;
const FIRST_NONCE_DIGITS: &[u8] = b"123456789";
const REST_NONCE_DIGITS: &[u8] = b"0123456789";

/// Generate an eight-digit nonce whose first digit is non-zero.
pub fn new_nonce() -> Nonce {
    let first = random_from_alphabet(FIRST_NONCE_DIGITS, 1);
    let rest = random_from_alphabet(REST_NONCE_DIGITS, NONCE_LENGTH - 1);
    Nonce::new(&format!("{first}{rest}")).expect("generated nonce is valid")
}

/// `f(N2) = N2 + 1`, returned in decimal without leading zeros.
pub fn f(n2: &str) -> Result<String, MessageError> {
    if n2.is_empty() || !n2.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(MessageError::NonceFormat {
            value: n2.to_string(),
        });
    }
    Ok(increment_decimal(n2))
}

fn normalize_decimal(value: &str) -> Option<&str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let trimmed = value.trim_start_matches('0');
    Some(if trimmed.is_empty() { "0" } else { trimmed })
}

fn increment_decimal(value: &str) -> String {
    let trimmed = normalize_decimal(value).expect("caller validated decimal digits");
    let mut digits: Vec<u8> = trimmed.bytes().collect();
    let mut carry = true;
    for digit in digits.iter_mut().rev() {
        if !carry {
            break;
        }
        if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            carry = false;
        }
    }
    if carry {
        digits.insert(0, b'1');
    }
    String::from_utf8(digits).expect("decimal digits are ASCII")
}

/// Verify the KDC reply and extract the session key.
pub fn parse_step2(
    key_a: &Key,
    ciphertext: &Hex,
    nonce: &Nonce,
    initiator: Option<&Id>,
    responder: Option<&Id>,
) -> Result<Key, MessageError> {
    let plaintext = decrypt_text(key_a.as_str(), ciphertext.as_str())?;
    let fields: Vec<&str> = plaintext.split('|').collect();
    if fields.len() != 4 {
        return Err(MessageError::Step2Fields(fields.len()));
    }

    let session_key = parse_session_key(fields[0])?;
    if fields[3] != nonce.as_str() {
        return Err(MessageError::NonceMismatch {
            expected: nonce.as_str().to_string(),
            actual: fields[3].to_string(),
        });
    }
    if let Some(initiator) = initiator
        && fields[1] != initiator.as_str()
    {
        return Err(MessageError::IdentityMismatch {
            expected: initiator.as_str().to_string(),
            actual: fields[1].to_string(),
        });
    }
    if let Some(responder) = responder
        && fields[2] != responder.as_str()
    {
        return Err(MessageError::IdentityMismatch {
            expected: responder.as_str().to_string(),
            actual: fields[2].to_string(),
        });
    }
    Ok(session_key)
}

/// Decrypt the ticket Bob receives and return `(Ks, initiator)`.
pub fn parse_ticket(key_b: &Key, ciphertext: &Hex) -> Result<(Key, Id), MessageError> {
    let plaintext = decrypt_text(key_b.as_str(), ciphertext.as_str())?;
    let fields: Vec<&str> = plaintext.split('|').collect();
    if fields.len() != 2 {
        return Err(MessageError::TicketFields(fields.len()));
    }

    let session_key = parse_session_key(fields[0])?;
    let initiator = Id::new(fields[1])?;
    Ok((session_key, initiator))
}

fn parse_session_key(value: &str) -> Result<Key, MessageError> {
    Key::new(value).map_err(|_| MessageError::SessionKeyLength(value.chars().count()))
}

/// Bob generates N2 and encrypts it under Ks.
pub fn make_step4(session_key: &Key) -> (Nonce, Hex) {
    let nonce = new_nonce();
    let ciphertext = encrypt_text(session_key.as_str(), nonce.as_str())
        .expect("encrypting a nonce with a valid key cannot fail");
    (nonce, ciphertext)
}

/// Alice decrypts N2 and returns E(Ks, f(N2)).
pub fn make_step5(session_key: &Key, step4: &Hex) -> Result<Hex, MessageError> {
    let nonce = decrypt_text(session_key.as_str(), step4.as_str())?;
    let proof = f(&nonce)?;
    Ok(encrypt_text(session_key.as_str(), &proof)?)
}

/// Bob checks that Alice proved knowledge of Ks.
pub fn verify_step5(session_key: &Key, nonce: &Nonce, step5: &Hex) -> Result<bool, MessageError> {
    let expected = f(nonce.as_str())?;
    let decrypted = decrypt_text(session_key.as_str(), step5.as_str())?;
    let Some(actual) = normalize_decimal(&decrypted) else {
        return Err(MessageError::NonceFormat { value: decrypted });
    };
    Ok(actual == expected)
}
