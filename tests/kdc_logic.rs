use std::collections::BTreeMap;
use std::collections::HashSet;

use key_distribution::crypto::codec::{Hex, Key, hex_to_bytes};
use key_distribution::crypto::modes::decrypt_text;
use key_distribution::protocol::kdc_logic::{SESSION_ALPHABET, generate_session_key, handle_step1};
use key_distribution::protocol::messages::{Id, MessageError, Nonce};

const KA: &str = "AliceKey12345678";
const KB: &str = "BobKey1111111111";

fn keys() -> BTreeMap<String, Key> {
    let mut keys = BTreeMap::new();
    keys.insert("alice".to_string(), Key::new(KA).unwrap());
    keys.insert("bob".to_string(), Key::new(KB).unwrap());
    keys
}

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

#[test]
fn session_key_is_sixteen_characters() {
    assert_eq!(generate_session_key().as_str().len(), 16);
}

#[test]
fn session_key_uses_printable_ascii_without_separator() {
    for _ in 0..50 {
        let key = generate_session_key();
        for character in key.as_str().chars() {
            assert!(SESSION_ALPHABET.contains(character));
        }
        assert!(!key.as_str().contains('|'));
        assert!(!key.as_str().contains(' '));
    }
}

#[test]
fn session_keys_are_random() {
    let samples: HashSet<String> = (0..20)
        .map(|_| generate_session_key().as_str().to_string())
        .collect();
    assert!(samples.len() > 1);
}

#[test]
fn step1_returns_two_hex_parts() {
    let (part_a, part_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    for part in [&part_a, &part_b] {
        assert_eq!(part.as_str(), part.as_str().to_uppercase());
        let bytes = hex_to_bytes(part.as_str()).unwrap();
        assert_eq!(bytes.len() % 16, 0);
        assert!(!bytes.is_empty());
    }
}

#[test]
fn part_a_contains_session_key_and_request_fields() {
    let (part_a, _) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    let plaintext = decrypt_text(KA, part_a.as_str()).unwrap();
    let fields: Vec<&str> = plaintext.split('|').collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[1], "alice");
    assert_eq!(fields[2], "bob");
    assert_eq!(fields[3], "7311");
    assert_eq!(fields[0].len(), 16);
}

#[test]
fn part_b_contains_session_key_and_initiator() {
    let (_, part_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    let plaintext = decrypt_text(KB, part_b.as_str()).unwrap();
    let fields: Vec<&str> = plaintext.split('|').collect();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1], "alice");
}

#[test]
fn both_parts_share_the_same_session_key() {
    let (part_a, part_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    let key_a = decrypt_text(KA, part_a.as_str())
        .unwrap()
        .split('|')
        .next()
        .unwrap()
        .to_string();
    let key_b = decrypt_text(KB, part_b.as_str())
        .unwrap()
        .split('|')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(key_a, key_b);
}

#[test]
fn unknown_identities_are_rejected() {
    let error = handle_step1(
        &keys(),
        &id("mallory"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .expect_err("unknown initiator");
    assert!(matches!(error, MessageError::UnknownIdentity(_)));

    let error = handle_step1(
        &keys(),
        &id("alice"),
        &id("mallory"),
        &Nonce::new("7311").unwrap(),
    )
    .expect_err("unknown responder");
    assert!(matches!(error, MessageError::UnknownIdentity(_)));
}

#[test]
fn same_identity_is_rejected() {
    let error = handle_step1(
        &keys(),
        &id("alice"),
        &id("alice"),
        &Nonce::new("7311").unwrap(),
    )
    .expect_err("same identity");
    assert!(matches!(error, MessageError::SameIdentity(_)));
}

#[test]
fn identity_with_separator_is_rejected_at_parse_time() {
    assert!(Id::new("bo|b").is_err());
}

#[test]
fn fresh_session_key_is_generated_each_time() {
    let (first_a, first_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    let (second_a, second_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    assert_ne!(first_a, second_a);
    assert_ne!(first_b, second_b);
}

#[test]
fn returned_parts_are_hex() {
    let (part_a, part_b) = handle_step1(
        &keys(),
        &id("alice"),
        &id("bob"),
        &Nonce::new("7311").unwrap(),
    )
    .unwrap();
    assert!(Hex::new(part_a.as_str()).is_ok());
    assert!(Hex::new(part_b.as_str()).is_ok());
}
