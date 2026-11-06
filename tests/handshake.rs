use std::collections::BTreeMap;

use key_distribution::crypto::codec::{Hex, Key};
use key_distribution::crypto::modes::{decrypt_text, encrypt_text};
use key_distribution::protocol::handshake::{
    f, make_step4, make_step5, new_nonce, parse_step2, parse_ticket, verify_step5,
};
use key_distribution::protocol::kdc_logic::handle_step1;
use key_distribution::protocol::messages::{Id, MessageError, Nonce};

const KA: &str = "AliceKey12345678";
const KB: &str = "BobKey1111111111";
const KS: &str = "SessionKeyABC123";
const N1: &str = "7311";

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn key(value: &str) -> Key {
    Key::new(value).unwrap()
}

fn keys() -> BTreeMap<String, Key> {
    let mut keys = BTreeMap::new();
    keys.insert("alice".to_string(), key(KA));
    keys.insert("bob".to_string(), key(KB));
    keys
}

fn establish() -> (Key, Key, Id, Hex) {
    let (part_a, part_b) =
        handle_step1(&keys(), &id("alice"), &id("bob"), &Nonce::new(N1).unwrap())
            .expect("step1 succeeds");
    let session_a = parse_step2(
        &key(KA),
        &part_a,
        &Nonce::new(N1).unwrap(),
        Some(&id("alice")),
        Some(&id("bob")),
    )
    .expect("step2 succeeds");
    let (session_b, initiator) = parse_ticket(&key(KB), &part_b).expect("ticket succeeds");
    (session_a, session_b, initiator, part_b)
}

#[test]
fn full_handshake_end_to_end() {
    let (session_a, session_b, initiator, _) = establish();
    assert_eq!(session_a, session_b);
    assert_eq!(initiator, id("alice"));

    let (nonce, step4) = make_step4(&session_b);
    let step5 = make_step5(&session_a, &step4).unwrap();
    assert!(verify_step5(&session_b, &nonce, &step5).unwrap());
}

#[test]
fn wrong_n1_is_rejected() {
    let (part_a, _) = handle_step1(&keys(), &id("alice"), &id("bob"), &Nonce::new(N1).unwrap())
        .expect("step1 succeeds");
    let error = parse_step2(&key(KA), &part_a, &Nonce::new("9999").unwrap(), None, None)
        .expect_err("nonce mismatch");
    assert!(matches!(error, MessageError::NonceMismatch { .. }));
}

#[test]
fn identity_mismatch_is_rejected() {
    let (part_a, _) = handle_step1(&keys(), &id("alice"), &id("bob"), &Nonce::new(N1).unwrap())
        .expect("step1 succeeds");
    let nonce = Nonce::new(N1).unwrap();

    let error = parse_step2(
        &key(KA),
        &part_a,
        &nonce,
        Some(&id("alice")),
        Some(&id("mallory")),
    )
    .expect_err("responder mismatch");
    assert!(matches!(error, MessageError::IdentityMismatch { .. }));

    let error = parse_step2(
        &key(KA),
        &part_a,
        &nonce,
        Some(&id("eve")),
        Some(&id("bob")),
    )
    .expect_err("initiator mismatch");
    assert!(matches!(error, MessageError::IdentityMismatch { .. }));
}

#[test]
fn step2_with_five_fields_is_rejected() {
    let bogus = encrypt_text(KA, &[KA; 5].join("|")).unwrap();
    let error = parse_step2(&key(KA), &bogus, &Nonce::new(N1).unwrap(), None, None)
        .expect_err("wrong field count");
    assert!(matches!(error, MessageError::Step2Fields(5)));
}

#[test]
fn ticket_yields_session_key_and_sender() {
    let (session_a, session_b, initiator, _) = establish();
    assert_eq!(session_a, session_b);
    assert_eq!(initiator, id("alice"));
    assert_eq!(session_b.as_str().len(), 16);
}

#[test]
fn ticket_with_three_fields_is_rejected() {
    let bogus = encrypt_text(KB, &[KB; 3].join("|")).unwrap();
    let error = parse_ticket(&key(KB), &bogus).expect_err("wrong field count");
    assert!(matches!(error, MessageError::TicketFields(3)));
}

#[test]
fn truncated_hex_and_bad_keys_are_rejected() {
    assert!(Hex::new("ABC").is_err());
    assert!(Key::new("short").is_err());
}

#[test]
fn step4_nonce_is_decimal_and_encrypted_under_ks() {
    let (nonce, step4) = make_step4(&key(KS));
    assert!(nonce.as_str().bytes().all(|byte| byte.is_ascii_digit()));
    assert!(!nonce.as_str().contains('|'));
    assert_eq!(decrypt_text(KS, step4.as_str()).unwrap(), nonce.as_str());
}

#[test]
fn step4_nonce_is_random_on_repeat_calls() {
    let samples: std::collections::HashSet<String> = (0..20)
        .map(|_| make_step4(&key(KS)).0.as_str().to_string())
        .collect();
    assert!(samples.len() > 1);
}

#[test]
fn step5_contains_f_of_n2() {
    let (nonce, step4) = make_step4(&key(KS));
    let step5 = make_step5(&key(KS), &step4).unwrap();
    let expected = (nonce.as_str().parse::<u64>().unwrap() + 1).to_string();
    assert_eq!(decrypt_text(KS, step5.as_str()).unwrap(), expected);
}

#[test]
fn verify_accepts_correct_proof() {
    let (nonce, step4) = make_step4(&key(KS));
    let step5 = make_step5(&key(KS), &step4).unwrap();
    assert!(verify_step5(&key(KS), &nonce, &step5).unwrap());
}

#[test]
fn verify_rejects_f_of_n2_plus_two() {
    let (nonce, _) = make_step4(&key(KS));
    let plus_two = (nonce.as_str().parse::<u64>().unwrap() + 2).to_string();
    let step5 = encrypt_text(KS, &plus_two).unwrap();
    assert!(!verify_step5(&key(KS), &nonce, &step5).unwrap());
}

#[test]
fn verify_rejects_replayed_nonce() {
    let (nonce, _) = make_step4(&key(KS));
    let (_, fresh_step4) = make_step4(&key(KS));
    let fresh_step5 = make_step5(&key(KS), &fresh_step4).unwrap();
    assert!(!verify_step5(&key(KS), &nonce, &fresh_step5).unwrap());
}

#[test]
fn generated_nonces_have_eight_digits_and_no_leading_zero() {
    for _ in 0..50 {
        let nonce = new_nonce();
        assert_eq!(nonce.as_str().len(), 8);
        assert!(nonce.as_str().bytes().all(|byte| byte.is_ascii_digit()));
        assert!(!nonce.as_str().starts_with('0'));
    }
}

#[test]
fn f_increments_decimal_strings() {
    assert_eq!(f("9").unwrap(), "10");
    assert_eq!(f("0009").unwrap(), "10");
    assert_eq!(f("7311").unwrap(), "7312");
    assert!(f("12a").is_err());
    assert!(f("").is_err());
}
