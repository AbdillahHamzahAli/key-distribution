use key_distribution::crypto::codec::Hex;
use key_distribution::protocol::messages::{Id, Message, MessageError, Nonce};

#[test]
fn step1_serializes_to_expected_json() {
    let message = Message::Step1 {
        initiator: Id::new("alice").unwrap(),
        responder: Id::new("bob").unwrap(),
        nonce: Nonce::new("7311").unwrap(),
    };
    assert_eq!(
        message.to_line(),
        r#"{"type":"step1","initiator":"alice","responder":"bob","nonce":"7311"}"#
    );
}

#[test]
fn bye_serializes_to_expected_json() {
    assert_eq!(Message::Bye.to_line(), r#"{"type":"bye"}"#);
}

#[test]
fn messages_roundtrip() {
    let messages = vec![
        Message::Step1 {
            initiator: Id::new("alice").unwrap(),
            responder: Id::new("bob").unwrap(),
            nonce: Nonce::new("84671352").unwrap(),
        },
        Message::Step2 {
            for_initiator: Hex::new("AABB").unwrap(),
            ticket: Hex::new("CCDD").unwrap(),
        },
        Message::Step3 {
            ticket: Hex::new("CCDD").unwrap(),
        },
        Message::Step4 {
            ciphertext: Hex::new("0102").unwrap(),
        },
        Message::Step5 {
            ciphertext: Hex::new("0304").unwrap(),
        },
        Message::Msg {
            ciphertext: Hex::new("0506").unwrap(),
        },
        Message::Bye,
        Message::Error {
            message: "boom".to_string(),
        },
    ];

    for message in messages {
        assert_eq!(Message::parse(&message.to_line()).unwrap(), message);
    }
}

#[test]
fn parsing_normalises_hex_to_uppercase() {
    let message = Message::parse(r#"{"type":"step3","ticket":"abcd"}"#).unwrap();
    assert_eq!(
        message,
        Message::Step3 {
            ticket: Hex::new("ABCD").unwrap()
        }
    );
    assert!(message.to_line().contains("\"ticket\":\"ABCD\""));
}

#[test]
fn parsing_strips_line_endings() {
    let parsed = Message::parse("{\"type\":\"bye\"}\r\n").unwrap();
    assert_eq!(parsed, Message::Bye);
}

#[test]
fn invalid_json_is_rejected() {
    assert!(matches!(
        Message::parse("not json"),
        Err(MessageError::Json(_))
    ));
}

#[test]
fn unknown_message_type_is_rejected() {
    assert!(Message::parse(r#"{"type":"unknown"}"#).is_err());
}

#[test]
fn identities_are_validated() {
    assert!(matches!(
        Id::new(""),
        Err(MessageError::Empty { field: "identity" })
    ));
    assert!(matches!(
        Id::new("alïce"),
        Err(MessageError::NotAscii { .. })
    ));
    assert!(matches!(
        Id::new("ali\nce"),
        Err(MessageError::ControlChar { .. })
    ));
    assert!(matches!(
        Id::new("bo|b"),
        Err(MessageError::Delimiter { .. })
    ));
    assert!(Id::new("alice").is_ok());
    assert!(Id::new("Alice Smith").is_ok());
}

#[test]
fn nonces_must_be_decimal_digits() {
    assert!(Nonce::new("7311").is_ok());
    assert!(Nonce::new("84671352").is_ok());
    assert!(matches!(
        Nonce::new("73a1"),
        Err(MessageError::NonceFormat { .. })
    ));
    assert!(matches!(
        Nonce::new(""),
        Err(MessageError::NonceFormat { .. })
    ));
}

#[test]
fn hex_payloads_must_be_valid_hex() {
    assert!(Message::parse(r#"{"type":"step3","ticket":"ABC"}"#).is_err());
    assert!(Message::parse(r#"{"type":"step3","ticket":"ZZ"}"#).is_err());
}

#[test]
fn message_kinds_are_stable() {
    assert_eq!(Message::Bye.kind(), "BYE");
    assert_eq!(
        Message::Step1 {
            initiator: Id::new("a").unwrap(),
            responder: Id::new("b").unwrap(),
            nonce: Nonce::new("1").unwrap(),
        }
        .kind(),
        "STEP1"
    );
}
