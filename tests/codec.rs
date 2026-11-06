use key_distribution::crypto::codec::{
    CodecError, Hex, Key, ascii_to_bytes, bytes_to_ascii, bytes_to_hex, hex_to_bytes, key_to_bytes,
};

#[test]
fn ascii_roundtrip() {
    assert_eq!(
        bytes_to_ascii(&ascii_to_bytes("hello").unwrap()).unwrap(),
        "hello"
    );
}

#[test]
fn empty_ascii_is_allowed() {
    assert_eq!(ascii_to_bytes("").unwrap(), b"");
    assert_eq!(bytes_to_ascii(b"").unwrap(), "");
}

#[test]
fn non_ascii_text_is_rejected() {
    assert!(matches!(ascii_to_bytes("héllo"), Err(CodecError::Ascii(_))));
    assert!(ascii_to_bytes("τ yogurt").is_err());
}

#[test]
fn hex_output_is_uppercase_without_prefix() {
    assert_eq!(bytes_to_hex(b"hello"), "68656C6C6F");
    assert_eq!(bytes_to_hex(b""), "");
}

#[test]
fn hex_roundtrip() {
    let data = b"\x00\x1b\xff secret \x41";
    assert_eq!(hex_to_bytes(&bytes_to_hex(data)).unwrap(), data);
}

#[test]
fn lowercase_and_whitespace_hex_is_tolerated() {
    assert_eq!(hex_to_bytes("68 65 6C   6C\n6f").unwrap(), b"hello");
    assert_eq!(hex_to_bytes("68656c6c6f").unwrap(), b"hello");
}

#[test]
fn odd_length_hex_is_rejected() {
    assert!(matches!(hex_to_bytes("ABC"), Err(CodecError::OddHex(3))));
}

#[test]
fn invalid_hex_characters_are_rejected() {
    assert!(matches!(
        hex_to_bytes("68--65"),
        Err(CodecError::InvalidHex(_))
    ));
    assert!(hex_to_bytes("ZZ00").is_err());
}

#[test]
fn valid_key_converts_to_bytes() {
    let key = key_to_bytes("MySecretKey12345").expect("valid key");
    assert_eq!(&key, b"MySecretKey12345");
}

#[test]
fn short_and_long_keys_are_rejected() {
    assert!(matches!(
        key_to_bytes("short"),
        Err(CodecError::KeyLength(5))
    ));
    assert!(key_to_bytes("kfullfiller160").is_err());
}

#[test]
fn non_ascii_key_is_rejected() {
    assert!(matches!(
        key_to_bytes("hellötüsch"),
        Err(CodecError::Ascii(_))
    ));
}

#[test]
fn key_newtype_accepts_valid_keys() {
    let key = Key::new("MySecretKey12345").expect("valid key");
    assert_eq!(key.as_str(), "MySecretKey12345");
    assert_eq!(key.as_bytes(), b"MySecretKey12345");
    assert_eq!(format!("{key:?}"), "Key(\"***\")");
}

#[test]
fn hex_newtype_normalises_case() {
    let hex = Hex::new("abCD01").expect("valid hex");
    assert_eq!(hex.as_str(), "ABCD01");
    assert_eq!(Hex::from_bytes(b"\xab\xcd\x01").as_str(), "ABCD01");
}
