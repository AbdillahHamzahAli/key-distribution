use key_distribution::crypto::aes::encrypt_block;
use key_distribution::crypto::codec::{CodecError, Hex};
use key_distribution::crypto::modes::{
    ModeError, cbc_decrypt, cbc_encrypt, decrypt_text, encrypt_text, pkcs7_pad, pkcs7_unpad,
};

const KEY: &[u8; 16] = b"KDCSecretKey1234";

#[test]
fn pad_to_block_multiple() {
    for size in [0usize, 1, 5, 15, 16, 17, 31, 32] {
        let padded = pkcs7_pad(&vec![b'A'; size]);
        assert_eq!(padded.len() % 16, 0);
        assert!(!padded.is_empty());
    }
}

#[test]
fn pad_value_is_correct() {
    assert_eq!(&pkcs7_pad(b"hello")[5..], &[11u8; 11]);
    assert_eq!(&pkcs7_pad(&[b'x'; 16])[16..], &[16u8; 16]);
}

#[test]
fn exact_block_gets_a_full_pad() {
    assert_eq!(pkcs7_pad(&[b'z'; 16]).len(), 32);
}

#[test]
fn unpad_roundtrips_lengths() {
    for size in [0usize, 1, 5, 15, 16, 17, 100, 133] {
        let data = vec![b'D'; size];
        assert_eq!(pkcs7_unpad(&pkcs7_pad(&data)).unwrap(), data);
    }
}

#[test]
fn unpad_rejects_empty_and_bad_lengths() {
    assert!(matches!(
        pkcs7_unpad(b""),
        Err(ModeError::DataLength {
            len: 0,
            block_size: 16
        })
    ));
    assert!(matches!(
        pkcs7_unpad(&[b'A'; 10]),
        Err(ModeError::DataLength { len: 10, .. })
    ));
}

#[test]
fn unpad_rejects_invalid_pad_value() {
    let mut bad = vec![b'B'; 15];
    bad.push(200);
    assert!(matches!(
        pkcs7_unpad(&bad),
        Err(ModeError::PaddingValue(200))
    ));
}

#[test]
fn unpad_rejects_wrong_pad_bytes() {
    let mut bad = vec![b'B'; 14];
    bad.extend_from_slice(&[3, 2]);
    assert!(matches!(pkcs7_unpad(&bad), Err(ModeError::PaddingBytes)));
}

#[test]
fn cbc_roundtrips_various_lengths() {
    for size in [0usize, 1, 16, 17, 33, 128] {
        let data = vec![0x5Au8; size];
        let encrypted = cbc_encrypt(&data, KEY).unwrap();
        assert_eq!(cbc_decrypt(&encrypted, KEY).unwrap(), data);
    }
}

#[test]
fn iv_is_random() {
    let data = b"same plaintext";
    let first = cbc_encrypt(data, KEY).unwrap();
    let second = cbc_encrypt(data, KEY).unwrap();
    assert_ne!(first, second);
    assert_ne!(first[..16], second[..16]);
}

#[test]
fn first_block_matches_ecb_xor_iv() {
    let plaintext = b"0123456789abcdef";
    let out = cbc_encrypt(plaintext, KEY).unwrap();
    let iv = &out[..16];
    let mut xored = [0u8; 16];
    for index in 0..16 {
        xored[index] = plaintext[index] ^ iv[index];
    }
    assert_eq!(&out[16..32], encrypt_block(&xored, KEY).unwrap());
}

#[test]
fn wrong_key_does_not_recover_plaintext() {
    let plaintext = b"attack at midnight";
    let encrypted = cbc_encrypt(plaintext, KEY).unwrap();

    for index in 0..32 {
        let mut wrong = format!("{index}");
        while wrong.len() < 16 {
            wrong.push('x');
        }
        match cbc_decrypt(&encrypted, wrong.as_bytes()) {
            Ok(recovered) => assert_ne!(recovered, plaintext),
            Err(ModeError::PaddingBytes | ModeError::PaddingValue(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

#[test]
fn cbc_rejects_bad_length() {
    assert!(matches!(
        cbc_decrypt(b"non16so*short!", KEY),
        Err(ModeError::CipherLength(_))
    ));
}

#[test]
fn text_wrappers_roundtrip() {
    let text = "Hello Bob, this is Alice @ KDC!";
    let hex = encrypt_text("MySecretKey12345", text).unwrap();
    assert_eq!(hex.as_str(), hex.as_str().to_uppercase());
    assert_eq!(hex.as_str().len() % 32, 0);
    assert_eq!(
        decrypt_text("MySecretKey12345", hex.as_str()).unwrap(),
        text
    );
}

#[test]
fn text_wrappers_reject_bad_key() {
    assert!(matches!(
        encrypt_text("short", "hi"),
        Err(ModeError::Codec(CodecError::KeyLength(5)))
    ));
}

#[test]
fn text_wrappers_reject_non_ascii_text() {
    assert!(matches!(
        encrypt_text("MySecretKey12345", "héllo"),
        Err(ModeError::Codec(CodecError::Ascii(_)))
    ));
}

#[test]
fn text_wrappers_reject_bad_hex() {
    assert!(matches!(
        decrypt_text("MySecretKey12345", "ZZ00"),
        Err(ModeError::Codec(CodecError::InvalidHex(_)))
    ));
    assert!(matches!(
        decrypt_text("MySecretKey12345", "ABC"),
        Err(ModeError::Codec(CodecError::OddHex(_)))
    ));
}

#[test]
fn hex_newtype_roundtrip() {
    let hex = Hex::new("ABCDEF").unwrap();
    assert_eq!(hex.as_str(), "ABCDEF");
}
