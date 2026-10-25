import unittest

from src.crypto.codec import (
    AsciiError,
    HexError,
    KeyLengthError,
    ascii_to_bytes,
    bytes_to_ascii,
    bytes_to_hex,
    hex_to_bytes,
    key_to_bytes,
)


class TestAsciiToBytes(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(bytes_to_ascii(ascii_to_bytes("hello")), "hello")

    def test_empty(self):
        self.assertEqual(ascii_to_bytes(""), b"")
        self.assertEqual(bytes_to_ascii(b""), "")

    def test_reject_non_ascii(self):
        with self.assertRaises(AsciiError):
            ascii_to_bytes("héllo")

    def test_error_is_valueerror(self):
        with self.assertRaises(ValueError):
            ascii_to_bytes("τ yogurt")


class TestBytesToHexRoundtrip(unittest.TestCase):
    def test_uppercase_no_prefix(self):
        self.assertEqual(bytes_to_hex(b"hello"), "68656C6C6F")

    def test_empty(self):
        self.assertEqual(bytes_to_hex(b""), "")

    def test_hex_to_bytes_roundtrip(self):
        data = b"\x00\x1b\xff secret \x41"
        self.assertEqual(hex_to_bytes(bytes_to_hex(data)), data)

    def test_lower_and_whitespace_tolerated(self):
        self.assertEqual(hex_to_bytes("68 65 6C   6C\n6f"), b"hello")
        self.assertEqual(hex_to_bytes("68656c6c6f"), b"hello")


class TestHexToBytesErrors(unittest.TestCase):
    def test_odd_length(self):
        with self.assertRaises(HexError):
            hex_to_bytes("ABC")

    def test_invalid_chars(self):
        with self.assertRaises(HexError):
            hex_to_bytes("68-65")

    def test_error_is_valueerror(self):
        with self.assertRaises(ValueError):
            hex_to_bytes("ZZ00")


class TestKeyToBytes(unittest.TestCase):
    KEY_16 = "MySecretKey12345"

    def test_valid_key(self):
        key = key_to_bytes(self.KEY_16)
        self.assertEqual(key, b"MySecretKey12345")
        self.assertEqual(len(key), 16)

    def test_too_short(self):
        with self.assertRaises(KeyLengthError):
            key_to_bytes("short")

    def test_too_long(self):
        with self.assertRaises(KeyLengthError):
            key_to_bytes("kfullfiller160")

    def test_non_ascii_key(self):
        with self.assertRaises(AsciiError):
            key_to_bytes("hellötüsch")


if __name__ == "__main__":
    unittest.main()
