import os
import unittest

from src.crypto import modes
from src.crypto.aes import encrypt_block
from src.crypto.codec import AsciiError, HexError, KeyLengthError

KEY = b"KDCSecretKey1234"


class TestPkcs7Pad(unittest.TestCase):
    def test_pad_to_block_multiple(self):
        for n in (0, 1, 5, 15, 16, 17, 31, 32):
            padded = modes.pkcs7_pad(b"A" * n)
            self.assertEqual(len(padded) % 16, 0)
            self.assertGreater(len(padded), 0)

    def test_pad_value(self):
        self.assertEqual(modes.pkcs7_pad(b"hello")[-11:], bytes([11]) * 11)
        self.assertEqual(modes.pkcs7_pad(b"x" * 16)[-16:], bytes([16]) * 16)

    def test_exact_block_gets_full_pad(self):
        self.assertEqual(len(modes.pkcs7_pad(b"z" * 16)), 32)


class TestPkcs7Unpad(unittest.TestCase):
    def test_roundtrip_lengths(self):
        for n in (0, 1, 5, 15, 16, 17, 100, 133):
            self.assertEqual(modes.pkcs7_unpad(modes.pkcs7_pad(b"D" * n)), b"D" * n)

    def test_reject_empty(self):
        with self.assertRaises(modes.DataLengthError):
            modes.pkcs7_unpad(b"")

    def test_reject_bad_length(self):
        with self.assertRaises(modes.DataLengthError):
            modes.pkcs7_unpad(b"A" * 10)

    def test_reject_invalid_pad_value(self):
        bad = b"B" * 15 + bytes([200])
        with self.assertRaises(modes.PaddingError):
            modes.pkcs7_unpad(bad)

    def test_reject_wrong_pad_bytes(self):
        bad = b"B" * 14 + bytes([3, 2])
        with self.assertRaises(modes.PaddingError):
            modes.pkcs7_unpad(bad)


class TestCbc(unittest.TestCase):
    def test_roundtrip_various_lengths(self):
        for n in (0, 1, 16, 17, 33, 128):
            data = os.urandom(n)
            self.assertEqual(modes.cbc_decrypt(modes.cbc_encrypt(data, KEY), KEY), data)

    def test_iv_is_random(self):
        data = b"same plaintext"
        c1 = modes.cbc_encrypt(data, KEY)
        c2 = modes.cbc_encrypt(data, KEY)
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(c1[:16], c2[:16])

    def test_first_block_matches_ecb_xor_iv(self):
        pt = b"0123456789abcdef"
        out = modes.cbc_encrypt(pt, KEY)
        iv = out[:16]
        expect = encrypt_block(bytes(x ^ y for x, y in zip(pt, iv)), KEY)
        self.assertEqual(out[16:32], expect)

    def test_wrong_key_fails(self):
        pt = b"attack at midnight"
        enc = modes.cbc_encrypt(pt, KEY)
        for i in range(32):
            wrong = bytes(str(i).ljust(16, "x"), "ascii")
            try:
                plain = modes.cbc_decrypt(enc, wrong)
            except modes.PaddingError:
                continue
            self.assertNotEqual(plain, pt)

    def test_reject_bad_length(self):
        with self.assertRaises(modes.DataLengthError):
            modes.cbc_decrypt(b"non16so*short!", KEY)


class TestTextWrappers(unittest.TestCase):
    def test_roundtrip(self):
        text = "Hello Bob, this is Alice @ KDC!"
        hexstr = modes.encrypt_text("MySecretKey12345", text)
        self.assertEqual(hexstr, hexstr.upper())
        self.assertEqual(len(hexstr) % 32, 0)
        self.assertEqual(modes.decrypt_text("MySecretKey12345", hexstr), text)

    def test_reject_bad_key(self):
        with self.assertRaises(KeyLengthError):
            modes.encrypt_text("short", "hi")

    def test_reject_non_ascii_text(self):
        with self.assertRaises(AsciiError):
            modes.encrypt_text("MySecretKey12345", "héllo")

    def test_reject_bad_hex(self):
        with self.assertRaises(HexError):
            modes.decrypt_text("MySecretKey12345", "ZZ00")


if __name__ == "__main__":
    unittest.main()
