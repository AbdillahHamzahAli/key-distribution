import unittest

from src.crypto.codec import hex_to_bytes
from src.crypto.modes import decrypt_text
from src.protocol.kdc_logic import (
    ALPHABET,
    DELIM,
    MessageError,
    generate_session_key,
    handle_step1,
)

KEYS = {
    "alice": "AliceKey12345678",
    "bob": "BobKey1111111111",
}


class TestGenerateSessionKey(unittest.TestCase):
    def test_length_is_16(self):
        self.assertEqual(len(generate_session_key()), 16)

    def test_printable_ascii_without_delim(self):
        for _ in range(50):
            ks = generate_session_key()
            for c in ks:
                self.assertIn(c, ALPHABET)
            self.assertNotIn(DELIM, ks)
            self.assertNotIn(" ", ks)

    def test_random_on_repeat_calls(self):
        samples = {generate_session_key() for _ in range(20)}
        self.assertGreater(len(samples), 1)


class TestHandleStep1(unittest.TestCase):
    def test_returns_two_hex_parts(self):
        hex_a, hex_b = handle_step1(KEYS, "alice", "bob", "7311")
        for part in (hex_a, hex_b):
            self.assertEqual(part, part.upper())
            self.assertEqual(len(hex_to_bytes(part)) % 16, 0)
            self.assertGreater(len(hex_to_bytes(part)), 0)

    def test_part_a_decrypts_to_ks_ida_idb_n1(self):
        hex_a, _ = handle_step1(KEYS, "alice", "bob", "7311")
        plain = decrypt_text(KEYS["alice"], hex_a)
        fields = plain.split(DELIM)
        self.assertEqual(len(fields), 4)
        ks, ida, idb, n1 = fields
        self.assertEqual(ida, "alice")
        self.assertEqual(idb, "bob")
        self.assertEqual(n1, "7311")
        self.assertEqual(len(ks), 16)

    def test_part_b_decrypts_to_ks_ida(self):
        _, hex_b = handle_step1(KEYS, "alice", "bob", "7311")
        plain = decrypt_text(KEYS["bob"], hex_b)
        fields = plain.split(DELIM)
        self.assertEqual(len(fields), 2)
        self.assertEqual(fields[1], "alice")

    def test_same_ks_in_both_parts(self):
        hex_a, hex_b = handle_step1(KEYS, "alice", "bob", "7311")
        ks_a = decrypt_text(KEYS["alice"], hex_a).split(DELIM)[0]
        ks_b = decrypt_text(KEYS["bob"], hex_b).split(DELIM)[0]
        self.assertEqual(ks_a, ks_b)

    def test_unknown_identity_rejected(self):
        with self.assertRaises(MessageError):
            handle_step1(KEYS, "mallory", "bob", "7311")
        with self.assertRaises(MessageError):
            handle_step1(KEYS, "alice", "mallory", "7311")

    def test_same_identity_rejected(self):
        with self.assertRaises(MessageError):
            handle_step1(KEYS, "alice", "alice", "7311")

    def test_field_with_delim_rejected(self):
        with self.assertRaises(MessageError):
            handle_step1(KEYS, "alice", "bo|b", "7311")

    def test_nonce_freshness(self):
        a1, b1 = handle_step1(KEYS, "alice", "bob", "7311")
        a2, b2 = handle_step1(KEYS, "alice", "bob", "7311")
        self.assertNotEqual(a1, a2)
        self.assertNotEqual(b1, b2)


if __name__ == "__main__":
    unittest.main()
