import unittest

from src.crypto.codec import KeyLengthError
from src.crypto.modes import decrypt_text, encrypt_text
from src.protocol.handshake import (
    MessageError,
    make_step4,
    make_step5,
    parse_step2,
    parse_ticket,
    verify_step5,
)
from src.protocol.kdc_logic import handle_step1

KA = "AliceKey12345678"
KB = "BobKey1111111111"
KS = "SessionKeyABC123"
KEYS = {"alice": KA, "bob": KB}
N1 = "7311"


def establish():
    hex_a, hex_b = handle_step1(KEYS, "alice", "bob", N1)
    ks = parse_step2(KA, hex_a, N1, ida="alice", idb="bob")
    ks_bob, ida = parse_ticket(KB, hex_b)
    return ks, ks_bob, ida, hex_b


class TestFullHandshake(unittest.TestCase):
    def test_end_to_end(self):
        ks, ks_bob, ida, _ = establish()
        self.assertEqual(ks, ks_bob)
        self.assertEqual(ida, "alice")
        n2, hex_step4 = make_step4(ks_bob)
        hex_step5 = make_step5(ks, hex_step4)
        self.assertTrue(verify_step5(ks_bob, n2, hex_step5))

    def test_wrong_n1_rejected(self):
        hex_a, _ = handle_step1(KEYS, "alice", "bob", N1)
        with self.assertRaises(MessageError):
            parse_step2(KA, hex_a, "9999")

    def test_id_mismatch_rejected(self):
        hex_a, _ = handle_step1(KEYS, "alice", "bob", N1)
        with self.assertRaises(MessageError):
            parse_step2(KA, hex_a, N1, idb="mallory")
        with self.assertRaises(MessageError):
            parse_step2(KA, hex_a, N1, ida="eve")

    def test_step2_five_fields_rejected(self):
        bogus = encrypt_text(KA, "|".join([KA] * 5))
        with self.assertRaises(MessageError):
            parse_step2(KA, bogus, N1)


class TestParseTicket(unittest.TestCase):
    def test_ticket_yields_ks_and_sender_id(self):
        _, ks_bob, ida, _ = establish()
        self.assertEqual(ida, "alice")
        self.assertEqual(len(ks_bob), 16)

    def test_ticket_ks_matches_alice_ks(self):
        ks, ks_bob, _, _ = establish()
        self.assertEqual(ks, ks_bob)

    def test_three_fields_rejected(self):
        bogus = encrypt_text(KB, "|".join([KB] * 3))
        with self.assertRaises(MessageError):
            parse_ticket(KB, bogus)

    def test_truncated_hex_rejected(self):
        with self.assertRaises(ValueError):
            parse_ticket(KB, "ABC")

    def test_bad_ticket_key_length(self):
        with self.assertRaises(KeyLengthError):
            parse_ticket("short", "ABCDEF")


class TestStep4Step5(unittest.TestCase):
    def test_step4_n2_is_digits_and_hex_uses_ks(self):
        n2, hex_step4 = make_step4(KS)
        self.assertTrue(n2.isdecimal())
        self.assertNotIn("|", n2)
        self.assertEqual(decrypt_text(KS, hex_step4), n2)

    def test_n2_random_on_repeat_calls(self):
        samples = {make_step4(KS)[0] for _ in range(20)}
        self.assertGreater(len(samples), 1)

    def test_step5_fn2_is_n2_plus_one(self):
        n2, hex_step4 = make_step4(KS)
        hex_step5 = make_step5(KS, hex_step4)
        self.assertEqual(decrypt_text(KS, hex_step5), str(int(n2) + 1))

    def test_verify_true_for_correct_fn2(self):
        n2, hex_step4 = make_step4(KS)
        hex_step5 = make_step5(KS, hex_step4)
        self.assertTrue(verify_step5(KS, n2, hex_step5))

    def test_verify_false_on_fn2_plus_two(self):
        n2, _ = make_step4(KS)
        fn2_plus_two = encrypt_text(KS, str(int(n2) + 2))
        self.assertFalse(verify_step5(KS, n2, fn2_plus_two))

    def test_verify_false_on_nonce_replay(self):
        n2, _ = make_step4(KS)
        _, hex_fresh = make_step4(KS)
        hex_step5_fresh = make_step5(KS, hex_fresh)
        self.assertFalse(verify_step5(KS, n2, hex_step5_fresh))

    def test_step4_key_length_enforced(self):
        with self.assertRaises(KeyLengthError):
            make_step4("short")


if __name__ == "__main__":
    unittest.main()
