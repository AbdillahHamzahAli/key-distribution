import unittest

from src.crypto import aes

KEY_FIPS = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
BLOCK_FIPS = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
Cipher_FIPS = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

KEY_C1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
BLOCK_C1 = bytes.fromhex("00112233445566778899aabbccddeeff")
Cipher_C1 = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

KEY_SP = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestKeyExpansion(unittest.TestCase):
    def test_returns_11_round_keys(self):
        rks = aes.key_expansion(KEY_FIPS)
        self.assertEqual(len(rks), 11)
        for rk in rks:
            self.assertEqual(len(rk), 16)

    def test_first_round_key_is_key(self):
        rks = aes.key_expansion(KEY_FIPS)
        self.assertEqual(bytes(rks[0]), KEY_FIPS)

    def test_last_round_key_sp800(self):
        rks = aes.key_expansion(KEY_FIPS)
        self.assertEqual(bytes(rks[10]), bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6"))

    def test_all_round_keys_distinct(self):
        rks = aes.key_expansion(KEY_SP)
        self.assertEqual(len(set(rks)), 11)

    def test_wrong_key_length(self):
        with self.assertRaises(ValueError):
            aes.key_expansion(b"short")


class TestTransforms(unittest.TestCase):
    def test_sub_bytes_known(self):
        self.assertEqual(
            bytes(aes.sub_bytes(list(bytes.fromhex("530001CA")))),
            bytes.fromhex("ED637C74"),
        )

    def test_sub_inv_sub_identity(self):
        st = list(range(16))
        self.assertEqual(aes.inv_sub_bytes(aes.sub_bytes(st)), st)

    def test_shift_rows_known(self):
        st = list(bytes.fromhex("00112233445566778899aabbccddeeff"))
        out = aes.shift_rows(st)
        self.assertEqual(bytes(out), bytes.fromhex("0055aaff4499ee3388dd2277cc1166bb"))

    def test_shift_inv_shift_identity(self):
        st = list(range(16))
        self.assertEqual(aes.inv_shift_rows(aes.shift_rows(st)), st)

    def test_mix_inv_mix_identity(self):
        st = list(bytes.fromhex("00112233445566778899aabbccddeeff"))
        self.assertEqual(
            bytes(aes.inv_mix_columns(aes.mix_columns(st))),
            bytes(st),
        )

    def test_add_round_key_involution(self):
        st = list(bytes.fromhex("00112233445566778899aabbccddeeff"))
        self.assertEqual(
            bytes(aes.add_round_key(aes.add_round_key(st, st), st)),
            bytes(st),
        )


class TestEncryptDecrypt(unittest.TestCase):
    def test_fips_appendix_b(self):
        self.assertEqual(aes.encrypt_block(BLOCK_FIPS, KEY_FIPS), Cipher_FIPS)

    def test_fips_appendix_c1(self):
        self.assertEqual(aes.encrypt_block(BLOCK_C1, KEY_C1), Cipher_C1)

    def test_decrypt_fips_appendix_b(self):
        self.assertEqual(aes.decrypt_block(Cipher_FIPS, KEY_FIPS), BLOCK_FIPS)

    def test_decrypt_fips_appendix_c1(self):
        self.assertEqual(aes.decrypt_block(Cipher_C1, KEY_C1), BLOCK_C1)

    def test_roundtrip_random(self):
        import os
        for _ in range(20):
            key = os.urandom(16)
            block = os.urandom(16)
            self.assertEqual(
                aes.decrypt_block(aes.encrypt_block(block, key), key),
                block,
            )

    def test_wrong_block_length(self):
        with self.assertRaises(ValueError):
            aes.encrypt_block(b"tooshort", KEY_FIPS)


if __name__ == "__main__":
    unittest.main()
