import unittest

from src.crypto.tables import INV_SBOX, RCON, S_BOX, _gmul


class TestSBox(unittest.TestCase):
    def test_known_fips_values(self):
        self.assertEqual(S_BOX[0x00], 0x63)
        self.assertEqual(S_BOX[0x01], 0x7C)
        self.assertEqual(S_BOX[0x53], 0xED)
        self.assertEqual(S_BOX[0xCA], 0x74)

    def test_is_permutation(self):
        self.assertEqual(sorted(S_BOX), list(range(256)))

    def test_first_row(self):
        self.assertEqual(
            S_BOX[:16],
            (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
             0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76),
        )


class TestInvSBox(unittest.TestCase):
    def test_known_fips_values(self):
        self.assertEqual(INV_SBOX[0x63], 0x00)
        self.assertEqual(INV_SBOX[0xED], 0x53)

    def test_inverse_of_sbox(self):
        for i in range(256):
            self.assertEqual(INV_SBOX[S_BOX[i]], i)

    def test_is_permutation(self):
        self.assertEqual(sorted(INV_SBOX), list(range(256)))


class TestRcon(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(RCON[0], 0x01)
        self.assertEqual(RCON[1], 0x02)
        self.assertEqual(RCON[9], 0x36)

    def test_length_15(self):
        self.assertEqual(len(RCON), 15)


class TestGmul(unittest.TestCase):
    def test_known_product(self):
        self.assertEqual(_gmul(0x57, 0x83), 0xC1)
        self.assertEqual(_gmul(0x53, 0xCA), 0x01)

    def test_identity(self):
        for x in (0x01, 0x53, 0xFF):
            self.assertEqual(_gmul(x, 0x01), x)


if __name__ == "__main__":
    unittest.main()
