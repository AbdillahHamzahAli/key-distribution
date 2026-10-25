def _gmul(a, b):
    result = 0
    while b:
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return result


def _inverse(a):
    if a == 0:
        return 0
    for x in range(1, 256):
        if _gmul(a, x) == 1:
            return x
    raise RuntimeError("no multiplicative inverse found")


def _affine(inv):
    out = 0
    for i in range(8):
        bit = (inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^ (inv >> ((i + 6) % 8)) ^ (inv >> ((i + 7) % 8))
        out |= (((bit & 1) ^ ((0x63 >> i) & 1)) << i)
    return out


S_BOX = tuple(_affine(_inverse(i)) for i in range(256))

inv = [0 for _ in range(256)]
for i, s in enumerate(S_BOX):
    inv[s] = i
INV_SBOX = tuple(inv)

RCON = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
)
