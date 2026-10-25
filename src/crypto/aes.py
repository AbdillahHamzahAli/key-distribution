from .tables import INV_SBOX, RCON, S_BOX, _gmul


def _require_block(block):
    if len(block) != 16:
        raise ValueError(f"block must be 16 bytes, got {len(block)}")


def _require_key(key):
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")


def _xor_word(a, b):
    return [x ^ y for x, y in zip(a, b)]


def _rot_word(word):
    return word[1:] + word[:1]


def _sub_word(word):
    return [S_BOX[b] for b in word]


def key_expansion(key):
    _require_key(key)
    words = [[key[4 * i + j] for j in range(4)] for i in range(4)]
    for i in range(4, 44):
        temp = words[i - 1]
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp = _xor_word(temp, [RCON[i // 4 - 1], 0, 0, 0])
        words.append(_xor_word(words[i - 4], temp))
    return [tuple(b for w in words[4 * r:4 * r + 4] for b in w) for r in range(11)]


def sub_bytes(state):
    return [S_BOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    out = list(state)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r + 4 * ((c + r) % 4)]
    return out


def inv_shift_rows(state):
    out = list(state)
    for r in range(4):
        for c in range(4):
            out[r + 4 * ((c + r) % 4)] = state[r + 4 * c]
    return out


def mix_columns(state):
    out = list(state)
    for c in range(4):
        s = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(s[0], 0x02) ^ _gmul(s[1], 0x03) ^ s[2] ^ s[3]
        out[4 * c + 1] = s[0] ^ _gmul(s[1], 0x02) ^ _gmul(s[2], 0x03) ^ s[3]
        out[4 * c + 2] = s[0] ^ s[1] ^ _gmul(s[2], 0x02) ^ _gmul(s[3], 0x03)
        out[4 * c + 3] = _gmul(s[0], 0x03) ^ s[1] ^ s[2] ^ _gmul(s[3], 0x02)
    return out


def inv_mix_columns(state):
    out = list(state)
    for c in range(4):
        s = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gmul(s[0], 0x0E) ^ _gmul(s[1], 0x0B) ^ _gmul(s[2], 0x0D) ^ _gmul(s[3], 0x09)
        out[4 * c + 1] = _gmul(s[0], 0x09) ^ _gmul(s[1], 0x0E) ^ _gmul(s[2], 0x0B) ^ _gmul(s[3], 0x0D)
        out[4 * c + 2] = _gmul(s[0], 0x0D) ^ _gmul(s[1], 0x09) ^ _gmul(s[2], 0x0E) ^ _gmul(s[3], 0x0B)
        out[4 * c + 3] = _gmul(s[0], 0x0B) ^ _gmul(s[1], 0x0D) ^ _gmul(s[2], 0x09) ^ _gmul(s[3], 0x0E)
    return out


def add_round_key(state, round_key):
    return [b ^ k for b, k in zip(state, round_key)]


def encrypt_block(block, key):
    _require_block(block)
    _require_key(key)
    round_keys = key_expansion(key)
    state = add_round_key(list(block), round_keys[0])
    for r in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return bytes(state)


def decrypt_block(block, key):
    _require_block(block)
    _require_key(key)
    round_keys = key_expansion(key)
    state = list(block)
    state = add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return bytes(state)
