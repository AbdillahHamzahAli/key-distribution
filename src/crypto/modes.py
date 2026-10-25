import secrets

from .aes import decrypt_block, encrypt_block
from .codec import ascii_to_bytes, bytes_to_ascii, bytes_to_hex, hex_to_bytes, key_to_bytes


class PaddingError(ValueError):
    pass


class DataLengthError(ValueError):
    pass


def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return bytes(data) + bytes([pad_len]) * pad_len


def pkcs7_unpad(data, block_size=16):
    if len(data) == 0 or len(data) % block_size != 0:
        raise DataLengthError(f"padded data must be a non-empty multiple of {block_size}, got {len(data)}")
    pad_len = data[-1]
    if not 1 <= pad_len <= block_size:
        raise PaddingError(f"invalid padding value: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise PaddingError("invalid padding bytes")
    return data[:-pad_len]


def cbc_encrypt(plaintext, key):
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    padded = pkcs7_pad(plaintext)
    iv = secrets.token_bytes(16)
    out = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(x ^ y for x, y in zip(padded[i:i + 16], prev))
        enc = encrypt_block(block, key)
        out.extend(enc)
        prev = enc
    return bytes(out)


def cbc_decrypt(data, key):
    if len(data) == 0 or len(data) % 16 != 0:
        raise DataLengthError(f"data must be a non-empty multiple of 16 bytes (IV + ciphertext), got {len(data)}")
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    prev = bytes(data[:16])
    out = bytearray()
    for i in range(16, len(data), 16):
        block = bytes(data[i:i + 16])
        plain = decrypt_block(block, key)
        out.extend(x ^ y for x, y in zip(plain, prev))
        prev = block
    return pkcs7_unpad(bytes(out))


def encrypt_text(key_ascii, text_ascii):
    key = key_to_bytes(key_ascii)
    plaintext = ascii_to_bytes(text_ascii)
    return bytes_to_hex(cbc_encrypt(plaintext, key))


def decrypt_text(key_ascii, hex_str):
    key = key_to_bytes(key_ascii)
    data = hex_to_bytes(hex_str)
    return bytes_to_ascii(cbc_decrypt(data, key))
