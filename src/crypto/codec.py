class AsciiError(ValueError):
    pass


class HexError(ValueError):
    pass


class KeyLengthError(ValueError):
    pass


def ascii_to_bytes(text):
    try:
        return text.encode("ascii")
    except UnicodeEncodeError as e:
        raise AsciiError(f"input must be ASCII only: invalid character at index {e.start}") from None


def bytes_to_ascii(data):
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as e:
        raise AsciiError(f"data is not printable ASCII: invalid byte at index {e.start}") from None


def bytes_to_hex(data):
    return data.hex().upper()


def hex_to_bytes(hexstr):
    cleaned = "".join(hexstr.split())
    if len(cleaned) % 2 != 0:
        raise HexError(f"hex string must have an even number of digits, got {len(cleaned)}")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        bad = [c for c in cleaned if c not in "0123456789abcdefABCDEF"]
        raise HexError(f"invalid hex characters: {''.join(sorted(set(bad)))}") from None


def key_to_bytes(key):
    data = ascii_to_bytes(key)
    if len(data) != 16:
        raise KeyLengthError(f"AES-128 key must be exactly 16 characters, got {len(data)}")
    return data
