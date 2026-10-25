import secrets

from .messages import MessageError, _validate_field

from ..crypto.modes import decrypt_text, encrypt_text

NONCE_LENGTH = 8
NONCE_ALPHABET = "0123456789"


def new_nonce():
    first = secrets.choice("123456789")
    rest = "".join(secrets.choice(NONCE_ALPHABET) for _ in range(NONCE_LENGTH - 1))
    return first + rest


def _f(n2):
    if not n2 or any(c not in NONCE_ALPHABET for c in n2):
        raise MessageError(f"nonce must be decimal digits, got {n2!r}")
    return str(int(n2) + 1)


def parse_step2(ka, hex_a, n1, ida=None, idb=None):
    _validate_field(n1, "n1")
    plain = decrypt_text(ka, hex_a)
    fields = plain.split("|")
    if len(fields) != 4:
        raise MessageError(f"step2 part A must have 4 fields, got {len(fields)}")
    ks, part_ida, part_idb, part_n1 = fields
    if len(ks) != 16:
        raise MessageError(f"session key must be 16 characters, got {len(ks)}")
    if part_n1 != n1:
        raise MessageError(f"nonce mismatch: expected {n1!r}, sent {part_n1!r}")
    if ida is not None and part_ida != ida:
        raise MessageError(f"identity mismatch: expected {ida!r}, sent {part_ida!r}")
    if idb is not None and part_idb != idb:
        raise MessageError(f"identity mismatch: expected {idb!r}, sent {part_idb!r}")
    return ks


def parse_ticket(kb, hex_ticket):
    plain = decrypt_text(kb, hex_ticket)
    fields = plain.split("|")
    if len(fields) != 2:
        raise MessageError(f"ticket must have 2 fields, got {len(fields)}")
    ks, ida = fields
    if len(ks) != 16:
        raise MessageError(f"session key must be 16 characters, got {len(ks)}")
    _validate_field(ida, "ida")
    return ks, ida


def make_step4(ks):
    n2 = new_nonce()
    return n2, encrypt_text(ks, n2)


def make_step5(ks, hex_step4):
    n2 = decrypt_text(ks, hex_step4)
    return encrypt_text(ks, _f(n2))


def verify_step5(ks, n2, hex_step5):
    _f(n2)
    fn2 = decrypt_text(ks, hex_step5)
    if not fn2 or any(c not in NONCE_ALPHABET for c in fn2):
        raise MessageError(f"f(N2) must be decimal digits, got {fn2!r}")
    return int(fn2) == int(n2) + 1
