import secrets

from .messages import DELIM, MessageError, _validate_field

from ..crypto.modes import encrypt_text

ALPHABET = "".join(chr(i) for i in range(0x21, 0x7F) if chr(i) != DELIM)


def generate_session_key():
    return "".join(secrets.choice(ALPHABET) for _ in range(16))


def handle_step1(keys, ida, idb, n1):
    _validate_field(ida, "ida")
    _validate_field(idb, "idb")
    _validate_field(n1, "n1")
    if ida == idb:
        raise MessageError(f"initiator and responder must differ, both are {ida!r}")
    if ida not in keys:
        raise MessageError(f"unknown identity: {ida!r}")
    if idb not in keys:
        raise MessageError(f"unknown identity: {idb!r}")
    ks = generate_session_key()
    for_part_a = build_plaintext(ks, ida, idb, n1)
    for_part_b = build_plaintext(ks, ida)
    return encrypt_text(keys[ida], for_part_a), encrypt_text(keys[idb], for_part_b)


def build_plaintext(*fields):
    return DELIM.join(fields)
