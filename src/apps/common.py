from ..crypto.codec import AsciiError, KeyLengthError, key_to_bytes
from ..protocol.messages import MessageError, _validate_field


def prompt_text(label, default=None):
    while True:
        suffix = f" (default {default}): " if default else ": "
        value = input(label + suffix).strip()
        if value:
            return value
        if default:
            return default


def prompt_port(label, default=None):
    while True:
        suffix = f" (default {default}): " if default else ": "
        raw = input(label + suffix).strip()
        if not raw and default:
            return default
        try:
            port = int(raw)
            if not 0 < port < 65536:
                raise ValueError
            return port
        except ValueError:
            print("-> must be an integer 1..65535")


def prompt_id(label):
    while True:
        value = input(label + ": ").strip()
        try:
            _validate_field(value, "id")
            return value
        except MessageError as e:
            print("->", e)


def prompt_key(label):
    while True:
        value = input(label + " (exactly 16 ASCII chars): ").strip()
        try:
            key_to_bytes(value)
            return value
        except (KeyLengthError, AsciiError) as e:
            print("->", e)
