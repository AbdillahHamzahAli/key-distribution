from ..crypto.codec import AsciiError, ascii_to_bytes

DELIM = "|"
LINE_ENDINGS = ("\r\n", "\n")


class MessageError(ValueError):
    pass


def _validate_field(field, role):
    if not isinstance(field, str):
        raise MessageError(f"{role} must be str, got {type(field).__name__}")
    if field == "":
        raise MessageError(f"{role} must not be empty")
    try:
        ascii_to_bytes(field)
    except AsciiError:
        raise MessageError(f"{role} must be ASCII only: {field!r}") from None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in field):
        raise MessageError(f"{role} must not contain control characters: {field!r}")
    if DELIM in field:
        raise MessageError(f"{role} must not contain {DELIM!r}: {field!r}")
    return field


def build_line(step, *fields):
    _validate_field(step, "step")
    for field in fields:
        _validate_field(field, "field")
    return DELIM.join((step,) + fields)


def parse_line(line):
    if not isinstance(line, str):
        raise MessageError(f"line must be str, got {type(line).__name__}")
    for ending in LINE_ENDINGS:
        if line.endswith(ending):
            line = line[: -len(ending)]
            break
    parts = line.split(DELIM)
    step = parts[0]
    _validate_field(step, "step")
    fields = tuple(_validate_field(f, "field") for f in parts[1:])
    return step, fields
