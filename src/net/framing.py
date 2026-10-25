import weakref

MAX_LINE = 65536
ENCODE = "utf-8"

PENDING = weakref.WeakKeyDictionary()


def _get_pending(sock):
    buffer = PENDING.get(sock)
    if buffer is None:
        buffer = bytearray()
        PENDING[sock] = buffer
    return buffer


def send_line(sock, text):
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    if "\n" in text or "\r" in text:
        raise ValueError("text must not contain line breaks")
    payload = (text + "\n").encode(ENCODE)
    total = 0
    while total < len(payload):
        sent = sock.send(payload[total:])
        if sent == 0:
            raise ConnectionError("socket connection broken during send")
        total += sent


def recv_line(sock):
    pending = _get_pending(sock)
    while True:
        if b"\n" in pending:
            line, _, rest = bytes(pending).partition(b"\n")
            pending[:] = rest
            return line.decode(ENCODE)
        if len(pending) > MAX_LINE:
            pending.clear()
            raise ConnectionError(f"line exceeds {MAX_LINE} bytes without newline")
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            raise ConnectionError("connection reset before newline") from None
        if chunk:
            pending.extend(chunk)
            continue
        leftover = bytes(pending)
        pending.clear()
        if leftover:
            raise ConnectionError(f"connection closed mid-line: {leftover!r}")
        return None
