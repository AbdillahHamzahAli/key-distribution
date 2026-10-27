import threading

from ..crypto.modes import decrypt_text, encrypt_text
from ..net.framing import recv_line, send_line


class ChatContext:
    def __init__(self, sock, ks, peer_label, longterm=None, key_name="", prompt_text="chat> "):
        self.sock = sock
        self.ks = ks
        self.peer_label = peer_label
        self.longterm = longterm
        self.key_name = key_name
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.prompt_text = prompt_text


def _print(msg, lock):
    with lock:
        print()
        print(msg, flush=True)


HELP = "type text to send encrypted | /key (change long-term key) | /rehandshake | /help | /quit"


def _receiver_loop(ctx):
    while not ctx.stop.is_set():
        try:
            line = recv_line(ctx.sock)
        except Exception as e:
            if not ctx.stop.is_set():
                _print(f"** connection error ({e})", ctx.lock)
            break
        if line is None:
            _print(f"** {ctx.peer_label} disconnected (press enter)", ctx.lock)
            break
        if line == "BYE":
            _print(f"** {ctx.peer_label} left the chat (BYE) (press enter)", ctx.lock)
            break
        if line.startswith("MSG|"):
            try:
                plain = decrypt_text(ctx.ks, line[4:])
            except Exception as e:
                _print(f"** undecryptable message ({e})", ctx.lock)
                continue
            _print(f"[{ctx.peer_label}] {plain}", ctx.lock)
        else:
            _print(f"** not an MSG| line: {line[:60]!r}", ctx.lock)
    ctx.stop.set()


def chat_loop(ctx):
    print(HELP)
    receiver = threading.Thread(target=_receiver_loop, args=(ctx,), daemon=True)
    receiver.start()
    reason = "quit"
    while not ctx.stop.is_set():
        try:
            line = input(ctx.prompt_text).strip()
        except (EOFError, KeyboardInterrupt):
            _print("", ctx.lock)
            break
        if ctx.stop.is_set():
            reason = "peer_left"
            break
        if not line:
            continue
        if line == "/quit":
            _try_send_line(ctx.sock, "BYE")
            reason = "quit"
            break
        if line == "/rehandshake":
            _try_send_line(ctx.sock, "BYE")
            reason = "rehandshake"
            break
        if line == "/key":
            _change_key(ctx)
            continue
        if line in ("/help", "/menu"):
            print(HELP)
            continue
        try:
            hexstr = encrypt_text(ctx.ks, line)
            send_line(ctx.sock, "MSG|" + hexstr)
            print(f"me> sent hex {hexstr}")
        except Exception as e:
            print(f"** send failed ({e})")
            reason = "peer_gone"
            break
    ctx.stop.set()
    return reason


def _try_send_line(sock, text):
    try:
        send_line(sock, text)
    except Exception:
        pass


#Changes :
#Empty input cancels
#CTRL+D and CTRL-C cancels
#Success message 
def _change_key(ctx):
    from ..crypto.codec import AsciiError, KeyLengthError, key_to_bytes
    if ctx.longterm is None:
        print("** key change not available here")
        return
    while True:
        try:
            new_key = input(f"new {ctx.key_name} (exactly 16 ASCII chars, empty to cancel): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n** key change cancelled")
            return
        if not new_key:
            print("** key change cancelled")
            return
        try:
            key_to_bytes(new_key)
        except (KeyLengthError, AsciiError) as e:
            print("->", e)
            continue
        ctx.longterm[ctx.key_name] = new_key
        print(f"{ctx.key_name} updated (applies on next handshake; the KDC needs the same key)")
        return