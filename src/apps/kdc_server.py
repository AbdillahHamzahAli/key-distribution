import socket
import threading
import time

#Removed unused lib
from ..crypto.codec import AsciiError, KeyLengthError, key_to_bytes
from ..net.framing import recv_line, send_line
from ..protocol.kdc_logic import handle_step1
from ..protocol.messages import MessageError, build_line, parse_line
from .common import prompt_id, prompt_key, prompt_port

EOF_IDLE = 0.25
HELP = (
    "kdc commands: /keys | /key <ID> <new 16-char key> | /help | /quit"
)


def _accept_loop(listener, keys):
    while True:
        try:
            conn, addr = listener.accept()
        except OSError:
            print("[KDC] listener closed", flush=True)
            return
        conn.settimeout(5)
        try:
            line = recv_line(conn)
            step, fields = parse_line(line)
            if step != "STEP1":
                raise MessageError(f"expected STEP1, got {step}")
            if len(fields) != 3:
                raise MessageError(f"STEP1 needs 3 fields (ida idb n1), got {len(fields)}")
            ida, idb, n1 = fields
            hex_a, hex_b = handle_step1(keys, ida, idb, n1)
            send_line(conn, build_line("STEP2", hex_a, hex_b))
            print(f"[KDC] STEP1 from {addr[0]}:{addr[1]}: ida={ida!r} idb={idb!r} n1={n1!r}", flush=True)
            print(f"[KDC] STEP2: generated fresh Ks (hidden); hex_for_a={hex_a}", flush=True)
            print(f"[KDC] STEP2: hex_for_b={hex_b}", flush=True)
            print(f"[KDC] done, connection closed", flush=True)
        except Exception as e:
            print(f"[KDC] rejected {addr}: {e}", flush=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _menu_loop(keys, listener):
    print(HELP)
    while True:
        try:
            cmd = input("kdc> ").strip()
        #Split the KeyboardInterrupt and EOFError
        except KeyboardInterrupt:
            print("\n[KDC] Shutting down", flush=True)
            listener.close()
            return 
        except EOFError:
            time.sleep(EOF_IDLE)
            continue
        if not cmd:
            continue
        if cmd == "/quit":
            print("[KDC] shutting down", flush=True)
            listener.close()
            return
        if cmd == "/keys":
            for ident in sorted(keys):
                print(f"[KDC] {ident}: {keys[ident]}", flush=True)
            continue
        if cmd == "/help":
            print(HELP)
            continue
        parts = cmd.split(maxsplit=2)
        if len(parts) == 3 and parts[0] == "/key":
            target, new_key = parts[1], parts[2]
            if target not in keys:
                print(f"[KDC] unknown identity {target!r}; known: {sorted(keys)}", flush=True)
                continue
            try:
                key_to_bytes(new_key)
            except (KeyLengthError, AsciiError) as e:
                print("[KDC] ->", e, flush=True)
                continue
            keys[target] = new_key
            print(f"[KDC] key for {target!r} updated (applies to next handshake)", flush=True)
            continue
        print("[KDC] unknown command;", HELP, flush=True)



def main():
    print("=" * 60)
    print("KDC SERVER -- key distribution via Needham-Schroeder-ish step")
    print("=" * 60)
    ida = prompt_id("Alice ID")
    ka = prompt_key(f"Ka (key for {ida})")
    #Added while loop to make sure that ida!=idb
    while True:
        idb = prompt_id("Bob ID")
        if idb != ida:
            break
        print("-> Bob's ID must differ from Alice's")
    kb = prompt_key(f"Kb (key for {idb})")
    port = prompt_port("Listen port", default=9001)
    keys = {ida: ka, idb: kb}

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(5)
    print(f"[KDC] registered identities: {sorted(keys)}")
    print(f"[KDC] listening on 0.0.0.0:{port}")
    print(f"[KDC] {HELP}")
    worker = threading.Thread(target=_accept_loop, args=(listener, keys), daemon=True)
    worker.start()
    _menu_loop(keys, listener)


if __name__ == "__main__":
    main()
