import socket

from ..crypto.modes import encrypt_text
from .chat import ChatContext, chat_loop
from ..net.framing import recv_line, send_line
from ..protocol.handshake import make_step4, make_step5, new_nonce, parse_step2, parse_ticket, verify_step5
from ..protocol.messages import MessageError, build_line, parse_line
from .common import prompt_id, prompt_key, prompt_port, prompt_text

BANNER = (
    "=" * 60
    + "\nPEER -- Alice (initiator) / Bob (responder)\n"
    + "=" * 60
)
MODE_CHOICES = " [1] Alice (initiator)  [2] Bob (responder)\nmode: "


def _expect(line, wanted_step, wanted_fields, where):
    step, fields = parse_line(line)
    if step != wanted_step:
        raise MessageError(f"{where}: expected {wanted_step}, got {step}")
    if len(fields) != wanted_fields:
        raise MessageError(f"{where}: {wanted_step} needs {wanted_fields} field(s), got {len(fields)}")
    return fields


def _alice_handshake(state, ida, idb, kdc_host, kdc_port, bob_host, bob_port):
    ka = state["ka"]
    n1 = new_nonce()
    try:
        conn_kdc = socket.create_connection((kdc_host, kdc_port), timeout=10)
    except OSError as e:
        raise MessageError(f"cannot reach KDC at {kdc_host}:{kdc_port} ({e})") from None
    try:
        send_line(conn_kdc, build_line("STEP1", ida, idb, n1))
        print(f"[A] STEP1 sent to KDC: ida={ida!r} idb={idb!r} n1={n1!r}", flush=True)
        line = recv_line(conn_kdc)
    finally:
        try:
            conn_kdc.close()
        except OSError:
            pass
    if line is None:
        raise MessageError("KDC closed connection before STEP2")
    hex_a, hex_b = _expect(line, "STEP2", 2, "KDC reply")
    print(f"[A] STEP2 received: hex_for_a={hex_a}", flush=True)
    print(f"[A] ticket for Bob: hex_for_b={hex_b}", flush=True)
    ks = parse_step2(ka, hex_a, n1, ida=ida, idb=idb)
    print("[A] Ks acquired (kept secret)", flush=True)

    try:
        sock_bob = socket.create_connection((bob_host, bob_port), timeout=10)
    except OSError as e:
        raise MessageError(f"cannot reach Bob at {bob_host}:{bob_port} ({e})") from None
    try:
        send_line(sock_bob, build_line("STEP3", hex_b))
        print(f"[A] STEP3 sent to Bob: ticket={hex_b}", flush=True)
        line = recv_line(sock_bob)
        if line is None:
            raise MessageError("Bob closed connection before STEP4")
        (hex_step4,) = _expect(line, "STEP4", 1, "Bob reply")
        print(f"[A] STEP4 received from Bob: hex={hex_step4}", flush=True)
        hex_step5 = make_step5(ks, hex_step4)
        send_line(sock_bob, build_line("STEP5", hex_step5))
        print(f"[A] STEP5 sent to Bob: hex={hex_step5}", flush=True)
    except Exception:
        try:
            sock_bob.close()
        except OSError:
            pass
        raise
    print("[A] handshake complete", flush=True)
    return sock_bob, ks


def _bob_handshake(listener, kb):
    conn, addr = listener.accept()
    print(f"[B] connection from {addr[0]}:{addr[1]}", flush=True)
    try:
        try:
            line = recv_line(conn)
        except Exception as e:
            raise MessageError(f"unreadable line ({e})") from None
        if line is None:
            raise MessageError("peer closed connection before STEP3")
        (hex_ticket,) = _expect(line, "STEP3", 1, "Alice request")
        print(f"[B] STEP3 received: ticket={hex_ticket}", flush=True)
        ks, ida = parse_ticket(kb, hex_ticket)
        print(f"[B] ticket decrypted: ida={ida!r}, Ks acquired", flush=True)
        n2, hex_step4 = make_step4(ks)
        send_line(conn, build_line("STEP4", hex_step4))
        print(f"[B] STEP4 sent: n2={n2} hex={hex_step4}", flush=True)
        try:
            line = recv_line(conn)
        except Exception as e:
            raise MessageError(f"unreadable STEP5 ({e})") from None
        if line is None:
            raise MessageError("peer closed connection before STEP5")
        (hex_step5,) = _expect(line, "STEP5", 1, "Alice proof")
        print(f"[B] STEP5 received: hex={hex_step5}", flush=True)
        if not verify_step5(ks, n2, hex_step5):
            raise MessageError("STEP5 verification failed: f(N2) mismatch")
        print(f"[B] STEP5 verified with {ida!r} -> mutual authentication OK", flush=True)
    except Exception:
        try:
            conn.close()
        except OSError:
            pass
        raise
    return conn, ks, ida


def run_alice():
    state = {"ka": prompt_key("Ka (your long-term key)")}
    ida = prompt_id("Your ID")
    idb = prompt_id("Responder ID")
    kdc_host = prompt_text("KDC host", default="127.0.0.1")
    kdc_port = prompt_port("KDC port", default=9001)
    bob_host = prompt_text("Bob host", default="127.0.0.1")
    bob_port = prompt_port("Bob port", default=9002)
    while True:
        try:
            sock, ks = _alice_handshake(state, ida, idb, kdc_host, kdc_port, bob_host, bob_port)
        except Exception as e:
            print(f"[A] handshake failed: {e}", flush=True)
            choice = input("[A] [r] retry handshake [q] quit: ").strip().lower()
            if choice != "r":
                break
            continue
        ctx = ChatContext(sock, ks, peer_label=idb, longterm=state, key_name="ka", prompt_text="[A] chat> ")
        reason = chat_loop(ctx)
        try:
            sock.close()
        except OSError:
            pass
        if reason == "quit":
            print("[A] bye", flush=True)
            break
        if reason == "rehandshake":
            print("[A] starting new handshake...", flush=True)
            continue
        print("[A] peer disconnected.", flush=True)
        choice = input("[A] [r] rehandshake [q] quit: ").strip().lower()
        if choice != "r":
            break
    print("[A] program finished", flush=True)


def run_bob():
    state = {"kb": prompt_key("Kb (your long-term key)")}
    port = prompt_port("Listen port", default=9002)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(5)
    print(f"[B] listening on 0.0.0.0:{port}; waiting for STEP3 from Alice...", flush=True)
    while True:
        try:
            conn, ks, ida = _bob_handshake(listener, state["kb"])
        except Exception as e:
            print(f"[B] handshake failed: {e}", flush=True)
            print("[B] still listening for the next connection...", flush=True)
            continue
        ctx = ChatContext(conn, ks, peer_label=ida, longterm=state, key_name="kb", prompt_text="[B] chat> ")
        reason = chat_loop(ctx)
        try:
            conn.close()
        except OSError:
            pass
        if reason == "quit":
            print("[B] bye", flush=True)
            break
        print("[B] waiting for next handshake...", flush=True)
    listener.close()
    print("[B] program finished", flush=True)


def main():
    print(BANNER)
    while True:
        mode = input(MODE_CHOICES).strip()
        if mode == "1":
            run_alice()
            return
        if mode == "2":
            run_bob()
            return
        print("-> enter 1 or 2")


if __name__ == "__main__":
    main()
