# key-distribution

Interactive KDC key distribution (Needham–Schroeder style, Stallings Figure 14.3) with a
two-way AES-128-encrypted chat — implemented **from scratch** in Python, using no crypto
libraries. Only the standard library (`socket`, `threading`, `secrets`, `unittest`) is used.

Three entities run on three machines/IPs:

- **KDC** — shares a fresh 16-character session key `Ks` between Alice and Bob
- **Alice** (initiator) — starts the distribution protocol, then chats
- **Bob** (responder) — accepts the ticket, verifies authentication, then chats

## Protocol

```
1. A → KDC : IDA || IDB || N1
2. KDC → A : E(Ka, [Ks || IDA || IDB || N1]) || E(Kb, [Ks || IDA])
3. A → B   : E(Kb, [Ks || IDA])                       (the ticket)
4. B → A   : E(Ks, N2)
5. A → B   : E(Ks, f(N2))                             (f(N2) = N2 + 1)
```

Steps 4–5 give mutual authentication. All step messages travel as delimited ASCII lines
(`STEP1|alice|bob|84671352`, `STEP2|<hexA>|<hexB>`, ...) framed with newlines over TCP.
Keys and plaintext are ASCII; ciphertext is uppercase hex.

## Crypto (all hand-written)

| Layer | File | What it does |
|---|---|---|
| GF(2^8) tables | `src/crypto/tables.py` | S-box (inverse + affine transform), inverse S-box, Rcon |
| AES-128 | `src/crypto/aes.py` | key expansion (11 round keys), SubBytes / ShiftRows / MixColumns / AddRoundKey + inverses |
| Modes | `src/crypto/modes.py` | CBC with random IV (`secrets.token_bytes`), PKCS#7 padding, text wrappers |
| Codec | `src/crypto/codec.py` | ASCII ↔ bytes ↔ hex, 16-character key validation |

Accuracy is pinned by tests against FIPS-197 block vectors (Appendix B / C.1) and the
SP 800-38A key-schedule example.

## How to run

From the project root on **each** machine (the project pins Python >= 3.14 in
`pyproject.toml`; runs as modules):

### Terminal 1 — KDC

```bash
python3 -m src.apps.kdc_server
```

Answer the prompts:

```
Alice ID: alice
Ka (key for alice)  (exactly 16 ASCII chars): AliceKey12345678
Bob ID: bob
Kb (key for bob)    (exactly 16 ASCII chars): BobKey1111111111
Listen port (default 9001): 9001
```

### Terminal 2 — Bob (responder, start first)

```bash
python3 -m src.apps.peer
```

```
mode: 2
Kb (your long-term key): BobKey1111111111
Listen port: 9002
```

Bob waits: `[B] listening on 0.0.0.0:9002; waiting for STEP3 from Alice...`

### Terminal 3 — Alice (initiator)

```bash
python3 -m src.apps.peer
```

```
mode: 1
Ka (your long-term key): AliceKey12345678
Your ID: alice
Responder ID: bob
KDC host: <KDC-IP>      (default 127.0.0.1 for localhost testing)
KDC port: 9001
Bob host: <BOB-IP>      (default 127.0.0.1; use real IPs across devices)
Bob port: 9002
```

Alice then runs the whole 5-step handshake automatically and drops into chat mode.
Every step is logged (IDs, nonces, and full ciphertext hex — never the plaintext keys,
and `Ks` stays hidden).

## Chat commands

Available on both peers (`[A] chat>` / `[B] chat>` prompts):

| Command     | Effect                                                                     |
|-------------|----------------------------------------------------------------------------|
| any text    | AES-CBC encrypted message; the hex is echoed on the sender's console       |
| `/key`      | change your long-term key (Ka/Kb) without restarting — applies on next handshake |
| `/rehandshake` | rerun the full 5-step protocol and get a fresh `Ks`                     |
| `/help`     | show available commands                                                    |
| `/quit`     | leave; sends `BYE` and ends the program                                    |

Incoming messages print as `[alice] <plaintext>` / `[bob] <plaintext>`; the receiver
thread decrypts them alive — the program does not pause while messages arrive.

## Changing keys live

1. On the peer console: type `/key`, then enter the new 16-char key.
2. On the **KDC** console, apply the matching change *before* the next handshake:
   ```
   /key <ID> <new 16-char key>      e.g. /key alice NewAliceKey12345
   /keys                            show registered keys
   /quit                            shut KDC down
   ```
3. Alice runs `/rehandshake`; the next 5-step exchange is encrypted under the new keys.

If Alice and Bob change keys without updating KDC (or the other way around), the next
handshake fails with a clear error (`nonce mismatch`, padding errors on the wrong key)
and the program keeps running — no crash, just retry after fixing.
