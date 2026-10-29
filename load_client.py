"""
load_client.py - generates fake traffic so the service's per-request crash
trigger (Trigger A) has something to fire on, AND proves state survives failover.

Sends one request every 200-500 ms:
  * ~10% malformed (missing fields, oversized payload, binary garbage)
  * logins (some with wrong passwords)
  * VERIFY of a token this client received earlier. After a failover this shows
    whether the state survived:
        VALID    -> the session was carried over by the checkpoint
        INVALID  -> the session was lost (issued after the last checkpoint, or
                    the checkpoint was rejected)

Keeps running while the service is down, so traffic resumes after failover.

Usage
    python load_client.py
    python load_client.py --malformed-rate 0.3 --verify-rate 0.4
    python load_client.py --status        # print the service's STATUS line once and exit
"""

import argparse
import random
import socket
import time
from datetime import datetime

import config

MAX_TRACKED_TOKENS = 50


def make_request(malformed_rate, verify_rate, tokens):
    """Return (label, bytes) for one request."""
    if random.random() < malformed_rate:
        kind = random.choice(["missing", "oversized", "garbage", "noline"])
        if kind == "missing":
            return "malformed:missing-fields", b"LOGIN alice\n"
        if kind == "oversized":
            return "malformed:oversized", b"LOGIN " + b"A" * (config.MAX_PAYLOAD * 2) + b" x\n"
        if kind == "garbage":
            return "malformed:garbage", bytes(random.getrandbits(8) for _ in range(40)) + b"\n"
        return "malformed:no-newline", b"LOGIN bob builder"
    if tokens and random.random() < verify_rate:
        return "verify", f"VERIFY {random.choice(list(tokens))}\n".encode()
    user = random.choice(list(config.USERS))
    # ~80% correct password, ~20% wrong, so we see both OK and DENIED.
    pw = config.USERS[user] if random.random() < 0.8 else "wrong-password"
    return "valid", f"LOGIN {user} {pw}\n".encode()


def send(label, payload):
    with socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2) as s:
        s.sendall(payload)
        if label == "malformed:no-newline":
            s.shutdown(socket.SHUT_WR)  # tell the server we're done sending
        return s.recv(512).decode(errors="replace").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malformed-rate", type=float, default=0.10)
    ap.add_argument("--verify-rate", type=float, default=0.25,
                    help="chance that a non-malformed request is a VERIFY of an earlier token")
    ap.add_argument("--status", action="store_true", help="print STATUS once and exit")
    args = ap.parse_args()

    if args.status:
        try:
            print(send("status", b"STATUS\n"))
        except OSError as e:
            print(f"NO RESPONSE ({type(e).__name__}) - service down?")
        return

    tokens = {}   # token -> time we received it (insertion ordered: oldest first)
    n = 0
    while True:
        n += 1
        label, payload = make_request(args.malformed_rate, args.verify_rate, tokens)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        try:
            reply = send(label, payload)
            note = ""
            if label == "valid" and reply.startswith("OK "):
                tokens[reply[3:]] = time.time()
                while len(tokens) > MAX_TRACKED_TOKENS:
                    tokens.pop(next(iter(tokens)))
            elif label == "verify":
                tok = payload.decode().split()[1]
                if reply == "INVALID":
                    note = "   <-- STATE LOST (this token was issued earlier)"
                    tokens.pop(tok, None)   # report each lost token once
                label = f"verify {tok[:6]}.."
            print(f"[{ts}] #{n:<4} {label:<24} -> {reply or '(empty reply)'}{note}", flush=True)
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError) as e:
            print(f"[{ts}] #{n:<4} {label:<24} -> NO RESPONSE ({type(e).__name__}) - service down?",
                  flush=True)
        time.sleep(random.uniform(0.2, 0.5))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nload client stopped")
