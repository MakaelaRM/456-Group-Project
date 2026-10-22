"""
load_client.py - generates fake login traffic so the service's per-request
crash trigger (Trigger A) has something to fire on.

Sends one login every 200-500 ms. About 10% of requests are malformed
(missing fields, oversized payload, binary garbage). Keeps running when the
service is down, so you can restart the service and traffic resumes.

Usage
    python load_client.py
    python load_client.py --malformed-rate 0.3
"""

import argparse
import random
import socket
import time
from datetime import datetime

import config


def make_request(malformed_rate):
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
    user = random.choice(list(config.USERS))
    # ~80% correct password, ~20% wrong, so we see both OK and DENIED.
    pw = config.USERS[user] if random.random() < 0.8 else "wrong-password"
    return "valid", f"LOGIN {user} {pw}\n".encode()


def send(label, payload):
    with socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2) as s:
        s.sendall(payload)
        if label == "malformed:no-newline":
            s.shutdown(socket.SHUT_WR)  # tell the server we're done sending
        return s.recv(256).decode(errors="replace").strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malformed-rate", type=float, default=0.10)
    args = ap.parse_args()

    n = 0
    while True:
        n += 1
        label, payload = make_request(args.malformed_rate)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        try:
            reply = send(label, payload)
            print(f"[{ts}] #{n:<4} {label:<24} -> {reply or '(empty reply)'}", flush=True)
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError) as e:
            print(f"[{ts}] #{n:<4} {label:<24} -> NO RESPONSE ({type(e).__name__}) - service down?",
                  flush=True)
        time.sleep(random.uniform(0.2, 0.5))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nload client stopped")
