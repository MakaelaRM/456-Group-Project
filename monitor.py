"""
monitor.py - heartbeat monitor. Alerts if auth_service.py stops sending beats.
 
How to run (start the monitor first, in its own terminal):
    python monitor.py
 
Optional, to test other timing values (T = interval in seconds, N = missed beats):
    python monitor.py --interval 0.05 --misses 1
 
Then start the service in a second terminal:
    python auth_service.py
 
Note: beats are not authenticated, so forged or replayed beats are accepted.
"""

import argparse
import json
import os
import socket
import threading
import time
from datetime import datetime

import config

_log_lock = threading.Lock()

# Monitor states
WAITING = "WAITING"   # no beat seen yet
UP = "UP"
DOWN = "DOWN"


def log(msg):
    """Print a timestamped line to stdout and append it to the monitor log."""
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] {msg}"
    print(line, flush=True)
    with _log_lock:
        os.makedirs(config.LOG_DIR, exist_ok=True)
        with open(config.MONITOR_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def parse_beat(data):
    """Return the beat dict if the datagram is a well-formed heartbeat, else None.

    Naive on purpose: only checks that it is a JSON object with the right
    service name. No signature, no seq/ts validation.
    """
    try:
        beat = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(beat, dict) or beat.get("svc") != config.SERVICE_NAME:
        return None
    return beat


def main():
    ap = argparse.ArgumentParser(description="Heartbeat monitor / failure detector")
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.MONITOR_PORT)
    ap.add_argument("--interval", type=float, default=config.HEARTBEAT_INTERVAL_S,
                    help="expected heartbeat period T in seconds")
    ap.add_argument("--misses", type=int, default=config.MISSED_BEATS_N,
                    help="missed beats N before declaring the service DOWN")
    ap.add_argument("--quiet", action="store_true",
                    help="do not print an OK line for every beat")
    args = ap.parse_args()

    T = args.interval
    N = args.misses
    timeout = N * T

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(T / 2)  # wake up often enough to check the timer

    log(f"monitor starting (pid={os.getpid()}, udp={args.host}:{args.port}, "
        f"T={T}s, N={N}, timeout={timeout:.2f}s)")

    state = WAITING
    last_beat = time.monotonic()
    down_since = None          # monotonic time of the last beat before DOWN
    beats_total = 0

    try:
        while True:
            # --- receive ---------------------------------------------------
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                data = None
            except OSError:
                data = None

            now = time.monotonic()

            if data is not None:
                beat = parse_beat(data)
                if beat is not None:
                    beats_total += 1
                    last_beat = now
                    if state == DOWN:
                        outage = now - down_since
                        log(f"RECOVERED: {config.SERVICE_NAME} service heartbeat resumed "
                            f"(seq={beat.get('seq')}, silent for {outage:.2f}s)")
                    elif state == WAITING:
                        log(f"{config.SERVICE_NAME} service detected, monitoring started "
                            f"(first seq={beat.get('seq')})")
                    state = UP
                    if not args.quiet:
                        print(f"OK seq={beat.get('seq')}", flush=True)
                # else: not a valid heartbeat -> silently ignored

            # --- timeout check --------------------------------------------
            silence = now - last_beat
            if state == UP and silence > timeout:
                state = DOWN
                down_since = last_beat
                log(f"ALERT: {config.SERVICE_NAME} service DOWN "
                    f"(no heartbeat for {silence:.2f}s, N={N} missed)")

    except KeyboardInterrupt:
        log(f"monitor shutting down (Ctrl+C), {beats_total} beats received")
    finally:
        sock.close()


if __name__ == "__main__":
    main()