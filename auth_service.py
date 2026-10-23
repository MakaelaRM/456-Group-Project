"""
auth_service.py - the critical process (fake authentication / ticket service).

What it does
  * TCP server on SERVICE_PORT. Protocol (one line per request):
        LOGIN <user> <password>\n
    Replies:  OK <session-token>\n   |   DENIED\n   |   ERR malformed\n
  * Pushes a UDP heartbeat to the monitor every T seconds from its own
    daemon thread, so a slow request never looks like a dead service.
  * Crashes NON-DETERMINISTICALLY, two independent ways:
      Trigger A: random chance on each request (higher for malformed input,
                 simulating a parser bug).
      Trigger B: a background fault-injector thread that sleeps a random
                 (exponentially distributed) time, then kills the process.
  * A crash is os._exit(1): the whole process ends immediately, including the
    heartbeat thread. It does NOT just sleep or hang.

Usage
    python auth_service.py
    python auth_service.py --monitor-port 9001     # send beats to attacker relay
    python auth_service.py --handler-delay 0.8     # test: slow requests must not stop heartbeats
    python auth_service.py --no-crash              # debugging only
"""

import argparse
import json
import os
import random
import secrets
import socket
import socketserver
import threading
import time
from datetime import datetime

import config

_log_lock = threading.Lock()


def log(msg):
    """Append a timestamped line to the service log and echo to stdout."""
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] {msg}"
    print(line, flush=True)
    with _log_lock:
        os.makedirs(config.LOG_DIR, exist_ok=True)
        with open(config.SERVICE_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())  # make sure the crash reason hits disk before we die


def crash(reason):
    """Terminate the whole process immediately (no cleanup, no graceful shutdown)."""
    log(f"CRASH: {reason} -- process terminating (pid={os.getpid()})")
    os._exit(1)


# ---------------------------------------------------------------------------
# Heartbeat sender (push model) - runs on its own thread
# ---------------------------------------------------------------------------
def heartbeat_loop(monitor_host, monitor_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = config.HEARTBEAT_INTERVAL_S
    next_beat = time.monotonic()
    while True:
        seq += 1
        beat = {"svc": config.SERVICE_NAME, "seq": seq, "ts": time.time()}
        try:
            sock.sendto(json.dumps(beat).encode("utf-8"), (monitor_host, monitor_port))
        except OSError as e:
            log(f"heartbeat send error: {e}")
        # Schedule against a fixed clock so timing doesn't drift.
        next_beat += interval
        time.sleep(max(0.0, next_beat - time.monotonic()))


# ---------------------------------------------------------------------------
# Trigger B: background fault injector
# ---------------------------------------------------------------------------
def fault_injector_loop(mean_seconds):
    delay = random.expovariate(1.0 / mean_seconds)
    log(f"fault injector armed (will fire in ~{delay:.1f}s)")
    time.sleep(delay)
    crash("background fault injector fired (simulated memory exhaustion)")


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------
class AuthHandler(socketserver.StreamRequestHandler):
    def handle(self):
        args = self.server.args
        raw = self.rfile.readline(config.MAX_PAYLOAD + 1)
        if not raw:
            return

        if args.handler_delay:
            time.sleep(args.handler_delay)  # test hook only

        malformed, user, password = self.parse(raw)

        # Trigger A: random crash chance on each request.
        if not args.no_crash:
            p = config.CRASH_PROB_MALFORMED if malformed else config.CRASH_PROB_NORMAL
            if random.random() < p:
                kind = "malformed" if malformed else "well-formed"
                crash(f"random fault while handling {kind} request from {self.client_address[0]}")

        if malformed:
            self.wfile.write(b"ERR malformed\n")
        elif config.USERS.get(user) == password:
            self.wfile.write(f"OK {secrets.token_hex(8)}\n".encode())
        else:
            self.wfile.write(b"DENIED\n")

    @staticmethod
    def parse(raw):
        """Return (malformed, user, password)."""
        if len(raw) > config.MAX_PAYLOAD or not raw.endswith(b"\n"):
            return True, None, None
        try:
            parts = raw.decode("utf-8").strip().split(" ")
        except UnicodeDecodeError:
            return True, None, None
        if len(parts) != 3 or parts[0] != "LOGIN" or not parts[1] or not parts[2]:
            return True, None, None
        return False, parts[1], parts[2]


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="Fake auth service with random crash injection")
    ap.add_argument("--monitor-host", default=config.HOST)
    ap.add_argument("--monitor-port", type=int, default=config.MONITOR_PORT)
    ap.add_argument("--handler-delay", type=float, default=0.0,
                    help="seconds to sleep in each request (tests heartbeat decoupling)")
    ap.add_argument("--crash-mean", type=float, default=config.BACKGROUND_FAULT_MEAN_S,
                    help="mean seconds until the background fault injector fires")
    ap.add_argument("--no-crash", action="store_true", help="disable all crash injection (debug)")
    args = ap.parse_args()

    log(f"auth service starting (pid={os.getpid()}, tcp={config.HOST}:{config.SERVICE_PORT}, "
        f"heartbeat -> {args.monitor_host}:{args.monitor_port} every {config.HEARTBEAT_INTERVAL_S}s)")

    threading.Thread(target=heartbeat_loop, args=(args.monitor_host, args.monitor_port),
                     daemon=True, name="heartbeat").start()
    if not args.no_crash:
        threading.Thread(target=fault_injector_loop, args=(args.crash_mean,),
                         daemon=True, name="fault-injector").start()

    server = Server((config.HOST, config.SERVICE_PORT), AuthHandler)
    server.args = args
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutdown requested (Ctrl+C) - clean exit, not a crash")


if __name__ == "__main__":
    main()
