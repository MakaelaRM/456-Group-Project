"""
auth_service.py - the critical process (fake authentication / ticket service).

PART 1 (unchanged behaviour)
  * TCP server on SERVICE_PORT, one request line per connection.
  * Pushes a UDP heartbeat to the monitor every T seconds from its own thread.
  * Crashes NON-DETERMINISTICALLY (random chance per request + background
    fault injector) via os._exit(1) - a real process death, not a hang.

PART 2 (new): recovery with passive redundancy (warm standby + checkpointing)
  * The service now keeps DYNAMIC STATE: login sessions, failed-login counters
    and temporary lockouts.
        LOGIN <user> <password>  -> OK <token> | DENIED | LOCKED
        VERIFY <token>           -> VALID <user> | INVALID
        STATUS                   -> STATUS epoch=<n> sessions=<n> locked=<users|->
  * CHECKPOINTING: every CHECKPOINT_INTERVAL_S the primary writes its state to
    state/checkpoint.json (atomic write, HMAC-signed, previous verified copy kept).
  * ROLES:
        --role primary   fresh start (epoch 1). WIPES old state files.
        --role standby   started by the monitor after a crash. Loads the
                         checkpoint, becomes epoch+1, binds the service port and
                         resumes serving + heartbeating.
  * EPOCH FENCING: the new primary publishes its epoch in state/leader.json.
    Any node that sees a higher epoch than its own steps down immediately, so
    two primaries cannot keep serving at once (split-brain protection).
  * POISON PILL DEFENCE: when a MALFORMED request crashes the node, its hash is
    appended to state/poison.log before dying. A promoted standby rejects those
    payloads instead of crashing on them too (no cascading failure).
  * Checkpoint integrity: loads verify the HMAC. A tampered/corrupt checkpoint
    is rejected -> fall back to the previous verified copy -> else start with
    EMPTY state (degraded). --insecure-checkpoint skips verification (BASELINE
    for the tampering demo).

Usage
    python auth_service.py                          # normal primary
    python auth_service.py --monitor-port 9001      # send beats to the attacker relay
    python auth_service.py --role standby           # normally launched by monitor.py
    python auth_service.py --no-crash               # debugging only
    python auth_service.py --insecure-checkpoint    # baseline: trust checkpoint blindly
"""

import argparse
import hashlib
import hmac
import json
import os
import random
import secrets
import shutil
import socket
import socketserver
import sys
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
# Dynamic service state
# ---------------------------------------------------------------------------
class ServiceState:
    """Everything that must survive a crash. All access goes through the lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}   # token -> {"user": str, "issued": float}
        self.failed = {}     # user  -> consecutive failed logins
        self.locked = {}     # user  -> unix time when the lockout ends

    def login(self, user, password):
        with self.lock:
            now = time.time()
            until = self.locked.get(user)
            if until is not None:
                if now < until:
                    return "LOCKED"
                del self.locked[user]
                self.failed[user] = 0
            if config.USERS.get(user) == password:
                token = secrets.token_hex(8)
                self.sessions[token] = {"user": user, "issued": now}
                while len(self.sessions) > config.MAX_SESSIONS:   # bound state size
                    self.sessions.pop(next(iter(self.sessions)))
                self.failed[user] = 0
                return f"OK {token}"
            if user in config.USERS:   # only track real users, so random names can't bloat state
                n = self.failed.get(user, 0) + 1
                self.failed[user] = n
                if n >= config.LOCKOUT_THRESHOLD:
                    self.locked[user] = now + config.LOCKOUT_SECONDS
                    log(f"lockout: user '{user}' locked for {config.LOCKOUT_SECONDS}s")
            return "DENIED"

    def verify(self, token):
        with self.lock:
            s = self.sessions.get(token)
            return f"VALID {s['user']}" if s else "INVALID"

    def status(self, epoch):
        with self.lock:
            now = time.time()
            locked = sorted(u for u, t in self.locked.items() if t > now)
            return f"STATUS epoch={epoch} sessions={len(self.sessions)} locked={','.join(locked) or '-'}"

    def snapshot(self):
        with self.lock:
            return {
                "sessions": {t: dict(s) for t, s in self.sessions.items()},
                "failed": dict(self.failed),
                "locked": dict(self.locked),
            }

    def restore(self, d):
        """Load a snapshot; raises ValueError if the structure is not what we expect."""
        try:
            sessions, failed, locked = d["sessions"], d["failed"], d["locked"]
        except (KeyError, TypeError):
            raise ValueError("state structure is missing fields")
        if not (isinstance(sessions, dict) and isinstance(failed, dict) and isinstance(locked, dict)):
            raise ValueError("state fields have the wrong type")
        for tok, s in sessions.items():
            if not isinstance(tok, str) or not isinstance(s, dict) or not isinstance(s.get("user"), str):
                raise ValueError("malformed session entry")
        with self.lock:
            self.sessions, self.failed, self.locked = sessions, failed, locked


# ---------------------------------------------------------------------------
# Checkpointing (primary writes, standby reads)
# ---------------------------------------------------------------------------
class CheckpointError(Exception):
    pass


def _sign(payload):
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(config.CHECKPOINT_KEY, blob, hashlib.sha256).hexdigest()


def _write_json_atomic(path, obj):
    """Write to a temp file, fsync, then rename over the target: readers never see half a file."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_checkpoint(path, verify=True):
    """Return the checkpoint dict, or raise CheckpointError with the reason."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise CheckpointError("file not found")
    except (OSError, ValueError) as e:          # ValueError covers bad JSON and bad UTF-8
        raise CheckpointError(f"unreadable or corrupt ({type(e).__name__})")
    if not isinstance(doc, dict) or not all(k in doc for k in ("epoch", "saved_at", "state")):
        raise CheckpointError("unexpected structure")
    if verify:
        payload = {k: doc[k] for k in ("epoch", "saved_at", "state")}
        sig = doc.get("hmac")
        if not isinstance(sig, str) or not hmac.compare_digest(sig, _sign(payload)):
            raise CheckpointError("HMAC mismatch - checkpoint was modified (tampering or corruption)")
    return doc


def write_checkpoint(state, epoch):
    payload = {"epoch": epoch, "saved_at": time.time(), "state": state.snapshot()}
    doc = dict(payload, hmac=_sign(payload))
    os.makedirs(config.STATE_DIR, exist_ok=True)
    # Keep the last *verified* generation as a fallback (never copy a tampered file).
    try:
        read_checkpoint(config.CHECKPOINT_FILE, verify=True)
        shutil.copyfile(config.CHECKPOINT_FILE, config.CHECKPOINT_PREV_FILE + ".tmp")
        os.replace(config.CHECKPOINT_PREV_FILE + ".tmp", config.CHECKPOINT_PREV_FILE)
    except CheckpointError:
        pass
    _write_json_atomic(config.CHECKPOINT_FILE, doc)


def load_for_standby(verify):
    """Return (ServiceState, checkpoint_epoch). Falls back: checkpoint -> previous -> empty."""
    for label, path in (("checkpoint", config.CHECKPOINT_FILE),
                        ("previous checkpoint", config.CHECKPOINT_PREV_FILE)):
        try:
            doc = read_checkpoint(path, verify=verify)
            st = ServiceState()
            st.restore(doc["state"])
            ep = doc["epoch"] if isinstance(doc["epoch"], int) else 0
            age = time.time() - doc["saved_at"] if isinstance(doc["saved_at"], (int, float)) else -1
            log(f"loaded {label}: epoch={ep}, saved {age:.1f}s before load, "
                f"sessions={len(st.sessions)}, integrity check={'ON' if verify else 'OFF (insecure)'}")
            return st, ep
        except (CheckpointError, ValueError) as e:
            log(f"{label} REJECTED: {e}")
    log("DEGRADED OPERATION: no usable checkpoint - starting with EMPTY state")
    return ServiceState(), 0


def read_leader():
    try:
        with open(config.LEADER_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def load_poison():
    try:
        with open(config.POISON_LOG, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def record_poison(payload_hash):
    os.makedirs(config.STATE_DIR, exist_ok=True)
    with open(config.POISON_LOG, "a", encoding="utf-8") as f:
        f.write(payload_hash + "\n")
        f.flush()
        os.fsync(f.fileno())


class Node:
    """Per-process identity: which epoch we are and when crash injection may start."""

    def __init__(self, role):
        self.role = role
        self.epoch = 1
        self.grace_until = 0.0   # monotonic time before which random crashes are disabled


# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------
def heartbeat_loop(monitor_host, monitor_port, node):
    """Push-model heartbeat on its own thread, so a busy request never looks like death."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = config.HEARTBEAT_INTERVAL_S
    next_beat = time.monotonic()
    while True:
        seq += 1
        beat = {"svc": config.SERVICE_NAME, "seq": seq, "ts": time.time(), "epoch": node.epoch}
        try:
            sock.sendto(json.dumps(beat).encode("utf-8"), (monitor_host, monitor_port))
        except OSError as e:
            log(f"heartbeat send error: {e}")
        next_beat += interval
        time.sleep(max(0.0, next_beat - time.monotonic()))


def checkpoint_loop(state, node):
    """Fence check + periodic checkpoint. Stepping down comes BEFORE writing, so a
    superseded primary can never overwrite the new primary's checkpoint."""
    while True:
        leader = read_leader()
        if leader and isinstance(leader.get("epoch"), int) and leader["epoch"] > node.epoch:
            log(f"FENCED: epoch {node.epoch} superseded by epoch {leader['epoch']} "
                f"(pid={leader.get('pid')}) - stepping down")
            os._exit(3)
        try:
            write_checkpoint(state, node.epoch)
        except OSError as e:
            log(f"checkpoint write failed: {e}")
        time.sleep(config.CHECKPOINT_INTERVAL_S)


def fault_injector_loop(mean_seconds, grace_seconds):
    """Trigger B: random background fault. Starts counting after any promotion grace period."""
    delay = grace_seconds + random.expovariate(1.0 / mean_seconds)
    log(f"fault injector armed (will fire in ~{delay:.1f}s)")
    time.sleep(delay)
    crash("background fault injector fired (simulated memory exhaustion)")


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------
class AuthHandler(socketserver.StreamRequestHandler):
    def handle(self):
        srv = self.server
        args, state, node = srv.args, srv.state, srv.node
        raw = self.rfile.readline(config.MAX_PAYLOAD + 1)
        if not raw:
            return  # e.g. the monitor's liveness probe: connect and close

        if args.handler_delay:
            time.sleep(args.handler_delay)  # test hook only

        malformed, cmd, params = self.parse(raw)
        payload_hash = hashlib.sha256(raw).hexdigest()

        # Poison-pill defence: refuse payloads that already killed a node.
        if payload_hash in srv.poison:
            log(f"REJECTED quarantined payload {payload_hash[:12]} (it crashed a previous node)")
            self.wfile.write(b"ERR rejected\n")
            return

        # Trigger A: random crash chance on each request (paused during promotion grace).
        if not args.no_crash and time.monotonic() >= node.grace_until:
            p = config.CRASH_PROB_MALFORMED if malformed else config.CRASH_PROB_NORMAL
            if random.random() < p:
                if malformed:
                    record_poison(payload_hash)   # remember it BEFORE we die
                kind = "malformed" if malformed else "well-formed"
                crash(f"random fault while handling {kind} request from {self.client_address[0]}")

        if malformed:
            reply = "ERR malformed"
        elif cmd == "LOGIN":
            reply = state.login(*params)
        elif cmd == "VERIFY":
            reply = state.verify(params[0])
        else:  # STATUS
            reply = state.status(node.epoch)
        self.wfile.write((reply + "\n").encode())

    @staticmethod
    def parse(raw):
        """Return (malformed, command, params)."""
        if len(raw) > config.MAX_PAYLOAD or not raw.endswith(b"\n"):
            return True, None, None
        try:
            parts = raw.decode("utf-8").strip().split(" ")
        except UnicodeDecodeError:
            return True, None, None
        if parts[0] == "LOGIN" and len(parts) == 3 and parts[1] and parts[2]:
            return False, "LOGIN", parts[1:]
        if parts[0] == "VERIFY" and len(parts) == 2 and parts[1]:
            return False, "VERIFY", parts[1:]
        if parts == ["STATUS"]:
            return False, "STATUS", []
        return True, None, None


class Server(socketserver.ThreadingTCPServer):
    # On Windows SO_REUSEADDR lets a second process bind a port that is already
    # being listened on, which would hide split-brain. Only enable it elsewhere.
    allow_reuse_address = os.name != "nt"
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description="Fake auth service: crash injection + checkpoint recovery")
    ap.add_argument("--role", choices=["primary", "standby"], default="primary")
    ap.add_argument("--monitor-host", default=config.HOST)
    ap.add_argument("--monitor-port", type=int, default=config.MONITOR_PORT)
    ap.add_argument("--handler-delay", type=float, default=0.0,
                    help="seconds to sleep in each request (tests heartbeat decoupling)")
    ap.add_argument("--crash-mean", type=float, default=config.BACKGROUND_FAULT_MEAN_S,
                    help="mean seconds until the background fault injector fires")
    ap.add_argument("--grace", type=float, default=None,
                    help="seconds of crash-free operation after start "
                         f"(default {config.PROMOTION_GRACE_S} for standby, 0 for primary)")
    ap.add_argument("--no-crash", action="store_true", help="disable all crash injection (debug)")
    ap.add_argument("--insecure-checkpoint", action="store_true",
                    help="BASELINE: load the checkpoint without verifying its HMAC")
    args = ap.parse_args()

    node = Node(args.role)
    grace = args.grace if args.grace is not None else (
        config.PROMOTION_GRACE_S if args.role == "standby" else 0.0)

    log(f"auth service starting (role={args.role}, pid={os.getpid()}, "
        f"tcp={config.HOST}:{config.SERVICE_PORT}, "
        f"heartbeat -> {args.monitor_host}:{args.monitor_port} every {config.HEARTBEAT_INTERVAL_S}s)")

    # Bind FIRST. If another node is already serving, the standby aborts here
    # without touching any shared state files.
    try:
        server = Server((config.HOST, config.SERVICE_PORT), AuthHandler)
    except OSError as e:
        log(f"cannot bind tcp {config.HOST}:{config.SERVICE_PORT} ({e}) - "
            f"another node is already serving, {args.role} exiting")
        sys.exit(2)

    os.makedirs(config.STATE_DIR, exist_ok=True)
    if args.role == "primary":
        for p in (config.CHECKPOINT_FILE, config.CHECKPOINT_PREV_FILE, config.LEADER_FILE,
                  config.PRIMARY_PID_FILE, config.POISON_LOG):
            try:
                os.remove(p)
            except OSError:
                pass
        state = ServiceState()
        node.epoch = 1
        log("fresh primary: epoch 1, empty state, old checkpoint files cleared")
    else:
        state, cp_epoch = load_for_standby(verify=not args.insecure_checkpoint)
        leader = read_leader()
        leader_epoch = leader["epoch"] if leader and isinstance(leader.get("epoch"), int) else 0
        node.epoch = max(cp_epoch, leader_epoch) + 1
        log(f"PROMOTED: standby is now PRIMARY (epoch {node.epoch}), "
            f"restored {len(state.sessions)} sessions; crash injection paused for {grace:.0f}s")

    node.grace_until = time.monotonic() + grace
    server.args, server.state, server.node = args, state, node
    server.poison = load_poison()
    if server.poison:
        log(f"loaded {len(server.poison)} quarantined payload hash(es)")

    # Announce leadership, then start serving.
    _write_json_atomic(config.LEADER_FILE, {"epoch": node.epoch, "pid": os.getpid(), "ts": time.time()})
    with open(config.PRIMARY_PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    try:
        write_checkpoint(state, node.epoch)
    except OSError as e:
        log(f"initial checkpoint failed: {e}")

    threading.Thread(target=heartbeat_loop, args=(args.monitor_host, args.monitor_port, node),
                     daemon=True, name="heartbeat").start()
    threading.Thread(target=checkpoint_loop, args=(state, node), daemon=True, name="checkpoint").start()
    if not args.no_crash:
        threading.Thread(target=fault_injector_loop, args=(args.crash_mean, grace),
                         daemon=True, name="fault-injector").start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("shutdown requested (Ctrl+C) - clean exit, not a crash")


if __name__ == "__main__":
    main()
