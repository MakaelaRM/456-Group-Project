"""
monitor.py - heartbeat monitor and failover controller. Alerts if auth_service.py
stops sending beats, then starts a standby that takes over from the last checkpoint.

How to run (start the monitor first, in its own terminal):
    python monitor.py

Optional, to test other timing values (T = interval in seconds, N = missed beats):
    python monitor.py --interval 0.5 --misses 1
        --> interval must always match HEARTBEAT_INTERVAL_S in config.py, so changing it requires it to also be edited there.

Optional, baselines for the attack tests:
    python monitor.py --no-fence              (do not kill the old primary)
    python monitor.py --insecure-checkpoint   (standby skips the checkpoint HMAC check)
    python monitor.py --no-crash              (standby never self-crashes, used by measure.py)

Then start the service in a second terminal:
    python auth_service.py

Note: beats are not authenticated, so forged or replayed beats are accepted.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

import config

_log_lock = threading.Lock()

SERVICE_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth_service.py")
FAILOVER_TIMEOUT_S = 10   # standby must send a new-epoch beat within this long
RETRY_DELAY_S = 3         # wait before trying another standby
MAX_ATTEMPTS = 3          # standby attempts per outage before giving up

# Monitor states
WAITING = "WAITING"   # no beat seen yet
UP = "UP"
DOWN = "DOWN"
FAILING_OVER = "FAILING_OVER"   # standby started, waiting for its first beat


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


def service_listening():
    """True if something is accepting connections on the service port."""
    try:
        with socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=0.3):
            return True
    except OSError:
        return False


def fence_old_primary():
    """Kill the old primary if it is still serving, and return what happened.

    Only kills if the service port is open, so a stale PID is never killed after a real crash.
    """
    if not service_listening():
        return "old primary already dead, nothing to kill"
    try:
        with open(config.PRIMARY_PID_FILE, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError):
        return "old primary still serving but primary.pid is unreadable, NOT fenced"
    try:
        os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))  # SIGTERM is a hard kill on Windows
    except OSError as e:
        return f"could not kill pid {pid} ({e}), NOT fenced"
    deadline = time.monotonic() + 3
    while service_listening() and time.monotonic() < deadline:
        time.sleep(0.1)   # wait for the port to free up
    return f"old primary was still serving, killed pid {pid}"


def start_standby(args):
    """Launch the standby as its own process. Returns right away, so the monitor keeps running."""
    cmd = [sys.executable, SERVICE_SCRIPT, "--role", "standby", "--monitor-port", str(args.port)]
    if args.insecure_checkpoint:
        cmd.append("--insecure-checkpoint")
    if args.no_crash:
        cmd.append("--no-crash")
    return subprocess.Popen(cmd)


def main():
    ap = argparse.ArgumentParser(description="Heartbeat monitor / failover controller")
    ap.add_argument("--host", default=config.HOST)
    ap.add_argument("--port", type=int, default=config.MONITOR_PORT)
    ap.add_argument("--interval", type=float, default=config.HEARTBEAT_INTERVAL_S,
                    help="expected heartbeat period T in seconds")
    ap.add_argument("--misses", type=int, default=config.MISSED_BEATS_N,
                    help="missed beats N before declaring the service DOWN")
    ap.add_argument("--no-fence", action="store_true",
                    help="do not kill the old primary before failover (baseline)")
    ap.add_argument("--insecure-checkpoint", action="store_true",
                    help="standby skips the checkpoint HMAC check (baseline)")
    ap.add_argument("--no-crash", action="store_true",
                    help="standby never self-crashes (for measure.py)")
    ap.add_argument("--quiet", action="store_true",
                    help="do not print an OK line for every beat")
    args = ap.parse_args()

    T = args.interval       # must match HEARTBEAT_INTERVAL_S in config.py
    N = args.misses
    timeout = N * T

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(T / 2)  # wake up often enough to check the timer

    log(f"monitor starting (pid={os.getpid()}, udp={args.host}:{args.port}, "
        f"T={T}s, N={N}, timeout={timeout:.2f}s, fencing={'OFF' if args.no_fence else 'ON'})")

    state = WAITING
    last_beat = time.monotonic()
    down_since = None          # monotonic time of the last beat before DOWN
    beats_total = 0
    epoch = None               # epoch of the current primary, taken from its beats
    detected_at = 0.0          # when the crash was detected (for MTTR)
    failover_at = 0.0          # when the current standby was started
    retry_at = 0.0             # earliest time for the next standby attempt
    attempts = 0
    standby = None
    warned = False             # log ignored beats once, not every time

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
                    b_epoch = beat.get("epoch")
                    if not isinstance(b_epoch, int) or isinstance(b_epoch, bool):
                        b_epoch = epoch or 1   # Part 1 beat without an epoch
                    stale = epoch is not None and b_epoch < epoch    # from a superseded node
                    old_alive = state == FAILING_OVER and b_epoch == epoch   # old primary still beating
                    if stale or old_alive:
                        if not warned:
                            log(f"ignoring heartbeat from epoch {b_epoch} "
                                f"(current epoch {epoch}, state {state})")
                            warned = True
                    else:
                        beats_total += 1
                        last_beat = now
                        if state in (DOWN, FAILING_OVER) and b_epoch > epoch:
                            log(f"[Service Restored] {config.SERVICE_NAME} service back as epoch {b_epoch} "
                                f"(MTTR {now - detected_at:.2f}s detect->restore, "
                                f"outage {now - down_since:.2f}s last beat->restore)")
                            warned = False
                        elif state == DOWN:
                            outage = now - down_since
                            log(f"RECOVERED: {config.SERVICE_NAME} service heartbeat resumed "
                                f"(seq={beat.get('seq')}, silent for {outage:.2f}s, false alarm)")
                        elif state == WAITING:
                            log(f"{config.SERVICE_NAME} service detected, monitoring started "
                                f"(epoch {b_epoch}, first seq={beat.get('seq')})")
                        state = UP
                        epoch = b_epoch
                        if not args.quiet:
                            print(f"OK seq={beat.get('seq')} epoch={epoch}", flush=True)
                # else: not a valid heartbeat -> silently ignored

            # --- timeout check --------------------------------------------
            silence = now - last_beat
            if state == UP and silence > timeout:
                state = DOWN
                down_since = last_beat
                detected_at, attempts, retry_at = now, 0, 0.0
                log(f"[Crash Detected] ALERT: {config.SERVICE_NAME} service DOWN "
                    f"(no heartbeat for {silence:.2f}s, N={N} missed, epoch {epoch})")

            # --- failover --------------------------------------------------
            if state == DOWN and now >= retry_at:
                attempts += 1
                log(f"[Failover Triggered] attempt {attempts}/{MAX_ATTEMPTS}: starting standby")
                log("fence: skipped (--no-fence)" if args.no_fence else f"fence: {fence_old_primary()}")
                if standby is not None:
                    standby.poll()   # reap the previous standby process
                standby = start_standby(args)
                state, failover_at, warned = FAILING_OVER, time.monotonic(), False
                log(f"standby started (pid={standby.pid}), waiting for a new-epoch heartbeat")

            if state == FAILING_OVER:
                rc = standby.poll()   # None while the standby is still running
                if rc is not None or now - failover_at > FAILOVER_TIMEOUT_S:
                    if rc is None:
                        standby.kill()
                        why = f"no new-epoch heartbeat within {FAILOVER_TIMEOUT_S}s"
                    elif rc == 2:
                        why = "standby exited: port in use, the old primary is still serving"
                    else:
                        why = f"standby exited with code {rc}"
                    log(f"[Failover Failed] attempt {attempts}/{MAX_ATTEMPTS}: {why}")
                    state = DOWN
                    if attempts >= MAX_ATTEMPTS:
                        log("[Failover Aborted] giving up, manual intervention needed")
                        retry_at = float("inf")
                    else:
                        retry_at = now + RETRY_DELAY_S

    except KeyboardInterrupt:
        log(f"monitor shutting down (Ctrl+C), {beats_total} beats received")
    finally:
        sock.close()


if __name__ == "__main__":
    main()