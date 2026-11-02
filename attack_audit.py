"""
Adversarial audit script
    Attempts to fool monitor.py by forging and replaying heartbeats (Part 1),
    and to break the Part 2 failover/checkpoint recovery path.

How you know it worked:
    spoof/relay : watch monitor.py -- "OK" with no "ALERT" during the attack window.
    split       : watch monitor.py log an ALERT/failover while auth_service.py's
                  own terminal shows it never crashed.
    tamper      : after the next failover, watch for "REJECTED" / "DEGRADED
                  OPERATION" in the standby's log -- unless --insecure-checkpoint
                  is set, in which case the tampered state may load instead.

Usage
    python attack_audit.py spoof
        --> Attack 1 (Part 1): Run after auth_service.py has crashed.
    python attack_audit.py relay
        --> Attack 2 (Part 1): Start after monitor.py, before auth_service.py, then run:
            --> python auth_service.py --monitor-port 9001

    python attack_audit.py split
        --> Attack Scenario 1 (Part 2): Start after monitor.py, before auth_service.py:
            --> python auth_service.py --monitor-port 9001
        --> Forwards real beats for 5s, then drops them for 3s, then stops.

    python attack_audit.py tamper
        --> Attack Scenario 2 (Part 2): Run any time while the cluster is up.
            Backs up then corrupts state/checkpoint.json. Run with --restore
            afterward to put the original back.
    python attack_audit.py tamper --kill-primary
        --> Also kills the current primary right away, so the standby loads
            the tampered file before the next legitimate checkpoint write
            overwrites it.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import time

import config
from monitor import parse_beat


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# Attack 1 (Part 1): Spoof

def cmd_spoof(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    log(f"spoofing beats to {args.host}:{args.port} every {args.interval}s "
        f"-- make sure auth_service.py is already dead. Ctrl+C to stop. "
        f"Watch monitor.py: it should keep printing OK with no ALERT.")

    seq = 99000
    try:
        while True:
            beat = {"svc": config.SERVICE_NAME, "seq": seq, "ts": time.time()}
            sock.sendto(json.dumps(beat).encode("utf-8"), (args.host, args.port))
            log(f"sent forged beat seq={seq}")
            seq += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log("spoof stopped")


# Attack 2 (Part 1): Relay

def cmd_relay(args):
    crash_timeout = (config.MISSED_BEATS_N - 0.5) * config.HEARTBEAT_INTERVAL_S

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(config.HEARTBEAT_INTERVAL_S / 4)

    log(f"relaying {args.host}:{args.port} -> monitor at "
        f"{config.HOST}:{config.MONITOR_PORT}. Point auth_service.py at "
        f"--monitor-port {args.port}. Ctrl+C to stop.")

    last_beat = None
    last_recv = None
    replaying = False
    next_replay = 0.0

    try:
        while True:
            now = time.monotonic()
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                data = None

            if data is not None and parse_beat(data) is not None:
                last_beat, last_recv = data, now
                sock.sendto(data, (config.HOST, config.MONITOR_PORT))
                if replaying:
                    log("real beat seen back to relaying")
                    replaying = False
                else:
                    log(f"relayed real beat: {data!r}")

            if (not replaying and last_recv is not None
                    and now - last_recv > crash_timeout):
                replaying = True
                next_replay = now
                log(f"no real beat for {crash_timeout:.2f}s -- service appears "
                    f"crashed, auto-replaying last beat: {last_beat!r}")

            if replaying and now >= next_replay:
                sock.sendto(last_beat, (config.HOST, config.MONITOR_PORT))
                log(f"replayed stale beat: {last_beat!r}")
                next_replay = now + config.HEARTBEAT_INTERVAL_S
    except KeyboardInterrupt:
        log("relay stopped")


# Attack Scenario 1 (Part 2): Split -- drop live beats to try to force a false failover

def cmd_split(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.settimeout(config.HEARTBEAT_INTERVAL_S / 4)

    log(f"relaying {args.host}:{args.port} -> monitor at {config.HOST}:{config.MONITOR_PORT}. "
        f"Point auth_service.py at --monitor-port {args.port}. Forwarding normally for "
        f"{args.up_for:.1f}s, then dropping real beats for {args.drop_for:.1f}s "
        f"(monitor timeout is {config.MISSED_BEATS_N * config.HEARTBEAT_INTERVAL_S:.2f}s), "
        f"even though the primary stays alive the whole time. Ctrl+C to stop.")

    dropping = False
    phase_start = time.monotonic()

    try:
        while True:
            now = time.monotonic()
            phase_len = args.drop_for if dropping else args.up_for
            if now - phase_start >= phase_len:
                dropping = not dropping
                phase_start = now
                log("entering drop window (primary is NOT crashing)" if dropping
                    else "drop window over, resuming relay, stopping after this window")
                if not dropping:
                    return

            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue

            beat = parse_beat(data)
            if beat is None:
                continue

            if dropping:
                log(f"DROPPED real beat seq={beat.get('seq')} (primary alive, monitor won't see it)")
            else:
                sock.sendto(data, (config.HOST, config.MONITOR_PORT))
                log(f"forwarded real beat seq={beat.get('seq')}")
    except KeyboardInterrupt:
        log("split stopped")


# Attack Scenario 2 (Part 2): Tamper -- corrupt the checkpoint file on disk

def cmd_tamper(args):
    path = config.CHECKPOINT_FILE
    backup = path + ".audit-backup"

    if args.restore:
        if not os.path.exists(backup):
            log(f"no backup at {backup}, nothing to restore")
            return
        shutil.copyfile(backup, path)
        os.remove(backup)
        log(f"restored {path} from backup")
        return

    if not os.path.exists(path):
        log(f"{path} does not exist yet -- let the primary run a bit first")
        return

    shutil.copyfile(path, backup)
    log(f"backed up {path} -> {backup}")

    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)
    doc.setdefault("state", {}).setdefault("sessions", {})["AUDIT-INJECTED"] = {
        "user": "attacker", "issued": time.time(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    log(f"injected a forged session into {path} without fixing the hmac "
        f"(payload/signature now mismatch)")

    if not args.kill_primary:
        log("trigger a failover now and watch the standby's log for REJECTED / "
            "DEGRADED OPERATION. Run with --restore afterward to undo this.")
        return

    try:
        with open(config.PRIMARY_PID_FILE, "r", encoding="utf-8") as f:
            pid = int(f.read().strip())
    except (OSError, ValueError) as e:
        log(f"could not read {config.PRIMARY_PID_FILE} ({e}), primary not killed")
        return
    try:
        os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        log(f"killed primary pid {pid} -- watch the standby's log for REJECTED / "
            f"DEGRADED OPERATION. Run with --restore afterward to undo this.")
    except OSError as e:
        log(f"could not kill pid {pid} ({e})")


def main():
    ap = argparse.ArgumentParser(description="Adversarial audit of the heartbeat/failover/checkpoint path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_spoof = sub.add_parser("spoof", help="Part 1 Attack 1: forge beats straight to the monitor")
    p_spoof.add_argument("--host", default=config.HOST)
    p_spoof.add_argument("--port", type=int, default=config.MONITOR_PORT)
    p_spoof.add_argument("--interval", type=float, default=config.HEARTBEAT_INTERVAL_S)
    p_spoof.set_defaults(func=cmd_spoof)

    p_relay = sub.add_parser(
        "relay", help="Part 1 Attack 2: relay real beats, auto-replay the last one on crash")
    p_relay.add_argument("--host", default=config.HOST)
    p_relay.add_argument("--port", type=int, default=config.RELAY_PORT)
    p_relay.set_defaults(func=cmd_relay)

    p_split = sub.add_parser(
        "split", help="Part 2 Attack Scenario 1: drop live beats to try to induce a false failover")
    p_split.add_argument("--host", default=config.HOST)
    p_split.add_argument("--port", type=int, default=config.RELAY_PORT)
    p_split.add_argument("--up-for", type=float, default=5.0)
    p_split.add_argument("--drop-for", type=float, default=3.0)
    p_split.set_defaults(func=cmd_split)

    p_tamper = sub.add_parser(
        "tamper", help="Part 2 Attack Scenario 2: corrupt the live checkpoint file on disk")
    p_tamper.add_argument("--restore", action="store_true",
                          help="restore the backup instead of corrupting")
    p_tamper.add_argument("--kill-primary", action="store_true",
                          help="kill the primary right after tampering, no waiting for Ctrl+C")
    p_tamper.set_defaults(func=cmd_tamper)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()