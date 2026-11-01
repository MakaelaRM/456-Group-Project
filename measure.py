"""
measure.py - Part 2 measurements (Person B).

Runs the real monitor and service in a temporary copy of the project, kills the
primary on purpose, and reads the results from the monitor's log. Your own
state/ and logs/ folders are not touched. Stop all other terminals first
(this script uses ports 5000 and 9000).

How to run:
    python measure.py mttr --runs 15
    python measure.py lost --intervals 1 2 5 --runs 8

mttr: kills the primary --runs times. Reports detection-to-restore time (MTTR),
      total outage, and whether a login from before the crash was still VALID.
lost: logs in continuously, kills the primary, then counts how many of those
      sessions were missing on the new node, for each checkpoint interval.
"""

import argparse
import os
import random
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config  # noqa: E402

RESTORED = re.compile(r"\[Service Restored\].*MTTR ([\d.]+)s.*outage ([\d.]+)s")


def request(line):
    with socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=2) as s:
        s.sendall(line.encode() + b"\n")
        return s.recv(256).decode().strip()


def port_open():
    try:
        socket.create_connection((config.HOST, config.SERVICE_PORT), timeout=0.3).close()
        return True
    except OSError:
        return False


def wait_for(cond, timeout, what):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {what}")


class Cluster:
    """Monitor + primary running in a temp copy of the project with a chosen checkpoint interval."""

    def __init__(self, interval):
        self.dir = tempfile.mkdtemp(prefix="cs456_measure_")
        for name in ("config.py", "auth_service.py", "monitor.py"):
            shutil.copy(os.path.join(HERE, name), self.dir)
        cfg = os.path.join(self.dir, "config.py")
        text = open(cfg, encoding="utf-8").read()
        text = re.sub(r"^CHECKPOINT_INTERVAL_S\s*=\s*[\d.]+", f"CHECKPOINT_INTERVAL_S = {interval}",
                      text, flags=re.M)
        open(cfg, "w", encoding="utf-8").write(text)
        self.out = open(os.path.join(self.dir, "procs.out"), "w")
        self.monitor = self.start("monitor.py", "--quiet", "--no-crash")
        time.sleep(0.5)
        self.start("auth_service.py", "--no-crash")
        wait_for(port_open, 5, "the primary to start")
        time.sleep(1.0)  # let the monitor see the first beats

    def start(self, script, *flags):
        return subprocess.Popen([sys.executable, script, *flags], cwd=self.dir,
                                stdout=self.out, stderr=subprocess.STDOUT)

    def restored_events(self):
        try:
            text = open(os.path.join(self.dir, "logs", "monitor.log"), encoding="utf-8").read()
        except OSError:
            return []
        return [(float(m.group(1)), float(m.group(2))) for m in RESTORED.finditer(text)]

    def kill_primary(self):
        with open(os.path.join(self.dir, "state", "primary.pid")) as f:
            pid = int(f.read())
        os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))

    def crash_and_wait(self):
        """Kill the primary; return (mttr, outage) once the monitor logs Service Restored."""
        before = len(self.restored_events())
        self.kill_primary()
        wait_for(lambda: len(self.restored_events()) > before, 30, "[Service Restored]")
        return self.restored_events()[-1]

    def close(self):
        self.monitor.terminate()
        self.monitor.wait()
        try:
            self.kill_primary()
        except (OSError, ValueError):
            pass
        wait_for(lambda: not port_open(), 5, "the service port to close")
        self.out.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def summary(label, values):
    print(f"  {label:<32} mean {statistics.mean(values):6.2f}   min {min(values):6.2f}   "
          f"max {max(values):6.2f}   stdev {statistics.pstdev(values):5.2f}")


def run_mttr(runs):
    interval = config.CHECKPOINT_INTERVAL_S
    cluster = Cluster(interval)
    mttrs, outages, survived = [], [], 0
    try:
        for i in range(1, runs + 1):
            token = request("LOGIN alice wonderland").split()[1]
            time.sleep(interval + 0.5)  # make sure a checkpoint includes this login
            mttr, outage = cluster.crash_and_wait()
            ok = request(f"VERIFY {token}").startswith("VALID")
            survived += ok
            mttrs.append(mttr)
            outages.append(outage)
            print(f"  run {i:>2}: MTTR {mttr:.2f}s  outage {outage:.2f}s  state survived: {'yes' if ok else 'NO'}")
    finally:
        cluster.close()
    print(f"\nResults over {runs} crashes (T={config.HEARTBEAT_INTERVAL_S}s, N={config.MISSED_BEATS_N}):")
    summary("MTTR (detect->restore, s)", mttrs)
    summary("Outage (last beat->restore, s)", outages)
    print(f"  state survived: {survived}/{runs}")


def run_lost(intervals, runs):
    print(f"{'interval':>9} {'avg lost':>9} {'max lost':>9} {'avg window':>11} {'max window':>11}   (logins every 0.1s)")
    for interval in intervals:
        cluster = Cluster(interval)
        lost_counts, windows = [], []
        try:
            for _ in range(runs):
                logins = []  # (time, token)
                stop = time.monotonic() + 2 * interval + random.uniform(0, interval)
                while time.monotonic() < stop:
                    logins.append((time.monotonic(), request("LOGIN alice wonderland").split()[1]))
                    time.sleep(0.1)
                t_kill = time.monotonic()
                cluster.crash_and_wait()
                lost = [t for t, tok in logins if not request(f"VERIFY {tok}").startswith("VALID")]
                lost_counts.append(len(lost))
                windows.append(t_kill - min(lost) if lost else 0.0)
        finally:
            cluster.close()
        print(f"{interval:>8}s {statistics.mean(lost_counts):>9.1f} {max(lost_counts):>9} "
              f"{statistics.mean(windows):>10.2f}s {max(windows):>10.2f}s")
    print("\nlost = logins missing on the new node; window = time between the first lost login and the crash.")


def main():
    ap = argparse.ArgumentParser(description="Part 2 measurements")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mttr", help="measure recovery time over many crashes")
    m.add_argument("--runs", type=int, default=15)
    lo = sub.add_parser("lost", help="measure lost updates vs checkpoint interval")
    lo.add_argument("--intervals", type=float, nargs="+", default=[1, 2, 5])
    lo.add_argument("--runs", type=int, default=8)
    args = ap.parse_args()

    if port_open():
        sys.exit("Port 5000 is already in use. Stop the running service/monitor first.")
    if args.cmd == "mttr":
        run_mttr(args.runs)
    else:
        run_lost(args.intervals, args.runs)


if __name__ == "__main__":
    main()