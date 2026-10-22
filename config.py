"""
Shared constants for the Resilient Security Systems project.
Every component (service, monitor, attack script) imports from here so the
ports and the heartbeat format stay in sync.

HEARTBEAT FORMAT (UDP datagram, UTF-8 JSON):
    {"svc": "auth", "seq": 42, "ts": 1761062400.123}
      svc : service name (str)
      seq : counter starting at 1, +1 per beat (int)
      ts  : sender wall-clock time, seconds since epoch (float)
"""

HOST = "127.0.0.1"

# --- Ports ---
SERVICE_PORT = 5000          # TCP: login requests to the auth service
MONITOR_PORT = 9000          # UDP: heartbeat listener (monitor)
RELAY_PORT = 9001            # UDP: attacker relay (replay demo only)

# --- Heartbeat timing ---
SERVICE_NAME = "auth"
HEARTBEAT_INTERVAL_S = 0.5   # T = 500 ms
MISSED_BEATS_N = 3           # N = 3  -> timeout = N * T = 1.5 s

# --- Crash injection (stochastic, never a fixed count) ---
CRASH_PROB_NORMAL = 0.03       # chance of crashing on any well-formed request
CRASH_PROB_MALFORMED = 0.20    # chance of crashing on malformed input (simulated parser bug)
BACKGROUND_FAULT_MEAN_S = 45   # mean of exponential delay for background fault injector

# --- Service protocol ---
MAX_PAYLOAD = 256              # bytes; anything larger counts as malformed
USERS = {                      # dummy credentials
    "alice": "wonderland",
    "bob": "builder",
    "carol": "password123",
}

# --- Logging ---
LOG_DIR = "logs"
SERVICE_LOG = "logs/service.log"
MONITOR_LOG = "logs/monitor.log"
