"""
Shared constants for the Resilient Security Systems project (Part 1 + Part 2).
Every component (service, monitor, attack scripts) imports from here so the
ports, file paths and the heartbeat format stay in sync.

HEARTBEAT FORMAT (UDP datagram, UTF-8 JSON):
    {"svc": "auth", "seq": 42, "ts": 1761062400.123, "epoch": 2}
      svc   : service name (str)
      seq   : counter starting at 1, +1 per beat (int)
      ts    : sender wall-clock time, seconds since epoch (float)
      epoch : leadership generation (int). A fresh primary is epoch 1; every
              failover promotes a standby with epoch = old epoch + 1.
              (Part 2 addition. Older beats without "epoch" are still accepted.)

SERVICE PROTOCOL (TCP, one request line per connection):
    LOGIN <user> <password>   -> OK <token> | DENIED | LOCKED
    VERIFY <token>            -> VALID <user> | INVALID
    STATUS                    -> STATUS epoch=<n> sessions=<n> locked=<users|->
    anything else             -> ERR malformed

CHECKPOINT FILE (state/checkpoint.json):
    {"epoch": int, "saved_at": float, "state": {...}, "hmac": "<hex>"}
    hmac = HMAC-SHA256(CHECKPOINT_KEY, canonical JSON of epoch/saved_at/state)
"""

import os as _os

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

# --- Service state (Part 2) ---
LOCKOUT_THRESHOLD = 3          # consecutive wrong passwords before a user is locked
LOCKOUT_SECONDS = 60           # how long a lockout lasts
MAX_SESSIONS = 2000            # oldest sessions are evicted beyond this (bounds state size)

# --- Recovery / checkpointing (Part 2) ---
STATE_DIR = "state"
CHECKPOINT_FILE = "state/checkpoint.json"
CHECKPOINT_PREV_FILE = "state/checkpoint.prev.json"   # last *verified* older generation
LEADER_FILE = "state/leader.json"                      # {"epoch", "pid", "ts"} of current primary
PRIMARY_PID_FILE = "state/primary.pid"                 # used by the monitor to fence a hung primary
POISON_LOG = "state/poison.log"                        # hashes of payloads that crashed a node
CHECKPOINT_INTERVAL_S = 2.0    # trade-off: shorter = fewer lost updates, more disk I/O
PROMOTION_GRACE_S = 10.0       # a freshly promoted standby does not self-crash for this long

# Key used to sign checkpoints. DEMO ONLY: a real deployment would keep this in a
# key store, not in source. Override with:  set CS456_CKPT_KEY=something-secret
CHECKPOINT_KEY = _os.environ.get("CS456_CKPT_KEY", "cs456-demo-key-CHANGE-ME").encode()

# --- Logging ---
LOG_DIR = "logs"
SERVICE_LOG = "logs/service.log"
MONITOR_LOG = "logs/monitor.log"
