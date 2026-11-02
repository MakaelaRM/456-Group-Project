# Adversarial Audit Summary

## Attack Scenario 1 -- Induced False Failover

`attack_audit.py split` relayed real heartbeats normally, then dropped them for
3 seconds while the primary stayed alive, to simulate a network partition.

The monitor logged `[Crash Detected]`, fenced (killed) the still-healthy
primary, and promoted a standby. No split-brain occurred -- only one node ever
served traffic -- but an attacker who only interferes with the heartbeat
channel was still able to force a real outage, since heartbeats are
unauthenticated and the monitor can't tell a dropped beat from a dead service.

## Attack Scenario 2 -- Tampered Checkpoint

`attack_audit.py tamper --kill-primary` corrupted `checkpoint.json` (injected
a forged session without updating the HMAC) and killed the primary
immediately so the standby would load it.

The standby rejected it (`checkpoint REJECTED: HMAC mismatch`) and fell back
to the last verified checkpoint instead, recovering successfully with slightly
older state. With `--insecure-checkpoint` enabled, the forged session loads
without rejection, confirming the HMAC check is what prevents this.

## Conclusion

The system never served traffic from two primaries at once and never accepted
tampered state. The main weakness found is the unauthenticated heartbeat
channel, which lets an attacker trigger a false failover without touching the
service itself.