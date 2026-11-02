# Contributions Part 1

## Service (config.py, auth_service.py, load_client.py)
- Isabella Sullivan: Wrote the auth service, crash injection, heartbeat sender, and load client.

## Monitor (monitor.py)
- Makaela Maryanski: wrote the heartbeat monitor, including timeout detection (N x T), DOWN/RECOVERED alerts, timestamped logging, and handling of invalid packets

## Attack (attack_audit.py)
- Atlas Middleton: Wrote the adversarial audit script, including heartbeat spoofing, a relay-based replay attack, and handling of the attack timing against the monitor's detection window.

## Write-up
- Adelle Ferris: Wrote up the README.md and PDF report for the project report. 

## Individual Reflections
- All teammates have completed their reflections seperately. 

# Contributions Part 2

## Monitor and measurements (monitor.py, measure.py)
- Makaela Maryanski: updated the monitor into the failover controller (state machine, fencing, standby launch, [Crash Detected]/[Failover Triggered]/[Service Restored] logging) and wrote measure.py for MTTR and lost-update measurements

## Attack (attack_audit.py)
- Atlas Middleton: Updated the attack audit script to perform the split brain and 