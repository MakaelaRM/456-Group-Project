This assignment is for Colorado State University, Course CS-456, taught by Professor Viktoria Koscinski
-- Mini Group Project 1, Resilient Security Systems (Part 1 - Failure Detection)
---- Team mates and authors: 
        -- Adelle Ferris
        -- Makaela Maryanski
        -- Isabella Sullivan
        -- Atlas Middleton



Purpose:
-- In this assignment, we are testing availability (of the CIA triad) through fault detection, one of the tactics deployed to maintain high availability (other tactics include disruption withstanding and operation recovery). 
        --> This group used an authentication service which crashes randomly, a Push-based UDP Heartbeat monitor to identify routine uptime and system failures, and an attack script that attempts to fool that monitor by spoofing the heartbeat and relaying and replaying the beats after it goes down. This assignment covers fault detection, as it is a lightweight security service that simulates realistic, non-deterministic system failures and malfunctions. The monitoring agent identifies when operational downtimes occur and reports when the service is not working as expected. This can be useful to identify when a tool is not working as expected and allow for a quick response. Additionally, understanding how monitoring and error detection protocols can be bypassed is important to prevent attacks from occuring and secure operational systems, as all fields use this type of technology. 
            --> *This script is for educational purposes only and should not be used for nefarious purposes*.



Instructions to Execute:
-- Check that Git and Python (v3.10 or newer) are installed 
        --> No virtual environment or package installs are required, only Python's standard library was used.
    *MacOS / Linux* (input):
        git --version
        python3 --version
    *Windows* (input):
        git --version
        py --list
-- Create the directory layout and clone our group's GitHub repository
    *MacOS / Linux / Windows* (input):
        mkdir CS-456-Group-Project
        cd CS-456-Group-Project
        git clone https://github.com/MakaelaRM/456-Group-Project.git
        cd 456-Group-Project
        git switch main
        git status
        git pull
-- Port Plan:
    *Component*                              *Port*          *Protocol*
        auth_service (login requests)	        5000	        TCP
        monitor (heartbeat listener)	        9000	        UDP
        attack_audit relay (replay demo)	    9001	        UDP
-- Commands:
    --> This execution requires four terminals to be open for proper processing.
        --> Each terminal must be open inside of the 456-Group-Project folder.
    --> Run each file in this order:
        1. Crash detection
            *Terminal 1*
                python monitor.py
                    --> Start first, it will print "OK seq=*n*" once beats appear.
            *Terminal 2*
                python auth_service.py
            *Terminal 3*
                python load_client.py
                    --> Wait for the service to print "CRASH"
                        ... Around 1.5 seconds later, monitor will log "ALERT".
        2. Heartbeat Spoof Attack (1) (after service has crashed)
            *Terminal 4*
                python attack_audit.py spoof
                    --> Monitor will log "RECOVERED" and continue to provide the sequence count, even though the service has crashed.
                    --> Stop the attack in *Terminal 4* (press *CTRL* with *C* at the same time).
                        ... Around 1.5 seconds later, monitor will log a new "ALERT".
        3. Relay Attack (2)
                --> Restart all terminals in this order
                    --> (press *CTRL* with *C* at the same time) - do this in every terminal
            *Terminal 1*
                python monitor.py
            *Terminal 2*
                python attack_audit.py relay
            *Terminal 3*
                python auth_service.py --monitor-port 9001
            *Terminal 4*
                python load_client.py
                    --> After the crash, the relay resends the last real beat, so the monitor keeps showing "OK" and the sequence number, with no "ALERT", which indicates succes and that the crash cannot be seen from the monitor. 
        4. Automated Failover (after Part 1 crash detection works)
            *Terminal 1*
                python monitor.py
                    --> On ALERT, fences the old primary and launches a standby,
                        logging [Crash Detected] -> [Failover Triggered] -> [Service Restored].
            *Terminal 2*
                python auth_service.py
            *Terminal 3*
                python load_client.py
                    --> After a crash, VERIFY replies show whether a token survived
                        ("VALID") or was lost ("INVALID ... STATE LOST").
        5. Checkpoint Tampering Attack
            *Terminal 1*
                python monitor.py
            *Terminal 2*
                python auth_service.py --no-crash
            *Terminal 3*
                python load_client.py
            *Terminal 4*
                python attack_audit.py tamper --kill-primary
                    --> Corrupts the checkpoint file and kills the primary immediately.
                        Monitor/standby should log "checkpoint REJECTED: HMAC mismatch"
                        and fall back to the last verified checkpoint.
                python attack_audit.py tamper --restore
        6. Split-Brain Attack
            *Terminal 1*
                python monitor.py
            *Terminal 2*
                python attack_audit.py split
                    --> Drops real heartbeats for a window while the primary stays alive,
                        to see if the monitor falsely declares it DOWN.
            *Terminal 3*
                python auth_service.py --monitor-port 9001
        7. MTTR and the lost updates
            *Stop all other terminals first*
                python measure.py mttr --runs 15
                    --> Crashes the primary 15 times and reports the detect-to-restore time, aka MTTR. It also identifies if a login from before the crash was still VALID afterward.
                python measure.py lost --intervals 1 2 5 --runs 8
                    --> Shows how many logins are lost on the new node for each checkpoint interval. 



Information regarding each component
-- README.md
        --> Provides information about each file and the setup / execution instructions for this assignment.


-- CONTRIBUTIONS.md
        --> Provides information regarding each author's involvement and effort.


-- config.py
        --> Configures the shared constants for the Resilient Security Systems project.
            --> Every component (service, monitor, attack script) imports from here and is in sync.
    What it does
        --> Ports (part 1)
        --> Heartbeat timing (part 1)
        --> Crash injection (part 1)
        --> Service protocol (part 1)
        --> Service state: Lockout threshold, lockout second, max sessions (part 2)
        --> Recovery: Checkpoint interval, promotion grace, file paths, HMAC key (part 2)
        --> Logging (part 1 and 2)


-- auth_service.py:
        --> The critical process (fake authentication / ticket service).
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
        python auth_service.py
            --> Run the file as normal
        python auth_service.py --monitor-port 9001     
            --> Send beats to attacker relay
        python auth_service.py --handler-delay 0.8
            --> test: slow requests must not stop heartbeats
        python auth_service.py --no-crash
            --> debugging only
        python auth_service.py --insecure-checkpoint
            --> trust checkpoint blindly, this is the baseline


-- load_client.py:
        --> Generates fake login traffic so service's per-request crash trigger has something to fire on, AND proves state survives failover.
            --> About 10% of requests are malformed (missing fields, oversized payload, binary garbage).
            --> Keeps running when the service is down, so you can restart the service and traffic resumes.
            --> Logins (some with wrong passwords)
            --> VERIFY of a token this client received earlier. After a failover this shows whether the state survived:
                    VALID    -> the session was carried over by the checkpoint
                    INVALID  -> the session was lost (issued after the last checkpoint, or the checkpoint was rejected)
    Usage
        python load_client.py
            --> Run with the 10% default rate of malformed requests.
        python load_client.py --malformed-rate 0.3 --verify-rate 0.4
            --> Send 30% malformed requests, so crashes occur more frequently.
        python load_client.py --status
          
            --> Print the service's STATUS line once and exit

-- monitor.py
        --> Heartbeat monitor and failover controller.
        --> Alerts if auth_service.py stops sending beats, then starts a standby that takes over from the last checkpoint.
            --> Prints "OK seq=*n*" for each beat.
            --> Prints and logs "ALERT: auth service DOWN" after 1.5 s (N x T) with no beat.
            --> Then kills the old primary if it is still serving, starts a standby, and logs "[Failover Triggered]" and "[Service Restored]" (with the MTTR).
            --> Logs "RECOVERED" if beats resume on their own. 
            --> Beats are not authenticated (intentional), so attack_audit.py can fool it.
    Usage
        python monitor.py
            --> Run the file as normal
        python monitor.py --interval 0.5 --misses 1
            --> test: N = 1 and the timeout interval = 0.5 seconds
                --> --interval must always match HEARTBEAT_INTERVAL_S in config.py, so changing it requires it to also be edited there.
        python monitor.py --no-fence
            --> baseline: do not kill the old primary (used by the split-brain attack)
        python monitor.py --insecure-checkpoint
            --> baseline: the standby skips the checkpoint HMAC check
        python monitor.py --no-crash
            --> the standby never self-crashes (used by measure.py)


-- measure.py
        --> Crashes the primary on purpose to measure MTTR and lost logins. Runs the real monitor and service in a tempoary copy of the project. Stop all other terminals first.

    Usage
        python measure.py mttr --runs 15
            --> Measure recovery time (MTTR) over many crashes, and if the pre-crash login survived. 
        python measure.py lost --intervals 1 2 5 --runs 8
            --> Measure lost updates against the checkpoint interval


-- attack_audit.py
        --> Adversarial audit script. Attempts to fool monitor.py by forging and replaying heartbeats (part 1), and to break the (part 2) failover / checkpoint recovery path.
            --> spoof: sends forged beats straight to the monitor so it reports the service healthy after a crash.
            --> relay: forwards real beats, then auto-replays the last one once the service goes silent.
            --> split: drops real heartbeats for a window while the primary is alive, to try to trigger a false failover / split-brain.
            --> tamper: corrupts the checkpoint file on disk to test the standby's HMAC check and fallback.
            --> success is shown by watching monitor.py: "OK" with no "ALERT" during the attack window, or (for tamper) if the standby loads the forged state or rejects it
    Usage
        python attack_audit.py spoof
            --> Attack 1: Run after auth_service.py has crashed.
        python attack_audit.py relay
            --> Attack 2: Start after monitor.py, before auth_service.py, then run:
                --> python auth_service.py --monitor-port 9001
        python attack_audit.py split
            --> Attack 1: Start after monitor.py, but before auth_service.py, then run:
                --> python auth_service.py --monitor-port 9001
        python attack_audit.py tamper
            --> Attack 2: Run while monitor.py and auth_service.py are up and a
                checkpoint has been written. Corrupts the state/checkpoint.json and kills
                the primary. Run with --restore afterward to put the original back
        python attack_audit.py tamper --kill-primary
            --> kills the primary right away, so the standby loads the tampered file before the next proper checkpoint write overwrites it.
        python attack_audit.py tamper --restore
            --> Restores the original checkpoint afterward.