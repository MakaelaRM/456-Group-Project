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



Information regarding each component
-- README.md
        --> Provides information about each file and the setup / execution instructions for this assignment.

-- CONTRIBUTIONS.md
        --> Provides information regarding each author's involvement and effort.

-- config.py
        --> Configures the shared constants for the Resilient Security Systems project.
            --> Every component (service, monitor, attack script) imports from here and is in sync.

    What it does
        --> Ports
        --> Heartbeat timing
        --> Crash injection
        --> Service protocol
        --> Logging

-- auth_service.py:
        --> The critical process (fake authentication / ticket service).

    What it does
  * TCP server on SERVICE_PORT. Protocol (one line per request):
        LOGIN *user* *password*\n
    Replies:  OK *session-token*\n   |   DENIED\n   |   ERR malformed\n
  * Pushes a UDP heartbeat to the monitor every T seconds from its own
    daemon thread, so a slow request never looks like a dead service.
  * Crashes NON-DETERMINISTICALLY, two independent ways:
      Trigger A: Random chance on each request (higher for malformed input,
                 simulating a parser bug).
      Trigger B: Background fault-injector thread that sleeps a random
                 (exponentially distributed) time, then kills the process.
  * A crash is os._exit(1): Whole process ends immediately
        --> Including the heartbeat thread.... It does NOT just sleep or hang.

    Usage
        python auth_service.py
            --> Run the file as normal
        python auth_service.py --monitor-port 9001     
            --> Send beats to attacker relay
        python auth_service.py --handler-delay 0.8
            --> test: slow requests must not stop heartbeats
        python auth_service.py --no-crash
            --> debugging only

-- load_client.py:
        --> Generates fake login traffic so service's per-request crash trigger has something to fire on.
            --> About 10% of requests are malformed (missing fields, oversized payload, binary garbage).
            --> Keeps running when the service is down, so you can restart the service and traffic resumes.

    Usage
        python load_client.py
            --> Run with the 10% default rate of malformed requests.
        python load_client.py --malformed-rate 0.3
            --> Send 30% malformed requests, so crashes occur more frequently.

-- monitor.py
        --> Heartbeat monitor. Runs as its own process and alerts when the service stops sending beats.
            --> Prints "OK seq=*n*" for each beat.
            --> Prints and logs "ALERT: auth service DOWN" after 1.5 s (N x T) with no beat.
            --> Logs "RECOVERED" if beats resume.
            --> Beats are not authenticated (intentional), so attack_audit.py can fool it.

    Usage
        python monitor.py
            --> Run the file as normal
        python monitor.py --interval 0.5 --misses 1
            --> test: N = 1 and the timeout interval = 0.5 seconds
                --> interval must always match HEARTBEAT_INTERVAL_S in config.py, so changing it requires it to also be edited there.

-- attack_audit.py
        --> Adversarial audit script. Attempts to fool monitor.py by forging and replaying heartbeats.
            --> spoof: sends forged beats straight to the monitor so it reports the service healthy after a crash.
            --> relay: forwards real beats, then auto-replays the last one once the service goes silent.
            --> Success is shown by watching monitor.py: "OK" with no "ALERT" during the attack window.

    Usage
        python attack_audit.py spoof
            --> Attack 1: Run after auth_service.py has crashed.
        python attack_audit.py relay
            --> Attack 2: Start after monitor.py, before auth_service.py, then run:
                --> python auth_service.py --monitor-port 9001
