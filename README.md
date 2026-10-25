This assignment is for CS-456, taught by Professor Viktoria Koscinski
-- Mini Group Project 1, Resilient Security Systems (Part 1 - Failure Detection)
---- Team mates and authors: 
        -- Adelle Ferris
        -- Makaela Maryanski
        -- Isabella Sullivan
        -- Atlas Middleton

Purpose:
-- In this assignment, we are testing availability (of the CIA triad) through fault detection via, disruption withstanding, and operation recovery.
        --> This group used authenticaton service that crashes randomly, a heartbeat monitor to identify those crashes, and a attack script that attempts to fool that monitor. This assignment primarily falls covers the fault detection side of this assignment, as it is a lightweight security service that simulates realistic, non-deterministic system malfunctions and ensures that a monitoring agent identifies when those downtimes occur and reports when the service is not working as expected. This can be useful to identify when a tool is not working as expected and allow for a quick response.
            --> *This script is for educational purposes only and should not be used for nefarious purposes*.

Instructions to Execute:
-- Check that Git and Python (v3.10) are installed 
    *MacOS / Linux* (input):
        git --version
        python3 --version
    *Windows* (input):
        git --version
        py --list
-- Create the directory layout and clone the Zephyr and Github repositories
    *MacOS / Linux / Windows* (input):
        mkdir CS-456-Group-Project
        cd CS-456-Group-Project
            git clone https://github.com/MakaelaRM/456-Group-Project.git
        git switch main
        git status
        git pull
-- Initialize the virtual environment <REMOVE if not required>
        --> Must be done everytime you open a new terminal
            --> Once you run this, (venv) should appear at the start of your shell's prompt.
            --> If it does not run, check the python version (see above) and update if needed. 
    *MacOS / Linux* (input):
        source venv/bin/activate
    *Windows* (input):
        venv/Scripts/activate.bat
-- Port Plan:
    *Component*                              *Port*          *Protocol*
        auth_service (login requests)	        5000	        TCP
        monitor (heartbeat listener)	        9000	        UDP
        attacker relay (replay demo only)	    9001	        UDP
-- Commands:
        --> This execution requires four terminals to be open for proper processing.
    *Terminal 1*
        python monitor.py
    *Terminal 2*
        python auth_service.py
    *Terminal 3*
        python load_client.py
    *Terminal 4*
        (after the crash)*
        python attack_audit.py spoof
    <FILL IN any additional information - above is the demo commands>

Information regarding each component
-- README.md
        --> Provides information about each file and the setup / execution instructions for this assignment.

-- CONTRIBUTIONS.md
        --> Provides information regarding each authors involvement and effort.

-- config.py
        --> Configures the shared constants for the Resilient Security Systems project.
            --> Every component (service, monitor, attack script) imports from here and is in sync.

    What it does
        --> Ports
        --> Hearbeat timing
        --> Crash injection
        --> Service protocol
        --> Logging

-- auth_service.py:
        --> The critical process (fake authentication / ticket service).

    What it does
  * TCP server on SERVICE_PORT. Protocol (one line per request):
        LOGIN <user> <password>\n
    Replies:  OK <session-token>\n   |   DENIED\n   |   ERR malformed\n
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
            --> Run
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
            --> FILL IN
        python load_client.py --malformed-rate 0.3
            --> FILL IN

-- monitor.py
        --> Heartbeat monitor. Runs as its own process and alerts when the service stops sending beats.
            --> Prints "OK seq=<n>" for each beat.
            --> Prints and logs "ALERT: auth service DOWN" after 1.5 s (N x T) with no beat.
            --> Logs "RECOVERED" if beats resume.
            --> Beats are not authenticated (intentional), so attack_audit.py can fool it.

    Usage
        python monitor.py
            --> Run (start this first)
        python monitor.py --interval 0.05 --misses 1
            --> test: change T and N values

-- attack_audit.py
        --> <FILL IN>
