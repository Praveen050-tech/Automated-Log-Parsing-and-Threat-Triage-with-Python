Automated Log Parsing and Threat Triage with Python

1. Project Overview
As enterprise environments scale, security teams ingest massive volumes of text-based telemetry. Manual inspection is impossible. This project bridges the gap between core Python programming and Security Operations (SecOps) by engineering a lightweight, automated log analysis engine. The tool dynamically monitors streaming log files, applies Regular Expressions (Regex) to extract Indicators of Compromise (IoCs), aggregates event velocity, and fires programmatic high-fidelity alerts when behavioral thresholds are breached.

2. Technical Architecture & Data Flow
The automation suite operates as a real-time pipeline tracking append operations on a localized flat-file datastore:

[ Active File Log Appends ] ──> [ Stateful I/O Stream Pointer ] ──> [ Regex Token Extraction ]
                                                                             │
                                                                             v
[ Standardized SOC Alert ] <── [ Threshold Compliance Rule ] <── [ Statistical Aggregator ]

3. Deployment & Implementation Steps
Step 1: Environment Initialization
Provision a clean, isolated project workspace within your Kali Linux terminal to host your script and telemetry data:

Bash

      mkdir -p ~/portfolio_labs/log_parser_automation
      cd ~/portfolio_labs/log_parser_automation

<img width="1918" height="976" alt="Screenshot 2026-06-27 204444" src="https://github.com/user-attachments/assets/b0cf4110-6612-47fb-9f1d-64a74c696081" />

Step 2: Telemetry Baseline Storage
Create the initial log database. This simulates a pre-existing operational baseline containing historical network connections, including a mix of successful connections (INFO) and security anomalies (WARN):

Bash

      nano network_security.log

Paste the following historical telemetry lines exactly into the text editor:

      2026-06-27 10:00:01 INFO Connection accepted from 192.168.1.50 to port 443
      2026-06-27 10:00:15 WARN Unauthorized access attempt from 10.0.0.99 to port 22
      2026-06-27 10:01:02 INFO Connection accepted from 192.168.1.50 to port 80
      2026-06-27 10:01:22 WARN Unauthorized access attempt from 10.0.0.99 to port 22
      2026-06-27 10:02:05 WARN Unauthorized access attempt from 10.0.0.99 to port 23
      2026-06-27 10:02:40 INFO Connection accepted from 192.168.1.75 to port 443
      2026-06-27 10:03:12 WARN Unauthorized access attempt from 10.0.0.99 to port 3389

<img width="1919" height="977" alt="Screenshot 2026-06-27 204332" src="https://github.com/user-attachments/assets/2b308d82-afe7-4dfd-96e8-4ed1d95639a9" />

Step 3: Developing the Real-Time Script
Create the automation script. This utilizes standard file descriptor pointer manipulation (file.seek(0, 2)) to consciously bypass the pre-existing historical records stored above, shifting the script's focus exclusively to streaming events appended in real-time.

Bash
nano log_parser.py

Python

      import re
      import time
      from collections import Counter
      
      # Configuration Baselines
      LOG_FILE_PATH = "network_security.log"
      ALERT_THRESHOLD = 3
      
      # Pre-compiled regular expression for optimized IPv4 token extraction
      IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
      
      # Metric aggregation data structure
      threat_matrix = Counter()
      
      print("[INFO] Initializing Real-Time Security Log Analysis Engine...")
      print("[INFO] Monitoring stream target context: " + LOG_FILE_PATH)
      print("-" * 70)
      
      try:
          with open(LOG_FILE_PATH, "r") as file:
              # Shift file descriptor offset directly to the end of the current stream
              # This bypasses the pre-stored historical data to await new appends
              file.seek(0, 2)  
              
              while True:
                  line = file.readline()
                  
                  # If no telemetry record is appended, yield processing context briefly
                  if not line:
                      time.sleep(0.1)
                      continue
                      
                  # Filter criteria for security anomaly flags
                  if "WARN" in line:
                      found_ips = IP_REGEX.findall(line)
                      for ip in found_ips:
                          threat_matrix[ip] += 1
                          print(f"[SECURITY_EVENT] Target Host: {ip} | Metric Count: {threat_matrix[ip]}")
                          
                          # Enforce programmatic threshold compliance rules
                          if threat_matrix[ip] == ALERT_THRESHOLD:
                              print(f"\n[CRITICAL_ALERT] Security Threshold Violation Detected from Host: {ip}")
                              print(f"  -> Rule ID: MSG_BRUTE_FORCE_SCANNING")
                              print(f"  -> Action: Initiating Automated Incident Isolation Protocol.")
                              print("-" * 70 + "\n")
      
      except FileNotFoundError:
          print(f"[FATAL_ERROR] Execution halted. Target file path not found: {LOG_FILE_PATH}")
      except KeyboardInterrupt:
          print("\n[INFO] Termination signal received. Flushing intentional buffers and shutting down.")

<img width="1919" height="977" alt="Screenshot 2026-06-27 204355" src="https://github.com/user-attachments/assets/b524f104-f3fa-44da-9a68-10f23a296444" />
    
4. Operational Verification & Validation
To observe the real-time parsing engine dynamically separating the pre-stored background log metrics from live adversarial injection, arrange two terminal windows side-by-side.

Execution Protocol:
Terminal 1 (SOC Console): Initialize the script within the proper directory:

Bash
    
    cd ~/portfolio_labs/log_parser_automation
    python3 log_parser.py


The script boots cleanly, skipping the pre-stored lines, and enters a polling loop.

Terminal 2 (Attacker Simulator): Append fresh anomaly indicators directly into the active file stream:

Bash

    cd ~/portfolio_labs/log_parser_automation
    echo "2026-06-27 20:30:00 WARN Unauthorized access from 10.0.0.99 to port 22" >> network_security.log
    echo "2026-06-27 20:30:05 WARN Unauthorized access from 10.0.0.99 to port 23" >> network_security.log
    echo "2026-06-27 20:30:10 WARN Unauthorized access from 10.0.0.99 to port 3389" >> network_security.log

<img width="1919" height="967" alt="Screenshot 2026-06-27 204259" src="https://github.com/user-attachments/assets/28c20e66-acbe-4c0a-b8ba-e10de8ff6762" />

Output Signature Verification:
The real-time parsing logic processes the live input stream instantaneously, triggering a standardized critical alert block the exact millisecond the threshold metrics match:

Output:

    [INFO] Initializing Real-Time Security Log Analysis Engine...
    [INFO] Monitoring stream target context: network_security.log
    ----------------------------------------------------------------------
    [SECURITY_EVENT] Target Host: 10.0.0.99 | Metric Count: 1
    [SECURITY_EVENT] Target Host: 10.0.0.99 | Metric Count: 2
    [SECURITY_EVENT] Target Host: 10.0.0.99 | Metric Count: 3
    
    [CRITICAL_ALERT] Security Threshold Violation Detected from Host: 10.0.0.99
      -> Rule ID: MSG_BRUTE_FORCE_SCANNING
      -> Action: Initiating Automated Incident Isolation Protocol.
    ----------------------------------------------------------------------


Metric Vector,Observed Result Value,Risk Classification
Target Host,10.0.0.99,Malicious Attacker Proxy
Total Violations,4 Failed Connection Strings,Threshold Breach
Attack Pattern,"Multi-port tracking (22, 23, 3389)",Vertical Scanning / Brute Force
