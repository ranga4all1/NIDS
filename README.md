# NIDS: Network Intrusion Detection System

## Problem Statement

The primary goal is to develop a Network Intrusion Detection System (NIDS) using Python to identify potential security threats and anomalies within network traffic. This involves capturing network packets, analyzing them for suspicious patterns, and generating alerts when threats are detected.

## Solution

The NIDS solution comprises several modules working together to achieve real-time threat detection:

- **Packet Capture:** Captures network packets from a specified interface.
- **Traffic Analysis:** Analyzes captured packets to extract relevant features.
- **Detection Engine:** Detects threats based on signature rules and anomaly detection.
- **Alert System:** Generates alerts when threats are detected.

## Logic

1.  **Packet Capture:** The [`PacketCapture`](packet_capture.py) module uses `scapy` to capture network packets. It captures packets from a specified network interface and puts them into a queue for further processing.
2.  **Traffic Analysis:** The [`TrafficAnalysis`](traffic_analysis.py) module analyzes each packet, extracting features such as packet size, flow duration, packet rate, byte rate, TCP flags, and window size.
3.  **Detection Engine:** The [`DetectionEngine`](detection_engine.py) module uses two methods for threat detection:
    -   **Signature-based detection:** It uses a set of predefined rules to identify known attack patterns.
    -   **Anomaly-based detection:** It employs an Isolation Forest model to identify unusual traffic patterns. The model is trained on normal traffic data to establish a baseline.
4.  **Alert System:** The [`AlertSystem`](alert_system.py) module generates alerts when a threat is detected. It logs the alerts with details such as timestamp, threat type, source IP, destination IP, and confidence level.

The main script, [`nids.py`](nids.py), ties these components together, orchestrating the packet capture, traffic analysis, threat detection, and alert generation processes.

## Files Used

-   [`nids.py`](nids.py): Main script to combine packet capture and traffic analysis.
-   [`packet_capture.py`](packet_capture.py): Packet capture module.
-   [`traffic_analysis.py`](traffic_analysis.py): Traffic analysis module.
-   [`detection_engine.py`](detection_engine.py): Detection engine module.
-   [`alert_system.py`](alert_system.py): Alert system module.
-   [`requirements.txt`](requirements.txt): List of required Python packages.
-   [`commands.md`](commands.md): Useful commands for setup and execution.

## Usage Instructions

1.  **Install required libraries:**

    ```
    conda create -n nids python
    conda deactivate
    conda activate nids

    sudo apt update
    sudo apt install libpcap0.8 libpcap0.8-dev tcpdump

    pip install -r requirements.txt
    ```
2.  **Start NIDS:**

    ```
    conda activate nids
    sudo /opt/conda/envs/nids/bin/python nids.py
    # Select interface 'lo' (loopback), if you plan to use traffic generator for testing
    ```

    Note: Make sure to use the `python` executable from your virtual environment.

3.  **Generate suspicious traffic (optional):**

    In another terminal:

    ```
    conda activate nids
    sudo /opt/conda/envs/nids/bin/python generate_suspicious_traffic.py
    ```
