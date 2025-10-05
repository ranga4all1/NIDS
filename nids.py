#!/opt/conda/envs/nids/bin/python

# Main script to combine packet capture and traffic analysis

import time
from packet_capture import PacketCapture  # Import PacketCapture from packet_capture.py
from traffic_analysis import TrafficAnalysis  # Import TrafficAnalysis from traffic_analysis.py
from detection_engine import DetectionEngine  # Import DetectionEngine from detection_engine.py
from scapy.all import IP, TCP


def main():
    # Initialize PacketCapture, TrafficAnalysis, and DetectionEngine
    capture = PacketCapture()  # Default interface
    analyzer = TrafficAnalysis()
    detector = DetectionEngine()

    # Start packet capture
    capture.start_capture()

    try:
        print("Capturing and analyzing traffic... Press Ctrl+C to stop.")
        while True:
            packet = capture.packet_queue.get(timeout=1)  # Get the next packet with a timeout of 1 second
            if packet:
                # Print packet details
                if IP in packet and TCP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    print(f"Packet Details: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")

                # Analyze the captured packet
                features = analyzer.analyze_packet(packet)
                if features:
                    print("Extracted Features:", features)

                    # Detect threats
                    threats = detector.detect_threats(features)
                    if threats:
                        print("Threats Detected:", threats)
            else:
                # No packet captured in the last second
                pass  # You can add a sleep or other logic here if needed

    except KeyboardInterrupt:
        print("Stopping capture and analysis...")
    finally:
        # Stop packet capture
        capture.stop()
        print("Capture stopped.")


if __name__ == "__main__":
    main()