#!/opt/conda/envs/nids/bin/python

# Main script to combine packet capture and traffic analysis

import time
from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalysis
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP


def main():
    # Initialize PacketCapture, TrafficAnalysis, and DetectionEngine
    capture = PacketCapture()
    analyzer = TrafficAnalysis()
    detector = DetectionEngine()
    alerter = AlertSystem()

    # Start packet capture
    capture.start_capture()

    # Training phase parameters
    training_samples = []
    training_phase = True
    min_training_packets = 20  # Collect 20 packets for baseline

    try:
        print("Capturing and analyzing traffic... Press Ctrl+C to stop.")
        print(f"[*] Training phase: Collecting {min_training_packets} packets for baseline...")
        
        packet_count = 0
        
        while True:
            packet = capture.packet_queue.get(timeout=1)
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
                    packet_count += 1

                    # Training phase: collect baseline data
                    if training_phase:
                        feature_vector = [
                            features['packet_size'],
                            features['packet_rate'],
                            features['byte_rate']
                        ]
                        training_samples.append(feature_vector)
                        
                        print(f"[*] Training sample {len(training_samples)}/{min_training_packets} collected")
                        
                        # Once we have enough samples, train the model
                        if len(training_samples) >= min_training_packets:
                            print("[+] Training anomaly detector...")
                            detector.train_anomaly_detector(training_samples)
                            training_phase = False
                            print("[+] Training complete! Now detecting threats...")
                    
                    # Detection phase: only run after training
                    else:
                        # Detect threats
                        threats = detector.detect_threats(features)
                        if threats:
                            print("=" * 60)
                            print("⚠️  THREATS DETECTED ⚠️")
                            for threat in threats:
                                if threat['type'] == 'signature':
                                    print(f"  [SIGNATURE] Rule: {threat['rule']}, Confidence: {threat['confidence']}")
                                    alerter.send_alert(f"Signature Threat Detected: Rule={threat['rule']}, Confidence={threat['confidence']}")  # Send alert
                                elif threat['type'] == 'anomaly':
                                    print(f"  [ANOMALY] Score: {threat['score']:.3f}, Confidence: {threat['confidence']:.3f}")
                                    alerter.send_alert(f"Anomaly Threat Detected: Score={threat['score']:.3f}, Confidence={threat['confidence']:.3f}")  # Send alert
                            print("=" * 60)
                        else:
                            print("✓ No threats detected")
            else:
                # No packet captured in the last second
                pass

    except KeyboardInterrupt:
        print("\nStopping capture and analysis...")
    finally:
        # Stop packet capture
        capture.stop()
        print("Capture stopped.")
        print(f"Total packets processed: {packet_count}")


if __name__ == "__main__":
    main()