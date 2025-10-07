#!/opt/conda/envs/nids/bin/python

# Main script to combine packet capture and traffic analysis

import time
from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalysis
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP, get_if_list
import queue


class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalysis()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

        # Training phase parameters
        self.training_samples = []
        self.training_phase = True
        self.min_training_packets = 50  # Collect 50 packets for baseline

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture()

        packet_count = 0

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                if packet:
                    # Print packet details
                    if IP in packet and TCP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        print(f"Packet Details: Source IP: {src_ip}, Destination IP: {dst_ip}, Source Port: {src_port}, Destination Port: {dst_port}")

                    features = self.traffic_analyzer.analyze_packet(packet)

                    if features:
                        print("Extracted Features:", features)
                        packet_count += 1

                        # Training phase: collect baseline data
                        if self.training_phase:
                            feature_vector = [
                                features['packet_size'],
                                features['packet_rate'],
                                features['byte_rate']
                            ]
                            self.training_samples.append(feature_vector)
                            
                            print(f"[*] Training sample {len(self.training_samples)}/{self.min_training_packets} collected")
                            
                            # Once we have enough samples, train the model
                            if len(self.training_samples) >= self.min_training_packets:
                                print("[+] Training anomaly detector...")
                                self.detection_engine.train_anomaly_detector(self.training_samples)
                                self.training_phase = False
                                print("[+] Training complete! Now detecting threats...")
                        
                        # Detection phase: only run after training
                        else:
                            threats = self.detection_engine.detect_threats(features)

                            if threats:
                                print("=" * 60)
                                print("⚠️  THREATS DETECTED ⚠️")
                                for threat in threats:
                                    packet_info = {
                                        'source_ip': packet[IP].src,
                                        'destination_ip': packet[IP].dst,
                                        'source_port': packet[TCP].sport,
                                        'destination_port': packet[TCP].dport
                                    }
                                    self.alert_system.generate_alert(threat, packet_info)
                                    if threat['type'] == 'signature':
                                        print(f"  [SIGNATURE] Rule: {threat['rule']}, Confidence: {threat['confidence']}")
                                        #self.alerter.send_alert(f"Signature Threat Detected: Rule={threat['rule']}, Confidence={threat['confidence']}")  # Send alert
                                    elif threat['type'] == 'anomaly':
                                        print(f"  [ANOMALY] Score: {threat['score']:.3f}, Confidence: {threat['confidence']:.3f}")
                                        #self.alerter.send_alert(f"Anomaly Threat Detected: Score={threat['score']:.3f}, Confidence={threat['confidence']}")  # Send alert
                                print("=" * 60)
                            else:
                                print("✓ No threats detected")

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("\nStopping capture and analysis...")
                break
            
        # Stop packet capture
        self.packet_capture.stop()
        print("Capture stopped.")
        print(f"Total packets processed: {packet_count}")


if __name__ == "__main__":
    # Detect available interfaces
    interfaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")

    # Ask user to select an interface
    while True:
        try:
            choice = int(input(f"Select an interface (default is eth0, enter 0): "))
            if choice == 0:
                selected_interface = "eth0"
                break
            elif 1 <= choice <= len(interfaces):
                selected_interface = interfaces[choice-1]
                break
            else:
                print("Invalid choice. Please select a valid interface.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    ids = IntrusionDetectionSystem(interface=selected_interface)
    ids.start()