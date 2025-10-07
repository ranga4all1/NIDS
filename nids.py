#!/opt/conda/envs/nids/bin/python

# Main script to combine packet capture and traffic analysis

import time
from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalysis
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP, get_if_list
import queue
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        try:
            self.packet_capture = PacketCapture()
            self.traffic_analyzer = TrafficAnalysis()
            self.detection_engine = DetectionEngine()
            self.alert_system = AlertSystem()
            self.interface = interface
            
            # Training phase parameters
            self.training_samples = []
            self.training_phase = True
            self.min_training_packets = 50
            
        except Exception as e:
            logger.error(f"Failed to initialize IDS: {e}")
            raise

    def start(self):
        try:
            print(f"Starting IDS on interface {self.interface}")
            self.packet_capture.start_capture(iface=self.interface)
            packet_count = 0

            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    
                    if not packet:
                        continue
                    
                    # Extract packet info safely
                    try:
                        if IP in packet and TCP in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                            print(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    except (AttributeError, IndexError) as e:
                        logger.debug(f"Error extracting packet info: {e}")
                        continue

                    # Analyze packet
                    features = self.traffic_analyzer.analyze_packet(packet)
                    if not features:
                        continue

                    print(f"Features: {features}")
                    packet_count += 1

                    # Training phase
                    if self.training_phase:
                        try:
                            feature_vector = [
                                features['packet_size'],
                                features['packet_rate'],
                                features['byte_rate']
                            ]
                            self.training_samples.append(feature_vector)
                            
                            print(f"[*] Training: {len(self.training_samples)}/{self.min_training_packets}")
                            
                            if len(self.training_samples) >= self.min_training_packets:
                                print("[+] Training anomaly detector...")
                                if self.detection_engine.train_anomaly_detector(self.training_samples):
                                    self.training_phase = False
                                    print("[+] Training complete! Now detecting threats...")
                                else:
                                    logger.error("Training failed, continuing to collect samples")
                                    
                        except (KeyError, TypeError, ValueError) as e:
                            logger.error(f"Error in training: {e}")
                            continue
                    
                    # Detection phase
                    else:
                        try:
                            threats = self.detection_engine.detect_threats(features)

                            if threats:
                                print("=" * 60)
                                print("⚠️  THREATS DETECTED ⚠️")
                                
                                packet_info = {
                                    'source_ip': src_ip,
                                    'destination_ip': dst_ip,
                                    'source_port': src_port,
                                    'destination_port': dst_port
                                }
                                
                                for threat in threats:
                                    self.alert_system.generate_alert(threat, packet_info)
                                    if threat['type'] == 'signature':
                                        print(f"  [SIGNATURE] Rule: {threat['rule']}, Confidence: {threat['confidence']}")
                                    elif threat['type'] == 'anomaly':
                                        print(f"  [ANOMALY] Score: {threat['score']:.3f}, Confidence: {threat['confidence']:.3f}")
                                
                                print("=" * 60)
                            else:
                                print("✓ No threats detected")
                                
                        except Exception as e:
                            logger.error(f"Error in threat detection: {e}")
                            continue

                except queue.Empty:
                    continue
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
        
        except KeyboardInterrupt:
            print("\nStopping capture and analysis...")
        except Exception as e:
            logger.error(f"Fatal error in IDS: {e}")
        finally:
            try:
                self.packet_capture.stop()
                print("Capture stopped.")
                print(f"Total packets processed: {packet_count}")
            except Exception as e:
                logger.error(f"Error stopping capture: {e}")


def select_interface():
    """Select network interface with validation."""
    try:
        interfaces = get_if_list()
        
        if not interfaces:
            logger.error("No network interfaces found")
            return None
        
        print("Available interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"{i+1}. {iface}")

        while True:
            try:
                choice = input(f"Select interface (1-{len(interfaces)}, or press Enter for first available): ").strip()
                
                # Default to first interface
                if not choice:
                    return interfaces[0]
                
                choice = int(choice)
                
                if 1 <= choice <= len(interfaces):
                    return interfaces[choice - 1]
                else:
                    print(f"Invalid choice. Enter 1-{len(interfaces)}")
                    
            except ValueError:
                print("Invalid input. Enter a number.")
            except (EOFError, KeyboardInterrupt):
                return None
                
    except Exception as e:
        logger.error(f"Error selecting interface: {e}")
        return None


if __name__ == "__main__":
    try:
        selected_interface = select_interface()
        
        if not selected_interface:
            print("No interface selected. Exiting.")
            exit(1)
        
        print(f"Using interface: {selected_interface}")
        
        ids = IntrusionDetectionSystem(interface=selected_interface)
        ids.start()
        
    except Exception as e:
        logger.error(f"Failed to start IDS: {e}")
        exit(1)