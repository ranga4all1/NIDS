#!/opt/conda/envs/nids/bin/python

# Main script to combine packet capture and traffic analysis

import time
import argparse
from packet_capture import PacketCapture
from traffic_analysis import TrafficAnalysis
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP, get_if_list
import queue
import logging

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')  # Changed to DEBUG
logger = logging.getLogger(__name__)


class IntrusionDetectionSystem:
    def __init__(self, interface="eth0", filter_expression=None, target_ips=None):
        try:
            self.packet_capture = PacketCapture(filter_expression=filter_expression)
            self.traffic_analyzer = TrafficAnalysis()
            self.detection_engine = DetectionEngine()
            self.alert_system = AlertSystem()
            self.interface = interface
            self.target_ips = target_ips or []
            
            # Training phase parameters
            self.training_samples = []
            self.training_phase = True
            self.min_training_packets = 20  # Reduced from 50 for faster demo
            
        except Exception as e:
            logger.error(f"Failed to initialize IDS: {e}")
            raise

    def should_process_packet(self, packet):
        """Check if packet matches our filter criteria."""
        if not self.target_ips:
            return True
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                return src_ip in self.target_ips or dst_ip in self.target_ips
        except Exception as e:
            logger.debug(f"Error checking packet filter: {e}")
        
        return False

    def start(self):
        try:
            print(f"\n{'='*70}")
            print(f"NIDS Started - Monitoring interface: {self.interface}")
            if self.target_ips:
                print(f"IP Filter: {', '.join(self.target_ips)}")
            print(f"{'='*70}")
            print("\nWaiting for packets... (Press Ctrl+C to stop)\n")
            
            self.packet_capture.start_capture(iface=self.interface)
            packet_count = 0
            filtered_count = 0
            last_packet_time = time.time()
            idle_warning_shown = False

            while True:
                try:
                    # Use longer timeout to prevent immediate termination
                    packet = self.packet_capture.packet_queue.get(timeout=5)
                    
                    if not packet:
                        continue
                    
                    last_packet_time = time.time()
                    idle_warning_shown = False
                    
                    # Apply IP filter if specified
                    if self.target_ips and not self.should_process_packet(packet):
                        filtered_count += 1
                        if filtered_count % 100 == 0:
                            print(f"[Filtered {filtered_count} non-target packets...]")
                        continue
                    
                    # Extract packet info safely
                    try:
                        if IP in packet and TCP in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst
                            src_port = packet[TCP].sport
                            dst_port = packet[TCP].dport
                            tcp_flags = packet[TCP].flags
                            
                            # Highlight suspicious destination ports
                            port_marker = " 🎯" if dst_port in [22, 23, 80, 443, 3389, 8080] else ""
                            print(f"Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}{port_marker} [flags:{tcp_flags}]")
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
                            # Pass packet context for better detection
                            packet_context = {
                                'source_ip': src_ip,
                                'dest_ip': dst_ip,
                                'source_port': src_port,
                                'dest_port': dst_port
                            }
                            
                            # Debug: Show when scanning suspicious ports
                            if dst_port in [22, 23, 80, 443, 3389, 8080]:
                                logger.debug(f"Checking suspicious port {dst_port}")
                            
                            threats = self.detection_engine.detect_threats(features, packet_context)

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
                    # Show idle warning every 30 seconds
                    if not idle_warning_shown and (time.time() - last_packet_time) > 30:
                        print(f"\n[*] No packets captured in last 30 seconds...")
                        print(f"[*] Packets processed so far: {packet_count}")
                        if self.target_ips:
                            print(f"[*] Make sure traffic is being generated to/from: {', '.join(self.target_ips)}")
                        print(f"[*] Still monitoring...\n")
                        idle_warning_shown = True
                    continue
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.error(f"Error processing packet: {e}")
                    continue
        
        except KeyboardInterrupt:
            print("\n\nStopping capture and analysis...")
        except Exception as e:
            logger.error(f"Fatal error in IDS: {e}")
        finally:
            try:
                self.packet_capture.stop()
                print("\n" + "="*70)
                print("NIDS Statistics:")
                print(f"  Total packets processed: {packet_count}")
                if self.target_ips:
                    print(f"  Packets filtered out: {filtered_count}")
                print("="*70)
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


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System (NIDS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with interface selection (interactive)
  sudo python nids.py
  
  # Filter for localhost traffic only (for demo with generate_suspicious_traffic.py)
  sudo python nids.py --interface lo --localhost-only
  
  # Filter for specific IP addresses
  sudo python nids.py --filter-ips 127.0.0.1 192.168.1.100
  
  # Use BPF filter for more control
  sudo python nids.py --bpf "host 127.0.0.1 and tcp"
  
  # Specify interface directly
  sudo python nids.py --interface lo --localhost-only
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        type=str,
        help='Network interface to monitor (e.g., eth0, lo). If not specified, will prompt for selection.'
    )
    
    parser.add_argument(
        '--localhost-only', '-l',
        action='store_true',
        help='Only monitor localhost/loopback traffic (127.0.0.1). Useful for demo with traffic generator.'
    )
    
    parser.add_argument(
        '--filter-ips',
        nargs='+',
        metavar='IP',
        help='Only monitor traffic to/from specified IP addresses (space-separated list).'
    )
    
    parser.add_argument(
        '--bpf',
        type=str,
        metavar='FILTER',
        help='BPF (Berkeley Packet Filter) expression for advanced filtering (e.g., "host 127.0.0.1 and tcp").'
    )
    
    parser.add_argument(
        '--no-interactive',
        action='store_true',
        help='Disable interactive interface selection (uses first available or --interface).'
    )
    
    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_arguments()
        
        # Determine interface
        if args.interface:
            selected_interface = args.interface
        elif args.no_interactive:
            interfaces = get_if_list()
            selected_interface = interfaces[0] if interfaces else None
        else:
            selected_interface = select_interface()
        
        if not selected_interface:
            print("No interface selected. Exiting.")
            exit(1)
        
        # Build BPF filter
        bpf_filter = None
        if args.bpf:
            bpf_filter = args.bpf
        elif args.localhost_only:
            # Use a simpler filter that should work on loopback
            bpf_filter = "tcp"  # Just capture TCP, we'll filter IPs in Python
            print("Capturing TCP traffic on loopback interface")
        
        # Build IP filter list
        target_ips = None
        if args.filter_ips:
            target_ips = args.filter_ips
            print(f"Filtering for IPs: {', '.join(target_ips)}")
        elif args.localhost_only:
            target_ips = ['127.0.0.1', '::1']  # IPv4 and IPv6 localhost
        
        if bpf_filter:
            print(f"BPF Filter: {bpf_filter}")
        
        ids = IntrusionDetectionSystem(
            interface=selected_interface,
            filter_expression=bpf_filter,
            target_ips=target_ips
        )
        ids.start()
        
    except Exception as e:
        logger.error(f"Failed to start IDS: {e}")
        exit(1)