#!/opt/conda/envs/nids/bin/python

import sys
import signal
import time
from scapy.all import IP, TCP, send

# Target configuration
TARGET_IP = "127.0.0.1"
SUSPICIOUS_PORTS = [22, 23, 3389, 8080]
SUSPICIOUS_FLAGS = ["F", "U", "S"]
ANOMALOUS_PACKET_SIZES = [64, 1500, 40, 1000]
ANOMALOUS_PACKET_RATES = [100, 500, 1000]

running = True

def signal_handler(sig, frame):
    """Handle Ctrl+C to stop traffic generation."""
    global running
    print("\n[!] Stopping traffic generation...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def generate_normal_traffic(target_ip, duration=30):
    """
    Generate normal-looking traffic for NIDS training phase.
    
    Args:
        target_ip: Target IP address
        duration: How long to generate normal traffic (seconds)
    """
    print(f"\n[*] Generating NORMAL traffic for {duration} seconds (for training)...")
    print("[*] Let the NIDS train on this baseline traffic")
    
    start_time = time.time()
    packet_count = 0
    
    try:
        while running and (time.time() - start_time) < duration:
            # Normal HTTP traffic
            packet = IP(dst=target_ip) / TCP(dport=80, flags="S") / ("X" * 100)
            send(packet, verbose=0)
            packet_count += 1
            
            # Small delay to simulate normal traffic rate
            time.sleep(0.1)
            
            if packet_count % 50 == 0:
                print(f"  Sent {packet_count} normal packets...")
    
    except Exception as e:
        print(f"[!] Error generating normal traffic: {e}")
        sys.exit(1)
    
    print(f"[+] Normal traffic complete ({packet_count} packets sent)")
    print("[+] NIDS should now be trained and ready to detect threats\n")

def generate_suspicious_traffic(target_ip, ports, flags, packet_sizes, packet_rates):
    """Generate various types of suspicious traffic."""
    global running
    
    print("[*] Starting SUSPICIOUS traffic generation...")
    print("[*] Watch for threat detections in the NIDS terminal!\n")
    
    # 1. Port scan simulation
    print("[1/4] Simulating PORT SCAN...")
    for port in ports:
        if not running:
            break
        for flag in flags:
            if not running:
                break
            print(f"  → Scanning port {port} with {flag} flag")
            try:
                packet = IP(dst=target_ip) / TCP(dport=port, flags=flag)
                send(packet, verbose=0)
                time.sleep(0.05)  # Small delay
            except Exception as e:
                print(f"[!] Error: {e}")
                sys.exit(1)
    
    time.sleep(2)
    
    # 2. Anomalous packet sizes
    print("\n[2/4] Sending ANOMALOUS PACKET SIZES...")
    for size in packet_sizes:
        if not running:
            break
        print(f"  → Sending {size}-byte packet")
        try:
            payload = "A" * min(size, 1400)  # Cap at reasonable size
            packet = IP(dst=target_ip) / TCP(dport=80) / payload
            send(packet, verbose=0)
            time.sleep(0.1)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
    
    time.sleep(2)
    
    # 3. High rate traffic (burst)
    print("\n[3/4] Sending HIGH RATE TRAFFIC BURSTS...")
    for rate in packet_rates:
        if not running:
            break
        print(f"  → Burst of {rate} packets")
        try:
            for i in range(rate):
                if not running:
                    break
                packet = IP(dst=target_ip) / TCP(dport=80) / "B"
                send(packet, verbose=0)
                
                # Very short delay to achieve high rate
                if i % 10 == 0:
                    time.sleep(0.001)
        except Exception as e:
            print(f"[!] Error: {e}")
            sys.exit(1)
        
        time.sleep(1)
    
    # 4. SYN flood simulation
    print("\n[4/4] Simulating SYN FLOOD...")
    try:
        for i in range(100):
            if not running:
                break
            packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
            send(packet, verbose=0)
            
            if i % 20 == 0:
                print(f"  → Sent {i} SYN packets")
            
            time.sleep(0.01)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    
    print("\n[+] Suspicious traffic generation complete!")

def main():
    print("=" * 70)
    print("NIDS Traffic Generator")
    print("=" * 70)
    print(f"Target: {TARGET_IP}")
    print("\nThis script will:")
    print("  1. Generate NORMAL traffic (30 sec) - for NIDS training")
    print("  2. Generate SUSPICIOUS traffic - to trigger detections")
    print("\nMake sure your NIDS is running and monitoring the 'lo' interface!")
    print("=" * 70)
    
    try:
        input("\nPress ENTER to start or Ctrl+C to cancel...")
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        sys.exit(0)
    
    try:
        # Phase 1: Normal traffic for training
        generate_normal_traffic(TARGET_IP, duration=30)
        
        # Wait for training to complete
        print("[*] Waiting 5 seconds for NIDS to complete training...")
        time.sleep(5)
        
        # Phase 2: Suspicious traffic
        generate_suspicious_traffic(
            TARGET_IP, 
            SUSPICIOUS_PORTS, 
            SUSPICIOUS_FLAGS, 
            ANOMALOUS_PACKET_SIZES, 
            ANOMALOUS_PACKET_RATES
        )
        
        print("\n" + "=" * 70)
        print("COMPLETE! Check the NIDS terminal for detected threats.")
        print("Also check: ids_alerts.log for logged alerts")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()