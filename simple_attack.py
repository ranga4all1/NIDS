#!/opt/conda/envs/nids/bin/python

"""
Clear and visible attack generator for NIDS testing
"""

import sys
import signal
import time
from scapy.all import IP, TCP, send

TARGET_IP = "127.0.0.1"
SOURCE_PORT = 54321  # Fixed source port for easy tracking
running = True

def signal_handler(sig, frame):
    global running
    print("\n[!] Stopping...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def wait_for_user():
    """Wait for user to press Enter."""
    print("\n" + "="*70)
    print("⚠️  IMPORTANT: Make sure NIDS is FULLY TRAINED first!")
    print("="*70)
    print("\nYou should see this message in NIDS:")
    print("  '[+] Training complete! Now detecting threats...'\n")
    try:
        input("Press ENTER when NIDS training is complete: ")
    except (EOFError, KeyboardInterrupt):
        sys.exit(0)

def slow_port_scan():
    """Perform a SLOW, CLEAR port scan that's easy to see."""
    ports = [22, 23, 80, 443, 3389, 8080]
    
    print("\n" + "="*70)
    print("🔍 ATTACK: Port Scan (SLOW AND VISIBLE)")
    print("="*70)
    print(f"Source IP: {TARGET_IP}")
    print(f"Source Port: {SOURCE_PORT} (fixed for tracking)")
    print(f"Target Ports: {ports}")
    print("="*70 + "\n")
    
    for i, port in enumerate(ports, 1):
        if not running:
            break
        
        print(f"[{i}/{len(ports)}] Scanning port {port}...")
        
        # Send multiple SYN packets to make it obvious
        for attempt in range(3):
            try:
                pkt = IP(dst=TARGET_IP)/TCP(dport=port, sport=SOURCE_PORT, flags="S")
                send(pkt, verbose=0)
                print(f"      → SYN sent to port {port}")
                time.sleep(0.2)  # Slow enough to see
            except Exception as e:
                print(f"      ✗ Error: {e}")
                break
        
        time.sleep(1)  # Pause between ports
        print()
    
    print("="*70)
    print("✓ Port scan complete!")
    print("="*70)
    print("\n⏳ Waiting 5 seconds for NIDS to process...")
    time.sleep(5)

def syn_flood():
    """Send a burst of SYN packets."""
    port = 80
    count = 150
    
    print("\n" + "="*70)
    print("🌊 ATTACK: SYN Flood")
    print("="*70)
    print(f"Target: {TARGET_IP}:{port}")
    print(f"Packet count: {count}")
    print(f"Source Port: {SOURCE_PORT}")
    print("="*70 + "\n")
    
    print(f"Sending {count} SYN packets rapidly...")
    for i in range(count):
        if not running:
            break
        
        try:
            pkt = IP(dst=TARGET_IP)/TCP(dport=port, sport=SOURCE_PORT, flags="S")
            send(pkt, verbose=0)
            
            if (i+1) % 30 == 0:
                print(f"  [{i+1}/{count}] packets sent...")
            
            time.sleep(0.01)  # Fast rate
        except Exception as e:
            print(f"  ✗ Error: {e}")
            break
    
    print(f"\n✓ Sent {count} packets")
    print("="*70)
    print("\n⏳ Waiting 5 seconds for NIDS to process...")
    time.sleep(5)

def large_packets():
    """Send large packets."""
    port = 80
    
    print("\n" + "="*70)
    print("📦 ATTACK: Large Packets")
    print("="*70)
    print(f"Target: {TARGET_IP}:{port}")
    print(f"Payload size: 1400+ bytes")
    print("="*70 + "\n")
    
    for i in range(5):
        if not running:
            break
        
        try:
            payload = "X" * 1400
            pkt = IP(dst=TARGET_IP)/TCP(dport=port, sport=SOURCE_PORT, flags="PA")/payload
            send(pkt, verbose=0)
            print(f"  [{i+1}/5] Sent {len(pkt)} byte packet")
            time.sleep(0.5)
        except Exception as e:
            print(f"  ✗ Error: {e}")
            break
    
    print("\n✓ Large packets sent")
    print("="*70)
    print("\n⏳ Waiting 5 seconds for NIDS to process...")
    time.sleep(5)

def suspicious_flags():
    """Send packets with weird TCP flags."""
    port = 80
    
    print("\n" + "="*70)
    print("🚩 ATTACK: Suspicious TCP Flags")
    print("="*70)
    print(f"Target: {TARGET_IP}:{port}")
    print("="*70 + "\n")
    
    tests = [
        ("FIN only (stealth scan)", "F"),
        ("URG only (unusual)", "U"),
        ("NULL scan (no flags)", ""),
    ]
    
    for name, flags in tests:
        if not running:
            break
        
        print(f"Testing: {name}")
        try:
            for i in range(5):
                pkt = IP(dst=TARGET_IP)/TCP(dport=port, sport=SOURCE_PORT, flags=flags)
                send(pkt, verbose=0)
                time.sleep(0.2)
            print(f"  ✓ Sent 5 packets with flags='{flags}'\n")
        except Exception as e:
            print(f"  ✗ Error: {e}\n")
    
    print("="*70)
    print("✓ Suspicious flags attack complete")
    print("="*70)

def main():
    print("="*70)
    print("        🎯 NIDS ATTACK SIMULATOR 🎯")
    print("="*70)
    print(f"\nTarget IP: {TARGET_IP}")
    print(f"Source Port: {SOURCE_PORT} (fixed)")
    print("\nThis will perform:")
    print("  1. Port Scan (6 ports, slow and visible)")
    print("  2. SYN Flood (150 packets)")
    print("  3. Large Packets (1400+ bytes)")
    print("  4. Suspicious TCP Flags")
    print("\nEach attack will:")
    print("  • Be clearly labeled")
    print("  • Run slowly so you can see it")
    print("  • Pause for NIDS to process")
    print("="*70)
    
    wait_for_user()
    
    try:
        print("\n\n🚀 Starting attacks in 3 seconds...\n")
        for i in range(3, 0, -1):
            print(f"   {i}...")
            time.sleep(1)
        print()
        
        slow_port_scan()
        syn_flood()
        large_packets()
        suspicious_flags()
        
        print("\n\n" + "="*70)
        print("        ✅ ALL ATTACKS COMPLETE!")
        print("="*70)
        print("\nCheck your NIDS terminal for threat detections!")
        print("Also check the log file: ids_alerts.log")
        print("="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()