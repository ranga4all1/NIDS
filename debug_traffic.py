#!/opt/conda/envs/nids/bin/python

"""
Debug script to verify traffic generation
"""

from scapy.all import IP, TCP, send, sniff
import sys
import time
import threading

TARGET_IP = "127.0.0.1"
SUSPICIOUS_PORTS = [22, 23, 80, 3389, 8080]

captured_packets = []
capture_running = False

def capture_packets():
    """Capture packets in background."""
    global capture_running
    
    def packet_handler(pkt):
        if IP in pkt and TCP in pkt:
            captured_packets.append({
                'src': pkt[IP].src,
                'dst': pkt[IP].dst,
                'sport': pkt[TCP].sport,
                'dport': pkt[TCP].dport,
                'flags': pkt[TCP].flags,
                'size': len(pkt)
            })
    
    capture_running = True
    print("[*] Starting packet capture...")
    sniff(iface="lo", prn=packet_handler, filter="tcp and host 127.0.0.1", 
          timeout=15, store=0)
    capture_running = False
    print("[*] Capture stopped")

def send_test_packets():
    """Send test packets."""
    time.sleep(2)  # Wait for capture to start
    
    print("\n[*] Sending test packets to suspicious ports...")
    for port in SUSPICIOUS_PORTS:
        print(f"  -> Sending to port {port}")
        try:
            # Try different methods
            
            # Method 1: SYN packet
            pkt1 = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
            send(pkt1, verbose=0)
            
            # Method 2: FIN packet
            pkt2 = IP(dst=TARGET_IP)/TCP(dport=port, flags="F")
            send(pkt2, verbose=0)
            
            time.sleep(0.1)
        except Exception as e:
            print(f"  ERROR: {e}")
    
    print("[*] Test packets sent")
    time.sleep(3)  # Wait for capture

if __name__ == "__main__":
    print("="*70)
    print("Traffic Generation Debug Tool")
    print("="*70)
    print("This will:")
    print("  1. Start capturing packets on loopback")
    print("  2. Send test packets to ports: " + str(SUSPICIOUS_PORTS))
    print("  3. Show what was captured")
    print("="*70)
    
    # Start capture in background
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()
    
    # Send packets
    send_test_packets()
    
    # Wait for capture to finish
    capture_thread.join()
    
    # Analyze results
    print("\n" + "="*70)
    print("RESULTS")
    print("="*70)
    
    if not captured_packets:
        print("❌ NO PACKETS CAPTURED!")
        print("\nPossible issues:")
        print("  1. Not running with sudo")
        print("  2. Firewall blocking loopback traffic")
        print("  3. Need to run: sudo sysctl -w net.ipv4.conf.all.route_localnet=1")
    else:
        print(f"✓ Captured {len(captured_packets)} packets\n")
        
        # Group by destination port
        by_port = {}
        for pkt in captured_packets:
            port = pkt['dport']
            if port not in by_port:
                by_port[port] = []
            by_port[port].append(pkt)
        
        print("Packets by destination port:")
        for port in sorted(by_port.keys()):
            pkts = by_port[port]
            print(f"\n  Port {port}: {len(pkts)} packets")
            for pkt in pkts[:3]:  # Show first 3
                print(f"    {pkt['src']}:{pkt['sport']} -> {pkt['dst']}:{pkt['dport']} "
                      f"flags={pkt['flags']} size={pkt['size']}")
            if len(pkts) > 3:
                print(f"    ... and {len(pkts)-3} more")
        
        # Check if suspicious ports were hit
        print("\n" + "-"*70)
        print("Suspicious ports check:")
        for port in SUSPICIOUS_PORTS:
            if port in by_port:
                print(f"  ✓ Port {port}: {len(by_port[port])} packets")
            else:
                print(f"  ❌ Port {port}: NO packets")
    
    print("\n" + "="*70)