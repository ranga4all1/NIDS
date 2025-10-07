import sys
import signal
from scapy.all import IP, TCP, send

# Define the target and traffic parameters
TARGET_IP = "127.0.0.1"  # **Replace with your target's IP address. Use loopback if running on same system as target.**
SUSPICIOUS_PORTS = [22, 23, 3389, 8080]  # Common ports for SSH, Telnet, RDP, HTTP-Alt
SUSPICIOUS_FLAGS = ["F", "U", "S"]  # FIN, URG, SYN flags
ANOMALOUS_PACKET_SIZES = [64, 1500, 40, 1000]  # Example packet sizes
ANOMALOUS_PACKET_RATES = [100, 500, 1000]  # Packets per second

# Global flag to control the traffic generation loop
running = True

def signal_handler(sig, frame):
    """Handles the Ctrl+C signal to stop traffic generation."""
    global running
    print("\nStopping traffic generation...")
    running = False
    sys.exit(0)

# Register the signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

print(f"Generating suspicious traffic to target: {TARGET_IP}")

def generate_traffic(target_ip, ports, flags, packet_sizes, packet_rates):
    """Generates and sends TCP packets with specified flags to suspicious ports and anomalous sizes/rates."""
    global running
    for port in ports:
        if not running:
            break
        for flag in flags:
            if not running:
                break
            print(f"Sending TCP packet with flag '{flag}' to port {port}")
            try:
                # Craft the IP and TCP layers of the packet
                packet = IP(dst=target_ip) / TCP(dport=port, flags=flag)
                # Send the packet
                send(packet, verbose=0)
            except Exception as e:
                print(f"An error occurred: {e}. Please ensure you are running with root/administrator privileges.")
                sys.exit(1)

    # Generate anomalous traffic based on packet sizes
    for size in packet_sizes:
        if not running:
            break
        print(f"Sending packet with anomalous size: {size}")
        try:
            packet = IP(dst=target_ip) / TCP(dport=80) / ("A" * size)  # HTTP traffic with specific size
            send(packet, verbose=0)
        except Exception as e:
            print(f"An error occurred: {e}. Please ensure you are running with root/administrator privileges.")
            sys.exit(1)

    # Generate anomalous traffic based on packet rates
    for rate in packet_rates:
        if not running:
            break
        print(f"Sending traffic with anomalous rate: {rate} packets/second")
        try:
            for _ in range(rate):
                if not running:
                    break
                packet = IP(dst=target_ip) / TCP(dport=80) / "B"  # HTTP traffic
                send(packet, verbose=0)
        except Exception as e:
            print(f"An error occurred: {e}. Please ensure you are running with root/administrator privileges.")
            sys.exit(1)

if __name__ == "__main__":
    generate_traffic(TARGET_IP, SUSPICIOUS_PORTS, SUSPICIOUS_FLAGS, ANOMALOUS_PACKET_SIZES, ANOMALOUS_PACKET_RATES)
    print("\nSuspicious traffic generation complete.")
