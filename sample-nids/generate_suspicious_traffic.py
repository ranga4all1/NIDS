import sys
from scapy.all import IP, TCP, send

# Define the target and traffic parameters
# TARGET_IP = "192.168.1.100"  # **Replace with your target's IP address**
TARGET_IP = "127.0.0.1"  # Localhost for testing purposes
SUSPICIOUS_PORTS = [22, 23, 3389, 8080]  # Common ports for SSH, Telnet, RDP, HTTP-Alt
SUSPICIOUS_FLAGS = ["F", "U", "S"]  # FIN, URG, SYN flags

print(f"Generating suspicious traffic to target: {TARGET_IP}")

def generate_traffic(target_ip, ports, flags):
    """Generates and sends TCP packets with specified flags to suspicious ports."""
    for port in ports:
        for flag in flags:
            print(f"Sending TCP packet with flag '{flag}' to port {port}")
            try:
                # Craft the IP and TCP layers of the packet
                packet = IP(dst=target_ip) / TCP(dport=port, flags=flag)
                # Send the packet
                send(packet, verbose=0)
            except Exception as e:
                print(f"An error occurred: {e}. Please ensure you are running with root/administrator privileges.")
                sys.exit(1)

if __name__ == "__main__":
    generate_traffic(TARGET_IP, SUSPICIOUS_PORTS, SUSPICIOUS_FLAGS)
    print("\nSuspicious traffic generation complete.")
