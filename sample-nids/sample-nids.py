# NIDS - simple nids to detect port scans

from scapy.all import sniff, IP, TCP

# Define suspicious ports or other rules
SUSPICIOUS_PORTS = {22, 23, 3389}  # Common ports for SSH, Telnet, RDP
SUSPICIOUS_FLAGS = {'F', 'U'}  # FIN or URG flags, sometimes used in stealth scans

def detect_threat(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Alert if traffic is to a suspicious port
        if dst_port in SUSPICIOUS_PORTS:
            print(f"[ALERT]: Suspicious port access detected! from {src_ip} -> {dst_ip}:{dst_port}")

        # Alert on unusual TCP flags
        if flags in SUSPICIOUS_FLAGS:
            print(f"[ALERT]: Unusual TCP flags from {src_ip} -> {dst_ip}:{dst_port} with flags {flags}")


print("Starting NIDS... Press Ctrl+C to stop.")
# Listen on loopback interface for testing, else use iface="eth0" or appropriate interface
sniff(iface="lo", prn=detect_threat, filter="tcp", store=0)
