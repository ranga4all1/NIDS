#!/opt/conda/envs/nids/bin/python

# NIDS - Network Intrusion Detection System

# Traffic analysis module

from scapy.all import sniff, IP, TCP, ls
from collections import defaultdict
import threading
import queue
import time
import logging

class TrafficAnalysis:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'end_time': None
        })
    
    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, port_src, ip_dst, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = time.time()

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time'] + 1e-6),
            'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time'] + 1e-6),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }
