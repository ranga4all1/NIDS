#!/opt/conda/envs/nids/bin/python

# NIDS - Network Intrusion Detection System

# Packet capture module

from scapy.all import sniff, IP, TCP, ls
from collections import defaultdict
import threading
import queue
import time
import logging

class PacketCapture:
    def __init__(self, filter_expression=None):
        """
        Initialize PacketCapture.
        
        Args:
            filter_expression: BPF filter string (e.g., "host 127.0.0.1")
        """
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.filter_expression = filter_expression
        
    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
    
    def start_capture(self, iface=None):
        def capture_thread():
            try:
                sniff(
                    iface=iface,
                    prn=self.packet_callback,
                    filter=self.filter_expression,  # Apply BPF filter
                    stop_filter=lambda x: self.stop_capture.is_set()
                )
            except Exception as e:
                print(f"Error during packet capture: {e}")

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()