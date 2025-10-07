#!/opt/conda/envs/nids/bin/python

# NIDS - Network Intrusion Detection System

# Traffic analysis module

from scapy.all import sniff, IP, TCP, ls
from collections import defaultdict
import threading
import queue
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TrafficAnalysis:
    def __init__(self, flow_timeout=300, max_flows=10000):
        """
        Initialize Traffic Analysis module.
        
        Args:
            flow_timeout: Time in seconds after which inactive flows are cleaned up
            max_flows: Maximum number of flows to track before cleanup
        """
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # Cleanup every 60 seconds
        
    def analyze_packet(self, packet):
        """
        Analyze a packet and extract features.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Extracted features or None if analysis fails
        """
        try:
            # Validate packet has required layers
            if not packet:
                logger.warning("Received null packet")
                return None
                
            if IP not in packet or TCP not in packet:
                logger.debug("Packet missing IP or TCP layer")
                return None
            
            # Extract packet information with error handling
            try:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
            except (AttributeError, IndexError) as e:
                logger.error(f"Error extracting packet fields: {e}")
                return None
            
            # Validate extracted data
            if not all([ip_src, ip_dst, port_src, port_dst]):
                logger.warning("Invalid packet data: missing required fields")
                return None
            
            # Validate port numbers
            if not (0 <= port_src <= 65535 and 0 <= port_dst <= 65535):
                logger.warning(f"Invalid port numbers: src={port_src}, dst={port_dst}")
                return None

            flow_key = (ip_src, port_src, ip_dst, port_dst)

            # Update flow statistics
            try:
                stats = self.flow_stats[flow_key]
                stats['packet_count'] += 1
                
                # Safely get packet length
                try:
                    packet_len = len(packet)
                    if packet_len < 0 or packet_len > 65535:
                        logger.warning(f"Suspicious packet length: {packet_len}")
                        packet_len = min(max(0, packet_len), 65535)
                    stats['byte_count'] += packet_len
                except (TypeError, OverflowError) as e:
                    logger.error(f"Error calculating packet length: {e}")
                    stats['byte_count'] += 0
                
                current_time = time.time()

                if not stats['start_time']:
                    stats['start_time'] = current_time
                stats['last_time'] = current_time

                # Periodic cleanup to prevent memory issues
                self._cleanup_old_flows()

                return self.extract_features(packet, stats)
                
            except Exception as e:
                logger.error(f"Error updating flow statistics: {e}")
                return None

        except Exception as e:
            logger.error(f"Unexpected error in analyze_packet: {e}", exc_info=True)
            return None

    def extract_features(self, packet, stats):
        """
        Extract features from packet and flow statistics.
        
        Args:
            packet: Scapy packet object
            stats: Flow statistics dictionary
            
        Returns:
            dict: Extracted features or None if extraction fails
        """
        try:
            # Calculate flow duration safely
            flow_duration = 0
            if stats['start_time'] and stats['last_time']:
                flow_duration = stats['last_time'] - stats['start_time']
                if flow_duration < 0:
                    logger.warning("Negative flow duration detected, resetting to 0")
                    flow_duration = 0
            
            # Calculate rates with division by zero protection
            time_divisor = max(flow_duration, 1e-6)
            packet_rate = stats['packet_count'] / time_divisor
            byte_rate = stats['byte_count'] / time_divisor
            
            # Validate rates (sanity check)
            if packet_rate > 1e6 or byte_rate > 1e9:
                logger.warning(f"Abnormally high rates detected: pkt_rate={packet_rate}, byte_rate={byte_rate}")
            
            # Extract TCP fields safely
            try:
                tcp_flags = packet[TCP].flags
                window_size = packet[TCP].window
                
                # Validate window size
                if window_size < 0 or window_size > 65535:
                    logger.warning(f"Invalid window size: {window_size}")
                    window_size = max(0, min(window_size, 65535))
                    
            except (AttributeError, IndexError, KeyError) as e:
                logger.error(f"Error extracting TCP fields: {e}")
                tcp_flags = 0
                window_size = 0
            
            # Get packet size safely
            try:
                packet_size = len(packet)
                if packet_size < 0 or packet_size > 65535:
                    packet_size = min(max(0, packet_size), 65535)
            except (TypeError, OverflowError):
                packet_size = 0
            
            features = {
                'packet_size': packet_size,
                'flow_duration': flow_duration,
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'tcp_flags': tcp_flags,
                'window_size': window_size
            }
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}", exc_info=True)
            return None
    
    def _cleanup_old_flows(self):
        """
        Clean up old inactive flows to prevent memory exhaustion.
        """
        try:
            current_time = time.time()
            
            # Only cleanup periodically
            if current_time - self.last_cleanup < self.cleanup_interval:
                return
            
            self.last_cleanup = current_time
            
            # Check if cleanup is needed
            if len(self.flow_stats) < self.max_flows:
                return
            
            # Remove flows that haven't seen traffic in flow_timeout seconds
            flows_to_remove = []
            for flow_key, stats in self.flow_stats.items():
                if stats['last_time'] and (current_time - stats['last_time']) > self.flow_timeout:
                    flows_to_remove.append(flow_key)
            
            # Remove old flows
            for flow_key in flows_to_remove:
                try:
                    del self.flow_stats[flow_key]
                    if flow_key in self.connections:
                        del self.connections[flow_key]
                except KeyError:
                    pass
            
            if flows_to_remove:
                logger.info(f"Cleaned up {len(flows_to_remove)} inactive flows")
                
        except Exception as e:
            logger.error(f"Error during flow cleanup: {e}", exc_info=True)
    
    def get_stats(self):
        """
        Get current statistics about tracked flows.
        
        Returns:
            dict: Statistics about current flows
        """
        try:
            return {
                'total_flows': len(self.flow_stats),
                'total_connections': len(self.connections),
                'last_cleanup': self.last_cleanup
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {'error': str(e)}
    
    def reset(self):
        """
        Reset all flow statistics and connections.
        """
        try:
            self.connections.clear()
            self.flow_stats.clear()
            self.last_cleanup = time.time()
            logger.info("Traffic analysis state reset")
        except Exception as e:
            logger.error(f"Error resetting state: {e}")