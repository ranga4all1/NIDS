#!/opt/conda/envs/nids/bin/python
# NIDS - Network Intrusion Detection System

# Alert system module

import logging
import json
from datetime import datetime
from pathlib import Path
import threading
from collections import deque
import time

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log", max_alerts_per_minute=100,
                 enable_console=True, enable_rate_limiting=True):
        """
        Initialize Alert System.
        
        Args:
            log_file: Path to the alert log file
            max_alerts_per_minute: Maximum alerts per minute (rate limiting)
            enable_console: Whether to also log to console
            enable_rate_limiting: Whether to enable rate limiting
        """
        try:
            self.log_file = log_file
            self.max_alerts_per_minute = max_alerts_per_minute
            self.enable_rate_limiting = enable_rate_limiting
            
            # Alert rate limiting
            self.alert_timestamps = deque(maxlen=max_alerts_per_minute)
            self.rate_limit_lock = threading.Lock()
            self.alerts_dropped = 0
            
            # Statistics
            self.total_alerts = 0
            self.alerts_by_type = {}
            self.stats_lock = threading.Lock()
            
            # Setup logger
            self.logger = self._setup_logger(log_file, enable_console)
            
            if self.logger:
                self.logger.info("Alert system initialized successfully")
            else:
                print("WARNING: Alert system logger not properly initialized")
                
        except Exception as e:
            print(f"CRITICAL: Error initializing alert system: {e}")
            # Create a basic fallback logger
            self.logger = logging.getLogger("IDS_Alerts_Fallback")
            self.logger.setLevel(logging.WARNING)
            handler = logging.StreamHandler()
            self.logger.addHandler(handler)

    def _setup_logger(self, log_file, enable_console):
        """
        Setup logger with file and optional console handlers.
        
        Args:
            log_file: Path to log file
            enable_console: Whether to enable console logging
            
        Returns:
            logging.Logger: Configured logger instance
        """
        try:
            logger = logging.getLogger("IDS_Alerts")
            logger.setLevel(logging.INFO)
            
            # Clear existing handlers to prevent duplicates
            logger.handlers.clear()
            
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # File handler with error handling
            try:
                file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
                formatter = logging.Formatter(
                    '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(formatter)
                file_handler.setLevel(logging.INFO)
                logger.addHandler(file_handler)
            except (IOError, OSError, PermissionError) as e:
                print(f"ERROR: Cannot create log file {log_file}: {e}")
                print("Falling back to console-only logging")
                enable_console = True
            
            # Console handler (optional)
            if enable_console:
                console_handler = logging.StreamHandler()
                console_formatter = logging.Formatter(
                    '%(levelname)s - %(message)s'
                )
                console_handler.setFormatter(console_formatter)
                console_handler.setLevel(logging.WARNING)
                logger.addHandler(console_handler)
            
            return logger
            
        except Exception as e:
            print(f"ERROR: Failed to setup logger: {e}")
            # Return basic logger as fallback
            fallback_logger = logging.getLogger("IDS_Alerts_Fallback")
            fallback_logger.setLevel(logging.WARNING)
            return fallback_logger

    def _check_rate_limit(self):
        """
        Check if alert rate limit is exceeded.
        
        Returns:
            bool: True if rate limit allows, False if exceeded
        """
        if not self.enable_rate_limiting:
            return True
        
        try:
            with self.rate_limit_lock:
                current_time = time.time()
                
                # Remove timestamps older than 1 minute
                cutoff_time = current_time - 60
                while self.alert_timestamps and self.alert_timestamps[0] < cutoff_time:
                    self.alert_timestamps.popleft()
                
                # Check if we're at the limit
                if len(self.alert_timestamps) >= self.max_alerts_per_minute:
                    self.alerts_dropped += 1
                    return False
                
                # Add current timestamp
                self.alert_timestamps.append(current_time)
                return True
                
        except Exception as e:
            self.logger.error(f"Error in rate limiting: {e}")
            return True  # Allow alert on error

    def _update_stats(self, threat_type):
        """
        Update alert statistics.
        
        Args:
            threat_type: Type of threat detected
        """
        try:
            with self.stats_lock:
                self.total_alerts += 1
                self.alerts_by_type[threat_type] = self.alerts_by_type.get(threat_type, 0) + 1
        except Exception as e:
            self.logger.error(f"Error updating stats: {e}")

    def _validate_threat(self, threat):
        """
        Validate threat dictionary has required fields.
        
        Args:
            threat: Threat dictionary
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not threat or not isinstance(threat, dict):
            self.logger.error("Threat is not a valid dictionary")
            return False
        
        if 'type' not in threat:
            self.logger.error("Threat missing 'type' field")
            return False
        
        # Validate confidence is a number between 0 and 1
        confidence = threat.get('confidence', 0.0)
        if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
            self.logger.warning(f"Invalid confidence value: {confidence}, using default 0.0")
            threat['confidence'] = 0.0
        
        return True

    def _validate_packet_info(self, packet_info):
        """
        Validate packet info dictionary.
        
        Args:
            packet_info: Packet information dictionary
            
        Returns:
            dict: Validated packet info with defaults
        """
        if not packet_info or not isinstance(packet_info, dict):
            self.logger.warning("Packet info is not a valid dictionary, using defaults")
            return {
                'source_ip': 'unknown',
                'destination_ip': 'unknown',
                'source_port': None,
                'destination_port': None
            }
        
        # Ensure required fields exist
        validated = {
            'source_ip': packet_info.get('source_ip', 'unknown'),
            'destination_ip': packet_info.get('destination_ip', 'unknown'),
            'source_port': packet_info.get('source_port'),
            'destination_port': packet_info.get('destination_port')
        }
        
        return validated

    def _sanitize_for_json(self, obj):
        """
        Sanitize object for JSON serialization.
        
        Args:
            obj: Object to sanitize
            
        Returns:
            JSON-serializable object
        """
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, dict):
            return {str(k): self._sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._sanitize_for_json(item) for item in obj]
        else:
            return str(obj)

    def generate_alert(self, threat, packet_info):
        """
        Generate an alert for a detected threat.
        
        Args:
            threat: Dictionary containing threat information
            packet_info: Dictionary containing packet information
            
        Returns:
            bool: True if alert generated successfully, False otherwise
        """
        try:
            # Validate inputs
            if not self._validate_threat(threat):
                return False
            
            # Check rate limit
            if not self._check_rate_limit():
                if self.alerts_dropped % 10 == 1:  # Log every 10th dropped alert
                    self.logger.warning(
                        f"Alert rate limit exceeded. Dropped {self.alerts_dropped} alerts."
                    )
                return False
            
            # Validate and sanitize packet info
            packet_info = self._validate_packet_info(packet_info)
            
            # Build alert dictionary
            try:
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'threat_type': str(threat['type']),
                    'source_ip': str(packet_info.get('source_ip', 'unknown')),
                    'destination_ip': str(packet_info.get('destination_ip', 'unknown')),
                    'source_port': packet_info.get('source_port'),
                    'destination_port': packet_info.get('destination_port'),
                    'confidence': float(threat.get('confidence', 0.0)),
                    'details': self._sanitize_for_json(threat)
                }
            except (KeyError, TypeError, ValueError) as e:
                self.logger.error(f"Error building alert dictionary: {e}")
                return False
            
            # Convert to JSON safely
            try:
                alert_json = json.dumps(alert, ensure_ascii=False, indent=None)
            except (TypeError, ValueError) as e:
                self.logger.error(f"Error serializing alert to JSON: {e}")
                # Try with sanitized version
                try:
                    sanitized_alert = self._sanitize_for_json(alert)
                    alert_json = json.dumps(sanitized_alert, ensure_ascii=False)
                except Exception as e2:
                    self.logger.error(f"Failed to serialize even after sanitization: {e2}")
                    return False
            
            # Log the alert
            self.logger.warning(alert_json)
            
            # Update statistics
            self._update_stats(threat['type'])
            
            # Handle high-confidence threats
            try:
                confidence = float(threat.get('confidence', 0.0))
                if confidence > 0.8:
                    self.logger.critical(
                        f"HIGH CONFIDENCE THREAT: {alert_json}"
                    )
                    self._send_critical_notification(alert)
            except (TypeError, ValueError) as e:
                self.logger.error(f"Error processing confidence level: {e}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Unexpected error generating alert: {e}", exc_info=True)
            return False

    def _send_critical_notification(self, alert):
        """
        Send notifications for critical threats.
        
        Args:
            alert: Alert dictionary
        """
        try:
            # Placeholder for additional notification methods
            # Examples: email, Slack, webhook, SIEM integration
            
            # Example: Write to separate critical alerts file
            try:
                critical_log = Path(self.log_file).parent / "critical_alerts.log"
                with open(critical_log, 'a', encoding='utf-8') as f:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    f.write(f"{timestamp} - CRITICAL - {json.dumps(alert)}\n")
            except (IOError, OSError) as e:
                self.logger.error(f"Failed to write critical alert to file: {e}")
            
            # Add your notification methods here:
            # - self._send_email(alert)
            # - self._send_slack_message(alert)
            # - self._send_to_siem(alert)
            
        except Exception as e:
            self.logger.error(f"Error sending critical notification: {e}")

    def send_alert(self, message):
        """
        Send a simple text alert message.
        
        Args:
            message: Alert message string
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not message or not isinstance(message, str):
                self.logger.error("Invalid alert message")
                return False
            
            # Check rate limit
            if not self._check_rate_limit():
                return False
            
            self.logger.warning(message)
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
            return False

    def get_stats(self):
        """
        Get alert statistics.
        
        Returns:
            dict: Statistics dictionary
        """
        try:
            with self.stats_lock:
                return {
                    'total_alerts': self.total_alerts,
                    'alerts_by_type': dict(self.alerts_by_type),
                    'alerts_dropped': self.alerts_dropped,
                    'log_file': self.log_file,
                    'rate_limit': self.max_alerts_per_minute
                }
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {'error': str(e)}

    def reset_stats(self):
        """
        Reset alert statistics.
        """
        try:
            with self.stats_lock:
                self.total_alerts = 0
                self.alerts_by_type.clear()
                self.alerts_dropped = 0
            
            with self.rate_limit_lock:
                self.alert_timestamps.clear()
            
            self.logger.info("Alert statistics reset")
            
        except Exception as e:
            self.logger.error(f"Error resetting stats: {e}")

    def test_alert_system(self):
        """
        Test the alert system functionality.
        
        Returns:
            bool: True if test successful, False otherwise
        """
        try:
            test_threat = {
                'type': 'test',
                'confidence': 0.9,
                'description': 'Test alert'
            }
            
            test_packet_info = {
                'source_ip': '192.168.1.100',
                'destination_ip': '192.168.1.1',
                'source_port': 12345,
                'destination_port': 80
            }
            
            result = self.generate_alert(test_threat, test_packet_info)
            
            if result:
                self.logger.info("Alert system test PASSED")
            else:
                self.logger.error("Alert system test FAILED")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error testing alert system: {e}")
            return False