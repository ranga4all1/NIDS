#!/opt/conda/envs/nids/bin/python
# NIDS - Network Intrusion Detection System
# Detection engine module
from sklearn.ensemble import IsolationForest
import numpy as np
import logging
import json
from pathlib import Path
from collections import defaultdict
import time

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Changed to DEBUG
logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, contamination=0.1, min_training_samples=10, 
                 anomaly_threshold=-0.5, max_training_samples=10000):
        """
        Initialize Detection Engine.
        
        Args:
            contamination: Expected proportion of outliers in training data
            min_training_samples: Minimum samples needed before training
            anomaly_threshold: Threshold for anomaly detection (lower = more anomalous)
            max_training_samples: Maximum training samples to prevent memory issues
        """
        try:
            self.anomaly_detector = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100
            )
            self.anomaly_threshold = anomaly_threshold
            self.signature_rules = self.load_signature_rules()
            self.training_data = []
            self.is_trained = False
            self.min_training_samples = max(10, min_training_samples)
            self.max_training_samples = max_training_samples
            self.feature_names = ['packet_size', 'packet_rate', 'byte_rate']
            
            # Track connections for port scan detection
            self.connection_tracker = defaultdict(lambda: {
                'dest_ports': set(),
                'last_update': time.time(),
                'packet_count': 0
            })
            self.tracker_timeout = 60  # 60 seconds
            
            logger.info(f"Detection engine initialized with contamination={contamination}, "
                       f"min_samples={self.min_training_samples}")
        except Exception as e:
            logger.error(f"Error initializing detection engine: {e}", exc_info=True)
            raise
    
    def load_signature_rules(self):
        """
        Load signature-based detection rules.
        
        Returns:
            dict: Dictionary of signature rules
        """
        try:
            return {
                'syn_flood': {
                    'description': 'SYN flood attack detection',
                    'condition': lambda features, context: (
                        str(features.get('tcp_flags', '')) == '2' and  # SYN flag only
                        features.get('packet_size', float('inf')) < 100 and
                        features.get('packet_rate', 0) > 100  # Higher threshold
                    )
                },
                'port_scan': {
                    'description': 'Port scanning detection',
                    'condition': lambda features, context: (
                        self._is_port_scan(context)
                    )
                },
                'large_packet': {
                    'description': 'Unusually large packet detection',
                    'condition': lambda features, context: (
                        features.get('packet_size', 0) > 1400
                    )
                },
                'high_rate': {
                    'description': 'Abnormally high packet rate',
                    'condition': lambda features, context: (
                        features.get('packet_rate', 0) > 1000
                    )
                },
                'suspicious_flags': {
                    'description': 'Suspicious TCP flag combinations',
                    'condition': lambda features, context: (
                        self._has_suspicious_flags(features.get('tcp_flags'))
                    )
                }
            }
        except Exception as e:
            logger.error(f"Error loading signature rules: {e}")
            return {}
    
    def _is_port_scan(self, context):
        """
        Detect port scanning by tracking unique destination ports per source.
        
        Args:
            context: Dictionary with source_ip and dest_port
            
        Returns:
            bool: True if port scan detected
        """
        try:
            if not context or 'source_ip' not in context or 'dest_port' not in context:
                logger.debug("Missing context for port scan detection")
                return False
            
            source_ip = context['source_ip']
            dest_port = context['dest_port']
            
            logger.debug(f"Port scan check: {source_ip} -> port {dest_port}")
            
            # Skip if dest_port is ephemeral (likely legitimate)
            if dest_port >= 32768:
                logger.debug(f"Skipping ephemeral port {dest_port}")
                return False
            
            # Update tracker
            tracker = self.connection_tracker[source_ip]
            tracker['dest_ports'].add(dest_port)
            tracker['last_update'] = time.time()
            tracker['packet_count'] += 1
            
            # Clean old entries
            self._clean_tracker()
            
            # Detect scan: multiple different destination ports in short time
            unique_ports = len(tracker['dest_ports'])
            
            # Debug logging - ALWAYS show when tracking suspicious ports
            if dest_port < 1024 or dest_port in [3389, 8080]:
                logger.info(f"📍 Tracking {source_ip}: {unique_ports} unique ports so far: {sorted(tracker['dest_ports'])}")
            
            # Port scan criteria - LOWERED THRESHOLD for demo
            # - At least 3 different well-known/suspicious ports
            well_known_ports = [p for p in tracker['dest_ports'] if p < 1024 or p in [3389, 8080]]
            
            if len(well_known_ports) >= 3:
                logger.warning(f"🚨 Port scan detected from {source_ip}: {unique_ports} unique ports, "
                           f"{len(well_known_ports)} suspicious ports: {sorted(well_known_ports)}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error in port scan detection: {e}")
            return False
    
    def _has_suspicious_flags(self, tcp_flags):
        """
        Check for suspicious TCP flag combinations.
        
        Args:
            tcp_flags: TCP flags from packet
            
        Returns:
            bool: True if suspicious flags detected
        """
        try:
            if tcp_flags is None:
                return False
            
            # Convert flags to integer if needed
            if hasattr(tcp_flags, 'value'):
                flag_value = int(tcp_flags.value)
            else:
                flag_value = int(tcp_flags)
            
            # Suspicious flag combinations:
            # FIN only (0x01)
            # URG only (0x20)
            # FIN+URG (0x21)
            # FIN+PSH (0x09)
            # No flags (0x00) - null scan
            
            suspicious_combos = [0x00, 0x01, 0x20, 0x21, 0x09, 0x29, 0x03]
            
            if flag_value in suspicious_combos:
                logger.info(f"Suspicious TCP flags detected: {flag_value:#x}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking TCP flags: {e}")
            return False
    
    def _clean_tracker(self):
        """Clean up old entries from connection tracker."""
        try:
            current_time = time.time()
            to_remove = []
            
            for source_ip, tracker in self.connection_tracker.items():
                if current_time - tracker['last_update'] > self.tracker_timeout:
                    to_remove.append(source_ip)
            
            for source_ip in to_remove:
                del self.connection_tracker[source_ip]
                
        except Exception as e:
            logger.error(f"Error cleaning tracker: {e}")
    
    def validate_features(self, features):
        """
        Validate that features dictionary contains required fields with valid values.
        
        Args:
            features: Dictionary of features
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not features or not isinstance(features, dict):
            logger.warning("Features is not a valid dictionary")
            return False
        
        required_features = ['packet_size', 'packet_rate', 'byte_rate']
        
        for feature in required_features:
            if feature not in features:
                logger.warning(f"Missing required feature: {feature}")
                return False
            
            value = features[feature]
            if not isinstance(value, (int, float, np.number)):
                logger.warning(f"Feature {feature} has invalid type: {type(value)}")
                return False
            
            if np.isnan(value) or np.isinf(value):
                logger.warning(f"Feature {feature} has invalid value: {value}")
                return False
            
            if value < 0:
                logger.warning(f"Feature {feature} has negative value: {value}")
                return False
        
        return True
    
    def add_training_sample(self, features):
        """
        Add a sample to training data and train if enough samples collected.
        
        Args:
            features: Dictionary of packet features
            
        Returns:
            bool: True if sample added successfully, False otherwise
        """
        try:
            # Validate features
            if not self.validate_features(features):
                logger.debug("Invalid features, skipping training sample")
                return False
            
            # Check if already at max capacity
            if len(self.training_data) >= self.max_training_samples:
                logger.warning(f"Training data at max capacity ({self.max_training_samples}), "
                             "sample not added")
                return False
            
            # Extract feature vector
            feature_vector = [
                float(features['packet_size']),
                float(features['packet_rate']),
                float(features['byte_rate'])
            ]
            
            # Validate extracted values
            if any(np.isnan(v) or np.isinf(v) or v < 0 for v in feature_vector):
                logger.warning(f"Invalid feature vector: {feature_vector}")
                return False
            
            self.training_data.append(feature_vector)
            logger.debug(f"Added training sample {len(self.training_data)}/{self.min_training_samples}")
            
            # Auto-train when we have enough samples
            if len(self.training_data) >= self.min_training_samples and not self.is_trained:
                self.train_anomaly_detector()
            
            return True
            
        except (KeyError, TypeError, ValueError) as e:
            logger.error(f"Error adding training sample: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error adding training sample: {e}", exc_info=True)
            return False
    
    def train_anomaly_detector(self, normal_traffic_data=None):
        """
        Train the anomaly detector with provided or collected data.
        
        Args:
            normal_traffic_data: Optional list of feature vectors for training
            
        Returns:
            bool: True if training successful, False otherwise
        """
        try:
            training_array = None
            sample_count = 0
            
            if normal_traffic_data is not None:
                # Validate provided data
                if not isinstance(normal_traffic_data, (list, np.ndarray)):
                    logger.error("Training data must be a list or numpy array")
                    return False
                
                if len(normal_traffic_data) < self.min_training_samples:
                    logger.error(f"Insufficient training samples: {len(normal_traffic_data)} "
                               f"< {self.min_training_samples}")
                    return False
                
                # Convert to numpy array
                training_array = np.array(normal_traffic_data)
                sample_count = len(normal_traffic_data)
                
            elif len(self.training_data) >= self.min_training_samples:
                # Use collected data
                training_array = np.array(self.training_data)
                sample_count = len(self.training_data)
                
            else:
                logger.warning(f"Need at least {self.min_training_samples} samples to train. "
                             f"Currently have {len(self.training_data)}")
                return False
            
            # Validate training array shape
            if training_array.ndim != 2 or training_array.shape[1] != 3:
                logger.error(f"Invalid training array shape: {training_array.shape}. "
                           "Expected (n_samples, 3)")
                return False
            
            # Check for invalid values
            if np.any(np.isnan(training_array)) or np.any(np.isinf(training_array)):
                logger.error("Training data contains NaN or Inf values")
                # Try to clean the data
                valid_rows = ~(np.isnan(training_array).any(axis=1) | 
                              np.isinf(training_array).any(axis=1))
                training_array = training_array[valid_rows]
                
                if len(training_array) < self.min_training_samples:
                    logger.error("Too few valid samples after cleaning")
                    return False
                
                logger.info(f"Cleaned training data: {len(training_array)} valid samples")
            
            # Train the model
            self.anomaly_detector.fit(training_array)
            self.is_trained = True
            
            logger.info(f"[+] Anomaly detector trained successfully with {sample_count} samples")
            
            # Log training data statistics
            try:
                means = np.mean(training_array, axis=0)
                stds = np.std(training_array, axis=0)
                logger.info(f"Training data statistics:")
                for i, name in enumerate(self.feature_names):
                    logger.info(f"  {name}: mean={means[i]:.2f}, std={stds[i]:.2f}")
            except Exception as e:
                logger.debug(f"Could not log training statistics: {e}")
            
            return True
            
        except ValueError as e:
            logger.error(f"ValueError during training: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during training: {e}", exc_info=True)
            return False
    
    def detect_threats(self, features, packet_context=None):
        """
        Detect threats using signature and anomaly-based detection.
        
        Args:
            features: Dictionary of packet features
            packet_context: Additional context (source_ip, dest_ip, dest_port, etc.)
            
        Returns:
            list: List of detected threats
        """
        threats = []
        
        try:
            # Validate features
            if not self.validate_features(features):
                logger.debug("Invalid features for threat detection")
                return threats
            
            # Prepare context
            context = packet_context or {}
            
            # Signature-based detection
            for rule_name, rule in self.signature_rules.items():
                try:
                    if 'condition' not in rule:
                        logger.warning(f"Rule {rule_name} missing condition")
                        continue
                    
                    if rule['condition'](features, context):
                        threats.append({
                            'type': 'signature',
                            'rule': rule_name,
                            'description': rule.get('description', 'No description'),
                            'confidence': 1.0
                        })
                        logger.info(f"🚨 Signature match: {rule_name}")
                        
                except KeyError as e:
                    logger.error(f"Missing key in features for rule {rule_name}: {e}")
                except TypeError as e:
                    logger.error(f"Type error evaluating rule {rule_name}: {e}")
                except Exception as e:
                    logger.error(f"Error evaluating rule {rule_name}: {e}")
            
            # Anomaly-based detection (only if trained)
            if self.is_trained:
                try:
                    # Extract and validate feature vector
                    feature_vector = np.array([[
                        float(features['packet_size']),
                        float(features['packet_rate']),
                        float(features['byte_rate'])
                    ]])
                    
                    # Check for invalid values
                    if np.any(np.isnan(feature_vector)) or np.any(np.isinf(feature_vector)):
                        logger.warning("Feature vector contains NaN or Inf, skipping anomaly detection")
                        return threats
                    
                    # Get anomaly score
                    anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
                    
                    # Validate anomaly score
                    if np.isnan(anomaly_score) or np.isinf(anomaly_score):
                        logger.warning(f"Invalid anomaly score: {anomaly_score}")
                        return threats
                    
                    # Check against threshold
                    if anomaly_score < self.anomaly_threshold:
                        # Calculate confidence (more negative = higher confidence)
                        confidence = min(1.0, abs(anomaly_score))
                        
                        threats.append({
                            'type': 'anomaly',
                            'score': float(anomaly_score),
                            'confidence': float(confidence),
                            'threshold': self.anomaly_threshold
                        })
                        logger.info(f"Anomaly detected: score={anomaly_score:.3f}, "
                                  f"confidence={confidence:.3f}")
                        
                except (KeyError, TypeError, ValueError) as e:
                    logger.error(f"Error in anomaly detection: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error in anomaly detection: {e}", exc_info=True)
            else:
                logger.debug("Anomaly detector not trained yet, skipping anomaly detection")
            
            return threats
            
        except Exception as e:
            logger.error(f"Unexpected error in detect_threats: {e}", exc_info=True)
            return threats
    
    def save_model(self, filepath):
        """
        Save the trained model to a file.
        
        Args:
            filepath: Path to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.is_trained:
                logger.error("Cannot save untrained model")
                return False
            
            import pickle
            
            model_data = {
                'anomaly_detector': self.anomaly_detector,
                'is_trained': self.is_trained,
                'training_samples': len(self.training_data),
                'anomaly_threshold': self.anomaly_threshold
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Model saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}", exc_info=True)
            return False
    
    def load_model(self, filepath):
        """
        Load a trained model from a file.
        
        Args:
            filepath: Path to load the model from
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import pickle
            
            if not Path(filepath).exists():
                logger.error(f"Model file not found: {filepath}")
                return False
            
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.anomaly_detector = model_data['anomaly_detector']
            self.is_trained = model_data['is_trained']
            self.anomaly_threshold = model_data.get('anomaly_threshold', -0.5)
            
            logger.info(f"Model loaded from {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}", exc_info=True)
            return False
    
    def get_stats(self):
        """
        Get statistics about the detection engine.
        
        Returns:
            dict: Statistics dictionary
        """
        try:
            return {
                'is_trained': self.is_trained,
                'training_samples': len(self.training_data),
                'min_training_samples': self.min_training_samples,
                'max_training_samples': self.max_training_samples,
                'signature_rules': len(self.signature_rules),
                'anomaly_threshold': self.anomaly_threshold,
                'tracked_sources': len(self.connection_tracker)
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {'error': str(e)}
    
    def reset(self):
        """
        Reset the detection engine to initial state.
        """
        try:
            self.training_data.clear()
            self.is_trained = False
            self.connection_tracker.clear()
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            logger.info("Detection engine reset")
        except Exception as e:
            logger.error(f"Error resetting detection engine: {e}")