#!/opt/conda/envs/nids/bin/python
# NIDS - Network Intrusion Detection System
# Detection engine module
from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []
        self.is_trained = False
        self.min_training_samples = 10  # Minimum samples before training
    
    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    str(features['tcp_flags']) == '2' and  # SYN flag 
                    features['packet_size'] < 100   
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and 
                    features['packet_rate'] > 50  
                )
            }
        }
    
    def add_training_sample(self, features):
        """Add a sample to training data and train if enough samples collected"""
        feature_vector = [
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]
        self.training_data.append(feature_vector)
        
        # Auto-train when we have enough samples
        if len(self.training_data) >= self.min_training_samples and not self.is_trained:
            self.train_anomaly_detector()
    
    def train_anomaly_detector(self, normal_traffic_data=None):
        """Train the anomaly detector with provided or collected data"""
        if normal_traffic_data is not None:
            # Train with provided data
            training_array = np.array(normal_traffic_data)
            self.anomaly_detector.fit(training_array)
            self.is_trained = True
            print(f"[+] Anomaly detector trained with {len(normal_traffic_data)} samples")
        elif len(self.training_data) >= self.min_training_samples:
            # Train with collected data
            training_array = np.array(self.training_data)
            self.anomaly_detector.fit(training_array)
            self.is_trained = True
            print(f"[+] Anomaly detector trained with {len(self.training_data)} samples")
        else:
            print(f"[-] Need at least {self.min_training_samples} samples to train. Currently have {len(self.training_data)}")
    
    def detect_threats(self, features):
        threats = []
        
        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'confidence': 1.0
                    })
            except Exception as e:
                # Skip if rule evaluation fails
                pass
        
        # Anomaly-based detection (only if trained)
        if self.is_trained:
            feature_vector = np.array([[
                features['packet_size'],
                features['packet_rate'],
                features['byte_rate']
            ]])
            anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
            
            if anomaly_score < -0.5:  # Threshold for anomaly detection
                threats.append({
                    'type': 'anomaly',
                    'score': float(anomaly_score),
                    'confidence': min(1.0, abs(anomaly_score))
                })
        
        return threats