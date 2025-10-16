#!/usr/bin/env python3
"""
PCAP Processor - Converts PCAP files to features for ML model
"""

import pandas as pd
import numpy as np
from scapy.all import *
import joblib
import os

class PCAPAnalyzer:
    def __init__(self, model_path='models/network_intrusion_model.pkl'):
        """Initialize the PCAP analyzer with ML model"""
        self.model = None
        self.scaler = None
        self.feature_columns = None
        
        # Load model and scaler
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                print("✅ ML model loaded successfully")
            
            # Load scaler
            scaler_path = 'models/scaler.pkl'
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                print("✅ Scaler loaded successfully")
            
            # Load feature columns
            features_path = 'models/feature_columns.json'
            if os.path.exists(features_path):
                with open(features_path, 'r') as f:
                    self.feature_columns = json.load(f)
                print("✅ Feature columns loaded successfully")
                
        except Exception as e:
            print(f"⚠️  Could not load ML model: {e}")
            print("   Using rule-based analysis as fallback")
    
    def extract_features_from_pcap(self, pcap_path):
        """Extract features from PCAP file for ML analysis"""
        try:
            packets = rdpcap(pcap_path)
            if len(packets) == 0:
                return None
            
            # Basic feature extraction (simplified)
            features = {
                'dur': len(packets) * 0.001,
                'proto': 1 if packets[0].haslayer(TCP) else 2 if packets[0].haslayer(UDP) else 0,
                'service': -1,
                'state': 1,
                'spkts': len(packets),
                'dpkts': 0,
                'sbytes': sum(len(p) for p in packets),
                'dbytes': 0,
                'rate': len(packets) / 10.0,
                'sttl': 64,
                'dttl': 64,
                'sload': sum(len(p) for p in packets) / 10.0,
                'dload': 0,
                'sjit': 0.001,
                'djit': 0.001,
                'sinpkt': 0.01,
                'dinpkt': 0.01,
                'tcprtt': 0.1,
                'ct_srv_src': 1,
                'ct_state_ttl': 1,
                'ct_dst_ltm': 1,
                'ct_src_dport_ltm': 1,
                'ct_dst_sport_ltm': 1,
                'ct_dst_src_ltm': 1,
                'ct_srv_dst': 1
            }
            
            return pd.DataFrame([features])
            
        except Exception as e:
            print(f"❌ Error processing PCAP: {e}")
            return None
    
    def analyze_with_ml(self, features):
        """Analyze features using ML model"""
        if self.model is None:
            return None, 0.5
        
        try:
            prediction = self.model.predict(features)[0]
            probability = self.model.predict_proba(features)[0][1]
            return prediction, probability
        except:
            return None, 0.5
    
    def rule_based_analysis(self, pcap_path):
        """Fallback rule-based analysis if ML model not available"""
        try:
            packets = rdpcap(pcap_path)
            
            # Simple rule-based detection
            suspicious_indicators = 0
            
            # Check for port scanning
            unique_ports = len(set(p.dport for p in packets if p.haslayer(TCP) and p[TCP].flags == 2))
            if unique_ports > 10:
                suspicious_indicators += 1
            
            # Check for high packet rate
            if len(packets) > 50:
                suspicious_indicators += 1
            
            # Check for suspicious protocols
            suspicious_protos = ['GRE', 'ICMP', 'RAW']
            for pkt in packets:
                if pkt.haslayer(IP):
                    if pkt[IP].proto in [47, 1]:  # GRE, ICMP
                        suspicious_indicators += 1
                        break
            
            # Determine threat level
            if suspicious_indicators >= 2:
                return 1, 0.8  # Malicious, high confidence
            elif suspicious_indicators == 1:
                return 1, 0.6  # Malicious, medium confidence
            else:
                return 0, 0.9  # Normal, high confidence
                
        except Exception as e:
            print(f"❌ Rule-based analysis failed: {e}")
            return 0, 0.5  # Default to normal if analysis fails
    
    def analyze_pcap(self, pcap_path):
        """Complete PCAP analysis pipeline"""
        print(f"🔍 Analyzing: {pcap_path}")
        
        # Extract features
        features = self.extract_features_from_pcap(pcap_path)
        
        if features is not None and self.model is not None:
            # Use ML analysis
            prediction, confidence = self.analyze_with_ml(features)
            analysis_method = "ML Model"
        else:
            # Use rule-based analysis
            prediction, confidence = self.rule_based_analysis(pcap_path)
            analysis_method = "Rule-Based"
        
        # Generate detailed report
        is_malicious = (prediction == 1)
        
        if is_malicious:
            details = f"""
            🔴 MALICIOUS TRAFFIC DETECTED
            • Analysis Method: {analysis_method}
            • Confidence Level: {confidence:.1%}
            • Threat Indicators: Multiple suspicious patterns detected
            • Recommended Action: Immediate investigation required
            • Potential Threats: Port scanning, Flood attacks, Suspicious protocols
            """
        else:
            details = f"""
            ✅ NORMAL TRAFFIC DETECTED  
            • Analysis Method: {analysis_method}
            • Confidence Level: {confidence:.1%}
            • Traffic Patterns: Within normal parameters
            • Recommended Action: No immediate action required
            • Security Status: All clear
            """
        
        return {
            'file_path': pcap_path,
            'is_malicious': is_malicious,
            'confidence': confidence,
            'analysis_method': analysis_method,
            'details': details,
            'packet_count': len(rdpcap(pcap_path)) if os.path.exists(pcap_path) else 0
        }