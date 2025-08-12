#!/usr/bin/env python3
"""
CerberusMesh ML Anomaly Engine - Real-time anomaly detection for honeypot events.

This module provides:
- Isolation Forest-based anomaly detection
- Time-windowed event analysis
- Configurable alert thresholds
- Real-time monitoring and alerting
"""

import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import time
import threading
import queue
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import pickle
import schedule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ml_anomaly.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class EventData:
    """Structure for individual honeypot events."""
    timestamp: datetime
    source_ip: str
    destination_port: int
    protocol: str
    event_type: str  # login_attempt, command_execution, file_upload, etc.
    honeypot_id: str
    session_id: str
    additional_data: Dict[str, Any]

@dataclass
class AnomalyAlert:
    """Structure for anomaly alerts."""
    timestamp: datetime
    anomaly_score: float
    event_count: int
    time_window: str
    anomalous_features: List[str]
    suggested_action: str
    confidence: float

@dataclass
class DetectorConfig:
    """Configuration for the anomaly detector."""
    contamination: float = 0.1  # Expected proportion of anomalies
    time_window_minutes: int = 10  # Time window for analysis
    alert_threshold: float = -0.5  # Anomaly score threshold
    min_events_for_analysis: int = 10  # Minimum events needed
    feature_columns: List[str] = None
    model_retrain_hours: int = 24  # Hours between model retraining

class AnomalyDetector:
    """ML-based anomaly detector for honeypot events."""
    
    def __init__(self, config: Optional[DetectorConfig] = None):
        """Initialize the anomaly detector."""
        self.config = config or DetectorConfig()
        if self.config.feature_columns is None:
            self.config.feature_columns = [
                'source_ip_hash', 'destination_port', 'protocol_num',
                'event_type_hash', 'events_per_minute', 'unique_ips_per_window',
                'port_diversity', 'session_duration'
            ]
        
        # Initialize components
        self.model = IsolationForest(
            contamination=self.config.contamination,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Data storage
        self.events = []
        self.alerts = []
        self.model_file = Path("anomaly_model.pkl")
        self.scaler_file = Path("anomaly_scaler.pkl")
        
        # Load existing model if available
        self._load_model()
        
        # Monitoring
        self.event_queue = queue.Queue()
        self.is_monitoring = False
        self.monitor_thread = None
        
        logger.info("Anomaly detector initialized")
    
    def _load_model(self) -> bool:
        """Load pre-trained model and scaler."""
        try:
            if self.model_file.exists() and self.scaler_file.exists():
                with open(self.model_file, 'rb') as f:
                    self.model = pickle.load(f)
                with open(self.scaler_file, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded pre-trained model")
                return True
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
        return False
    
    def _save_model(self):
        """Save trained model and scaler."""
        try:
            with open(self.model_file, 'wb') as f:
                pickle.dump(self.model, f)
            with open(self.scaler_file, 'wb') as f:
                pickle.dump(self.scaler, f)
            logger.info("Model saved successfully")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def _hash_string(self, s: str) -> int:
        """Simple hash function for string features."""
        return hash(s) % (2**31)
    
    def _extract_features(self, events: List[EventData], time_window: timedelta) -> pd.DataFrame:
        """Extract features from events for ML analysis."""
        if not events:
            return pd.DataFrame()
        
        # Convert to DataFrame for easier manipulation
        event_dicts = []
        for event in events:
            event_dict = {
                'timestamp': event.timestamp,
                'source_ip': event.source_ip,
                'destination_port': event.destination_port,
                'protocol': event.protocol,
                'event_type': event.event_type,
                'honeypot_id': event.honeypot_id,
                'session_id': event.session_id
            }
            event_dicts.append(event_dict)
        
        df = pd.DataFrame(event_dicts)
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        time_groups = df.groupby(pd.Grouper(key='timestamp', freq=f'{self.config.time_window_minutes}T'))
        
        features_list = []
        
        for time_group, group_events in time_groups:
            if len(group_events) == 0:
                continue
            
            # Basic features
            features = {
                'time_window': time_group,
                'event_count': len(group_events),
                'unique_ips': group_events['source_ip'].nunique(),
                'unique_ports': group_events['destination_port'].nunique(),
                'unique_protocols': group_events['protocol'].nunique(),
                'unique_event_types': group_events['event_type'].nunique(),
                'unique_honeypots': group_events['honeypot_id'].nunique(),
                'unique_sessions': group_events['session_id'].nunique()
            }
            
            # Derived features
            features['events_per_minute'] = features['event_count'] / self.config.time_window_minutes
            features['ips_per_event'] = features['unique_ips'] / features['event_count']
            features['ports_per_ip'] = features['unique_ports'] / max(features['unique_ips'], 1)
            features['sessions_per_ip'] = features['unique_sessions'] / max(features['unique_ips'], 1)
            
            # Most common values (hashed for numerical representation)
            features['top_ip_hash'] = self._hash_string(group_events['source_ip'].mode().iloc[0] if not group_events['source_ip'].mode().empty else '')
            features['top_port'] = group_events['destination_port'].mode().iloc[0] if not group_events['destination_port'].mode().empty else 0
            features['top_protocol_hash'] = self._hash_string(group_events['protocol'].mode().iloc[0] if not group_events['protocol'].mode().empty else '')
            features['top_event_type_hash'] = self._hash_string(group_events['event_type'].mode().iloc[0] if not group_events['event_type'].mode().empty else '')
            
            # Port distribution features
            port_counts = group_events['destination_port'].value_counts()
            features['port_entropy'] = -sum((port_counts / len(group_events)) * np.log2(port_counts / len(group_events) + 1e-10))
            features['port_diversity'] = len(port_counts) / len(group_events)
            
            # Time-based patterns
            time_diffs = group_events['timestamp'].diff().dt.total_seconds().dropna()
            features['avg_time_between_events'] = time_diffs.mean() if len(time_diffs) > 0 else 0
            features['time_variance'] = time_diffs.var() if len(time_diffs) > 0 else 0
            
            features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    def train(self, training_events: List[EventData], retrain: bool = False) -> bool:
        """Train the anomaly detection model."""
        if not training_events:
            logger.warning("No training events provided")
            return False
        
        if self.is_trained and not retrain:
            logger.info("Model already trained. Use retrain=True to force retraining.")
            return True
        
        try:
            logger.info(f"Training model with {len(training_events)} events")
            
            # Extract features
            time_window = timedelta(minutes=self.config.time_window_minutes)
            features_df = self._extract_features(training_events, time_window)
            
            if len(features_df) < self.config.min_events_for_analysis:
                logger.warning(f"Insufficient data for training: {len(features_df)} < {self.config.min_events_for_analysis}")
                return False
            
            # Select feature columns
            available_features = [col for col in self.config.feature_columns if col in features_df.columns]
            if not available_features:
                logger.error("No matching feature columns found")
                return False
            
            X = features_df[available_features].fillna(0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model.fit(X_scaled)
            self.is_trained = True
            
            # Save model
            self._save_model()
            
            logger.info(f"Model trained successfully with {len(available_features)} features")
            return True
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return False
    
    def analyze_events(self, events: List[EventData]) -> List[AnomalyAlert]:
        """Analyze events for anomalies."""
        if not self.is_trained:
            logger.warning("Model not trained. Cannot analyze events.")
            return []
        
        if not events:
            return []
        
        try:
            # Extract features
            time_window = timedelta(minutes=self.config.time_window_minutes)
            features_df = self._extract_features(events, time_window)
            
            if len(features_df) < self.config.min_events_for_analysis:
                logger.debug(f"Insufficient events for analysis: {len(features_df)}")
                return []
            
            # Select and scale features
            available_features = [col for col in self.config.feature_columns if col in features_df.columns]
            X = features_df[available_features].fillna(0)
            X_scaled = self.scaler.transform(X)
            
            # Predict anomalies
            anomaly_scores = self.model.decision_function(X_scaled)
            anomaly_predictions = self.model.predict(X_scaled)
            
            # Generate alerts for anomalies
            alerts = []
            for i, (score, prediction) in enumerate(zip(anomaly_scores, anomaly_predictions)):
                if prediction == -1 and score <= self.config.alert_threshold:
                    # Find anomalous features
                    row = features_df.iloc[i]
                    anomalous_features = self._identify_anomalous_features(row, X.iloc[i])
                    
                    # Determine suggested action
                    suggested_action = self._suggest_action(score, row, anomalous_features)
                    
                    alert = AnomalyAlert(
                        timestamp=datetime.now(),
                        anomaly_score=score,
                        event_count=int(row['event_count']),
                        time_window=f"{self.config.time_window_minutes} minutes",
                        anomalous_features=anomalous_features,
                        suggested_action=suggested_action,
                        confidence=abs(score)  # Higher magnitude = higher confidence
                    )
                    alerts.append(alert)
            
            if alerts:
                logger.warning(f"Detected {len(alerts)} anomalies")
                self.alerts.extend(alerts)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return []
    
    def _identify_anomalous_features(self, row: pd.Series, features: pd.Series) -> List[str]:
        """Identify which features contributed to the anomaly."""
        anomalous_features = []
        
        # Simple heuristics for feature importance
        if row['events_per_minute'] > 50:  # High event rate
            anomalous_features.append('high_event_rate')
        
        if row['unique_ips'] > 20:  # Many unique IPs
            anomalous_features.append('many_unique_ips')
        
        if row['port_diversity'] > 0.8:  # High port diversity
            anomalous_features.append('high_port_diversity')
        
        if row['unique_ports'] > 10:  # Many unique ports
            anomalous_features.append('many_unique_ports')
        
        if row.get('port_entropy', 0) > 3.0:  # High entropy
            anomalous_features.append('high_port_entropy')
        
        return anomalous_features if anomalous_features else ['unknown_anomaly']
    
    def _suggest_action(self, score: float, row: pd.Series, anomalous_features: List[str]) -> str:
        """Suggest remediation action based on anomaly characteristics."""
        severity = "HIGH" if score < -0.8 else "MEDIUM" if score < -0.5 else "LOW"
        
        actions = [f"SEVERITY: {severity}"]
        
        if 'high_event_rate' in anomalous_features:
            actions.append("Consider rate limiting or IP blocking")
        
        if 'many_unique_ips' in anomalous_features:
            actions.append("Potential coordinated attack - investigate IP patterns")
        
        if 'high_port_diversity' in anomalous_features:
            actions.append("Port scanning detected - monitor for exploitation attempts")
        
        if 'many_unique_ports' in anomalous_features:
            actions.append("Service enumeration detected - harden exposed services")
        
        # Default action
        if len(actions) == 1:
            actions.append("Manual investigation recommended")
        
        return " | ".join(actions)
    
    def add_event(self, event: EventData):
        """Add a single event for processing."""
        self.event_queue.put(event)
    
    def start_monitoring(self):
        """Start real-time monitoring thread."""
        if self.is_monitoring:
            logger.warning("Monitoring already active")
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        # Schedule periodic model retraining
        schedule.every(self.config.model_retrain_hours).hours.do(self._retrain_model)
        
        logger.info("Started real-time monitoring")
    
    def stop_monitoring(self):
        """Stop real-time monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Stopped monitoring")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        buffer = []
        last_analysis = datetime.now()
        analysis_interval = timedelta(minutes=self.config.time_window_minutes)
        
        while self.is_monitoring:
            try:
                # Collect events from queue
                try:
                    event = self.event_queue.get(timeout=1)
                    buffer.append(event)
                    self.events.append(event)
                except queue.Empty:
                    pass
                
                # Analyze periodically
                if datetime.now() - last_analysis >= analysis_interval:
                    if buffer:
                        alerts = self.analyze_events(buffer)
                        for alert in alerts:
                            self._handle_alert(alert)
                        buffer = []
                        last_analysis = datetime.now()
                
                # Run scheduled tasks
                schedule.run_pending()
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(1)
    
    def _handle_alert(self, alert: AnomalyAlert):
        """Handle an anomaly alert."""
        logger.warning(f"ANOMALY ALERT: Score={alert.anomaly_score:.3f}, "
                      f"Events={alert.event_count}, Features={alert.anomalous_features}")
        logger.warning(f"Suggested Action: {alert.suggested_action}")
        
        # Save alert to file
        alert_file = Path("anomaly_alerts.jsonl")
        with open(alert_file, 'a') as f:
            alert_dict = asdict(alert)
            alert_dict['timestamp'] = alert.timestamp.isoformat()
            f.write(json.dumps(alert_dict) + '\n')
    
    def _retrain_model(self):
        """Periodic model retraining."""
        if len(self.events) > self.config.min_events_for_analysis * 10:
            logger.info("Starting periodic model retraining")
            recent_events = self.events[-1000:]  # Use recent events for retraining
            self.train(recent_events, retrain=True)
    
    def get_statistics(self) -> Dict:
        """Get detector statistics."""
        return {
            "total_events_processed": len(self.events),
            "total_alerts_generated": len(self.alerts),
            "is_trained": self.is_trained,
            "is_monitoring": self.is_monitoring,
            "model_config": asdict(self.config)
        }

def load_sample_events(file_path: str) -> List[EventData]:
    """Load sample events from JSON file for testing."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        events = []
        for item in data:
            event = EventData(
                timestamp=datetime.fromisoformat(item['timestamp']),
                source_ip=item['source_ip'],
                destination_port=item['destination_port'],
                protocol=item['protocol'],
                event_type=item['event_type'],
                honeypot_id=item['honeypot_id'],
                session_id=item['session_id'],
                additional_data=item.get('additional_data', {})
            )
            events.append(event)
        
        return events
    except Exception as e:
        logger.error(f"Failed to load events: {e}")
        return []

def main():
    """CLI interface for the anomaly detector."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CerberusMesh ML Anomaly Detector")
    parser.add_argument("action", choices=["train", "analyze", "monitor", "stats"], 
                       help="Action to perform")
    parser.add_argument("--events-file", 
                       help="JSON file containing events for training/analysis")
    parser.add_argument("--contamination", type=float, default=0.1,
                       help="Expected contamination rate")
    parser.add_argument("--time-window", type=int, default=10,
                       help="Time window in minutes")
    parser.add_argument("--threshold", type=float, default=-0.5,
                       help="Anomaly score threshold")
    
    args = parser.parse_args()
    
    # Initialize detector
    config = DetectorConfig(
        contamination=args.contamination,
        time_window_minutes=args.time_window,
        alert_threshold=args.threshold
    )
    detector = AnomalyDetector(config)
    
    # Execute action
    if args.action == "train":
        if not args.events_file:
            print("Error: --events-file required for training")
            return
        
        events = load_sample_events(args.events_file)
        if detector.train(events):
            print(f"Training completed with {len(events)} events")
        else:
            print("Training failed")
    
    elif args.action == "analyze":
        if not args.events_file:
            print("Error: --events-file required for analysis")
            return
        
        events = load_sample_events(args.events_file)
        alerts = detector.analyze_events(events)
        print(f"Analysis completed. Found {len(alerts)} anomalies:")
        for alert in alerts:
            print(f"  - Score: {alert.anomaly_score:.3f}, Events: {alert.event_count}")
            print(f"    Features: {alert.anomalous_features}")
            print(f"    Action: {alert.suggested_action}")
    
    elif args.action == "monitor":
        print("Starting real-time monitoring... Press Ctrl+C to stop")
        detector.start_monitoring()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            detector.stop_monitoring()
            print("Monitoring stopped")
    
    elif args.action == "stats":
        stats = detector.get_statistics()
        print("Detector Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

if __name__ == "__main__":
    main()
