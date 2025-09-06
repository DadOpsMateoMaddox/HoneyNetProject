# Data Flow Analysis

## 🔄 Event Pipeline - From Honey to Intelligence

### Stage 1: Event Collection
```mermaid
graph LR
    A[SSH Login Attempt] --> B[Cowrie Honeypot]
    C[Web Form Submission] --> D[Flask Trap]
    E[Database Query] --> F[SQLite Honeypot]
    B --> G[Event Normalizer]
    D --> G
    F --> G
    G --> H[Redis Event Queue]
```

#### Raw Event Structure
```json
{
  "timestamp": "2024-01-15T14:30:22Z",
  "source_ip": "192.168.1.100",
  "session_id": "ssh_session_001",
  "honeypot_type": "ssh",
  "event_type": "login_attempt",
  "data": {
    "username": "admin",
    "password": "password123",
    "command": null,
    "user_agent": null
  },
  "geolocation": {
    "country": "Unknown",
    "city": "Unknown",
    "asn": "Unknown"
  }
}
```

### Stage 2: Event Enrichment
```mermaid
graph TB
    A[Raw Event] --> B[Geolocation Enricher]
    B --> C[MITRE Mapper]
    C --> D[GPT-4 Analyzer]
    D --> E[ML Feature Extractor]
    E --> F[Enriched Event]
```

#### Enriched Event Structure
```json
{
  "original_event": { /* Raw event data */ },
  "enrichment": {
    "geolocation": {
      "country": "Russia",
      "city": "Moscow",
      "asn": "AS12345 Example ISP",
      "is_vpn": true,
      "is_tor": false
    },
    "mitre_techniques": [
      {
        "technique_id": "T1110.001",
        "technique_name": "Password Spraying",
        "confidence": 0.85,
        "tactic": "Credential Access"
      }
    ],
    "gpt_analysis": {
      "threat_level": "medium",
      "behavior_summary": "Automated password spraying attempt",
      "recommended_action": "monitor",
      "persona_response": "worried_admin"
    },
    "ml_features": {
      "login_frequency": 15.2,
      "inter_request_time": 0.5,
      "credential_entropy": 2.1,
      "anomaly_score": 0.73
    }
  }
}
```

### Stage 3: Decision Engine
```mermaid
graph TB
    A[Enriched Event] --> B{Anomaly Score > 0.7?}
    B -->|Yes| C[High Risk Path]
    B -->|No| D[Low Risk Path]
    C --> E{Auto Response Enabled?}
    E -->|Yes| F[Execute Response]
    E -->|No| G[Log & Alert]
    D --> H[Standard Monitoring]
    F --> I[Response Actions]
    G --> J[SIEM Integration]
    H --> J
    I --> J
```

#### Decision Tree Logic
```python
# From agent/cerberus_agent.py
def make_decision(self, enriched_event):
    score = enriched_event['enrichment']['ml_features']['anomaly_score']
    techniques = enriched_event['enrichment']['mitre_techniques']
    
    # Score-based thresholds
    if score >= 0.9:
        return Decision(action="escalate", confidence=0.95)
    elif score >= 0.7:
        return Decision(action="launch_decoy", confidence=0.8)
    elif score >= 0.5:
        return Decision(action="rotate_key", confidence=0.6)
    else:
        return Decision(action="monitor", confidence=0.3)
```

### Stage 4: Response Execution
```mermaid
graph LR
    A[Decision] --> B{Action Type}
    B -->|monitor| C[Enhanced Logging]
    B -->|rotate_key| D[SSH Key Rotation]
    B -->|launch_decoy| E[Deploy Honeypot]
    B -->|escalate| F[Alert Security Team]
    C --> G[Update Dashboard]
    D --> H[Deception Layer]
    E --> H
    F --> I[Incident Response]
    G --> J[Analytics Store]
    H --> J
    I --> J
```

## 🔄 Real-Time Processing

### Event Throughput
- **Peak Capacity**: 10,000 events/minute
- **Processing Latency**: < 500ms per event
- **Storage**: Rolling 30-day retention
- **Alerting**: Sub-second critical alerts

### Data Retention Strategy
```mermaid
graph TB
    A[Real-time Events] --> B[Redis Cache - 1 hour]
    B --> C[SQLite - 7 days]
    C --> D[PostgreSQL - 30 days]
    D --> E[Cold Storage - 1 year]
```

## 🎯 Data Quality & Validation

### Event Validation Pipeline
1. **Schema Validation**: JSON schema compliance
2. **IP Validation**: RFC compliance, GeoIP lookup
3. **Timing Validation**: Chronological ordering
4. **Content Validation**: Command sanitization
5. **Deduplication**: Hash-based duplicate detection

### Quality Metrics
- **Event Loss Rate**: < 0.1%
- **False Positive Rate**: < 5%
- **Processing Accuracy**: > 99%
- **Data Integrity**: 100% (checksums)

## 🔐 Security & Privacy

### Data Protection
- **Encryption**: AES-256 at rest, TLS 1.3 in transit
- **Anonymization**: IP masking for non-critical events
- **Access Control**: Role-based permissions
- **Audit Trail**: All data access logged

### Compliance Considerations
- **PII Handling**: Automatic detection and masking
- **Data Sovereignty**: Regional storage options
- **Retention Policies**: Configurable cleanup
- **Export Controls**: ITAR/EAR compliance

## 📊 Analytics Flow

### Metrics Collection
```mermaid
graph LR
    A[Event Stream] --> B[Metric Extractor]
    B --> C[Time Series DB]
    C --> D[Grafana Dashboard]
    B --> E[Anomaly Detector]
    E --> F[Alert Manager]
    F --> G[Notification System]
```

### Key Performance Indicators
- **Attack Volume**: Events per hour/day
- **Technique Distribution**: MITRE frequency
- **Geographic Patterns**: Source country trends
- **Response Effectiveness**: Action success rates

## 🔄 Integration Points

### Inbound Data Sources
- **Honeypot Events**: SSH, Web, Database
- **Network Telemetry**: Firewall logs, NetFlow
- **Threat Intelligence**: IOC feeds, YARA rules
- **Security Tools**: Nessus scans, vulnerability data

### Outbound Data Consumers
- **SIEM Platforms**: Splunk, QRadar, Sentinel
- **Orchestration**: SOAR platforms, playbooks
- **Dashboards**: Grafana, Kibana, custom UIs
- **APIs**: RESTful endpoints for integration

---

## 📚 Related Notes

- [[Component Deep Dive]] - Technical implementation details
- [[System Overview]] - High-level architecture
- [[Performance Tuning]] - Optimization strategies
- [[Troubleshooting]] - Common issues and solutions

---
*Tags: #dataflow #architecture #pipeline #realtime #analytics*
