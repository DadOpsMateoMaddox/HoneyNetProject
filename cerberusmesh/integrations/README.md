# CerberusMesh Enterprise Integrations

## 🚀 Complete Enterprise Integration Ecosystem

CerberusMesh now provides comprehensive enterprise-grade integrations for SIEM, vulnerability management, database support, and visualization dashboards. This modular addon system transforms CerberusMesh from a research platform into a production-ready enterprise security solution.

## 🎯 Available Integrations

### 1. **Splunk SIEM Integration** 📊
- **HTTP Event Collector (HEC)** forwarding with real-time event streaming
- **10+ SPL Query Templates** for threat hunting and analysis
- **Dashboard Panels** for intrusion detection and attack visualization
- **Batch Processing** with configurable flush intervals
- **Event Formatters** for structured data ingestion

**Key Features:**
- Real-time honeypot event forwarding to Splunk
- Pre-built SPL queries for common threat hunting scenarios
- Geographic attack analysis and MITRE ATT&CK technique mapping
- Configurable data indexing and source type management

### 2. **Nessus Vulnerability Scanner Integration** 🔍
- **Automated Vulnerability Scanning** with policy-based configurations
- **Attack Pattern Correlation** linking vulnerabilities to observed attacks
- **MITRE Technique Mapping** for comprehensive threat analysis
- **Compliance Reporting** (PCI, HIPAA, SOX)
- **Remediation Prioritization** based on attack exposure

**Key Features:**
- Automated scan scheduling and target management
- Real-time vulnerability correlation with honeypot attacks
- Comprehensive reporting with risk scoring
- Integration with enterprise compliance frameworks

### 3. **Multi-Database Support** 🗄️
- **MariaDB/MySQL** - Enterprise-grade relational database support
- **PostgreSQL** - Advanced analytics and JSON querying capabilities
- **SQLite** - Lightweight deployments and development environments
- **Schema Management** - Automated table creation and migrations
- **Connection Pooling** - High-performance async database operations

**Key Features:**
- Unified data model across all database types
- Advanced analytics queries and reporting
- High-availability connection pooling
- Comprehensive audit logging and data retention

### 4. **Grafana-Style Dashboard UI** 📈
- **Real-time Monitoring Dashboards** with WebSocket updates
- **Custom Visualization Panels** (graphs, heatmaps, geographic maps)
- **Interactive Analytics** with drill-down capabilities
- **Alert Management** with multi-channel notifications
- **Responsive Design** supporting multiple themes

**Key Features:**
- Real-time attack timeline visualization
- Geographic attack distribution mapping
- MITRE ATT&CK technique heatmaps
- AI agent performance metrics
- Customizable dashboard layouts

## 🛠️ Installation & Setup

### Prerequisites
```bash
# Install database drivers (choose based on your setup)
pip install aiomysql      # For MySQL/MariaDB
pip install asyncpg       # For PostgreSQL  
pip install aiosqlite     # For SQLite

# Install web framework for UI
pip install fastapi uvicorn jinja2

# Install HTTP client for integrations
pip install aiohttp
```

### Quick Start
```python
from cerberusmesh.integrations import get_integration

# Initialize Splunk integration
splunk_config = {
    "hec_url": "https://splunk.example.com:8088/services/collector",
    "hec_token": "your-hec-token",
    "index": "cerberusmesh",
    "verify_ssl": True
}
splunk = get_integration('splunk', splunk_config)
await splunk.initialize()

# Initialize database integration
db_config = {
    "db_type": "postgresql",
    "host": "postgres.example.com",
    "database": "cerberusmesh",
    "username": "cerberus",
    "password": "secure_password"
}
db = get_integration('database', db_config)
await db.initialize()

# Start Grafana UI
ui_config = {
    "host": "0.0.0.0",
    "port": 3000,
    "theme": "dark"
}
ui = get_integration('grafana_ui', ui_config)
ui.run()
```

## 📋 Configuration Examples

### Splunk Configuration
```yaml
splunk:
  hec_url: "https://splunk.example.com:8088/services/collector"
  hec_token: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
  index: "cerberusmesh"
  sourcetype: "honeypot:json"
  verify_ssl: true
  batch_size: 100
  flush_interval: 30
  enable_dashboards: true
  dashboard_panels:
    - "honeypot_connections"
    - "suspicious_commands"
    - "credential_attacks"
    - "geographic_analysis"
    - "mitre_techniques"
```

### Database Configuration
```yaml
database:
  # PostgreSQL (Recommended for production)
  db_type: "postgresql"
  host: "postgres.example.com"
  port: 5432
  database: "cerberusmesh"
  username: "cerberus"
  password: "secure_password"
  ssl_enabled: true
  pool_size: 10
  
  # MySQL/MariaDB Alternative
  # db_type: "mysql"
  # host: "mysql.example.com"
  # port: 3306
  
  # SQLite for Development
  # db_type: "sqlite"
  # sqlite_path: "/var/lib/cerberusmesh/cerberus.db"
```

### Nessus Configuration
```yaml
nessus:
  server_url: "https://nessus.example.com:8834"
  access_key: "your-nessus-access-key"
  secret_key: "your-nessus-secret-key"
  verify_ssl: true
  scan_templates: ["basic", "discovery", "web_app"]
  auto_scan_interval: 3600
  target_networks: ["192.168.1.0/24", "10.0.0.0/8"]
  compliance_checks: ["PCI", "HIPAA", "SOX"]
  enable_correlation: true
```

### Grafana UI Configuration
```yaml
grafana_ui:
  host: "0.0.0.0"
  port: 3000
  enable_websocket: true
  refresh_interval: 5
  theme: "dark"
  enable_alerts: true
  dashboard_settings:
    auto_refresh: true
    time_range: "6h"
    timezone: "browser"
  panels:
    enable_geographic_map: true
    enable_mitre_heatmap: true
    enable_threat_timeline: true
```

## 🐳 Docker Deployment

### Docker Compose
```yaml
version: '3.8'

services:
  cerberusmesh:
    image: cerberusmesh:latest
    ports:
      - "8000:8000"
    environment:
      - DB_TYPE=postgresql
      - DB_HOST=postgres
      - SPLUNK_HEC_URL=https://splunk:8088/services/collector
      - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
    depends_on:
      - postgres
    volumes:
      - ./config:/etc/cerberusmesh
      - ./data:/var/lib/cerberusmesh

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=cerberusmesh
      - POSTGRES_USER=cerberus
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  grafana_ui:
    image: cerberusmesh-ui:latest
    ports:
      - "3000:3000"
    depends_on:
      - cerberusmesh

volumes:
  postgres_data:
```

## ☸️ Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cerberusmesh
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cerberusmesh
  template:
    metadata:
      labels:
        app: cerberusmesh
    spec:
      containers:
      - name: cerberusmesh
        image: cerberusmesh:latest
        ports:
        - containerPort: 8000
        env:
        - name: CONFIG_PATH
          value: /etc/config/config.yaml
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

## 📈 SPL Query Templates

The Splunk integration includes 10+ pre-built SPL query templates:

### 1. Honeypot Connections Analysis
```spl
index=cerberusmesh source_ip=* 
| stats count as connections, dc(destination_port) as ports_hit, 
  earliest(_time) as first_seen, latest(_time) as last_seen by source_ip
| eval duration=last_seen-first_seen
| sort -connections
```

### 2. Suspicious Command Detection
```spl
index=cerberusmesh event_type="command_execution" command=*
| eval suspicious_score=case(
    match(command, "(?i)(wget|curl|nc|netcat)"), 3,
    match(command, "(?i)(rm -rf|dd if=)"), 4,
    match(command, "(?i)(sudo|su -)"), 2,
    1=1, 1)
| where suspicious_score >= 2
| sort -suspicious_score
```

### 3. MITRE ATT&CK Technique Mapping
```spl
index=cerberusmesh mitre_technique=*
| stats count by mitre_technique, tactic
| eval technique_id=mitre_technique
| sort -count
```

## 🔒 Security Features

### Data Encryption
- **Encryption at Rest**: Database encryption support
- **Encryption in Transit**: TLS/SSL for all communications
- **API Security**: Rate limiting and authentication
- **Audit Logging**: Comprehensive security event logging

### Access Control
- **Role-Based Access**: Configurable user permissions
- **API Keys**: Secure service-to-service authentication
- **Session Management**: Secure session handling
- **CSRF Protection**: Cross-site request forgery prevention

## 📊 Analytics & Reporting

### Real-time Dashboards
- **Attack Timeline**: Chronological attack visualization
- **Geographic Distribution**: World map of attack origins
- **Threat Score Trending**: Risk assessment over time
- **Agent Performance**: AI decision-making metrics

### Advanced Analytics
- **Threat Intelligence**: IOC correlation and enrichment
- **Behavioral Analysis**: Anomaly detection patterns
- **Attack Attribution**: Advanced persistent threat tracking
- **Compliance Reporting**: Automated compliance documentation

## 🔧 API Integration

### REST API Endpoints
```python
# Dashboard Management
GET    /api/dashboards              # List all dashboards
GET    /api/dashboards/{id}         # Get specific dashboard
POST   /api/dashboards              # Create new dashboard
PUT    /api/dashboards/{id}         # Update dashboard
DELETE /api/dashboards/{id}         # Delete dashboard

# Data Queries
POST   /api/datasources/query       # Execute data query
GET    /api/alerts                  # List active alerts
POST   /api/alerts                  # Create new alert

# Real-time Updates
WS     /ws                          # WebSocket for live updates
```

### WebSocket Events
```javascript
// Subscribe to dashboard updates
ws.send(JSON.stringify({
    "type": "subscribe",
    "dashboard_id": "overview"
}));

// Receive real-time data
{
    "type": "data_update",
    "timestamp": "2024-01-15T10:30:00Z",
    "metrics": {
        "attacks_total": 150,
        "unique_attackers": 25,
        "threat_score": 0.67
    }
}
```

## 🚀 Performance Optimization

### Database Optimization
- **Connection Pooling**: Async connection management
- **Query Optimization**: Indexed columns for fast queries
- **Batch Processing**: Efficient bulk data operations
- **Data Partitioning**: Time-based data segmentation

### Caching Strategy
- **Redis Integration**: High-performance caching layer
- **Query Caching**: Repeated query result caching
- **Session Caching**: User session state management
- **Asset Caching**: Static resource optimization

## 🔍 Monitoring & Observability

### Health Checks
```python
# Integration health monitoring
async def check_integration_health():
    health_status = {
        "splunk": await splunk.health_check(),
        "database": await db.health_check(),
        "nessus": await nessus.health_check(),
        "ui": ui.health_check()
    }
    return health_status
```

### Metrics Collection
- **Prometheus Metrics**: Standard observability metrics
- **Custom Metrics**: Application-specific measurements
- **Performance Tracking**: Response time monitoring
- **Error Tracking**: Comprehensive error logging

## 📚 Advanced Usage

### Custom Panel Creation
```python
# Create custom visualization panel
custom_panel = ui.create_custom_panel(
    panel_type='graph',
    title='Custom Attack Analysis',
    query='cerberusmesh_custom_metric',
    legend='Attack Frequency',
    panel_options={
        'tooltip': {'mode': 'multi'},
        'legend': {'displayMode': 'list'}
    }
)
```

### Database Analytics
```python
# Generate comprehensive analytics report
report = await db.generate_analytics_report(days=7)
print(f"Total events: {report['summary']['total_events']}")
print(f"Unique attackers: {report['summary']['unique_attackers']}")
```

### Threat Intelligence Enrichment
```python
# Enrich attack data with threat intelligence
enriched_data = await nessus.enrich_attack_with_vulnerabilities(
    attack_data=attack_event,
    correlation_window=1800
)
```

## 🤝 Contributing

We welcome contributions to the CerberusMesh enterprise integration ecosystem:

1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** your integration or enhancement
4. **Add** comprehensive tests
5. **Submit** a pull request

### Integration Development Guidelines
- Follow the modular addon architecture
- Implement comprehensive error handling
- Include configuration examples
- Add unit and integration tests
- Document API endpoints and usage

## 📞 Support

For enterprise support and custom integrations:

- **Documentation**: Full API documentation available
- **Community**: GitHub Discussions for community support
- **Enterprise Support**: Commercial support packages available
- **Custom Integrations**: Professional services for custom integrations

## 🏆 Enterprise Features Summary

✅ **SIEM Integration** - Splunk HEC with SPL queries  
✅ **Vulnerability Management** - Nessus automated scanning  
✅ **Multi-Database Support** - MySQL, PostgreSQL, SQLite  
✅ **Real-time Dashboards** - Grafana-style UI with WebSocket  
✅ **Advanced Analytics** - Threat intelligence and correlation  
✅ **Enterprise Security** - Encryption, RBAC, audit logging  
✅ **Cloud-Native Deployment** - Docker, Kubernetes ready  
✅ **High Performance** - Async operations, connection pooling  
✅ **Comprehensive Monitoring** - Health checks, metrics, alerts  
✅ **Production Ready** - Scalable, reliable, maintainable

---

🔥 **CerberusMesh Enterprise Integrations** - Transforming honeypot research into production-grade enterprise security solutions! 🔥
