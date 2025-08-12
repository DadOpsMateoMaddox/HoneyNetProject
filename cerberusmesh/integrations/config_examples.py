#!/usr/bin/env python3
"""
CerberusMesh Integration Configuration Examples

Complete configuration examples for all enterprise integrations.
Copy and modify these configurations for your deployment.
"""

# Splunk SIEM Integration Configuration
SPLUNK_CONFIG = {
    "hec_url": "https://splunk.example.com:8088/services/collector",
    "hec_token": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
    "index": "cerberusmesh",
    "sourcetype": "honeypot:json",
    "verify_ssl": True,
    "batch_size": 100,
    "flush_interval": 30,
    "enable_dashboards": True,
    "dashboard_panels": [
        "honeypot_connections",
        "suspicious_commands", 
        "credential_attacks",
        "geographic_analysis",
        "mitre_techniques"
    ]
}

# Nessus Vulnerability Scanner Configuration
NESSUS_CONFIG = {
    "server_url": "https://nessus.example.com:8834",
    "access_key": "your-nessus-access-key",
    "secret_key": "your-nessus-secret-key",
    "verify_ssl": True,
    "scan_templates": ["basic", "discovery", "web_app", "malware"],
    "auto_scan_interval": 3600,  # seconds
    "target_networks": ["192.168.1.0/24", "10.0.0.0/8"],
    "exclude_networks": ["192.168.1.1", "10.0.0.1"],
    "compliance_checks": ["PCI", "HIPAA", "SOX"],
    "enable_correlation": True,
    "correlation_window": 1800  # seconds
}

# Database Integration Configurations

# MariaDB/MySQL Configuration
MYSQL_CONFIG = {
    "db_type": "mysql",
    "host": "mysql.example.com",
    "port": 3306,
    "database": "cerberusmesh",
    "username": "cerberus",
    "password": "secure_database_password",
    "ssl_enabled": True,
    "pool_size": 10,
    "charset": "utf8mb4",
    "connect_timeout": 30,
    "read_timeout": 30,
    "write_timeout": 30
}

# PostgreSQL Configuration
POSTGRESQL_CONFIG = {
    "db_type": "postgresql",
    "host": "postgres.example.com",
    "port": 5432,
    "database": "cerberusmesh",
    "username": "cerberus",
    "password": "secure_database_password",
    "ssl_enabled": True,
    "ssl_mode": "require",
    "pool_size": 10,
    "min_pool_size": 2,
    "max_pool_size": 20,
    "statement_timeout": 30000,
    "command_timeout": 60
}

# SQLite Configuration (for lightweight deployments)
SQLITE_CONFIG = {
    "db_type": "sqlite",
    "sqlite_path": "/var/lib/cerberusmesh/cerberusmesh.db",
    "wal_mode": True,
    "synchronous": "NORMAL",
    "journal_mode": "WAL",
    "cache_size": 10000,
    "temp_store": "memory"
}

# Grafana UI Integration Configuration
GRAFANA_UI_CONFIG = {
    "host": "0.0.0.0",
    "port": 3000,
    "enable_websocket": True,
    "websocket_path": "/ws",
    "refresh_interval": 5,  # seconds
    "theme": "dark",  # dark, light
    "enable_alerts": True,
    "alert_channels": ["email", "slack", "webhook"],
    "dashboard_settings": {
        "auto_refresh": True,
        "time_range": "6h",
        "timezone": "browser",
        "editable": True
    },
    "panels": {
        "enable_geographic_map": True,
        "enable_mitre_heatmap": True,
        "enable_threat_timeline": True,
        "enable_agent_metrics": True
    },
    "security": {
        "enable_authentication": True,
        "session_timeout": 3600,
        "csrf_protection": True
    }
}

# Complete Enterprise Integration Configuration
ENTERPRISE_CONFIG = {
    "integrations": {
        "splunk": SPLUNK_CONFIG,
        "nessus": NESSUS_CONFIG,
        "database": MYSQL_CONFIG,  # or POSTGRESQL_CONFIG or SQLITE_CONFIG
        "grafana_ui": GRAFANA_UI_CONFIG
    },
    "global_settings": {
        "log_level": "INFO",
        "enable_metrics": True,
        "metrics_port": 8080,
        "health_check_interval": 60,
        "data_retention_days": 90,
        "backup_enabled": True,
        "backup_interval": "daily",
        "backup_location": "/var/backups/cerberusmesh"
    },
    "security": {
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "api_rate_limiting": True,
        "api_rate_limit": 1000,  # requests per hour
        "enable_audit_logging": True,
        "audit_log_path": "/var/log/cerberusmesh/audit.log"
    }
}

# Docker Compose Integration Configuration
DOCKER_COMPOSE_CONFIG = """
version: '3.8'

services:
  cerberusmesh:
    image: cerberusmesh:latest
    ports:
      - "8000:8000"
    environment:
      - DB_TYPE=postgresql
      - DB_HOST=postgres
      - DB_NAME=cerberusmesh
      - DB_USER=cerberus
      - DB_PASSWORD=secure_password
      - SPLUNK_HEC_URL=https://splunk:8088/services/collector
      - SPLUNK_HEC_TOKEN=${SPLUNK_HEC_TOKEN}
      - NESSUS_URL=https://nessus:8834
      - NESSUS_ACCESS_KEY=${NESSUS_ACCESS_KEY}
      - NESSUS_SECRET_KEY=${NESSUS_SECRET_KEY}
    depends_on:
      - postgres
      - redis
    volumes:
      - ./data:/var/lib/cerberusmesh
      - ./logs:/var/log/cerberusmesh

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=cerberusmesh
      - POSTGRES_USER=cerberus
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  grafana_ui:
    image: cerberusmesh-ui:latest
    ports:
      - "3000:3000"
    environment:
      - GRAFANA_SECURITY_ADMIN_PASSWORD=admin
    depends_on:
      - cerberusmesh

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - cerberusmesh
      - grafana_ui

volumes:
  postgres_data:
  redis_data:
"""

# Kubernetes Deployment Configuration
KUBERNETES_CONFIG = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: cerberusmesh-config
data:
  config.yaml: |
    integrations:
      database:
        db_type: postgresql
        host: postgres-service
        port: 5432
        database: cerberusmesh
        username: cerberus
        password: secure_password
        ssl_enabled: true
        pool_size: 10
      splunk:
        hec_url: https://splunk-service:8088/services/collector
        hec_token: SPLUNK_TOKEN_FROM_SECRET
        index: cerberusmesh
        verify_ssl: true
      grafana_ui:
        host: 0.0.0.0
        port: 3000
        enable_websocket: true

---
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
        volumeMounts:
        - name: config
          mountPath: /etc/config
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: cerberusmesh-config

---
apiVersion: v1
kind: Service
metadata:
  name: cerberusmesh-service
spec:
  selector:
    app: cerberusmesh
  ports:
  - port: 8000
    targetPort: 8000
  type: LoadBalancer
"""

# Environment Variables Configuration
ENV_CONFIG = """
# CerberusMesh Environment Configuration

# Database Configuration
DB_TYPE=postgresql
DB_HOST=postgres.example.com
DB_PORT=5432
DB_NAME=cerberusmesh
DB_USER=cerberus
DB_PASSWORD=secure_database_password
DB_SSL_ENABLED=true
DB_POOL_SIZE=10

# Splunk Integration
SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector
SPLUNK_HEC_TOKEN=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
SPLUNK_INDEX=cerberusmesh
SPLUNK_VERIFY_SSL=true
SPLUNK_BATCH_SIZE=100

# Nessus Integration
NESSUS_SERVER_URL=https://nessus.example.com:8834
NESSUS_ACCESS_KEY=your-nessus-access-key
NESSUS_SECRET_KEY=your-nessus-secret-key
NESSUS_VERIFY_SSL=true
NESSUS_AUTO_SCAN_INTERVAL=3600

# Grafana UI
GRAFANA_UI_HOST=0.0.0.0
GRAFANA_UI_PORT=3000
GRAFANA_UI_THEME=dark
GRAFANA_UI_ENABLE_WEBSOCKET=true

# Security Settings
ENCRYPTION_KEY=your-32-character-encryption-key-here
JWT_SECRET=your-jwt-secret-key-here
API_RATE_LIMIT=1000
ENABLE_AUDIT_LOGGING=true

# Monitoring
LOG_LEVEL=INFO
METRICS_ENABLED=true
METRICS_PORT=8080
HEALTH_CHECK_INTERVAL=60

# Data Retention
DATA_RETENTION_DAYS=90
BACKUP_ENABLED=true
BACKUP_INTERVAL=daily
BACKUP_LOCATION=/var/backups/cerberusmesh
"""

# Installation Script Configuration
INSTALL_SCRIPT = """#!/bin/bash
# CerberusMesh Enterprise Integration Installation Script

set -e

echo "Installing CerberusMesh Enterprise Integrations..."

# Install system dependencies
apt-get update
apt-get install -y python3 python3-pip python3-venv postgresql-client mysql-client

# Create virtual environment
python3 -m venv /opt/cerberusmesh/venv
source /opt/cerberusmesh/venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install optional database drivers
pip install aiomysql asyncpg aiosqlite

# Install web UI dependencies
pip install fastapi uvicorn jinja2

# Install HTTP client for integrations
pip install aiohttp

# Create configuration directory
mkdir -p /etc/cerberusmesh
mkdir -p /var/lib/cerberusmesh
mkdir -p /var/log/cerberusmesh

# Copy configuration templates
cp config/enterprise_config.yaml /etc/cerberusmesh/
cp config/integrations.yaml /etc/cerberusmesh/

# Set permissions
chown -R cerberus:cerberus /etc/cerberusmesh
chown -R cerberus:cerberus /var/lib/cerberusmesh
chown -R cerberus:cerberus /var/log/cerberusmesh

# Create systemd service
cp scripts/cerberusmesh.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable cerberusmesh

echo "Installation complete!"
echo "1. Edit /etc/cerberusmesh/enterprise_config.yaml"
echo "2. Configure your integrations in /etc/cerberusmesh/integrations.yaml"
echo "3. Start the service: systemctl start cerberusmesh"
echo "4. Check status: systemctl status cerberusmesh"
echo "5. Access dashboard: http://localhost:3000"
"""

if __name__ == "__main__":
    import json
    
    print("CerberusMesh Enterprise Integration Configuration Examples")
    print("=" * 60)
    
    print("\n1. Splunk SIEM Integration:")
    print(json.dumps(SPLUNK_CONFIG, indent=2))
    
    print("\n2. Nessus Vulnerability Scanner:")
    print(json.dumps(NESSUS_CONFIG, indent=2))
    
    print("\n3. Database Configurations:")
    print("MySQL/MariaDB:", json.dumps(MYSQL_CONFIG, indent=2))
    print("PostgreSQL:", json.dumps(POSTGRESQL_CONFIG, indent=2))
    print("SQLite:", json.dumps(SQLITE_CONFIG, indent=2))
    
    print("\n4. Grafana UI Dashboard:")
    print(json.dumps(GRAFANA_UI_CONFIG, indent=2))
    
    print("\n5. Complete Enterprise Configuration:")
    print(json.dumps(ENTERPRISE_CONFIG, indent=2))
