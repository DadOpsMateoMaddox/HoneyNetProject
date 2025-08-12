# 🔥 CerberusMesh Complete Deployment Guide

## 🗝️ **REQUIRED API KEYS & CREDENTIALS**

### 1. **AWS Credentials** (REQUIRED)
```bash
# AWS IAM User with these permissions:
# - EC2FullAccess (for honeypot instances)
# - SSMFullAccess (for parameter store)
# - IAMReadOnlyAccess (for role management)

export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
```

### 2. **OpenAI API Key** (REQUIRED for AI Agent)
```bash
# Get from: https://platform.openai.com/account/api-keys
export OPENAI_API_KEY="sk-..."
```

### 3. **Splunk Integration** (OPTIONAL - Enterprise)
```bash
# Splunk HTTP Event Collector (HEC) Token
# Get from: Splunk Web > Settings > Data Inputs > HTTP Event Collector
export SPLUNK_HEC_URL="https://your-splunk.com:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-hec-token-here"
export SPLUNK_INDEX="cerberusmesh"
```

### 4. **Nessus Vulnerability Scanner** (OPTIONAL - Enterprise)
```bash
# Nessus API Keys
# Get from: Nessus Web UI > Settings > My Account > API Keys
export NESSUS_SERVER_URL="https://your-nessus.com:8834"
export NESSUS_ACCESS_KEY="your-access-key"
export NESSUS_SECRET_KEY="your-secret-key"
```

### 5. **Database Credentials** (OPTIONAL - Choose One)
```bash
# PostgreSQL (Recommended for production)
export DB_TYPE="postgresql"
export DB_HOST="your-postgres-host.com"
export DB_PORT="5432"
export DB_NAME="cerberusmesh"
export DB_USER="cerberus"
export DB_PASSWORD="secure_database_password"

# OR MySQL/MariaDB
export DB_TYPE="mysql"
export DB_HOST="your-mysql-host.com"
export DB_PORT="3306"

# OR SQLite (Development only)
export DB_TYPE="sqlite"
export DB_PATH="/var/lib/cerberusmesh/cerberus.db"
```

### 6. **Webhook Integration** (FOR YOUR WEBSITE)
```bash
# Your website's webhook endpoint for attack notifications
export WEBHOOK_URL="https://your-website.com/api/attack-webhook"
export WEBHOOK_SECRET="your-webhook-secret-key"
export WEBHOOK_TIMEOUT="30"
```

---

## 🚀 **QUICK DEPLOYMENT STEPS**

### Step 1: Clone & Setup
```bash
git clone https://github.com/DadOpsMateoMaddox/HoneyNetProject.git
cd HoneyNetProject/cerberusmesh
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Configure API Keys
```bash
# Create environment file
cp .env.example .env

# Edit .env with your API keys
nano .env
```

### Step 3: Initialize Infrastructure
```bash
# Create AWS infrastructure
python controller/main.py --init

# Deploy honeypots
python controller/main.py --deploy --count 3 --regions us-east-1,us-west-2
```

### Step 4: Start Monitoring
```bash
# Start the AI agent
python agent/cerberus_agent.py --config agent/config.ini

# Start the dashboard (if using Grafana UI)
python integrations/grafana_ui.py --port 3000
```

---

## 🔌 **WEBSITE INTEGRATION**

### Webhook Endpoint Setup
Add this to your website's API:

```python
# Example webhook handler for your website
from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)

@app.route('/api/attack-webhook', methods=['POST'])
def attack_webhook():
    # Verify webhook signature
    signature = request.headers.get('X-Signature')
    payload = request.get_data()
    
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    # Process attack data
    attack_data = request.json
    
    # Log attack to your database
    log_attack_to_database(attack_data)
    
    # Send alert to admin
    send_admin_alert(attack_data)
    
    # Update security dashboard
    update_security_dashboard(attack_data)
    
    return jsonify({'status': 'received'}), 200

def log_attack_to_database(data):
    """Log attack data to your website's database."""
    # Your database logging logic here
    pass

def send_admin_alert(data):
    """Send alert to website administrators."""
    # Your alerting logic here (email, Slack, etc.)
    pass

def update_security_dashboard(data):
    """Update your website's security dashboard."""
    # Your dashboard update logic here
    pass
```

### Real-time Attack Stream
```javascript
// JavaScript for real-time attack monitoring on your website
const ws = new WebSocket('ws://your-cerberusmesh-server:3000/ws');

ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    
    if (data.type === 'attack_detected') {
        // Update your website's security dashboard
        updateSecurityDashboard(data);
        
        // Show notification to admin users
        showSecurityAlert(data);
        
        // Log to browser console for debugging
        console.log('Attack detected:', data);
    }
};

function updateSecurityDashboard(attackData) {
    // Update attack counter
    document.getElementById('attack-count').textContent = attackData.total_attacks;
    
    // Add to attack timeline
    addToTimeline(attackData);
    
    // Update threat level indicator
    updateThreatLevel(attackData.threat_score);
}
```

---

## 📋 **COMPLETE ENVIRONMENT FILE**

Create `.env` file in your project root:

```bash
# === REQUIRED CREDENTIALS ===

# AWS Configuration (REQUIRED)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# OpenAI API (REQUIRED for AI Agent)
OPENAI_API_KEY=sk-...

# === OPTIONAL ENTERPRISE INTEGRATIONS ===

# Splunk SIEM Integration
SPLUNK_HEC_URL=https://your-splunk.com:8088/services/collector
SPLUNK_HEC_TOKEN=your-hec-token
SPLUNK_INDEX=cerberusmesh
SPLUNK_VERIFY_SSL=true

# Nessus Vulnerability Scanner
NESSUS_SERVER_URL=https://your-nessus.com:8834
NESSUS_ACCESS_KEY=your-access-key
NESSUS_SECRET_KEY=your-secret-key
NESSUS_VERIFY_SSL=true

# Database Configuration (Choose one)
DB_TYPE=postgresql
DB_HOST=your-postgres-host.com
DB_PORT=5432
DB_NAME=cerberusmesh
DB_USER=cerberus
DB_PASSWORD=secure_database_password
DB_SSL_ENABLED=true

# === WEBSITE INTEGRATION ===

# Webhook for your website
WEBHOOK_URL=https://your-website.com/api/attack-webhook
WEBHOOK_SECRET=your-webhook-secret-key
WEBHOOK_TIMEOUT=30

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_KEY=your-api-key-for-external-access

# === MONITORING & SECURITY ===

# Grafana UI Dashboard
GRAFANA_UI_HOST=0.0.0.0
GRAFANA_UI_PORT=3000
GRAFANA_UI_THEME=dark
GRAFANA_UI_ENABLE_WEBSOCKET=true

# Security Settings
ENCRYPTION_KEY=your-32-character-encryption-key
JWT_SECRET=your-jwt-secret-key
API_RATE_LIMIT=1000
ENABLE_AUDIT_LOGGING=true

# Monitoring
LOG_LEVEL=INFO
METRICS_ENABLED=true
HEALTH_CHECK_INTERVAL=60

# === HONEYPOT CONFIGURATION ===

# Deployment Settings
HONEYPOT_COUNT=3
HONEYPOT_REGIONS=us-east-1,us-west-2,eu-west-1
HONEYPOT_INSTANCE_TYPE=t3.micro
HONEYPOT_AMI_ID=ami-0c02fb55956c7d316

# Attack Simulation
ENABLE_ATTACK_SIMULATION=true
SIMULATION_FREQUENCY=3600
SIMULATION_INTENSITY=medium

# Data Retention
DATA_RETENTION_DAYS=90
BACKUP_ENABLED=true
BACKUP_INTERVAL=daily
```

---

## 🏗️ **INFRASTRUCTURE SETUP**

### AWS Infrastructure Requirements
```bash
# 1. IAM User with these policies:
# - EC2FullAccess
# - SSMFullAccess
# - IAMReadOnlyAccess

# 2. VPC & Security Groups (auto-created)
# - Default VPC or custom VPC
# - Security groups for SSH (22) and honeypot services

# 3. EC2 Key Pairs (auto-created)
# - SSH keys for honeypot access

# 4. Systems Manager (for secure parameter storage)
# - API keys stored in Parameter Store
```

### Domain & SSL Setup (Optional)
```bash
# If you want custom domains for honeypots
export HONEYPOT_DOMAIN="honeypot.your-domain.com"
export SSL_CERTIFICATE_ARN="arn:aws:acm:region:account:certificate/..."
```

---

## 🔧 **TESTING YOUR SETUP**

### 1. Test AWS Connection
```bash
python -c "
import boto3
ec2 = boto3.client('ec2')
print('AWS Connection:', ec2.describe_regions()['Regions'][0]['RegionName'])
"
```

### 2. Test OpenAI API
```bash
python -c "
import openai
openai.api_key = 'your-openai-key'
print('OpenAI Connection: OK')
"
```

### 3. Test Webhook
```bash
curl -X POST https://your-website.com/api/attack-webhook \
  -H "Content-Type: application/json" \
  -H "X-Signature: test-signature" \
  -d '{"test": "webhook"}'
```

### 4. Launch Test Honeypot
```bash
python controller/main.py --test-deploy --count 1
```

---

## 🎯 **ATTACK MONITORING FOR YOUR WEBSITE**

### Real-time Attack Data Structure
```json
{
  "event_id": "attack-001",
  "timestamp": "2025-08-12T10:30:00Z",
  "source_ip": "192.168.1.100",
  "attack_type": "ssh_brute_force",
  "target_honeypot": "honeypot-us-east-1a",
  "credentials_attempted": ["admin:password", "root:123456"],
  "commands_executed": ["whoami", "ls -la", "cat /etc/passwd"],
  "threat_score": 0.85,
  "mitre_techniques": ["T1110", "T1078"],
  "geolocation": {
    "country": "Unknown",
    "city": "Unknown",
    "lat": 0.0,
    "lon": 0.0
  },
  "agent_decision": {
    "action": "escalate_monitoring",
    "confidence": 0.92,
    "reasoning": "High-confidence credential attack with privilege escalation attempts"
  }
}
```

### Website Integration Code
```python
# Add this to your website's security monitoring
class CerberusMeshIntegration:
    def __init__(self, webhook_url, api_key):
        self.webhook_url = webhook_url
        self.api_key = api_key
        
    def process_attack_data(self, attack_data):
        """Process incoming attack data from CerberusMesh."""
        
        # 1. Log to your security database
        self.log_attack(attack_data)
        
        # 2. Check if attack targets your website
        if self.is_targeting_website(attack_data):
            self.alert_security_team(attack_data)
            
        # 3. Update threat intelligence
        self.update_threat_intel(attack_data)
        
        # 4. Adjust security policies
        self.adjust_security_policies(attack_data)
    
    def log_attack(self, data):
        """Log attack to your website's security log."""
        # Your database logging logic
        pass
        
    def is_targeting_website(self, data):
        """Check if attack patterns match your website."""
        # Your pattern matching logic
        return data.get('target_type') == 'web_application'
        
    def alert_security_team(self, data):
        """Send immediate alert to security team."""
        # Your alerting logic (email, Slack, PagerDuty)
        pass
```

---

## 🚨 **SECURITY BEST PRACTICES**

### 1. API Key Security
```bash
# Never commit API keys to git
echo ".env" >> .gitignore

# Use AWS Parameter Store for production
aws ssm put-parameter --name "/cerberusmesh/openai-key" --value "sk-..." --type "SecureString"

# Rotate keys regularly
# Set up automated key rotation in AWS IAM
```

### 2. Network Security
```bash
# Restrict API access by IP
export ALLOWED_IPS="192.168.1.0/24,10.0.0.0/8"

# Use VPN for management access
export VPN_SUBNET="172.16.0.0/16"

# Enable AWS CloudTrail for audit logging
```

### 3. Data Protection
```bash
# Encrypt data at rest
export ENCRYPTION_AT_REST=true

# Use TLS for all communications
export FORCE_TLS=true

# Anonymize sensitive data
export ANONYMIZE_IPS=true
```

---

## 📊 **MONITORING YOUR DEPLOYMENT**

### Health Check Endpoints
```bash
# CerberusMesh health
curl http://your-server:8000/health

# Grafana dashboard
curl http://your-server:3000/api/health

# Database connection
curl http://your-server:8000/api/db-health
```

### Log Monitoring
```bash
# Monitor CerberusMesh logs
tail -f /var/log/cerberusmesh/cerberus.log

# Monitor honeypot logs
tail -f /opt/cowrie/var/log/cowrie/cowrie.json

# Monitor system logs
tail -f /var/log/syslog
```

---

## 🎉 **FINAL CHECKLIST**

✅ **AWS credentials configured**  
✅ **OpenAI API key added**  
✅ **Webhook endpoint created on your website**  
✅ **Database connection tested**  
✅ **Honeypots deployed and running**  
✅ **AI agent monitoring attacks**  
✅ **Dashboard accessible**  
✅ **Website integration active**  
✅ **Security policies configured**  
✅ **Monitoring and alerting setup**  

---

## 🔥 **YOU'RE READY TO DEFEND!**

Your CerberusMesh installation is now monitoring for attacks and will send real-time alerts to your website whenever threats are detected. The AI agent will automatically analyze attack patterns and provide intelligent threat assessments to help protect your infrastructure.

**Dashboard URL:** `http://your-server:3000`  
**API Endpoint:** `http://your-server:8000`  
**Webhook:** `https://your-website.com/api/attack-webhook`

**Next Steps:**
1. Monitor the dashboard for incoming attacks
2. Review webhook data on your website
3. Customize alert thresholds based on your needs
4. Scale honeypots based on attack volume
5. Integrate with your existing security tools
