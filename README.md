# 🔥 CerberusMesh HoneyNet Project 

## Because Sometimes You Gotta Fight Fire With Fire

[![GitHub last commit](https://img.shields.io/github/last-commit/DadOpsMateoMaddox/HoneyNetProject)](https://github.com/DadOpsMateoMaddox/HoneyNetProject)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-EC2%20%7C%20SSM-orange.svg)](https://aws.amazon.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-green.svg)](https://openai.com/)

*Listen up, cyber warriors. This ain't your grandpa's honeypot. CerberusMesh is a next-level AI-powered deception platform that doesn't just catch attackers - it learns from them, adapts to them, and serves them a taste of their own medicine.*

**⚠️ FAIR WARNING: This is NOT a beginner project.** If you're new to cybersecurity, cloud infrastructure, or Python development, maybe start with something simpler. This is enterprise-grade cyber warfare tech that requires serious knowledge and responsibility.

---

## 🎯 What The Hell Is This Thing?

CerberusMesh is an advanced honeypot network that:

- **🤖 AI-Powered Defense**: GPT-4 analyzes attack patterns in real-time and makes intelligent decisions
- **🕸️ Distributed Honeypots**: Deploys multiple honeypots across AWS regions to catch attackers
- **🔍 Threat Intelligence**: Correlates attacks with vulnerability scans and SIEM data
- **⚡ Real-Time Response**: Automatically adapts defenses based on attack patterns
- **🌐 Enterprise Integration**: Hooks into Splunk, Nessus, databases, and your website
- **📊 Grafana-Style UI**: Beautiful dashboards for monitoring the chaos

This isn't just a honeypot. It's a full cyber deception ecosystem that fights back intelligently.

---

## 🚨 Prerequisites (Read This Or Suffer Later)

### For Advanced Users (Recommended Path)
You should already know:
- ✅ Python 3.8+ development
- ✅ AWS EC2, VPC, IAM concepts
- ✅ Basic cybersecurity principles
- ✅ Docker and containerization
- ✅ SIEM tools (Splunk preferred)
- ✅ Database administration
- ✅ Network security fundamentals

### For Brave Beginners (Proceed With Caution)
If you're determined to try this anyway:
- 📚 **Study first**: Learn Python, AWS basics, and cybersecurity fundamentals
- 💰 **Budget warning**: AWS costs money. Start small or you'll get a nasty bill
- ⏰ **Time investment**: Expect 20+ hours to fully understand and deploy
- 🆘 **Get help**: Have experienced friends or mentors available

---

## 🔧 System Requirements

### Hardware/Cloud
- **AWS Account** with billing set up (you'll spend $20-100/month minimum)
- **Local Machine**: 8GB+ RAM, 50GB+ disk space
- **Network**: Stable internet connection

### Software Dependencies
```bash
# Core Requirements
Python 3.8+
AWS CLI v2
Git
Docker (optional but recommended)

# Python Packages (installed automatically)
boto3>=1.26.0
openai>=0.27.0
fastapi>=0.95.0
uvicorn>=0.20.0
aiohttp>=3.8.0
redis>=4.5.0
psycopg2-binary>=2.9.0  # PostgreSQL
aiomysql>=0.1.1         # MySQL
aiosqlite>=0.19.0       # SQLite
```

---

## 🗝️ API Keys You'll Need

### REQUIRED (Don't Even Think About Starting Without These)

#### 1. AWS Credentials
```bash
# Get from: AWS IAM Console
AWS_ACCESS_KEY_ID="AKIA..."
AWS_SECRET_ACCESS_KEY="..."
AWS_DEFAULT_REGION="us-east-1"

# Required IAM Permissions:
# - EC2FullAccess
# - SSMFullAccess  
# - IAMReadOnlyAccess
```

#### 2. OpenAI API Key
```bash
# Get from: https://platform.openai.com/account/api-keys
OPENAI_API_KEY="sk-..."

# Cost Warning: Expect $10-50/month depending on usage
```

### OPTIONAL (Enterprise Features)

#### 3. Splunk Integration
```bash
# Get from: Splunk Web UI > Settings > Data Inputs > HTTP Event Collector
SPLUNK_HEC_URL="https://your-splunk.com:8088/services/collector"
SPLUNK_HEC_TOKEN="your-token"
```

#### 4. Nessus Vulnerability Scanner
```bash
# Get from: Nessus Web UI > Settings > API Keys
NESSUS_SERVER_URL="https://your-nessus.com:8834"
NESSUS_ACCESS_KEY="your-key"
NESSUS_SECRET_KEY="your-secret"
```

#### 5. Database (Choose Your Poison)
```bash
# PostgreSQL (Recommended)
DB_TYPE="postgresql"
DB_HOST="your-postgres.com"
DB_USER="cerberus"
DB_PASSWORD="complex_password"

# MySQL/MariaDB (Alternative)
DB_TYPE="mysql"

# SQLite (Development Only)
DB_TYPE="sqlite"
```

---

## 🚀 Installation Guide

### Quick Start (For The Impatient)
```bash
# Clone the repo
git clone https://github.com/DadOpsMateoMaddox/HoneyNetProject.git
cd HoneyNetProject/cerberusmesh

# Run the magic setup script
python quick_start.py

# Follow the prompts and pray to the cyber gods
```

### Manual Installation (For Control Freaks)

#### Step 1: Clone and Setup Environment
```bash
git clone https://github.com/DadOpsMateoMaddox/HoneyNetProject.git
cd HoneyNetProject/cerberusmesh

# Create virtual environment (because dependency hell is real)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Step 2: Configure API Keys
```bash
# Copy the template
cp env_template.txt .env

# Edit with your keys (use nano, vim, or whatever doesn't make you cry)
nano .env

# CRITICAL: Never commit this file to git
echo ".env" >> .gitignore
```

#### Step 3: AWS Setup
```bash
# Configure AWS CLI
aws configure

# Test connection (should show your account info)
aws sts get-caller-identity

# Initialize infrastructure
python controller/main.py --init
```

#### Step 4: Deploy Honeypots
```bash
# Deploy 3 honeypots across 2 regions (adjust for your budget)
python controller/main.py --deploy --count 3 --regions us-east-1,us-west-2

# Check deployment status
python controller/main.py --status
```

#### Step 5: Start The AI Beast
```bash
# Start the AI agent (this is where the magic happens)
python agent/cerberus_agent.py --config agent/config.ini

# Start the dashboard
python integrations/grafana_ui.py --port 3000

# Start API server
python api/server.py --port 8000
```

---

## 🎮 Usage Guide

### Dashboard Access
- **Main Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

### Monitoring Attacks
```bash
# Watch live attack logs
tail -f controller.log

# Check honeypot status
python controller/main.py --status

# View AI agent decisions
tail -f agent/decisions.log
```

### Integrate With Your Website
```python
# Add this webhook to your site to receive attack alerts
@app.route('/api/attack-webhook', methods=['POST'])
def handle_attack_alert():
    attack_data = request.json
    
    print(f"🚨 ATTACK DETECTED!")
    print(f"Source: {attack_data['source_ip']}")
    print(f"Type: {attack_data['attack_type']}")
    print(f"Threat Score: {attack_data['threat_score']}")
    
    # Your security response logic here
    alert_security_team(attack_data)
    
    return jsonify({'status': 'received'})
```

---

## 🏗️ Architecture Overview

```
                    🌐 Internet (Attackers)
                           |
                    ┌─────────────┐
                    │   AWS ALB   │
                    └─────────────┘
                           |
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────────┐       ┌────────┐       ┌────────┐
    │Honeypot│       │Honeypot│       │Honeypot│
    │   #1   │       │   #2   │       │   #3   │
    │(SSH/Web)│      │(Telnet)│       │ (FTP)  │
    └────────┘       └────────┘       └────────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
                    ┌─────────────┐
                    │ AI Agent    │
                    │ (GPT-4)     │
                    └─────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────────┐       ┌────────┐       ┌────────┐
    │ Splunk │       │Database│       │Your Web│
    │  SIEM  │       │ (PSQL) │       │  Site  │
    └────────┘       └────────┘       └────────┘
```

### Component Breakdown

#### 🕸️ Honeypot Network
- **Cowrie SSH/Telnet Honeypots**: Simulate vulnerable Linux servers
- **Web Application Honeypots**: Fake login portals and admin panels
- **Service Emulation**: FTP, SMTP, MySQL, and other common services
- **Geographic Distribution**: Multiple AWS regions for global coverage

#### 🤖 AI Agent (The Brain)
- **Real-Time Analysis**: GPT-4 powered threat assessment
- **Decision Engine**: Autonomous response to attack patterns
- **Learning System**: Adapts tactics based on attacker behavior
- **MITRE ATT&CK Mapping**: Categorizes attacks using industry standards

#### 🔌 Enterprise Integrations
- **Splunk SIEM**: Real-time event forwarding with custom SPL queries
- **Nessus Vulnerability Scanner**: Correlates attacks with known vulnerabilities
- **Multi-Database Support**: PostgreSQL, MySQL, or SQLite storage
- **Grafana Dashboard**: Beautiful real-time visualization

#### 🌐 Website Integration
- **Webhook Alerts**: Real-time attack notifications to your site
- **REST API**: Programmatic access to threat data
- **WebSocket Streaming**: Live attack feeds for dashboards

---

## 🔒 Security Considerations

### 🚨 CRITICAL WARNINGS

#### Legal Compliance
- **Know Your Laws**: Honeypots may be illegal in some jurisdictions
- **Data Privacy**: You'll collect attacker data - handle it responsibly
- **Attribution**: Never use collected data to hack back - that's illegal
- **Logging**: Maintain detailed logs for legal compliance

#### Operational Security
- **Network Isolation**: Keep honeypots separated from production systems
- **Access Control**: Limit who can access the management interface
- **Key Rotation**: Regularly rotate all API keys and credentials
- **Monitoring**: Watch for signs of compromise on your infrastructure

#### AWS Security
- **IAM Policies**: Use least-privilege access principles
- **VPC Configuration**: Properly segment honeypot networks
- **Security Groups**: Restrict access to management interfaces
- **CloudTrail**: Enable audit logging for all AWS actions

### 🛡️ Best Practices

#### Deployment Security
```bash
# Use strong passwords everywhere
export DB_PASSWORD=$(openssl rand -base64 32)

# Enable encryption at rest
export ENCRYPTION_ENABLED=true

# Use private subnets for sensitive components
export USE_PRIVATE_SUBNETS=true

# Enable comprehensive logging
export AUDIT_LOGGING=true
```

#### Monitoring and Alerting
```bash
# Set up alerts for unusual activity
export ALERT_THRESHOLD=0.8

# Monitor AWS costs (honeypots can get expensive)
aws budgets create-budget --account-id $(aws sts get-caller-identity --query Account --output text) \
  --budget '{
    "BudgetName": "CerberusMesh-Monthly",
    "BudgetLimit": {"Amount": "100", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST"
  }'

# Set up CloudWatch alarms
aws cloudwatch put-metric-alarm \
  --alarm-name "CerberusMesh-HighCosts" \
  --alarm-description "Alert when costs exceed $50" \
  --metric-name "EstimatedCharges" \
  --namespace "AWS/Billing" \
  --statistic "Maximum" \
  --period 86400 \
  --threshold 50 \
  --comparison-operator "GreaterThanThreshold"
```

---

## 🎯 Configuration Examples

### Basic Configuration (.env)
```bash
# === REQUIRED ===
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
OPENAI_API_KEY=sk-...

# === WEBSITE INTEGRATION ===
WEBHOOK_URL=https://yoursite.com/api/attack-webhook
WEBHOOK_SECRET=your-secure-secret

# === HONEYPOT SETTINGS ===
HONEYPOT_COUNT=3
HONEYPOT_REGIONS=us-east-1,us-west-2
HONEYPOT_INSTANCE_TYPE=t3.micro

# === MONITORING ===
GRAFANA_UI_PORT=3000
API_PORT=8000
LOG_LEVEL=INFO
```

### Advanced Configuration
```bash
# === ENTERPRISE INTEGRATIONS ===
SPLUNK_HEC_URL=https://splunk.company.com:8088/services/collector
SPLUNK_HEC_TOKEN=your-hec-token
NESSUS_SERVER_URL=https://nessus.company.com:8834
NESSUS_ACCESS_KEY=your-access-key

# === DATABASE ===
DB_TYPE=postgresql
DB_HOST=postgres.company.com
DB_NAME=cerberusmesh
DB_USER=cerberus
DB_PASSWORD=super-secure-password

# === SECURITY ===
ENCRYPTION_KEY=your-32-char-encryption-key
JWT_SECRET=your-jwt-secret
API_RATE_LIMIT=1000
ENABLE_AUDIT_LOGGING=true

# === PERFORMANCE ===
MAX_CONCURRENT_ANALYSES=10
CACHE_TTL=3600
BATCH_SIZE=100
```

---

## 📊 Monitoring and Analytics

### Built-in Dashboards

#### Attack Overview Dashboard
- **Real-time Attack Counter**: Live count of ongoing attacks
- **Geographic Heat Map**: Where attacks are coming from
- **Attack Type Distribution**: SSH vs Web vs Other protocols
- **Threat Score Timeline**: Risk assessment over time

#### AI Agent Performance
- **Decision Accuracy**: How well the AI is performing
- **Response Times**: Speed of threat analysis
- **Confidence Scores**: AI certainty in decisions
- **Learning Progress**: Adaptation over time

#### System Health
- **Honeypot Status**: Which traps are online
- **Resource Usage**: CPU, memory, network utilization
- **Error Rates**: System reliability metrics
- **Cost Tracking**: AWS spending breakdown

### Custom Alerts

#### High-Severity Threats
```python
# Alert when threat score exceeds 0.8
if threat_score > 0.8:
    send_immediate_alert({
        'level': 'CRITICAL',
        'message': f'High-threat attack detected from {source_ip}',
        'threat_score': threat_score,
        'recommended_action': 'Investigate immediately'
    })
```

#### Cost Monitoring
```python
# Alert when daily AWS costs exceed budget
if daily_cost > budget_limit:
    send_budget_alert({
        'current_cost': daily_cost,
        'budget_limit': budget_limit,
        'recommendation': 'Consider scaling down honeypots'
    })
```

---

## 🧪 Testing Your Setup

### Smoke Tests
```bash
# Test AWS connectivity
python -c "import boto3; print('AWS OK:', boto3.client('ec2').describe_regions()['Regions'][0]['RegionName'])"

# Test OpenAI API
python -c "import openai; print('OpenAI OK')"

# Test database connection
python controller/main.py --test-db

# Test honeypot deployment
python controller/main.py --test-deploy --count 1
```

### Attack Simulation
```bash
# Generate fake attacks for testing
python tests/simulate_attacks.py --target honeypot-ip --attack-type ssh_brute_force

# Test AI agent responses
python tests/test_agent_decisions.py

# Validate webhook delivery
curl -X POST http://localhost:8000/test-webhook \
  -H "Content-Type: application/json" \
  -d '{"test": "attack", "source_ip": "192.168.1.100"}'
```

### Performance Testing
```bash
# Load test the API
python tests/load_test.py --concurrent 50 --duration 300

# Test database performance
python tests/db_stress_test.py --operations 10000

# Monitor resource usage
htop  # or your favorite system monitor
```

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### "AWS Credentials Not Found"
```bash
# Check AWS configuration
aws configure list

# Verify credentials work
aws sts get-caller-identity

# If using environment variables, check they're set
echo $AWS_ACCESS_KEY_ID
```

#### "OpenAI API Rate Limit Exceeded"
```bash
# Check your usage at: https://platform.openai.com/usage
# Reduce AI agent frequency in config:
echo "decision_threshold = 0.8" >> agent/config.ini
echo "max_events_per_minute = 50" >> agent/config.ini
```

#### "Honeypot Deployment Failed"
```bash
# Check AWS service limits
aws service-quotas get-service-quota \
  --service-code ec2 \
  --quota-code L-1216C47A  # Running On-Demand t3.micro instances

# Verify VPC has available subnets
aws ec2 describe-subnets --filters "Name=state,Values=available"

# Check security group rules
aws ec2 describe-security-groups --group-names cerberusmesh-sg
```

#### "Database Connection Failed"
```bash
# Test database connectivity
python -c "
import psycopg2
conn = psycopg2.connect(
    host='your-host',
    database='cerberusmesh',
    user='cerberus',
    password='your-password'
)
print('Database OK')
"
```

#### "Dashboard Won't Load"
```bash
# Check if services are running
ps aux | grep python
netstat -tlnp | grep :3000

# Check firewall rules
sudo ufw status  # Ubuntu
# or
sudo firewall-cmd --list-all  # CentOS/RHEL

# Check logs for errors
tail -f grafana.log
```

### Performance Issues

#### High AWS Costs
```bash
# Check instance usage
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,InstanceType]'

# Stop unused instances
python controller/main.py --stop-all

# Use smaller instance types
export HONEYPOT_INSTANCE_TYPE=t3.nano  # Cheapest option
```

#### Slow AI Responses
```bash
# Reduce AI model complexity
export OPENAI_MODEL=gpt-3.5-turbo  # Faster than GPT-4

# Increase decision threshold
export DECISION_THRESHOLD=0.8  # Only analyze high-confidence events

# Enable caching
export ENABLE_REDIS_CACHE=true
```

#### Database Performance
```bash
# Add database indexes
python controller/main.py --optimize-db

# Enable connection pooling
export DB_POOL_SIZE=20

# Use read replicas for analytics
export DB_READ_REPLICA_HOST=your-replica-host
```

---

## 🚀 Advanced Usage

### Custom AI Prompts
```python
# Customize AI decision-making in agent/prompts.py
CUSTOM_ANALYSIS_PROMPT = """
You are a cybersecurity expert analyzing honeypot attacks.
Focus specifically on:
1. Advanced Persistent Threat (APT) indicators
2. Cryptocurrency mining activities  
3. Ransomware deployment patterns
4. Supply chain attack vectors

Your analysis should be paranoid but accurate.
"""
```

### Enterprise Deployment
```bash
# Deploy across multiple AWS accounts
export AWS_PROFILE=production
python controller/main.py --deploy --account production

# Use custom VPCs
export VPC_ID=vpc-12345678
export SUBNET_IDS=subnet-abcd1234,subnet-efgh5678

# Enable high availability
export ENABLE_MULTI_AZ=true
export AUTO_SCALING_ENABLED=true
```

### Integration with Security Tools

#### SOAR Platform Integration
```python
# Phantom/Splunk SOAR integration
def send_to_phantom(attack_data):
    phantom_api.create_artifact({
        'container_id': security_container_id,
        'name': f'CerberusMesh Attack: {attack_data["attack_type"]}',
        'severity': calculate_severity(attack_data['threat_score']),
        'cef': {
            'sourceAddress': attack_data['source_ip'],
            'deviceEventClassId': attack_data['mitre_technique']
        }
    })
```

#### Threat Intelligence Feeds
```python
# VirusTotal integration
def enrich_with_virustotal(ip_address):
    vt_data = virustotal_api.get_ip_report(ip_address)
    return {
        'malicious_score': vt_data['positives'],
        'total_engines': vt_data['total'],
        'reputation': 'malicious' if vt_data['positives'] > 5 else 'clean'
    }
```

---

## 🔄 Maintenance and Updates

### Regular Maintenance Tasks

#### Weekly
```bash
# Update threat intelligence feeds
python maintenance/update_threat_feeds.py

# Rotate honeypot IP addresses
python controller/main.py --rotate-ips

# Clean old log files
find logs/ -name "*.log" -mtime +7 -delete

# Check for security updates
pip list --outdated
```

#### Monthly
```bash
# Rotate AWS access keys
aws iam create-access-key --user-name cerberusmesh-user
# Update .env with new keys
aws iam delete-access-key --access-key-id OLD_KEY --user-name cerberusmesh-user

# Update AI model prompts based on new attack trends
python maintenance/update_ai_prompts.py

# Generate security report
python reports/generate_monthly_report.py
```

#### Quarterly
```bash
# Review and update security groups
python maintenance/audit_security_groups.py

# Analyze cost optimization opportunities
python maintenance/cost_analysis.py

# Update honeypot configurations based on threat landscape
python maintenance/update_honeypot_configs.py
```

### Version Updates
```bash
# Check for updates
git fetch origin
git log HEAD..origin/main --oneline

# Update to latest version
git pull origin main
pip install -r requirements.txt --upgrade

# Run migration scripts if needed
python maintenance/migrate_database.py
```

---

## 📈 Scaling and Optimization

### Horizontal Scaling
```bash
# Add more regions
export HONEYPOT_REGIONS=us-east-1,us-west-2,eu-west-1,ap-southeast-1

# Increase honeypot count
export HONEYPOT_COUNT=10

# Use auto-scaling groups
export ENABLE_AUTO_SCALING=true
export MIN_INSTANCES=3
export MAX_INSTANCES=20
```

### Performance Optimization
```bash
# Enable Redis caching
export REDIS_HOST=your-redis-cluster.cache.amazonaws.com
export CACHE_TTL=3600

# Use database read replicas
export DB_READ_REPLICA_HOST=your-read-replica.rds.amazonaws.com

# Enable CloudFront for dashboard
export CLOUDFRONT_DISTRIBUTION_ID=your-distribution-id
```

### Cost Optimization
```bash
# Use Spot instances for non-critical honeypots
export USE_SPOT_INSTANCES=true
export SPOT_PRICE=0.01

# Schedule honeypots to run only during business hours
export SCHEDULE_ENABLED=true
export SCHEDULE_START="08:00"
export SCHEDULE_STOP="18:00"

# Use Reserved Instances for long-term deployments
aws ec2 purchase-reserved-instances-offering \
  --reserved-instances-offering-id offering-id \
  --instance-count 3
```

---

## 🤝 Contributing

Want to help make CerberusMesh even more badass? Here's how:

### Development Setup
```bash
# Fork the repo and clone your fork
git clone https://github.com/YOUR_USERNAME/HoneyNetProject.git
cd HoneyNetProject

# Create feature branch
git checkout -b feature/your-awesome-feature

# Set up development environment
python -m venv dev-env
source dev-env/bin/activate
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 cerberusmesh/
black cerberusmesh/
```

### Code Style
- **Python**: Follow PEP 8, use Black formatter
- **Documentation**: Write docstrings for all functions
- **Testing**: Add tests for new features
- **Security**: Never commit secrets or credentials

### Contribution Guidelines
1. **Issues First**: Open an issue before starting work
2. **Small PRs**: Keep changes focused and reviewable
3. **Tests Required**: All new features need tests
4. **Documentation**: Update docs for user-facing changes
5. **Security Review**: Security changes get extra scrutiny

---

## 📚 Additional Resources

### Learning Resources
- **Honeypot Theory**: "The Cuckoo's Egg" by Cliff Stoll
- **AI Security**: "Adversarial Machine Learning" by Biggio & Roli
- **AWS Security**: AWS Security Best Practices whitepaper
- **Threat Hunting**: "Threat Hunting" by Bianco et al.
- **Cloud Computing**: [Practice Questions](docs/cloud_computing_practice_questions.md) for cybersecurity professionals

### Related Projects
- **Cowrie**: SSH/Telnet honeypot (used internally)
- **T-Pot**: Multi-honeypot platform
- **MISP**: Threat intelligence sharing platform
- **TheHive**: Security incident response platform

### Community
- **Discord**: [Join our Discord](https://discord.gg/cybersecurity) (fictional link)
- **Reddit**: r/cybersecurity, r/AWSCloud
- **Twitter**: Follow [@DadOpsMateo](https://twitter.com/DadOpsMateo) (fictional)
- **Blog**: [CyberOps Blog](https://blog.dadops.tech) (fictional)

---

## ⚖️ Legal Disclaimer

**READ THIS CAREFULLY OR GET YOURSELF IN TROUBLE**

This software is for **EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**. By using CerberusMesh, you agree to:

1. **Only deploy on infrastructure you own or have explicit permission to use**
2. **Comply with all applicable laws and regulations in your jurisdiction**
3. **Never use collected data for offensive purposes or "hack back"**
4. **Properly secure and anonymize any collected attacker data**
5. **Take responsibility for any costs, damages, or legal issues arising from use**

**THE AUTHORS ARE NOT RESPONSIBLE FOR:**
- Misuse of this software
- Legal consequences of deployment
- AWS bills that make you cry
- Relationship problems caused by obsessing over attack logs
- Loss of sleep from watching real-time attacks

**USE AT YOUR OWN RISK.** If you break something, that's on you.

---

## 📞 Support

### Getting Help

#### Before You Ask
1. **Read this README completely**
2. **Check the troubleshooting section**
3. **Search existing GitHub issues**
4. **Try the basic debugging steps**

#### Support Channels
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and community help
- **Wiki**: Extended documentation and tutorials
- **Email**: security@dadops.tech (for security issues only)

#### What to Include
```
- Operating system and version
- Python version
- Complete error messages
- Relevant log files
- Steps to reproduce the issue
- What you were trying to accomplish
```

### Professional Services
Need help with enterprise deployment? Custom integrations? Training?

Contact: consulting@dadops.tech

We offer:
- **Custom deployment consulting**
- **Enterprise integration development**
- **Security team training**
- **Managed honeypot services**
- **24/7 monitoring and response**

---

## 🎉 Final Words

If you've made it this far, you're either really dedicated or really bored. Either way, you now have the tools to build a badass AI-powered honeypot network that'll make attackers think twice.

Remember:
- **Be responsible** with the data you collect
- **Stay legal** in everything you do
- **Keep learning** as the threat landscape evolves
- **Share knowledge** with the security community
- **Have fun** watching attackers stumble into your traps

Now go forth and deploy some digital karma. The internet needs more people like you fighting the good fight.

**Stay safe out there, cyber warriors.** 🛡️

---

## 📜 License

MIT License - Because sharing is caring, but attribution is required.

See [LICENSE](LICENSE) file for details.

---

*Made with ☕, 🍕, and a healthy dose of paranoia by [@DadOpsMateoMaddox](https://github.com/DadOpsMateoMaddox)*

*"If you're not getting attacked, you're not worth attacking. CerberusMesh makes you worth attacking... safely."*
