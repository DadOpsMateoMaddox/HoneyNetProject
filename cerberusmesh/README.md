# CerberusMesh - Advanced Honeypot Orchestration Platform

A multi-service honeypot management platform that automatically deploys, monitors, and responds to threats using ML anomaly detection and GPT-powered CVSS scoring.

## Architecture

```
cerberusmesh/
├── controller/         # Main orchestration service
├── ml/                # ML anomaly detection engine  
├── gpt_cvss/          # GPT-4 powered CVSS scoring
├── dashboard/         # FastAPI backend + React frontend
├── agent/             # AI watchdog agent with autonomous responses
├── infra/             # Terraform infrastructure
├── shared/            # Common utilities and MITRE mapping
└── docker/            # Container configurations
```

## Quick Start

1. **Setup Environment**
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure AWS Credentials**
```bash
aws configure
# OR set environment variables:
# export AWS_ACCESS_KEY_ID=your_key
# export AWS_SECRET_ACCESS_KEY=your_secret
# export AWS_DEFAULT_REGION=us-east-1
```

3. **Set OpenAI API Key** (for CVSS scoring)
```bash
export OPENAI_API_KEY=your_openai_key
```

4. **Deploy Infrastructure**
```bash
cd infra
terraform init
terraform plan
terraform apply
```

5. **Launch Services**
```bash
# Start controller
python controller/main.py

# Start dashboard (separate terminal)
cd dashboard
uvicorn api:app --reload --port 8000

# Start ML engine (separate terminal)  
python ml/anomaly.py

# Start Cerberus Agent (separate terminal)
cd agent
python cerberus_agent.py
```

## Components

### Controller
- **Purpose**: Orchestrates EC2 honeypot instances
- **Key Features**: Launch/terminate instances, SSH key management, security groups
- **Location**: `controller/main.py`

### ML Anomaly Engine
- **Purpose**: Detects unusual patterns in honeypot traffic
- **Algorithm**: Isolation Forest with configurable thresholds
- **Location**: `ml/anomaly.py`

### GPT CVSS Scoring
- **Purpose**: Generates CVSS v3.1 scores using GPT-4
- **Features**: Threat analysis, remediation suggestions
- **Location**: `gpt_cvss/score.py`

### Dashboard
- **Backend**: FastAPI with real-time monitoring endpoints
- **Frontend**: React with real-time honeypot status and attack visualization
- **Location**: `dashboard/`

### Cerberus Agent
- **Purpose**: AI-powered watchdog that monitors events and makes autonomous defensive decisions
- **Features**: MITRE ATT&CK mapping, GPT-4 threat analysis, automated responses (key rotation, decoy deployment)
- **Location**: `agent/cerberus_agent.py`

### Infrastructure
- **Tool**: Terraform
- **Resources**: VPC, subnets, security groups, EC2 instances
- **Location**: `infra/deploy.tf`

## Usage Examples

```python
# Launch honeypot instances
from controller.main import HoneypotController
controller = HoneypotController()
instances = controller.launch_honeypots(count=3)

# Analyze events with ML
from ml.anomaly import AnomalyDetector
detector = AnomalyDetector()
alerts = detector.analyze_events(events)

# Score threats with GPT
from gpt_cvss.score import CVSSScorer
scorer = CVSSScorer()
score = scorer.analyze_ioc("suspicious_ip", "1.2.3.4")
```

## Security Notes
- All instances use non-default SSH keys
- Security groups restrict access to necessary ports only
- Logs are encrypted in transit and at rest
- API keys should be stored in environment variables, never committed

## Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License
MIT License - see LICENSE file for details
