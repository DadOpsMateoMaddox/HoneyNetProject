# CerberusMesh Agent

The CerberusMesh Agent is an intelligent AI-powered watchdog that monitors honeypot intrusions and makes autonomous defensive decisions using MITRE ATT&CK mapping and GPT-4 analysis.

## Features

### 🔍 **Event Monitoring**
- **Real-time intrusion detection** from multiple honeypot sources
- **Cowrie SSH honeypot integration** with JSON log parsing
- **AWS CloudWatch integration** for infrastructure monitoring
- **Multi-protocol support** (SSH, Telnet, HTTP, etc.)

### 🧠 **AI-Powered Analysis**
- **MITRE ATT&CK mapping** for attack pattern recognition
- **GPT-4 behavioral analysis** with threat scoring
- **Machine learning correlation** with existing attack patterns
- **Confidence-based decision making**

### ⚡ **Autonomous Actions**
- **SSH key rotation** for compromised credentials
- **Decoy honeypot deployment** for attack redirection
- **Session trap insertion** with deceptive content
- **Threat escalation** to security teams
- **Enhanced monitoring** for persistent threats

### 📊 **Monitoring & Metrics**
- **Real-time dashboard** integration
- **Performance metrics** tracking
- **Decision history** and audit trail
- **Cache-based optimization** with Redis

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Event Sources │    │  MITRE Mapper   │    │    GPT-4 LLM    │
│                 │    │                 │    │                 │
│  • Cowrie Logs  │    │  • ATT&CK DB    │    │  • Behavioral   │
│  • CloudWatch   │────▶  • Technique    │────▶    Analysis     │
│  • Controller   │    │    Mapping      │    │  • Threat Score │
│  • Custom APIs  │    │  • Kill Chain   │    │  • Recommendations│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Cerberus Agent Core                         │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │   Event     │  │  Decision   │  │   Action    │            │
│  │  Monitor    │──▶   Engine    │──▶  Executor   │            │
│  │             │  │             │  │             │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Redis Cache    │    │   Controller    │    │   Dashboard     │
│                 │    │                 │    │                 │
│  • Event Cache  │    │  • SSH Keys     │    │  • Metrics      │
│  • Decisions    │    │  • Honeypots    │    │  • Alerts       │
│  • Metrics      │    │  • Infrastructure│    │  • Status       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Configuration

### Environment Variables

```bash
# Required API Keys
OPENAI_API_KEY=your_openai_api_key_here
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key

# Optional Configuration
CERBERUS_LLM_MODEL=gpt-4
CERBERUS_LLM_TEMP=0.2
CERBERUS_THRESHOLD=0.7
CERBERUS_AUTO_ACTION=true
CERBERUS_MAX_EVENTS=100

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=1

# AWS Configuration
AWS_DEFAULT_REGION=us-east-1
```

### Configuration File

See `config.ini` for detailed configuration options:

- **Agent behavior** (thresholds, auto-actions)
- **LLM settings** (model, temperature, timeouts)
- **AWS integration** (region, instance limits)
- **Monitoring sources** (log paths, event types)
- **Security policies** (escalation rules, rotation)

## Usage

### Standalone Execution

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY="your_key_here"
export AWS_ACCESS_KEY_ID="your_aws_key"
export AWS_SECRET_ACCESS_KEY="your_aws_secret"

# Run the agent
python cerberus_agent.py
```

### Docker Deployment

```bash
# Build the container
docker build -t cerberusmesh-agent .

# Run with environment file
docker run -d \
  --name cerberus-agent \
  --env-file .env \
  -v /opt/cowrie/var/log:/opt/cowrie/var/log:ro \
  -p 8001:8001 \
  cerberusmesh-agent
```

### Docker Compose Integration

```yaml
services:
  cerberus-agent:
    build: ./agent
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - REDIS_HOST=redis
    depends_on:
      - redis
    volumes:
      - /opt/cowrie/var/log:/opt/cowrie/var/log:ro
    networks:
      - cerberusmesh
```

## Event Processing Flow

### 1. **Event Detection**
```python
# Multiple event sources monitored
- Cowrie SSH honeypot JSON logs
- AWS CloudWatch infrastructure logs  
- Controller instance notifications
- Custom API endpoints
```

### 2. **MITRE Enrichment**
```python
# Attack pattern mapping
event → mitre_mapper.map_attack_pattern() → AttackMapping
- Technique identification (T1078, T1110, etc.)
- Kill chain phase mapping
- Confidence scoring
```

### 3. **LLM Analysis**
```python
# GPT-4 behavioral analysis
mitre_context + event_data → llm_analyze() → ThreatContext
- Threat scoring (0.0 - 1.0)
- Behavioral pattern detection
- Attack sophistication assessment
- Recommended actions
```

### 4. **Decision Making**
```python
# Autonomous decision engine
threat_context → decision_engine() → AgentDecision
- Confidence-based thresholds
- Pattern-based rules
- LLM recommendation integration
```

### 5. **Action Execution**
```python
# Automated defensive actions
decision → action_executor() → execution_result
- SSH key rotation
- Decoy honeypot deployment
- Session trap insertion
- Threat escalation
```

## Decision Types

| Decision Type | Trigger Conditions | Actions Taken |
|---------------|-------------------|---------------|
| **monitor** | Low threat score (<0.6) | Enhanced logging, no action |
| **rotate_key** | Credential attacks detected | Generate new SSH keypair |
| **launch_decoy** | Attack escalation patterns | Deploy additional honeypot |
| **insert_trap** | Command injection/RCE | Add deceptive session content |
| **escalate** | Critical threats (>0.9) | Alert security team, lock down |

## MITRE ATT&CK Integration

### Supported Techniques

| Phase | Techniques | Detection Method |
|-------|------------|------------------|
| **Initial Access** | T1078 (Valid Accounts) | Login pattern analysis |
| **Execution** | T1059 (Command Execution) | Command monitoring |
| **Persistence** | T1053 (Scheduled Tasks) | File system monitoring |
| **Discovery** | T1083 (File Discovery) | Access pattern analysis |
| **Collection** | T1005 (Data Collection) | Data access monitoring |

### Kill Chain Mapping

```python
# Automatic kill chain phase detection
reconnaissance → initial_access → execution → persistence → escalation
```

## Threat Analysis

### LLM Prompt Engineering

The agent uses carefully crafted prompts for GPT-4 analysis:

```
Analyze this honeypot intrusion event:

EVENT DETAILS:
- Source IP, timestamps, protocols
- Commands, credentials, session data
- MITRE ATT&CK context

ANALYSIS REQUIREMENTS:
- Threat scoring (0.0-1.0)
- Attack sophistication assessment
- Behavioral pattern identification  
- Recommended defensive actions
```

### Response Format

```json
{
  "threat_score": 0.85,
  "severity": "high", 
  "behavioral_patterns": ["credential_stuffing", "lateral_movement"],
  "attack_sophistication": "automated_with_human_oversight",
  "recommended_action": "rotate_key",
  "confidence": 0.92,
  "reasoning": "Detailed analysis...",
  "indicators_of_compromise": ["192.168.1.100", "malicious_script.sh"]
}
```

## Performance Metrics

### Real-time Monitoring

- **Events processed per minute**
- **Decision latency** (ms)
- **Action success rate** (%)
- **False positive rate** (%)
- **Cache hit ratio** (%)

### Historical Analysis

- **Attack pattern trends**
- **Decision effectiveness**
- **Response time optimization**
- **Resource utilization**

## API Endpoints

The agent exposes monitoring endpoints:

```bash
GET /health                    # Health check
GET /status                    # Agent status
GET /metrics                   # Performance metrics
GET /decisions?limit=10        # Recent decisions
GET /events?limit=100          # Recent events
POST /config                   # Update configuration
```

## Security Considerations

### Access Control
- **API key encryption** in environment
- **AWS IAM roles** for minimal permissions
- **Redis authentication** for cache access
- **Network isolation** for containers

### Operational Security
- **Decision audit trails** for compliance
- **Encrypted cache storage** for sensitive data
- **Rate limiting** for LLM API calls
- **Fail-safe defaults** when services unavailable

## Troubleshooting

### Common Issues

1. **LLM API Failures**
   ```bash
   # Check API key and quota
   export OPENAI_API_KEY="valid_key"
   # Monitor rate limits in logs
   ```

2. **AWS Permission Errors**
   ```bash
   # Verify IAM permissions
   aws sts get-caller-identity
   # Check EC2 describe permissions
   ```

3. **Redis Connection Issues**
   ```bash
   # Test Redis connectivity
   redis-cli -h localhost -p 6379 ping
   # Check network configuration
   ```

4. **Cowrie Log Access**
   ```bash
   # Verify log file permissions
   ls -la /opt/cowrie/var/log/cowrie/
   # Check volume mounts in Docker
   ```

### Debug Mode

```bash
# Enable debug logging
export CERBERUS_LOG_LEVEL=DEBUG

# Run with verbose output
python cerberus_agent.py --debug --dry-run
```

## Integration Examples

### Custom Event Sources

```python
# Add custom event monitoring
async def check_custom_source(self):
    # Your custom event detection logic
    events = parse_custom_logs()
    for event in events:
        await self.event_queue.put(event)
```

### Custom Decision Actions

```python
# Add custom response actions  
async def custom_action(self, decision):
    # Your custom defensive action
    result = execute_custom_response(decision)
    return f"Custom action executed: {result}"
```

## Development

### Code Style
- **Black formatting** for consistent style
- **Type hints** for better maintainability  
- **Async/await** for concurrent processing
- **Structured logging** for observability

### Testing

```bash
# Run unit tests
pytest tests/

# Run integration tests
pytest tests/integration/

# Run with coverage
pytest --cov=cerberus_agent tests/
```

### Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

This project is part of the CerberusMesh honeypot platform and follows the same licensing terms.

---

**⚠️ Security Notice**: This agent makes autonomous decisions that can affect infrastructure. Always test in a safe environment before production deployment.
