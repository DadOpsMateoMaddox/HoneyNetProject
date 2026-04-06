# CerberusMesh

A distributed honeypot mesh and AI-assisted deception platform built on AWS. CerberusMesh deploys Cowrie SSH honeypots across EC2 instances, enriches captured sessions with MITRE ATT&CK context, and uses an LLM-backed agent to make real-time decisions about attacker engagement and threat classification.

This tool intentionally avoids abstraction beyond its specific use case to preserve clarity and correctness.

---

## Architecture

```
Attacker
   |
Cowrie SSH Honeypot (EC2)
   |
Engagement Engine (traps/engage.py)     <-- session monitoring, tripwires
   |
Cerberus Agent (agent/cerberus_agent.py) <-- MITRE enrichment, GPT-4 analysis
   |
Controller (controller/main.py)          <-- EC2 lifecycle, keypair, SG management
```

The agent runs on a polling loop: pulls intrusion events from Redis, maps them to ATT&CK techniques via `mitreattack-python`, and sends structured prompts to OpenAI to decide whether to engage, escalate, or log. Engagement responses are injected back into active Cowrie sessions via the session monitor.

---

## Components

- `cerberusmesh/agent/` -- AI watchdog agent. Polls for intrusion events, enriches with MITRE context, calls GPT-4 for triage decisions.
- `cerberusmesh/controller/` -- EC2 lifecycle management. Handles instance creation, SSH keypair setup, security group config, and Cowrie deployment.
- `cerberusmesh/traps/` -- Cowrie integration hooks. `engage.py` monitors active sessions; `chatbot.py` handles persona responses; `tripwire.py` handles detection triggers.
- `cerberusmesh/integrations/` -- External service hooks (GreyNoise, AbuseIPDB, Shodan enrichment).
- `cerberusmesh/dashboard/` -- Streamlit/Dash UI for session monitoring.

---

## Requirements

Python 3.10+, AWS credentials with EC2/SSM access, Redis instance, OpenAI API key.

```bash
pip install -r cerberusmesh/requirements.txt
```

Key dependencies: `boto3`, `openai`, `mitreattack-python`, `paramiko`, `redis`, `scikit-learn`.

---

## Setup

```bash
cp cerberusmesh/env_template.txt cerberusmesh/.env
# Fill in: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, OPENAI_API_KEY, REDIS_URL

# Deploy a honeypot instance
python cerberusmesh/controller/main.py --deploy

# Start the agent
python cerberusmesh/agent/cerberus_agent.py --config cerberusmesh/agent/config.ini
```

The controller provisions a `t3.micro` running Amazon Linux 2, installs Cowrie, and registers the instance for agent monitoring. The agent begins polling once the honeypot reports its first session.

---

## Limitations

- Tested against real SSH brute-force and credential-stuffing sessions observed on personal AWS infrastructure. Behavior against more sophisticated adversaries is not characterized.
- GPT-4 decision latency (~1-3s) means engagement responses lag behind fast automated sessions. Works better for interactive attackers.
- Redis is required for agent-to-trap coordination -- no fallback for local-only deployments.
- EC2 costs are real. A single `t3.micro` honeypot runs ~$8-10/month. The controller has no auto-teardown on idle.

---

## Related Work

- `patriot-pot-aws-honeypot` -- earlier single-node SSH honeypot with attacker behavior research writeup
- `HONEYBOMBCERBERUS` -- Cerberus-1 training data, IOC samples, and OSINT enrichment config used to train the agent's threat tagging logic

