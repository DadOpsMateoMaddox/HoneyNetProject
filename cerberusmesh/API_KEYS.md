# CerberusMesh — Required API keys & recommended API Gateway

Quick recommendation

- If you only need lightweight REST endpoints (low cost, low latency) use the HTTP API in API Gateway.
- If you need API Gateway features such as API Keys + Usage Plans, stages with throttling and built‑in API Key management, choose the REST API type.

In short: choose HTTP API for performance; choose REST API if you plan to issue API keys to external clients and use usage plans.

Required environment variables (minimum to run core features)

- OPENAI_API_KEY        # OpenAI API key (needed for GPT/CVSS and AI agents)
- AWS_ACCESS_KEY_ID     # AWS IAM key with least privilege for deployments
- AWS_SECRET_ACCESS_KEY # AWS IAM secret (do NOT paste real secrets into documentation)
- AWS_DEFAULT_REGION    # e.g. us-east-1

Optional integration keys (only if you enable those features)

- SPLUNK_HEC_URL        # Splunk HTTP Event Collector URL
- SPLUNK_HEC_TOKEN      # Splunk HEC token
- NESSUS_SERVER_URL     # Nessus server API URL
- NESSUS_ACCESS_KEY
- NESSUS_SECRET_KEY
- DB_TYPE, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD  # Database credentials (Postgres recommended)
- GRAFANA_UI_HOST / GRAFANA_UI_PORT  # Grafana settings (if provisioning dashboards)
- ENCRYPTION_KEY, JWT_SECRET, API_KEY  # Internal secrets used by the app
- WEBHOOK_URL, WEBHOOK_SECRET  # If you configure external webhook callbacks

If you plan to protect your API endpoints with API Gateway API keys (clients must supply an API key):

- Use the REST API type in the AWS Console (it supports API Keys and Usage Plans more directly)
- Example placeholders to add to `.env` if you want to track them locally:
  - API_GATEWAY_TYPE=REST    # or HTTP
  - API_GATEWAY_ID=your-api-id
  - API_GATEWAY_STAGE=prod
  - API_GATEWAY_APIKEY=replace_with_api_key_for_clients

# Create a local `.env` from these placeholders

- Copy the example below into `cerberusmesh/.env` (do NOT commit real secrets to git):

```env
# Minimal required
OPENAI_API_KEY=sk-REPLACE_WITH_YOUR_KEY
AWS_ACCESS_KEY_ID=AKIAREPLACE
AWS_SECRET_ACCESS_KEY=REPLACE_SECRET
AWS_DEFAULT_REGION=us-east-1

# Optional integrations
SPLUNK_HEC_URL=
SPLUNK_HEC_TOKEN=
NESSUS_SERVER_URL=
NESSUS_ACCESS_KEY=
NESSUS_SECRET_KEY=
DB_TYPE=sqlite
DB_HOST=
DB_PORT=5432
DB_NAME=cerberusmesh
DB_USER=cerberus
DB_PASSWORD=

# API Gateway (optional)
API_GATEWAY_TYPE=HTTP
API_GATEWAY_ID=
API_GATEWAY_STAGE=
API_GATEWAY_APIKEY=

# Internal
ENCRYPTION_KEY=
JWT_SECRET=
API_KEY=
```

Notes & security

- Do not commit `.env` to version control. Add it to `.gitignore` if not already ignored.
- For production, prefer secrets managers (AWS Secrets Manager, Parameter Store, HashiCorp Vault) or Docker/Kubernetes secrets instead of `.env`.
- Use least-privilege AWS credentials and rotate keys regularly.

Where this file came from

- This file was generated from `env_template.txt` in the repository and the project README; it centralizes the API keys you must provide to run CerberusMesh.

