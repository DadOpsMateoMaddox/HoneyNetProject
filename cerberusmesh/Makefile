# CerberusMesh Makefile - Development and deployment automation

.PHONY: help install dev build deploy clean test lint format docs

# Default target
help:
	@echo "CerberusMesh - Available commands:"
	@echo "  install     - Install dependencies"
	@echo "  dev         - Start development environment"
	@echo "  build       - Build Docker images"
	@echo "  deploy      - Deploy infrastructure with Terraform"
	@echo "  destroy     - Destroy infrastructure"
	@echo "  test        - Run tests"
	@echo "  lint        - Run linting"
	@echo "  format      - Format code"
	@echo "  clean       - Clean up temporary files"
	@echo "  logs        - View application logs"
	@echo "  status      - Check service status"

# Installation
install:
	@echo "Installing CerberusMesh dependencies..."
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	@echo "Dependencies installed successfully!"

# Development
dev:
	@echo "Starting CerberusMesh development environment..."
	docker-compose up --build

dev-detached:
	@echo "Starting CerberusMesh in detached mode..."
	docker-compose up -d --build

stop:
	@echo "Stopping CerberusMesh services..."
	docker-compose down

restart: stop dev-detached

# Building
build:
	@echo "Building CerberusMesh Docker images..."
	docker-compose build

build-no-cache:
	@echo "Building CerberusMesh Docker images (no cache)..."
	docker-compose build --no-cache

# Infrastructure deployment
deploy-check:
	@echo "Checking Terraform configuration..."
	cd infra && terraform fmt -check
	cd infra && terraform validate

deploy-plan:
	@echo "Planning Terraform deployment..."
	cd infra && terraform plan

deploy:
	@echo "Deploying CerberusMesh infrastructure..."
	cd infra && terraform init
	cd infra && terraform plan
	cd infra && terraform apply

deploy-auto:
	@echo "Auto-deploying CerberusMesh infrastructure..."
	cd infra && terraform init
	cd infra && terraform apply -auto-approve

destroy:
	@echo "Destroying CerberusMesh infrastructure..."
	cd infra && terraform destroy

destroy-auto:
	@echo "Auto-destroying CerberusMesh infrastructure..."
	cd infra && terraform destroy -auto-approve

# Testing
test:
	@echo "Running CerberusMesh tests..."
	python -m pytest tests/ -v

test-coverage:
	@echo "Running tests with coverage..."
	python -m pytest tests/ --cov=. --cov-report=html

# Code quality
lint:
	@echo "Running linting checks..."
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

format:
	@echo "Formatting code..."
	black .
	isort .

type-check:
	@echo "Running type checks..."
	mypy controller/ ml/ gpt_cvss/ dashboard/ shared/

# Service management
logs:
	@echo "Viewing CerberusMesh logs..."
	docker-compose logs -f

logs-api:
	@echo "Viewing API logs..."
	docker-compose logs -f dashboard-api

logs-ml:
	@echo "Viewing ML engine logs..."
	docker-compose logs -f ml-engine

logs-controller:
	@echo "Viewing controller logs..."
	docker-compose logs -f controller

status:
	@echo "Checking service status..."
	docker-compose ps

# Honeypot management
launch-honeypots:
	@echo "Launching honeypot instances..."
	python controller/main.py launch --count 2

list-honeypots:
	@echo "Listing honeypot instances..."
	python controller/main.py list

terminate-honeypots:
	@echo "Terminating all honeypots..."
	python controller/main.py cleanup

# ML model management
train-model:
	@echo "Training anomaly detection model..."
	python ml/anomaly.py train --events-file sample_data/events.json

analyze-events:
	@echo "Analyzing events for anomalies..."
	python ml/anomaly.py analyze --events-file sample_data/events.json

# CVSS scoring
score-ioc:
	@echo "Scoring IOC with GPT-4..."
	python gpt_cvss/score.py analyze --ioc-type ip --ioc-value 192.168.1.100

generate-report:
	@echo "Generating CVSS report..."
	python gpt_cvss/score.py report

# Data management
export-data:
	@echo "Exporting attack data..."
	curl -o "attacks_export_$(shell date +%Y%m%d_%H%M%S).json" \
		"http://localhost:8000/api/v1/export/attacks?hours=24"

backup-data:
	@echo "Backing up data volumes..."
	docker-compose exec dashboard-api tar czf /tmp/dashboard_backup.tar.gz /app/data
	docker cp $$(docker-compose ps -q dashboard-api):/tmp/dashboard_backup.tar.gz ./backups/

# Cleanup
clean:
	@echo "Cleaning up temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	docker system prune -f

clean-all: clean
	@echo "Cleaning up Docker images and volumes..."
	docker-compose down -v
	docker system prune -af

# Documentation
docs:
	@echo "Generating documentation..."
	mkdir -p docs/build
	python -m sphinx -b html docs/source docs/build

docs-serve:
	@echo "Serving documentation..."
	cd docs/build && python -m http.server 8080

# Security
security-scan:
	@echo "Running security scans..."
	bandit -r . -x tests/
	safety check

# Monitoring commands
monitor-attacks:
	@echo "Monitoring attacks in real-time..."
	watch -n 5 'curl -s http://localhost:8000/api/v1/statistics | jq'

monitor-honeypots:
	@echo "Monitoring honeypot status..."
	watch -n 10 'curl -s http://localhost:8000/api/v1/status | jq'

# Development utilities
shell-api:
	@echo "Opening shell in API container..."
	docker-compose exec dashboard-api bash

shell-ml:
	@echo "Opening shell in ML container..."
	docker-compose exec ml-engine bash

shell-controller:
	@echo "Opening shell in controller container..."
	docker-compose exec controller bash

# Quick start for new developers
quick-start:
	@echo "Quick start setup for CerberusMesh..."
	@echo "1. Copying environment file..."
	cp .env.example .env
	@echo "2. Building and starting services..."
	make build
	make dev-detached
	@echo "3. Waiting for services to start..."
	sleep 30
	@echo "4. Checking service status..."
	make status
	@echo ""
	@echo "CerberusMesh is now running!"
	@echo "Dashboard API: http://localhost:8000"
	@echo "Grafana: http://localhost:3000 (admin/cerberusmesh)"
	@echo ""
	@echo "Next steps:"
	@echo "- Edit .env with your API keys"
	@echo "- Run 'make deploy' to provision AWS infrastructure"
	@echo "- Run 'make launch-honeypots' to start honeypots"

# Production deployment
prod-deploy:
	@echo "Deploying to production..."
	@echo "WARNING: This will deploy to production environment!"
	@read -p "Are you sure? (y/N): " confirm && [ "$$confirm" = "y" ]
	CERBERUSMESH_ENV=production make deploy-auto

# CI/CD helpers
ci-test:
	@echo "Running CI tests..."
	make lint
	make type-check
	make test
	make security-scan

ci-build:
	@echo "Building for CI..."
	make build-no-cache

# Terraform helpers
tf-init:
	@echo "Initializing Terraform..."
	cd infra && terraform init

tf-plan:
	@echo "Planning Terraform changes..."
	cd infra && terraform plan

tf-apply:
	@echo "Applying Terraform changes..."
	cd infra && terraform apply

tf-output:
	@echo "Showing Terraform outputs..."
	cd infra && terraform output

# AWS helpers
aws-status:
	@echo "Checking AWS resources..."
	aws ec2 describe-instances --filters "Name=tag:Project,Values=CerberusMesh" \
		--query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' \
		--output table

aws-logs:
	@echo "Viewing CloudWatch logs..."
	aws logs describe-log-groups --log-group-name-prefix "/cerberusmesh"
