# CerberusMesh Agent Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create directories for logs and cache
RUN mkdir -p /app/logs /app/cache

# Set environment variables
ENV PYTHONPATH=/app
ENV CERBERUS_LOG_LEVEL=INFO
ENV CERBERUS_CACHE_DIR=/app/cache

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health')" || exit 1

# Expose monitoring port
EXPOSE 8001

# Run the agent
CMD ["python", "cerberus_agent.py"]
