# ML Engine Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ml/ ./ml/
COPY shared/ ./shared/

# Create data directory
RUN mkdir -p /app/data

# Run the ML engine
CMD ["python", "-m", "ml.anomaly", "monitor"]
