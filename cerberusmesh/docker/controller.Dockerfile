# Controller Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies including AWS CLI
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY controller/ ./controller/
COPY shared/ ./shared/

# Create data directory
RUN mkdir -p /app/data

# Run the controller
CMD ["python", "-m", "controller.main"]
