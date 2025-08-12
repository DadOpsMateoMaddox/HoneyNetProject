# CVSS Scorer Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY gpt_cvss/ ./gpt_cvss/
COPY shared/ ./shared/

# Create data directory
RUN mkdir -p /app/data

# Run the CVSS scorer
CMD ["python", "-m", "gpt_cvss.score", "monitor"]
