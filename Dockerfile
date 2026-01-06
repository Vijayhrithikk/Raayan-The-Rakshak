FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Scapy and ML
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    g++ \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

# Set working directory to backend for uvicorn
WORKDIR /app/backend

# Environment variables
ENV PYTHONPATH=/app/backend

# Expose API port
EXPOSE 8000

# Start server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
