# SSH Honeypot Dockerfile
# Multi-stage build for security and size optimization

FROM python:3.11-slim as base

# Security: Run as non-root user
RUN groupadd -r honeypot && useradd -r -g honeypot -s /bin/false honeypot

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY honeypot/ /app/honeypot/
COPY ml/ /app/ml/
COPY dashboard/ /app/dashboard/
COPY reports/ /app/reports/
COPY config/ /app/config/

# Create necessary directories
RUN mkdir -p /app/data /app/logs /app/reports /var/log/honeypot && \
    chown -R honeypot:honeypot /app /var/log/honeypot

# Switch to non-root user
USER honeypot

# Environment variables
ENV PYTHONPATH=/app
ENV HONEYPOT_HOST=0.0.0.0
ENV HONEYPOT_PORT=2222
ENV DASHBOARD_HOST=0.0.0.0
ENV DASHBOARD_PORT=8080
ENV HOST_KEY_FILE=/app/config/host_key_rsa
ENV FLASK_SECRET_KEY=change-me-in-production

# Expose ports
EXPOSE 2222 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import socket; socket.socket().connect(('localhost', 2222))" || exit 1

# Default command
CMD ["python", "-m", "honeypot.ssh_server"]
