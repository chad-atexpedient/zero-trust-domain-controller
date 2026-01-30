FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    cargo \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN groupadd -r ztdc && useradd -r -g ztdc -u 1000 ztdc

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=ztdc:ztdc . /app/

# Create necessary directories
RUN mkdir -p /app/certs /app/logs /app/config && \
    chown -R ztdc:ztdc /app

# Switch to non-root user
USER ztdc

# Expose ports
EXPOSE 8443 9443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || exit 1

# Start application
CMD ["python", "main.py"]