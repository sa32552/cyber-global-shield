# =============================================================================
# Stage 1: Build dependencies
# =============================================================================
FROM python:3.11-slim AS builder

LABEL maintainer="Cyber Global Shield Team"
LABEL description="Cyber Global Shield - Autonomous Agentic SIEM Platform"

# Install build dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only requirements first for better layer caching
COPY requirements.txt .

# Install dependencies into a virtual environment
RUN python -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir debugpy  # Optional: for debugging

# =============================================================================
# Stage 2: Runtime image (slim)
# =============================================================================
FROM python:3.11-slim AS runtime

LABEL maintainer="Cyber Global Shield Team"
LABEL description="Cyber Global Shield - Autonomous Agentic SIEM Platform"
LABEL version="2.0.0"

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copy application code (with proper ownership)
COPY --chown=65534:65534 . .

# Create non-root user (using nobody:nogroup for minimal footprint)
USER 65534:65534

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Use exec form for proper signal handling
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--limit-concurrency", "1000"]
