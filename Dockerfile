# ──────────────────────────────────────────────────────────────────────────────
# Zero Trust Secure API Gateway — Docker image
# Build:  docker build -t zero-trust-gateway .
# ──────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System packages needed by some wheels (psycopg2, scikit-learn, geoip2, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install -r requirements.txt

# Application code
COPY . .

# Runtime directories (SQLite database + logs)
RUN mkdir -p /app/data /app/logs

# Run as a non-root user (defense in depth: limits impact if the app is compromised)
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser \
    && chown -R appuser:appgroup /app/data /app/logs

# SQLite database persists across container restarts via a named volume
VOLUME /app/data

# Only the gateway is exposed on the host; the mock backend (8001) stays internal.
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)"

USER appuser

# The mock backend (port 8001) runs inside this process — no separate service.
CMD ["uvicorn", "gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
