FROM python:3.11-slim AS base

LABEL maintainer="Oteria B3 Team"
LABEL description="Orchestrator API - Ransomware Defense System"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Production stage ──
FROM base AS production

COPY orchestrator/ ./orchestrator/

# Non-root user
RUN useradd -m -u 1000 orchestrator && \
    chown -R orchestrator:orchestrator /app
USER orchestrator

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# PAS de --reload en production
CMD ["uvicorn", "orchestrator.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# ── Dev stage ──
FROM base AS development

COPY orchestrator/ ./orchestrator/

CMD ["uvicorn", "orchestrator.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
