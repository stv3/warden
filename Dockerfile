# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install build deps in a separate layer for better caching
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Create non-root user
RUN groupadd -r warden && useradd -r -g warden -s /sbin/nologin warden

WORKDIR /app

# Copy only installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=warden:warden . .

# Remove dev files that should not be in the image
RUN rm -f .env bandit_results.json semgrep_results.json zap_report.xml zap_report.json

USER warden

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
