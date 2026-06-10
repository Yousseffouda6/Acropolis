# Acropolis Notes - container image for the Phase 1 vulnerable app.
# Multi-arch friendly (works natively on arm64 / Apple Silicon).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Patch base-image OS packages before anything else so known-fixed CVEs
# (e.g. CVE-2026-45447 in openssl/libssl3t64) are resolved at build time.
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first to keep this layer cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code, templates and static assets.
COPY . .

# Drop to a non-root user — gives the process the minimum privilege it needs.
# chown first so the user can create the SQLite database at runtime.
RUN adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

# Seed the SQLite database, then start the app.
CMD ["sh", "-c", "python db.py && python app.py"]
