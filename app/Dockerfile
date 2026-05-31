# Acropolis Notes - container image for the Phase 1 vulnerable app.
# Multi-arch friendly (works natively on arm64 / Apple Silicon).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first to keep this layer cached across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code, templates and static assets.
COPY . .

EXPOSE 5000

# Seed the SQLite database, then start the app (debug server, by design).
CMD ["sh", "-c", "python db.py && python app.py"]
