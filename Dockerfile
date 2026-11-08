# NexoraAI V14.2 Cloud Commercial Service — Production Dockerfile
# Zero heavy dependencies: Runs pure Python 3 stdlib under 50 MB RAM for free-tier hosting.
FROM python:3.11-slim

# Create dedicated non-root service user
RUN groupadd -g 1001 nexora && \
    useradd -u 1001 -g nexora -m -s /bin/bash nexora

WORKDIR /app

# Copy commercial platform application
COPY --chown=nexora:nexora commercial_platform /app/commercial_platform

# Ensure data and backup directories exist with write permissions
RUN mkdir -p /app/data /app/commercial_platform/backups && \
    chown -R nexora:nexora /app

USER nexora

# Standard environment defaults
ENV PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080 \
    NEXORA_DB_PATH=/app/data/nexora_commercial_v14_1.sqlite3 \
    PYTHONPATH=/app

EXPOSE 8080

# Built-in lightweight health check (zero curl dependency)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)" || exit 1

ENTRYPOINT ["python3", "/app/commercial_platform/api/wsgi_production_server.py"]
