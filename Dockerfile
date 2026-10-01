# SecureHire Python Runtime (Single-stage, zero Node.js/npm build dependency)
FROM python:3.12-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_APP=run_local:app

# Install curl for container health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy application source code (including vendored static assets in app/static/vendor/bootstrap)
COPY . .

# Install the package in editable mode
RUN pip install --no-deps -e .

# Make entrypoint executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["flask", "--app", "run_local:app", "run", "--host=0.0.0.0", "--port=5000"]
