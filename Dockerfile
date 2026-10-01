# syntax=docker/dockerfile:1

# Stage 1: Front-end vendor assets compilation (Bootstrap 5)
FROM node:20-slim AS assets
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY scripts/copy_bootstrap.mjs ./scripts/
RUN node scripts/copy_bootstrap.mjs

# Stage 2: SecureHire Python Runtime
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

# Copy application source code
COPY . .

# Copy Bootstrap vendor assets from Stage 1 into the application's static directory
COPY --from=assets /build/app/static/vendor/bootstrap ./app/static/vendor/bootstrap

# Install the package in editable mode
RUN pip install --no-deps -e .

# Make entrypoint executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["flask", "--app", "run_local:app", "run", "--host=0.0.0.0", "--port=5000"]
