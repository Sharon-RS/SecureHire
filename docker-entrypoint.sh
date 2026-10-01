#!/bin/sh
set -e

echo "=== SecureHire Docker Entrypoint ==="

# Wait for database readiness if DATABASE_URL points to MySQL
if [ -n "$DATABASE_URL" ]; then
    echo "Waiting for database readiness..."
    python - <<'EOF'
import os
import sys
import time
from urllib.parse import urlparse
import pymysql

url = os.getenv("DATABASE_URL", "")
if not url.startswith("mysql"):
    sys.exit(0)

clean = url.replace("mysql+pymysql://", "http://").replace("mysql://", "http://")
parsed = urlparse(clean)
host = parsed.hostname or "127.0.0.1"
port = parsed.port or 3306
user = parsed.username or "root"
password = parsed.password or ""
database = parsed.path.lstrip("/")

for attempt in range(1, 31):
    try:
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            connect_timeout=3,
        )
        conn.close()
        print(f"Connected to MySQL database '{database}' on {host}:{port}.")
        sys.exit(0)
    except Exception as exc:
        print(f"Attempt {attempt}/30: Database not ready ({exc}). Retrying in 2s...")
        time.sleep(2)

print("Error: Timed out waiting for database readiness.", file=sys.stderr)
sys.exit(1)
EOF
fi

# Run database schema migrations
echo "Applying database migrations..."
flask db upgrade

# Seed synthetic demo data if enabled
if [ "$SEED_DEMO" = "true" ]; then
    echo "Seeding synthetic demo accounts and marketplace records..."
    python scripts/seed_demo.py || echo "Seed completed or records already exist."
fi

echo "=== Starting SecureHire Application ==="
exec "$@"
