#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] applying schema + optional seed..."
python -m app.seed

echo "[entrypoint] starting uvicorn..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers
