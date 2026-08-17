#!/usr/bin/env bash
# Native deploy without sudo — micromamba provides postgres, nginx, node, python.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

MAMBA="${HOME}/.local/bin/micromamba"
ENV_NAME="trapline"
ENV_PREFIX="${HOME}/.local/share/mamba/envs/${ENV_NAME}"
PUBLIC_IP="${PUBLIC_IP:-$(curl -4 -sf ifconfig.me 2>/dev/null || echo 127.0.0.1)}"
HTTP_PORT="${HTTP_PORT:-8080}"
RUN_DIR="${ROOT}/.run"
LOG_DIR="${ROOT}/.logs"
PGDATA="${RUN_DIR}/pgdata"

mkdir -p "$RUN_DIR" "$LOG_DIR" "$PGDATA"

# ── Install micromamba (user-local) ─────────────────────────────────────────
if [[ ! -x "$MAMBA" ]]; then
  echo "==> Installing micromamba..."
  mkdir -p "${HOME}/.local/bin"
  curl -Ls -o /tmp/micromamba.tar.bz2 https://micro.mamba.pm/api/micromamba/linux-64/latest
  python3 -c "
import tarfile
with tarfile.open('/tmp/micromamba.tar.bz2', 'r:bz2') as tf:
    for m in tf.getmembers():
        if m.name.endswith('bin/micromamba'):
            m.name = 'micromamba'
            tf.extract(m, '${HOME}/.local/bin')
"
  chmod +x "$MAMBA"
fi

export MAMBA_ROOT_PREFIX="${HOME}/.local/share/mamba"

if [[ ! -d "$ENV_PREFIX" ]]; then
  echo "==> Creating conda env (postgres, python, nodejs, nginx)..."
  "$MAMBA" create -y -n "$ENV_NAME" -c conda-forge \
    python=3.12 nodejs=20 postgresql=16 nginx
fi

export PATH="${ENV_PREFIX}/bin:${PATH}"

# ── .env ────────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cat > .env <<EOF
POSTGRES_USER=lure
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
POSTGRES_DB=trapline
SECRET_KEY=${SECRET}
SEED_ON_START=false
CORS_ORIGINS=http://${PUBLIC_IP}:${HTTP_PORT},http://localhost:${HTTP_PORT}
HTTP_PORT=${HTTP_PORT}
NEXT_PUBLIC_API_BASE=http://${PUBLIC_IP}:${HTTP_PORT}/api/v1
EOF
fi
set -a; source .env; set +a

# ── PostgreSQL ──────────────────────────────────────────────────────────────
export PGDATA="$PGDATA"

if [[ ! -f "$PGDATA/PG_VERSION" ]]; then
  echo "==> Initializing PostgreSQL..."
  initdb -D "$PGDATA" -U "$POSTGRES_USER" --auth-local=trust --auth-host=trust
  pg_ctl -D "$PGDATA" -l "$LOG_DIR/postgres.log" start -w -o "-p 5433"
  createdb -p 5433 -U "$POSTGRES_USER" "$POSTGRES_DB" 2>/dev/null || true
else
  pg_ctl -D "$PGDATA" status >/dev/null 2>&1 || \
    pg_ctl -D "$PGDATA" -l "$LOG_DIR/postgres.log" start -w -o "-p 5433"
fi

export DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:5433/${POSTGRES_DB}"

# ── Backend ─────────────────────────────────────────────────────────────────
echo "==> Setting up backend..."
cd "$ROOT/backend"
pip install -q -r requirements.txt
export DATABASE_URL SECRET_KEY SEED_ON_START CORS_ORIGINS
python -m app.seed

if ! pgrep -f "uvicorn app.main:app.*8001" >/dev/null 2>&1; then
  echo "==> Starting API on :8001..."
  cd "$ROOT/backend"
  nohup python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --proxy-headers \
    > "$LOG_DIR/api.log" 2>&1 &
  echo $! > "$RUN_DIR/api.pid"
fi

# ── Frontend ────────────────────────────────────────────────────────────────
cd "$ROOT/frontend"
export NEXT_PUBLIC_API_BASE="http://${PUBLIC_IP}:${HTTP_PORT}/api/v1"
if [[ ! -d node_modules ]]; then npm install --no-audit --no-fund; fi
if [[ ! -f .next/standalone/server.js ]]; then
  NEXT_PUBLIC_API_BASE="$NEXT_PUBLIC_API_BASE" npm run build
  cp -r .next/static .next/standalone/.next/static
  [[ -d public ]] && cp -r public .next/standalone/public
fi

if ! pgrep -f "node server.js" >/dev/null 2>&1; then
  echo "==> Starting dashboard on :3001..."
  cd "$ROOT/frontend/.next/standalone"
  PORT=3001 nohup node server.js > "$LOG_DIR/dashboard.log" 2>&1 &
  echo $! > "$RUN_DIR/dashboard.pid"
fi

# ── Nginx ───────────────────────────────────────────────────────────────────
NGINX_CONF="${RUN_DIR}/nginx.conf"
cat > "$NGINX_CONF" <<EOF
worker_processes 1;
error_log ${LOG_DIR}/nginx-error.log;
pid ${RUN_DIR}/nginx.pid;

events { worker_connections 1024; }

http {
    upstream lure_api { server 127.0.0.1:8001; }
    upstream lure_dashboard { server 127.0.0.1:3001; }

    server {
        listen ${HTTP_PORT};
        server_name _;
        client_max_body_size 10M;

        location /api/ {
            proxy_pass http://lure_api;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
        location /docs {
            proxy_pass http://lure_api;
            proxy_set_header Host \$host;
        }
        location / {
            proxy_pass http://lure_dashboard;
            proxy_http_version 1.1;
            proxy_set_header Host \$host;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
EOF

if [[ -f "$RUN_DIR/nginx.pid" ]] && kill -0 "$(cat "$RUN_DIR/nginx.pid")" 2>/dev/null; then
  nginx -s reload -c "$NGINX_CONF" 2>/dev/null || true
else
  echo "==> Starting nginx on :${HTTP_PORT}..."
  nginx -c "$NGINX_CONF"
fi

sleep 2
curl -sf "http://127.0.0.1:${HTTP_PORT}/api/v1/health" | python3 -m json.tool

echo
echo "=========================================="
echo "  Dashboard : http://${PUBLIC_IP}:${HTTP_PORT}/"
echo "  API docs  : http://${PUBLIC_IP}:${HTTP_PORT}/docs"
echo "  Ingestion : http://${PUBLIC_IP}:${HTTP_PORT}/api/v1/events"
echo "=========================================="
echo
echo "Register sensors:"
echo "  CENTRAL=http://${PUBLIC_IP}:${HTTP_PORT}/api/v1 SECRET_KEY=${SECRET_KEY} bash deploy/register-sensors.sh"
