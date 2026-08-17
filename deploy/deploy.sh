#!/usr/bin/env bash
# Full production deploy: Docker stack + nginx reverse proxy on this C2 host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PUBLIC_IP="${PUBLIC_IP:-$(curl -4 -sf ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')}"
HTTP_PORT="${HTTP_PORT:-80}"

echo "==> Trapline C2 deploy (public: http://${PUBLIC_IP}:${HTTP_PORT})"

# Install Docker if missing
if ! command -v docker &>/dev/null; then
  echo "==> Installing Docker..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq docker.io docker-compose-v2
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER" 2>/dev/null || true
fi

# Create .env if absent
if [[ ! -f .env ]]; then
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  cat > .env <<EOF
POSTGRES_USER=trapline
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
POSTGRES_DB=trapline
SECRET_KEY=${SECRET}
FERNET_KEY=
SEED_ON_START=false
CORS_ORIGINS=http://${PUBLIC_IP},http://localhost
HTTP_PORT=${HTTP_PORT}
NEXT_PUBLIC_API_BASE=http://${PUBLIC_IP}/api/v1
EOF
  echo "==> Created .env (SECRET_KEY generated)"
else
  echo "==> Using existing .env"
fi

echo "==> Building and starting stack (db + api + dashboard + nginx)..."
sudo docker compose up --build -d

echo "==> Waiting for API health..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${HTTP_PORT}/api/v1/health" >/dev/null 2>&1; then
    echo "==> API is healthy"
    break
  fi
  sleep 3
done

curl -sf "http://127.0.0.1:${HTTP_PORT}/api/v1/health" | python3 -m json.tool || {
  echo "ERROR: API did not become healthy. Check: sudo docker compose logs"
  exit 1
}

echo
echo "=========================================="
echo "  Dashboard : http://${PUBLIC_IP}/"
echo "  API docs  : http://${PUBLIC_IP}/docs"
echo "  Ingestion : http://${PUBLIC_IP}/api/v1/events"
echo "=========================================="
echo
echo "Next: register SENSOR-01/SENSOR-02/SENSOR-03 sensors:"
echo "  CENTRAL=http://${PUBLIC_IP}/api/v1 bash deploy/register-sensors.sh"
echo
echo "Then deploy shipper agents ON each honeypot VPS:"
echo "  SENSOR-01/SENSOR-02: deploy/agents/install-log-shipper.sh"
echo "  SENSOR-03:     deploy/agents/install-pg-shipper.sh"
