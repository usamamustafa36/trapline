#!/usr/bin/env bash
# Install PostgreSQL shipper agent on SENSOR-03 honeypot VPS.
# Run ON the SENSOR-03 box as root:
#   CENTRAL_URL=http://13.140.175.16/api/v1 API_KEY=lsk_... DATABASE_URL=postgresql://... bash install-pg-shipper.sh
set -euo pipefail

CENTRAL_URL="${CENTRAL_URL:?Set CENTRAL_URL (e.g. http://13.140.175.16/api/v1)}"
API_KEY="${API_KEY:?Set API_KEY from central sensor registration}"
DATABASE_URL="${DATABASE_URL:?Set DATABASE_URL (SENSOR-03 honeypot Postgres DSN)}"
VERIFY_TLS="${VERIFY_TLS:-false}"
START_FROM="${START_FROM:-now}"

echo "==> Installing Trapline PostgreSQL shipper (SENSOR-03)"

id trapline &>/dev/null || useradd -r -s /usr/sbin/nologin trapline
mkdir -p /opt/trapline-shipper /etc/trapline /var/lib/trapline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/../../agent/shipper_pg.py" /opt/trapline-shipper/
python3 -m venv /opt/trapline-shipper/.venv
/opt/trapline-shipper/.venv/bin/pip install -q requests PyYAML psycopg2-binary

cat > /etc/trapline/config.postgres.yaml <<EOF
central_url: "$CENTRAL_URL"
api_key: "$API_KEY"
database_url: "$DATABASE_URL"
start_from: "$START_FROM"
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper_pg.checkpoint"
buffer_path: "/var/lib/trapline/shipper_pg.buffer.jsonl"
verify_tls: $VERIFY_TLS
EOF

cp "$SCRIPT_DIR/../../agent/trapline-shipper-pg.service" /etc/systemd/system/
chown -R trapline:trapline /var/lib/trapline /opt/trapline-shipper

systemctl daemon-reload
systemctl enable --now trapline-shipper-pg
systemctl status trapline-shipper-pg --no-pager

echo "==> PostgreSQL shipper running. Reading events table → $CENTRAL_URL"
