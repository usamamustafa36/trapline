#!/usr/bin/env bash
# Install shipper agent on a file-based honeypot VPS (SENSOR-01 or SENSOR-02).
# Run ON the honeypot box as root:
#   CENTRAL_URL=http://13.140.175.16/api/v1 API_KEY=lsk_... LOGS_PATH=/path/to/Myfile.log bash install-log-shipper.sh
set -euo pipefail

CENTRAL_URL="${CENTRAL_URL:?Set CENTRAL_URL (e.g. http://13.140.175.16/api/v1)}"
API_KEY="${API_KEY:?Set API_KEY from central sensor registration}"
LOGS_PATH="${LOGS_PATH:-/opt/honeypot/logs/events.log}"
VERIFY_TLS="${VERIFY_TLS:-false}"

echo "==> Installing Trapline log-tail shipper"

id trapline &>/dev/null || useradd -r -s /usr/sbin/nologin trapline
mkdir -p /opt/trapline-shipper /etc/trapline /var/lib/trapline

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/../../agent/shipper.py" /opt/trapline-shipper/
python3 -m venv /opt/trapline-shipper/.venv
/opt/trapline-shipper/.venv/bin/pip install -q requests PyYAML

cat > /etc/trapline/config.yaml <<EOF
central_url: "$CENTRAL_URL"
api_key: "$API_KEY"
logs_path: "$LOGS_PATH"
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper.checkpoint"
buffer_path: "/var/lib/trapline/shipper.buffer.jsonl"
verify_tls: $VERIFY_TLS
EOF

cp "$SCRIPT_DIR/../../agent/trapline-shipper.service" /etc/systemd/system/
chown -R trapline:trapline /var/lib/trapline /opt/trapline-shipper

systemctl daemon-reload
systemctl enable --now trapline-shipper
systemctl status trapline-shipper --no-pager

echo "==> Shipper running. Tailing $LOGS_PATH → $CENTRAL_URL"
