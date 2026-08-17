#!/usr/bin/env bash
# Register SENSOR-01, SENSOR-02, and SENSOR-03 honeypot sensors on the central C2 platform.
# Run once after the stack is up. Prints per-node API keys for shipper agents.
set -euo pipefail

CENTRAL="${CENTRAL:-http://localhost/api/v1}"
SECRET_KEY="${SECRET_KEY:-change-me-in-prod-please-0000000000000000}"
export SECRET_KEY
ADMIN="$(python3 -c "import hashlib, os; print(hashlib.sha256(f\"admin:{os.environ['SECRET_KEY']}\".encode()).hexdigest())")"

echo "==> Registering sensors at $CENTRAL"

register() {
  local alias="$1" name="$2" url="$3" stack="$4"
  echo "--- $alias ---"
  curl -sf -X POST "$CENTRAL/vps/register" \
    -H "Authorization: Bearer $ADMIN" \
    -H "Content-Type: application/json" \
    -d "{\"alias\":\"$alias\",\"display_name\":\"$name\",\"base_url\":\"$url\",\"stack_type\":\"$stack\"}" \
    | python3 -m json.tool
  echo
}

register "SENSOR-01" "Sensor 01"  "http://192.0.2.11:9999/"            "html_fastapi"
register "SENSOR-02" "Sensor 02"  "http://198.51.100.22:9999/"         "html_fastapi"
register "SENSOR-03" "Sensor 03"  "http://203.0.113.33:9999/dashboard" "react_pg"

echo "==> Done. Copy each api_key into the matching shipper config on that VPS."
echo "    See deploy/agents/ for ready-to-edit config templates."
