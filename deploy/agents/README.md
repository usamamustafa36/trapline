# Shipper agent configs — fill in api_key after running deploy/register-sensors.sh

## SENSOR-01 (log-tail shipper on Jakarta honeypot)

```yaml
central_url: "http://13.140.175.16/api/v1"
api_key: "lsk_REPLACE_WITH_SENSOR_01_KEY"
logs_path: "/opt/honeypot/logs/events.log"   # wherever this sensor writes JSON-lines
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper.checkpoint"
buffer_path: "/var/lib/trapline/shipper.buffer.jsonl"
verify_tls: false
```

Install on SENSOR-01 VPS:
```bash
CENTRAL_URL=http://13.140.175.16/api/v1 \
API_KEY=lsk_<SENSOR_01_KEY> \
LOGS_PATH=/path/to/Myfile.log \
bash install-log-shipper.sh
```

## SENSOR-02 (log-tail shipper on Montréal honeypot)

Same as SENSOR-01 — use the SENSOR-02 api_key from registration.

## SENSOR-03 (PostgreSQL shipper on Karachi honeypot)

```yaml
central_url: "http://13.140.175.16/api/v1"
api_key: "lsk_REPLACE_WITH_SENSOR_03_KEY"
database_url: "postgresql://USER:PASS@localhost:5432/trapline"
start_from: "now"
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper_pg.checkpoint"
buffer_path: "/var/lib/trapline/shipper_pg.buffer.jsonl"
verify_tls: false
```

Install on SENSOR-03 VPS:
```bash
CENTRAL_URL=http://13.140.175.16/api/v1 \
API_KEY=lsk_<SENSOR_03_KEY> \
DATABASE_URL=postgresql://... \
bash install-pg-shipper.sh
```

Each shipper runs as a **systemd service** (`Restart=always`) and continuously tails new attacker IPs/events every 45 seconds.
