# Shipper agent configs

Fill in `api_key` after running `deploy/register-sensors.sh`. Set `CENTRAL_URL` to your own
platform; use HTTPS in production and leave `verify_tls: true`.

## Log-tail sensors

For sensors that write a JSON-lines event log.

```yaml
central_url: "https://your-central-platform/api/v1"
api_key: "lsk_REPLACE_WITH_SENSOR_01_KEY"
logs_path: "/opt/honeypot/logs/events.log"   # wherever this sensor writes JSON-lines
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper.checkpoint"
buffer_path: "/var/lib/trapline/shipper.buffer.jsonl"
verify_tls: true
```

Install on the sensor host:

```bash
CENTRAL_URL=https://your-central-platform/api/v1 \
API_KEY=lsk_<SENSOR_01_KEY> \
LOGS_PATH=/opt/honeypot/logs/events.log \
bash install-log-shipper.sh
```

Repeat per sensor, using that sensor's own key from registration.

## PostgreSQL-backed sensors

For sensors whose honeypot writes events straight into Postgres.

```yaml
central_url: "https://your-central-platform/api/v1"
api_key: "lsk_REPLACE_WITH_SENSOR_03_KEY"
database_url: "postgresql://USER:PASS@localhost:5432/trapline"
start_from: "now"
batch_interval_seconds: 45
max_batch: 500
checkpoint_path: "/var/lib/trapline/shipper_pg.checkpoint"
buffer_path: "/var/lib/trapline/shipper_pg.buffer.jsonl"
verify_tls: true
```

Install on the sensor host:

```bash
CENTRAL_URL=https://your-central-platform/api/v1 \
API_KEY=lsk_<SENSOR_03_KEY> \
DATABASE_URL=postgresql://... \
bash install-pg-shipper.sh
```

Each shipper runs as a **systemd service** (`Restart=always`) and ships new events on the configured
interval.
