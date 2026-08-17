# Trapline // Shipper Agent

The edge component. One instance runs on **each honeypot sensor** and pushes that
sensor's events to the central platform.

> **Two variants, pick by how the sensor stores events:**
> - [`shipper.py`](./shipper.py) — **log-tail**, for sensors that write a JSON-lines
>   event log. Config: [`config.example.yaml`](./config.example.yaml),
>   service: `trapline-shipper.service`.
> - [`shipper_pg.py`](./shipper_pg.py) — **PostgreSQL reader**, for sensors whose
>   honeypot writes rows into an `events` table. Config:
>   [`config.postgres.example.yaml`](./config.postgres.example.yaml),
>   service: `trapline-shipper-pg.service`.

> **Push, don't pull. Normalize at the edge.** The agent is the only thing that
> knows a sensor's local quirks; central storage only ever sees canonical events.

## Expected input format

The log-tail shipper reads **one JSON object per line**. Lines may be wrapped in a
logrus-style envelope, in which case the event is unwrapped from the `event` key:

```json
{"event": { ... }, "level": "info", "msg": "New Event"}
```

Fields read from each event, all optional except a source address:

| Input field | Canonical field | Notes |
|---|---|---|
| `SourceIp` | `src_ip` | Required. An event without one is skipped as non-attack traffic |
| `SourcePort` | kept in `raw_payload` | |
| `Protocol` | `protocol` | `ssh`, `http`, `telnet`, `ftp`, `smtp`, `tcp` |
| `DateTime` | `occurred_at` | ISO-8601 |
| `User` | `username_tried` | |
| `Password` | `password_tried` | |
| `Description` | `event_type` | Free text, normalised against a controlled vocabulary |
| `ID` | `event_uuid` | Used directly when present; otherwise a deterministic UUID is derived from the line |
| everything else | `raw_payload` | Nothing is discarded |

`Description` is free text and varies by emulated service, so the agent maps it to a
small controlled vocabulary (`ssh_login_attempt`, `http_scan`, `telnet_login_attempt`,
`ftp_login_attempt`, `smtp_probe`, `tcp_connect`) and keeps the original string in
`raw_payload`.

Any honeypot that can emit this shape works. Nothing in the platform is tied to a
particular engine.

## What the log-tail shipper does

1. Tails the sensor's JSON-lines log from a saved **inode plus byte-offset**
   checkpoint, so restarts and log rotation cause neither duplicates nor gaps.
2. Maps each event into the canonical schema above and derives a stable
   `event_uuid`.
3. POSTs batches to `POST /api/v1/events` with the per-sensor bearer key.
4. **Buffers to local disk** and retries with exponential backoff when central is
   unreachable, then flushes on recovery, so nothing is lost.
5. Heartbeats `POST /api/v1/vps/heartbeat` between batches, which drives the
   online/stale/offline indicator on the dashboard.

`country_code` is deliberately left to the **central GeoIP enrichment** worker, so the
agent stays a dependency-light log reader.

## Install (systemd)

```bash
sudo useradd -r -s /usr/sbin/nologin trapline
sudo mkdir -p /opt/trapline-shipper /etc/trapline /var/lib/trapline
sudo cp shipper.py /opt/trapline-shipper/
python3 -m venv /opt/trapline-shipper/.venv
/opt/trapline-shipper/.venv/bin/pip install -r requirements.txt

sudo cp config.example.yaml /etc/trapline/config.yaml
sudo nano /etc/trapline/config.yaml     # set central_url, api_key, logs_path

sudo cp trapline-shipper.service /etc/systemd/system/
sudo chown -R trapline:trapline /opt/trapline-shipper /var/lib/trapline
sudo systemctl daemon-reload
sudo systemctl enable --now trapline-shipper
sudo journalctl -u trapline-shipper -f
```

## Quick local test

```bash
pip install -r requirements.txt
python shipper.py --config config.yaml
```

## Alternative: message-queue ingestion

For near-real-time ingestion the agent can be skipped entirely if your sensor can
publish events to a broker directly. Point each sensor's tracing output at a central
AMQP broker and run a consumer on the platform. Trade-off: needs outbound AMQP from
every sensor plus broker infrastructure centrally. The log-tail agent is the simpler
starting point.
