#!/usr/bin/env python3
"""
Trapline // Shipper Agent — PostgreSQL source

For sensors whose honeypot writes events straight into PostgreSQL (`events`
table, plus an enriched `attacker_ips` table) rather than to a log file. This
agent reads NEW rows from `events` since a saved checkpoint (the monotonic
`created_at` insert time), normalizes them into the central canonical schema,
and POSTs batches to the central ingestion API with the sensor's bearer key.

Buffers to disk + retries with backoff when central is unreachable; the central
endpoint is idempotent (dedupes on event_uuid), so overlap on restart is safe.

  pip install requests psycopg2-binary pyyaml
  python shipper_pg.py --config config.postgres.yaml
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras
import requests
import yaml

log = logging.getLogger("shipper-pg")

TYPE_MAP = {"ssh": "ssh_login_attempt", "http": "http_scan", "telnet": "telnet_login_attempt",
            "ftp": "ftp_login_attempt", "smtp": "smtp_probe", "tcp": "tcp_connect"}
DEFAULT_PORT = {"ssh": 22, "http": 80, "https": 443, "telnet": 23, "ftp": 21, "smtp": 25}


def normalize_type(protocol, description) -> str:
    hay = f"{protocol or ''} {description or ''}".lower()
    for key, canon in TYPE_MAP.items():
        if key in hay:
            return canon
    return (protocol or "unknown").lower() + "_event"


def stable_uuid(event_id, raw: dict) -> str:
    if event_id:
        try:
            return str(uuid.UUID(str(event_id)))
        except ValueError:
            return str(uuid.uuid5(uuid.NAMESPACE_URL, str(event_id)))
    return str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(raw, sort_keys=True, default=str)))


def severity(protocol, text) -> int:
    t = (text or "").lower()
    if any(x in t for x in (".env", "eval-stdin", "shell", "wget", "upload", "gponform")):
        return 3
    return 1


def map_row(row: dict) -> dict:
    raw = row.get("raw") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = {"_raw": raw}
    protocol = (row.get("protocol") or "").lower() or None
    dt = row.get("datetime")
    occurred = dt.astimezone(timezone.utc).isoformat() if isinstance(dt, datetime) else str(dt)
    descriptor = row.get("description") or row.get("request_uri") or row.get("command")
    sev_text = " ".join(str(row.get(k) or "") for k in ("description", "command", "request_uri", "body"))
    return {
        "event_uuid": stable_uuid(row.get("event_id"), raw),
        "occurred_at": occurred,
        "src_ip": row.get("source_ip"),
        "dst_port": DEFAULT_PORT.get(protocol),
        "protocol": protocol,
        "event_type": normalize_type(protocol, row.get("description")),
        "severity": severity(protocol, sev_text),
        "username_tried": row.get("user_name") or None,
        "password_tried": row.get("password") or None,
        "payload_excerpt": descriptor or None,
        # country_code omitted → central GeoIP enrichment (Phase 2).
        "raw": raw,
    }


class Checkpoint:
    """Persists the last-shipped events.created_at (ISO) across restarts."""

    def __init__(self, path: str, start_from: str):
        self.path = Path(path)
        self.cursor: str | None = None
        self._load(start_from)

    def _load(self, start_from: str) -> None:
        if self.path.exists():
            try:
                self.cursor = json.loads(self.path.read_text()).get("created_at")
                return
            except (json.JSONDecodeError, OSError):
                pass
        if start_from.lower() == "beginning":
            self.cursor = "1970-01-01T00:00:00+00:00"
        elif start_from.lower() == "now":
            self.cursor = datetime.now(timezone.utc).isoformat()
        else:
            self.cursor = start_from  # explicit ISO timestamp

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"created_at": self.cursor}))
        tmp.replace(self.path)


QUERY = """
    SELECT event_id, datetime, host(source_ip) AS source_ip, source_port, protocol,
           status, description, command, command_output, user_name, password,
           http_method, request_uri, user_agent, raw, created_at
    FROM events
    WHERE created_at > %s
    ORDER BY created_at ASC
    LIMIT %s
"""


class PgShipper:
    def __init__(self, cfg: dict):
        self.central = cfg["central_url"].rstrip("/")
        self.api_key = cfg["api_key"]
        self.dsn = cfg["database_url"]
        self.interval = int(cfg.get("batch_interval_seconds", 45))
        self.batch_cap = int(cfg.get("max_batch", 500))
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self.ckpt = Checkpoint(cfg.get("checkpoint_path", "shipper_pg.checkpoint"),
                               str(cfg.get("start_from", "now")))
        self.buffer_path = Path(cfg.get("buffer_path", "shipper_pg.buffer.jsonl"))
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self.conn = None
        self.running = True

    def _db(self):
        if self.conn is None or self.conn.closed:
            self.conn = psycopg2.connect(self.dsn)
            self.conn.autocommit = True
        return self.conn

    def fetch_new(self) -> list[dict]:
        with self._db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(QUERY, (self.ckpt.cursor, self.batch_cap))
            rows = cur.fetchall()
        if not rows:
            return []
        events = [map_row(dict(r)) for r in rows]
        # advance checkpoint to newest created_at in the batch
        newest = rows[-1]["created_at"]
        self._pending_cursor = (
            newest.astimezone(timezone.utc).isoformat() if isinstance(newest, datetime) else str(newest)
        )
        return events

    # ── shipping (mirrors the log shipper) ─────────────────────────────────
    def flush_buffer(self):
        if not self.buffer_path.exists():
            return
        pending = [json.loads(l) for l in self.buffer_path.read_text().splitlines() if l.strip()]
        if pending and self.post(pending, from_buffer=True):
            self.buffer_path.unlink(missing_ok=True)
            log.info("flushed %d buffered events", len(pending))

    def buffer(self, events: list[dict]):
        with self.buffer_path.open("a", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        log.warning("buffered %d events to disk (central unreachable)", len(events))

    def post(self, events: list[dict], from_buffer: bool = False) -> bool:
        for attempt in range(4):
            try:
                r = self.session.post(f"{self.central}/events", json={"events": events},
                                      timeout=20, verify=self.verify_tls)
                if r.status_code in (200, 202):
                    body = r.json()
                    log.info("shipped %d (accepted=%s dup=%s)", len(events),
                             body.get("accepted"), body.get("duplicates"))
                    return True
                if r.status_code == 429:
                    time.sleep(2 ** attempt)
                    continue
                log.error("central rejected batch: %s %s", r.status_code, r.text[:200])
                return False
            except requests.RequestException as exc:
                log.warning("post failed (attempt %d): %s", attempt + 1, exc)
                time.sleep(min(2 ** attempt, 10))
        if not from_buffer:
            self.buffer(events)
        return False

    def heartbeat(self):
        try:
            self.session.post(f"{self.central}/vps/heartbeat", timeout=10, verify=self.verify_tls)
        except requests.RequestException:
            pass

    def run(self):
        log.info("pg shipper online → %s (interval %ds, from %s)",
                 self.central, self.interval, self.ckpt.cursor)
        while self.running:
            try:
                self.flush_buffer()
                self._pending_cursor = None
                events = self.fetch_new()
                if events:
                    if self.post(events):
                        if self._pending_cursor:
                            self.ckpt.cursor = self._pending_cursor
                        self.ckpt.save()
                else:
                    self.heartbeat()
            except Exception:
                log.exception("cycle error")
                self.conn = None  # force reconnect next cycle
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)
        log.info("pg shipper shutting down")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="Trapline PostgreSQL shipper agent")
    ap.add_argument("--config", default="config.postgres.yaml")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
    if not os.path.exists(args.config):
        log.error("config not found: %s (copy config.postgres.example.yaml)", args.config)
        sys.exit(1)
    cfg = yaml.safe_load(Path(args.config).read_text())
    shipper = PgShipper(cfg)
    signal.signal(signal.SIGINT, shipper.stop)
    signal.signal(signal.SIGTERM, shipper.stop)
    shipper.run()


if __name__ == "__main__":
    main()
