#!/usr/bin/env python3
"""
Trapline // Shipper Agent  (Option A — log-tail)

Runs on each honeypot sensor. Tails the sensor's JSON-lines event log from a
saved byte-offset/inode checkpoint, normalizes each event into the central
canonical schema, and POSTs batches to the central ingestion API with the
per-sensor bearer key. Buffers to local disk and retries with backoff when central is unreachable,
so nothing is lost across outages or restarts.

  pip install requests pyyaml
  python shipper.py --config config.yaml

Deploy as a systemd service (see trapline-shipper.service).
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

import requests
import yaml

log = logging.getLogger("shipper")

# Free-text service Description → controlled event-type vocabulary.
TYPE_MAP = {"ssh": "ssh_login_attempt", "http": "http_scan", "telnet": "telnet_login_attempt",
            "ftp": "ftp_login_attempt", "smtp": "smtp_probe", "tcp": "tcp_connect"}


def normalize_type(protocol: str | None, description: str | None) -> str:
    hay = f"{protocol or ''} {description or ''}".lower()
    for key, canon in TYPE_MAP.items():
        if key in hay:
            return canon
    return (protocol or "unknown").lower() + "_event"


def stable_uuid(raw: dict) -> str:
    """Prefer the sensor's own event ID; else derive a deterministic UUID from the line."""
    rid = raw.get("ID") or raw.get("id")
    if rid:
        try:
            return str(uuid.UUID(str(rid)))
        except ValueError:
            return str(uuid.uuid5(uuid.NAMESPACE_URL, str(rid)))
    seed = json.dumps(raw, sort_keys=True)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def parse_dt(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def event_from_line(line: str) -> dict | None:
    """
    Unwrap one logrus-style JSON line from a sensor log.

    Real lines look like:
        {"event": {...sensor event...}, "level":"info", "msg":"New Event", ...}
    Non-attack lines (service start, session End with empty SourceIp) are skipped.
    """
    if '"event"' not in line or '"New Event"' not in line:
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if data.get("msg") != "New Event":
        return None
    ev = data.get("event")
    if not isinstance(ev, dict) or not ev.get("SourceIp"):
        return None
    return ev


def to_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def map_event(raw: dict) -> dict:
    protocol = raw.get("Protocol") or raw.get("protocol")
    return {
        "event_uuid": stable_uuid(raw),
        "occurred_at": parse_dt(raw.get("DateTime") or raw.get("datetime")),
        "src_ip": raw.get("SourceIp") or raw.get("RemoteAddr", "").split(":")[0] or "0.0.0.0",
        # dst_port = the honeypot service port (by protocol); SourcePort is the
        # attacker's ephemeral port and is preserved in raw.
        "dst_port": _default_port(protocol),
        "protocol": (protocol or "").lower() or None,
        "event_type": normalize_type(protocol, raw.get("Description")),
        "severity": _severity(protocol, raw.get("Description")),
        "username_tried": raw.get("User") or None,
        "password_tried": raw.get("Password") or None,
        "payload_excerpt": (raw.get("Description") or None),
        # country_code intentionally omitted → central GeoIP enrichment (Phase 2).
        "raw": raw,
    }


def _default_port(protocol: str | None) -> int | None:
    return {"ssh": 22, "http": 80, "https": 443, "telnet": 23, "ftp": 21, "smtp": 25}.get(
        (protocol or "").lower()
    )


def _severity(protocol: str | None, description: str | None) -> int:
    desc = (description or "").lower()
    if any(x in desc for x in (".env", "eval-stdin", "shell", "wget", "upload")):
        return 3
    return 1


class Checkpoint:
    """Persists inode + byte offset so restarts don't re-send old lines."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.inode = 0
        self.offset = 0
        self._load()

    def _load(self):
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text())
                self.inode, self.offset = data.get("inode", 0), data.get("offset", 0)
            except (json.JSONDecodeError, OSError):
                pass

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"inode": self.inode, "offset": self.offset}))
        tmp.replace(self.path)


class Shipper:
    def __init__(self, cfg: dict):
        self.central = cfg["central_url"].rstrip("/")
        self.api_key = cfg["api_key"]
        self.logs_path = cfg["logs_path"]
        self.interval = int(cfg.get("batch_interval_seconds", 45))
        self.batch_cap = int(cfg.get("max_batch", 500))
        self.verify_tls = bool(cfg.get("verify_tls", True))
        self.ckpt = Checkpoint(cfg.get("checkpoint_path", "shipper.checkpoint"))
        self.buffer_path = Path(cfg.get("buffer_path", "shipper.buffer.jsonl"))
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {self.api_key}"})
        self.running = True

    # ── log reading ────────────────────────────────────────────────────────
    def read_new_lines(self) -> list[dict]:
        p = Path(self.logs_path)
        if not p.exists():
            log.warning("logs_path not found: %s", self.logs_path)
            return []
        st = p.stat()
        # Rotation / truncation detection.
        if st.st_ino != self.ckpt.inode or st.st_size < self.ckpt.offset:
            log.info("log rotation detected — resetting offset")
            self.ckpt.inode, self.ckpt.offset = st.st_ino, 0

        events: list[dict] = []
        with p.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(self.ckpt.offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                raw = event_from_line(line)
                if raw is None:
                    continue
                events.append(map_event(raw))
                if len(events) >= self.batch_cap:
                    break
            self.ckpt.offset = f.tell()
        return events

    # ── shipping ───────────────────────────────────────────────────────────
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
                r = self.session.post(
                    f"{self.central}/events",
                    json={"events": events},
                    timeout=20,
                    verify=self.verify_tls,
                )
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

    # ── main loop ──────────────────────────────────────────────────────────
    def run(self):
        log.info("shipper online → %s (interval %ds)", self.central, self.interval)
        while self.running:
            try:
                self.flush_buffer()
                events = self.read_new_lines()
                if events:
                    if self.post(events):
                        self.ckpt.save()
                else:
                    self.heartbeat()
                    self.ckpt.save()
            except Exception:  # keep the daemon alive
                log.exception("cycle error")
            for _ in range(self.interval):
                if not self.running:
                    break
                time.sleep(1)
        log.info("shipper shutting down")

    def stop(self, *_):
        self.running = False


def main():
    ap = argparse.ArgumentParser(description="Trapline shipper agent")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )
    if not os.path.exists(args.config):
        log.error("config not found: %s (copy config.example.yaml)", args.config)
        sys.exit(1)

    cfg = yaml.safe_load(Path(args.config).read_text())
    shipper = Shipper(cfg)
    signal.signal(signal.SIGINT, shipper.stop)
    signal.signal(signal.SIGTERM, shipper.stop)
    shipper.run()


if __name__ == "__main__":
    main()
