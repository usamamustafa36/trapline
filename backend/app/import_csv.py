"""
Import a honeypot report CSV into Trapline.

Loads real sensor telemetry exported from an upstream console and rebuilds the
derived state the platform runs on: the IP registry, per-sensor sightings, and
cross-sensor flags.

Two things this does deliberately.

**Sensor identities are anonymised on the way in.** Whatever alias the source CSV
uses, sensors are renumbered SENSOR-01, SENSOR-02, ... in order of first
appearance. Deployment-identifying aliases never reach the database, so a public
instance cannot leak who operates which sensor. The mapping is printed once so
you can still read your own data locally.

**Import is idempotent.** Each event gets a UUIDv5 derived from its content, so
re-running over the same CSV updates nothing and inserts nothing twice.

Usage
-----
    python -m app.import_csv report.csv
    python -m app.import_csv report.csv --truncate-ips     # zero the last octet
    python -m app.import_csv report.csv --keep-aliases     # keep source aliases

Expected columns (extras are preserved into raw_payload):
    occurred_at, vps_alias, src_ip, country_code, protocol, dst_port,
    event_type, severity, username_tried, password_tried, payload_excerpt
"""
from __future__ import annotations

import argparse
import csv
import sys
import uuid
from collections import Counter, OrderedDict
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select

from .database import Base, SessionLocal, engine
from .models import Event, IpRegistry, IpVpsSighting, VpsSource
from .security import generate_api_key, hash_api_key

# Stable namespace so the same row always yields the same event_uuid.
EVENT_NS = uuid.UUID("5f3a9c1e-7b42-4d18-9f0a-2c6e8b1d4a37")

REQUIRED = {"occurred_at", "vps_alias", "src_ip"}


def _die(msg: str) -> None:
    print(f"[import] error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _parse_ts(value: str) -> datetime:
    """Accept ISO-8601, tolerating a trailing Z."""
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        _die(f"unparseable timestamp {value!r}")
        raise  # unreachable, keeps type checkers happy


def _truncate(ip: str) -> str:
    """Zero the final octet of an IPv4 address, leave anything else alone."""
    parts = ip.split(".")
    return ".".join(parts[:3] + ["0"]) if len(parts) == 4 else ip


def _blank_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


def _event_uuid(alias: str, row: dict[str, str]) -> uuid.UUID:
    """Content-addressed id: same row in, same uuid out."""
    key = "|".join(
        (
            alias,
            row.get("occurred_at", ""),
            row.get("src_ip", ""),
            row.get("event_type", ""),
            row.get("dst_port", ""),
            row.get("username_tried", ""),
            row.get("password_tried", ""),
        )
    )
    return uuid.uuid5(EVENT_NS, key)


def load(path: Path, *, truncate_ips: bool, keep_aliases: bool) -> None:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))

    if not rows:
        _die("CSV contains no data rows")

    missing = REQUIRED - set(rows[0])
    if missing:
        _die(f"CSV missing required column(s): {', '.join(sorted(missing))}")

    # Renumber sensors in order of first appearance unless told otherwise.
    source_aliases = list(OrderedDict.fromkeys(r["vps_alias"].strip() for r in rows))
    if keep_aliases:
        alias_map = {a: a for a in source_aliases}
    else:
        alias_map = {a: f"SENSOR-{i:02d}" for i, a in enumerate(source_aliases, start=1)}

    Base.metadata.create_all(bind=engine)
    inserted = skipped = 0

    with SessionLocal() as db:
        # Ensure a VpsSource row exists for every sensor in the file.
        sensors: dict[str, VpsSource] = {}
        for source_alias, alias in alias_map.items():
            sensor = db.scalar(select(VpsSource).where(VpsSource.alias == alias))
            if sensor is None:
                sensor = VpsSource(
                    alias=alias,
                    display_name=alias.replace("-", " ").title(),
                    stack_type="imported",
                    api_key_hash=hash_api_key(generate_api_key()),
                )
                db.add(sensor)
                db.flush()
            sensors[source_alias] = sensor

        for row in rows:
            source_alias = row["vps_alias"].strip()
            alias = alias_map[source_alias]
            sensor = sensors[source_alias]

            ev_uuid = _event_uuid(alias, row)
            if db.scalar(select(Event.id).where(Event.event_uuid == ev_uuid)) is not None:
                skipped += 1
                continue

            ip = row["src_ip"].strip()
            if truncate_ips:
                ip = _truncate(ip)

            occurred_at = _parse_ts(row["occurred_at"])
            port = _blank_to_none(row.get("dst_port"))
            severity = _blank_to_none(row.get("severity"))
            country = _blank_to_none(row.get("country_code"))

            db.add(
                Event(
                    event_uuid=ev_uuid,
                    vps_id=sensor.id,
                    occurred_at=occurred_at,
                    src_ip=ip,
                    dst_port=int(port) if port and port.isdigit() else None,
                    protocol=_blank_to_none(row.get("protocol")),
                    event_type=_blank_to_none(row.get("event_type")),
                    severity=int(severity) if severity and severity.isdigit() else 0,
                    username_tried=_blank_to_none(row.get("username_tried")),
                    password_tried=_blank_to_none(row.get("password_tried")),
                    payload_excerpt=_blank_to_none(row.get("payload_excerpt")),
                    country_code=(country[:2].upper() if country else None),
                    # Keep the row verbatim minus the identifying alias, so nothing
                    # is silently discarded but nothing identifying is retained.
                    raw_payload={k: v for k, v in row.items() if k != "vps_alias"}
                    | {"import_source": path.name, "sensor": alias},
                )
            )
            inserted += 1

        db.commit()
        _rebuild_derived(db)
        db.commit()

        totals = _summarise(db)

    if not keep_aliases:
        print("[import] sensor mapping (local reference only, not stored):")
        for source_alias, alias in alias_map.items():
            print(f"           {source_alias:<12} -> {alias}")

    print(f"[import] {inserted} event(s) inserted, {skipped} already present")
    print(
        f"[import] database now holds {totals['events']} event(s), "
        f"{totals['ips']} distinct address(es), "
        f"{totals['cross']} seen by more than one sensor"
    )
    if truncate_ips:
        print("[import] source addresses truncated to /24")


def _rebuild_derived(db) -> None:
    """Recompute ip_registry and ip_vps_sightings from the events table."""
    db.query(IpVpsSighting).delete()
    db.query(IpRegistry).delete()
    db.flush()

    per_ip = db.execute(
        select(
            Event.src_ip,
            func.min(Event.occurred_at),
            func.max(Event.occurred_at),
            func.count(Event.id),
            func.count(func.distinct(Event.vps_id)),
            func.max(Event.country_code),
        ).group_by(Event.src_ip)
    ).all()

    for ip, first_seen, last_seen, total, vps_count, country in per_ip:
        db.add(
            IpRegistry(
                ip=str(ip),
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                total_events=total,
                vps_count=vps_count,
                country_code=country,
                is_cross_vps=vps_count > 1,
            )
        )

    per_pair = db.execute(
        select(
            Event.src_ip,
            Event.vps_id,
            func.min(Event.occurred_at),
            func.max(Event.occurred_at),
            func.count(Event.id),
        ).group_by(Event.src_ip, Event.vps_id)
    ).all()

    for ip, vps_id, first_seen, last_seen, count in per_pair:
        db.add(
            IpVpsSighting(
                ip=str(ip),
                vps_id=vps_id,
                first_seen_at=first_seen,
                last_seen_at=last_seen,
                event_count=count,
            )
        )

    # Keep each sensor's last_seen_at consistent with what it actually reported.
    for sensor_id, last_seen in db.execute(
        select(Event.vps_id, func.max(Event.occurred_at)).group_by(Event.vps_id)
    ).all():
        sensor = db.get(VpsSource, sensor_id)
        if sensor is not None:
            sensor.last_seen_at = last_seen


def _summarise(db) -> dict[str, int]:
    return {
        "events": db.scalar(select(func.count(Event.id))) or 0,
        "ips": db.scalar(select(func.count(IpRegistry.ip))) or 0,
        "cross": db.scalar(
            select(func.count(IpRegistry.ip)).where(IpRegistry.is_cross_vps.is_(True))
        )
        or 0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Import a honeypot report CSV into Trapline.")
    ap.add_argument("csv", type=Path, help="path to the report CSV")
    ap.add_argument(
        "--truncate-ips",
        action="store_true",
        help="zero the last octet of IPv4 source addresses before storing",
    )
    ap.add_argument(
        "--keep-aliases",
        action="store_true",
        help="store the source sensor aliases verbatim instead of renumbering them",
    )
    args = ap.parse_args()

    if not args.csv.is_file():
        _die(f"no such file: {args.csv}")

    load(args.csv, truncate_ips=args.truncate_ips, keep_aliases=args.keep_aliases)


if __name__ == "__main__":
    main()
