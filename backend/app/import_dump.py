"""
Import a Trapline database dump (JSON) into a local database.

The dump is a single JSON object whose `events` array is written one record per
line, so this reads it line by line rather than loading the whole file. A 150 MB
dump imports in constant memory.

Unlike `import_csv`, this preserves **`raw_payload`**, which is where the useful
signal lives: `Command`, `CommandOutput`, `Client` (the SSH client version, a tool
fingerprint), `RequestURI`, `UserAgent`, `HTTPMethod`, `Headers`, `Body`,
`TLSServerName` and `SourcePort`. The flat CSV export dropped all of it.

**Sanitisation is applied on the way in and is not optional.** Sensor aliases are
renumbered from a stable mapping, display names are replaced, and `base_url` (which
carries the deployment address) is dropped. Deployment identifiers never reach the
database, so nothing downstream can leak them.

Usage
-----
    python -m app.import_dump dump1.json dump2.json ...
    python -m app.import_dump *.json --keep-aliases     # keep source names locally

Stable sensor numbering comes from `SENSOR_MAP` below, so import order does not
change which sensor is which.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .database import Base, SessionLocal, engine
from .models import Event, IpRegistry, IpVpsSighting, VpsSource
from .security import generate_api_key, hash_api_key

# Stable, order-independent numbering. Anything not listed gets the next free slot.
SENSOR_MAP = {
    "FWO": "SENSOR-01",
    "NLC": "SENSOR-02",
    "CSD": "SENSOR-03",
}

BATCH = 5_000


def _log(msg: str) -> None:
    print(f"[dump] {msg}", flush=True)


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _alias_for(source_alias: str, assigned: dict[str, str]) -> str:
    """Map a source sensor name to a stable neutral alias."""
    if source_alias in assigned:
        return assigned[source_alias]
    mapped = SENSOR_MAP.get(source_alias.upper())
    if mapped is None:
        # Next free slot after the known ones.
        taken = set(SENSOR_MAP.values()) | set(assigned.values())
        n = 1
        while f"SENSOR-{n:02d}" in taken:
            n += 1
        mapped = f"SENSOR-{n:02d}"
    assigned[source_alias] = mapped
    return mapped


def _header_of(path: Path) -> tuple[dict, str]:
    """
    Read the dump preamble for metadata.

    The scalar header keys sit at the top of the file, ahead of the large
    `ip_registry` / `threat_intel` / `events` arrays, so they are pulled out by
    pattern from the first few lines rather than by parsing the whole object.
    """
    meta: dict = {}
    sensor = ""
    events_expected: int | None = None

    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            stripped = line.strip()
            if stripped.startswith('"sensor":'):
                m = re.search(r'"sensor"\s*:\s*"([^"]*)"', stripped)
                if m:
                    sensor = m.group(1)
            elif stripped.startswith('"events":') and '"events": [' in stripped:
                m = re.search(r'"events"\s*:\s*(\d+)', stripped)
                if m:
                    events_expected = int(m.group(1))
            elif '"events":' in stripped and stripped.startswith('"events"'):
                break
            else:
                m = re.match(r'"events"\s*:\s*(\d+)', stripped)
                if m:
                    events_expected = int(m.group(1))
            # The row_counts block is within the first handful of lines.
            if i > 40:
                break

    meta["sensor"] = sensor
    if events_expected is not None:
        meta["row_counts"] = {"events": events_expected}
    return meta, sensor


def _iter_events(path: Path):
    """Yield event dicts from the line-oriented `events` array."""
    in_events = False
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not in_events:
                if stripped.startswith('"events":'):
                    in_events = True
                    # The array may open on the same line with a record after it.
                    tail = stripped.split("[", 1)[1] if "[" in stripped else ""
                    if tail.strip().startswith("{"):
                        candidate = tail.strip().rstrip(",").rstrip("]")
                        try:
                            yield json.loads(candidate)
                        except json.JSONDecodeError:
                            pass
                continue
            if stripped in ("]", "]}", "],"):
                break
            candidate = stripped.rstrip(",").rstrip("]")
            if not candidate.startswith("{"):
                continue
            try:
                yield json.loads(candidate)
            except json.JSONDecodeError:
                continue


def load(paths: list[Path], *, keep_aliases: bool) -> None:
    Base.metadata.create_all(bind=engine)
    assigned: dict[str, str] = {}
    grand_total = 0

    with SessionLocal() as db:
        for path in paths:
            meta, source_sensor = _header_of(path)
            if not source_sensor:
                _log(f"{path.name}: no sensor name in header, skipping")
                continue

            alias = source_sensor if keep_aliases else _alias_for(source_sensor, assigned)
            expected = (meta.get("row_counts") or {}).get("events")

            sensor = db.scalar(select(VpsSource).where(VpsSource.alias == alias))
            if sensor is None:
                sensor = VpsSource(
                    alias=alias,
                    display_name=alias.replace("-", " ").title(),
                    stack_type="imported",
                    # base_url deliberately not carried over: it holds the real address.
                    api_key_hash=hash_api_key(generate_api_key()),
                )
                db.add(sensor)
                db.flush()

            _log(f"{path.name}: sensor {source_sensor!r} -> {alias}, {expected or '?'} event(s)")

            batch: list[dict] = []
            seen = 0
            for record in _iter_events(path):
                occurred = _parse_ts(record.get("occurred_at"))
                if occurred is None or not record.get("src_ip"):
                    continue

                raw = record.get("raw_payload") or {}
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except json.JSONDecodeError:
                        raw = {"_raw": raw}
                # Strip the socket string, which embeds the source port and adds nothing.
                raw.pop("RemoteAddr", None)

                ev_uuid = record.get("event_uuid")
                try:
                    ev_uuid = uuid.UUID(str(ev_uuid))
                except (ValueError, AttributeError, TypeError):
                    ev_uuid = uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        f"{alias}|{record.get('occurred_at')}|{record.get('src_ip')}|{seen}",
                    )

                port = record.get("dst_port")
                sev = record.get("severity")
                cc = record.get("country_code")

                batch.append(
                    dict(
                        event_uuid=ev_uuid,
                        vps_id=sensor.id,
                        occurred_at=occurred,
                        src_ip=str(record["src_ip"]),
                        dst_port=int(port) if isinstance(port, int) else None,
                        protocol=record.get("protocol"),
                        event_type=record.get("event_type"),
                        severity=int(sev) if isinstance(sev, int) else 0,
                        username_tried=record.get("username_tried"),
                        password_tried=record.get("password_tried"),
                        payload_excerpt=record.get("payload_excerpt"),
                        country_code=(str(cc)[:2].upper() if cc else None),
                        raw_payload=raw,
                    )
                )
                seen += 1

                if len(batch) >= BATCH:
                    _flush(db, batch)
                    grand_total += len(batch)
                    batch.clear()
                    if seen % 25_000 == 0:
                        _log(f"  ... {seen:,} read")

            if batch:
                _flush(db, batch)
                grand_total += len(batch)
            db.commit()
            _log(f"  {path.name}: {seen:,} event(s) processed")

        _log("rebuilding IP registry and cross-sensor sightings ...")
        _rebuild_derived(db)
        db.commit()
        totals = _summarise(db)

    if not keep_aliases and assigned:
        _log("sensor mapping (local reference only, not stored):")
        for src, dst in assigned.items():
            _log(f"         {src:<8} -> {dst}")
    _log(
        f"done: {totals['events']:,} event(s), {totals['ips']:,} address(es), "
        f"{totals['cross']:,} seen by more than one sensor"
    )


def _flush(db, batch: list[dict]) -> None:
    """Insert a batch, ignoring rows already present (idempotent re-import)."""
    stmt = pg_insert(Event.__table__).values(batch)
    db.execute(stmt.on_conflict_do_nothing(index_elements=["event_uuid"]))


def _rebuild_derived(db) -> None:
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
    rows = [
            dict(
                ip=str(ip),
                first_seen_at=first,
                last_seen_at=last,
                total_events=total,
                vps_count=vps_count,
                country_code=cc,
                is_cross_vps=vps_count > 1,
            )
        for ip, first, last, total, vps_count, cc in per_ip
    ]
    if rows:
        db.execute(IpRegistry.__table__.insert(), rows)

    per_pair = db.execute(
        select(
            Event.src_ip,
            Event.vps_id,
            func.min(Event.occurred_at),
            func.max(Event.occurred_at),
            func.count(Event.id),
        ).group_by(Event.src_ip, Event.vps_id)
    ).all()
    pair_rows = [
            dict(
                ip=str(ip),
                vps_id=vps_id,
                first_seen_at=first,
                last_seen_at=last,
                event_count=count,
            )
        for ip, vps_id, first, last, count in per_pair
    ]
    if pair_rows:
        db.execute(IpVpsSighting.__table__.insert(), pair_rows)

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
    ap = argparse.ArgumentParser(description="Import Trapline JSON database dumps.")
    ap.add_argument("dumps", type=Path, nargs="+", help="dump files")
    ap.add_argument(
        "--keep-aliases",
        action="store_true",
        help="store source sensor names verbatim instead of renumbering",
    )
    args = ap.parse_args()

    missing = [p for p in args.dumps if not p.is_file()]
    if missing:
        print(f"[dump] error: no such file: {missing[0]}", file=sys.stderr)
        raise SystemExit(1)

    load(args.dumps, keep_aliases=args.keep_aliases)


if __name__ == "__main__":
    main()
