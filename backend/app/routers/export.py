"""
CSV export.

Streams filtered events out as CSV so an analyst can take a slice away for
offline work, and so a fleet can hand a dataset to another Trapline instance.
The column order matches what `app.import_csv` expects, which makes export and
import a closed loop: pull a window from one deployment, load it into another.

Rows are streamed straight from a server-side cursor rather than materialised,
so exporting a month of events does not hold the whole result set in memory.

**Source addresses can be anonymised on the way out.** `?anonymise=true`
truncates IPv4 to /24 and replaces sensor aliases with SENSOR-01, SENSOR-02, ...
numbered in first-appearance order. That produces a dataset which preserves the
behavioural structure (timing, protocols, credentials attempted, cross-sensor
coincidence) while identifying neither the attackers nor the operator, which is
the form a honeypot dataset should be in before it is published or shared.
"""
from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Event, VpsSource

router = APIRouter(tags=["export"])

COLUMNS = [
    "occurred_at",
    "vps_alias",
    "src_ip",
    "country_code",
    "protocol",
    "dst_port",
    "event_type",
    "severity",
    "username_tried",
    "password_tried",
    "payload_excerpt",
]

# Rows fetched per round trip to the database while streaming.
CHUNK = 2_000


def _truncate_ipv4(ip: str) -> str:
    """Zero the final octet; leave IPv6 and anything unexpected untouched."""
    parts = ip.split(".")
    return ".".join(parts[:3] + ["0"]) if len(parts) == 4 else ip


def _rows(
    db: Session,
    *,
    since: datetime | None,
    until: datetime | None,
    alias: str | None,
    anonymise: bool,
) -> Iterator[list[object]]:
    stmt = (
        select(Event, VpsSource.alias)
        .join(VpsSource, Event.vps_id == VpsSource.id)
        .order_by(Event.occurred_at.desc())
    )
    if since is not None:
        stmt = stmt.where(Event.occurred_at >= since)
    if until is not None:
        stmt = stmt.where(Event.occurred_at <= until)
    if alias:
        stmt = stmt.where(VpsSource.alias == alias)

    # Assigned lazily so numbering follows the order rows actually appear in.
    alias_map: dict[str, str] = {}

    for event, source_alias in db.execute(stmt).yield_per(CHUNK):
        if anonymise:
            if source_alias not in alias_map:
                alias_map[source_alias] = f"SENSOR-{len(alias_map) + 1:02d}"
            out_alias = alias_map[source_alias]
            out_ip = _truncate_ipv4(str(event.src_ip))
        else:
            out_alias = source_alias
            out_ip = str(event.src_ip)

        yield [
            event.occurred_at.isoformat() if event.occurred_at else "",
            out_alias,
            out_ip,
            event.country_code or "",
            event.protocol or "",
            event.dst_port if event.dst_port is not None else "",
            event.event_type or "",
            event.severity if event.severity is not None else "",
            event.username_tried or "",
            event.password_tried or "",
            event.payload_excerpt or "",
        ]


@router.get("/export/events.csv", response_class=StreamingResponse)
def export_events_csv(
    db: Session = Depends(get_db),
    since: datetime | None = Query(None, description="Only events at or after this timestamp"),
    until: datetime | None = Query(None, description="Only events at or before this timestamp"),
    alias: str | None = Query(None, description="Restrict to a single sensor alias"),
    anonymise: bool = Query(
        False,
        description=(
            "Truncate source addresses to /24 and renumber sensor aliases. "
            "Use for any dataset leaving your own infrastructure."
        ),
    ),
) -> StreamingResponse:
    """Stream matching events as CSV, in the column order `app.import_csv` reads."""

    def generate() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.writer(buffer)

        def flush() -> str:
            value = buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            return value

        writer.writerow(COLUMNS)
        yield flush()

        for row in _rows(db, since=since, until=until, alias=alias, anonymise=anonymise):
            writer.writerow(row)
            yield flush()

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    suffix = "-anonymised" if anonymise else ""
    filename = f"trapline-events-{stamp}{suffix}.csv"

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
