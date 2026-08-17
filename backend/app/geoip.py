"""Geo-enrichment for source IPs.

The honeypot event stream carries no geolocation, so `country_code` arrives
NULL. This module resolves country codes for IPs in `ip_registry` using the
free ip-api.com batch endpoint (up to 100 IPs/request, ~15 requests/min), then
denormalizes the result onto `ip_registry` and `events`.

Used both for a one-time backfill (`python -m app.geoip`) and by a lightweight
background loop that keeps newly-seen IPs enriched.
"""
from __future__ import annotations

import asyncio
import time

import httpx
from sqlalchemy import select, text, update
from sqlalchemy.orm import Session

from .database import SessionLocal
from .models import Event, IpRegistry

BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,query"
BATCH_SIZE = 100
# ip-api free batch tier allows ~15 requests/min. We read the returned X-Rl /
# X-Ttl headers to pace precisely, with this as a conservative fallback.
_FALLBACK_SLEEP = 4.5


def _pending_ips(db: Session, limit: int | None = None) -> list[str]:
    stmt = select(IpRegistry.ip).where(IpRegistry.country_code.is_(None))
    if limit:
        stmt = stmt.limit(limit)
    return [str(ip) for ip in db.execute(stmt).scalars()]


def _resolve_batch(client: httpx.Client, ips: list[str]) -> dict[str, str]:
    payload = [{"query": ip} for ip in ips]
    resp = client.post(BATCH_URL, json=payload, timeout=30)
    resp.raise_for_status()
    out: dict[str, str] = {}
    for row in resp.json():
        if row.get("status") == "success" and row.get("countryCode"):
            out[row["query"]] = row["countryCode"]

    # Respect the documented rate limit using response headers when present.
    remaining = resp.headers.get("X-Rl")
    ttl = resp.headers.get("X-Ttl")
    if remaining is not None and ttl is not None and int(remaining) <= 0:
        time.sleep(int(ttl) + 1)
    else:
        time.sleep(_FALLBACK_SLEEP)
    return out


def _apply_registry(db: Session, resolved: dict[str, str]) -> None:
    for ip, cc in resolved.items():
        db.execute(
            update(IpRegistry)
            .where(IpRegistry.ip == ip, IpRegistry.country_code.is_(None))
            .values(country_code=cc)
        )
    db.commit()


def backfill_events_country(db: Session) -> int:
    """Denormalize resolved country codes from ip_registry onto events."""
    result = db.execute(
        text(
            """
            UPDATE events e
            SET country_code = r.country_code
            FROM ip_registry r
            WHERE e.src_ip = r.ip
              AND e.country_code IS NULL
              AND r.country_code IS NOT NULL
            """
        )
    )
    db.commit()
    return result.rowcount or 0


def enrich(limit: int | None = None, backfill_events: bool = True, verbose: bool = False) -> dict:
    """Resolve pending IPs and (optionally) backfill events. Returns a summary."""
    db = SessionLocal()
    try:
        pending = _pending_ips(db, limit)
        total = len(pending)
        resolved_count = 0
        if verbose:
            print(f"[geoip] {total} IP(s) need a country", flush=True)

        with httpx.Client(headers={"User-Agent": "trapline-geoip/1.0"}) as client:
            for i in range(0, total, BATCH_SIZE):
                chunk = pending[i : i + BATCH_SIZE]
                try:
                    resolved = _resolve_batch(client, chunk)
                except Exception as exc:  # noqa: BLE001
                    if verbose:
                        print(f"[geoip] batch failed ({exc!r}); retrying after pause", flush=True)
                    time.sleep(10)
                    continue
                _apply_registry(db, resolved)
                resolved_count += len(resolved)
                if verbose and (i // BATCH_SIZE) % 10 == 0:
                    print(
                        f"[geoip] {min(i + BATCH_SIZE, total):,}/{total:,} processed, "
                        f"{resolved_count:,} resolved",
                        flush=True,
                    )

        events_updated = 0
        if backfill_events and resolved_count:
            if verbose:
                print("[geoip] backfilling events.country_code ...", flush=True)
            events_updated = backfill_events_country(db)

        summary = {
            "pending": total,
            "resolved": resolved_count,
            "events_updated": events_updated,
        }
        if verbose:
            print(f"[geoip] done: {summary}", flush=True)
        return summary
    finally:
        db.close()


async def geo_enrich_loop(interval: float = 300.0, per_cycle: int = 500) -> None:
    """Background task: periodically resolve country for newly-seen IPs.

    Runs the (blocking) enrich() in a worker thread so the event loop stays free.
    Capped per cycle to stay well within the free API rate limit.
    """
    while True:
        try:
            await asyncio.to_thread(enrich, per_cycle, True, False)
        except Exception as exc:  # noqa: BLE001
            print(f"[geoip] enrichment cycle failed: {exc!r}")
        await asyncio.sleep(interval)


if __name__ == "__main__":
    enrich(verbose=True)
