"""VPS sensor health — shipper liveness, log flow, and honeypot reachability probes."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import SessionLocal
from .config import settings
from .models import Event, VpsSource

log = logging.getLogger(__name__)

STALE_SECONDS = 300       # >5m without logs/heartbeat => stale
OFFLINE_SECONDS = 1800    # >30m => offline
PROBE_INTERVAL_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 8

# In-memory reachability cache: alias -> (reachable, checked_at UTC)
_probe_cache: dict[str, tuple[bool, datetime]] = {}


def status_from_age(seconds: float | None) -> str:
    if seconds is None:
        return "offline"
    if seconds <= STALE_SECONDS:
        return "online"
    if seconds <= OFFLINE_SECONDS:
        return "stale"
    return "offline"


def effective_last_contact(db: Session, vps: VpsSource) -> datetime | None:
    """
    Most recent shipper activity for this sensor.
    Uses heartbeat/ingest timestamp and latest event received_at (whichever is newer).
    """
    candidates: list[datetime] = []
    if vps.last_seen_at is not None:
        candidates.append(vps.last_seen_at)
    last_rx = db.execute(
        select(func.max(Event.received_at)).where(Event.vps_id == vps.id)
    ).scalar_one_or_none()
    if last_rx is not None:
        candidates.append(last_rx)
    return max(candidates) if candidates else None


def dataset_now(db: Session) -> datetime | None:
    """The newest event timestamp in the dataset: its 'now' for an archived capture."""
    return db.execute(select(func.max(Event.occurred_at))).scalar_one_or_none()


def vps_status(db: Session, vps: VpsSource) -> tuple[str, float | None]:
    """
    Derive online | stale | offline.

    Live mode, measured against wall clock:
      - online  — logs/heartbeat within 5 minutes
      - stale   — quiet 5-30m OR honeypot URL reachable but not shipping logs
      - offline — no recent logs and honeypot unreachable (or no URL)

    Archived-dataset mode (`DATASET_MODE=true`), measured against the newest event in
    the dataset: a sensor still shipping at the end of the capture window reads online,
    one that stopped partway reads stale or offline. That is a statement about the
    capture, not a claim that anything is running now.
    """
    if settings.dataset_mode:
        # Compare like with like. effective_last_contact() prefers received_at, which
        # is later than occurred_at, and mixing the two yields negative ages.
        reference = dataset_now(db)
        last = db.execute(
            select(func.max(Event.occurred_at)).where(Event.vps_id == vps.id)
        ).scalar_one_or_none()
        if reference is None or last is None:
            return "offline", None
        age = (reference - last).total_seconds()
        # Generous windows: a day of quiet inside a two-month capture is not a fault.
        if age <= 86_400:
            return "online", age
        if age <= 604_800:
            return "stale", age
        return "offline", age

    now = datetime.now(timezone.utc)
    last = effective_last_contact(db, vps)

    if last is not None:
        age = (now - last).total_seconds()
        if age <= OFFLINE_SECONDS:
            return status_from_age(age), age

    probe = _probe_cache.get(vps.alias)
    if probe and probe[0]:
        probe_age = (now - probe[1]).total_seconds()
        if probe_age <= OFFLINE_SECONDS:
            # Node responds on HTTP but central is not getting fresh logs
            return "stale", probe_age

    if last is not None:
        return "offline", (now - last).total_seconds()
    return "offline", None


async def _probe_url(url: str) -> bool:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=PROBE_TIMEOUT_SECONDS) as client:
            for method in ("HEAD", "GET"):
                try:
                    r = await client.request(method, url)
                    if r.status_code < 500:
                        return True
                except httpx.HTTPError:
                    continue
    except Exception:
        pass
    return False


async def probe_all_vps() -> None:
    db = SessionLocal()
    try:
        rows = db.execute(select(VpsSource).where(VpsSource.is_active.is_(True))).scalars().all()
        now = datetime.now(timezone.utc)
        for vps in rows:
            if not vps.base_url:
                _probe_cache[vps.alias] = (False, now)
                continue
            ok = await _probe_url(vps.base_url)
            _probe_cache[vps.alias] = (ok, now)
            log.info("probe %s (%s) → %s", vps.alias, vps.base_url, "reachable" if ok else "unreachable")
    finally:
        db.close()


async def health_monitor_loop() -> None:
    """Background loop — re-probe every honeypot base_url."""
    await asyncio.sleep(5)  # let API finish booting
    while True:
        try:
            await probe_all_vps()
        except Exception:
            log.exception("VPS reachability probe failed")
        await asyncio.sleep(PROBE_INTERVAL_SECONDS)


def repair_last_seen_from_events(db: Session) -> int:
    """Align last_seen_at with the newest received event per VPS (one-time repair)."""
    rows = db.execute(
        select(Event.vps_id, func.max(Event.received_at)).group_by(Event.vps_id)
    ).all()
    updated = 0
    for vps_id, max_rx in rows:
        if max_rx is None:
            continue
        vps = db.get(VpsSource, vps_id)
        if vps is None:
            continue
        if vps.last_seen_at is None or vps.last_seen_at < max_rx:
            vps.last_seen_at = max_rx
            updated += 1
    if updated:
        db.commit()
    return updated
