"""Aggregate + per-VPS statistics powering the dashboard."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..cache import cached
from ..database import SessionLocal
from ..models import Event, IpRegistry, IpVpsSighting, ThreatIntel, VpsSource
from ..schemas import (
    CrossVpsIp,
    GeoCount,
    Kpi,
    NamedCount,
    StatsOverview,
    TimelinePoint,
    VpsHealth,
)
from ..services import coordination_score
from .vps import vps_status as _vps_status

router = APIRouter(prefix="/stats", tags=["stats"])

_WINDOWS: dict[str, timedelta | None] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "all": None,
}


def _since(window: str) -> datetime | None:
    delta = _WINDOWS.get(window, _WINDOWS["7d"])
    if delta is None:
        return None
    return datetime.now(timezone.utc) - delta


def _bucket_expr(window: str):
    grain = "hour" if window == "24h" else "day"
    return func.date_trunc(grain, Event.occurred_at)


def _with_since(stmt, since: datetime | None):
    if since is not None:
        stmt = stmt.where(Event.occurred_at >= since)
    return stmt


def _build_overview(db: Session, window: str, vps_alias: str | None = None) -> StatsOverview:
    now = datetime.now(timezone.utc)
    since = _since(window)

    base = select(Event)
    vps_id = None
    if vps_alias:
        vps = db.execute(select(VpsSource).where(VpsSource.alias == vps_alias)).scalar_one_or_none()
        if vps is None:
            raise HTTPException(status_code=404, detail="VPS not found")
        vps_id = vps.id

    def scoped(stmt):
        return stmt.where(Event.vps_id == vps_id) if vps_id else stmt

    def count_since(delta: timedelta | None) -> int:
        stmt = scoped(select(func.count()).select_from(Event))
        if delta is not None:
            stmt = stmt.where(Event.occurred_at >= now - delta)
        return db.execute(stmt).scalar_one()

    # ── KPIs ────────────────────────────────────────────────────────────────
    active_vps = 0
    total_vps = 0
    for v in db.execute(select(VpsSource)).scalars():
        total_vps += 1
        st, _ = _vps_status(db, v)
        if st == "online":
            active_vps += 1

    # Unique / cross-VPS / malicious IP KPIs must honour the selected window —
    # previously these were all-time totals while Events alone followed the filter.
    unique_stmt = scoped(select(func.count(func.distinct(Event.src_ip))).select_from(Event))
    unique_ips = db.execute(_with_since(unique_stmt, since)).scalar_one()

    # Cross-VPS within the window: IPs that hit ≥2 distinct sensors in range.
    # For a single-sensor page, count only those that also touched this sensor.
    cross_filters = [Event.occurred_at >= since] if since is not None else []
    cross_base = (
        select(Event.src_ip)
        .select_from(Event)
        .where(*cross_filters)
        .group_by(Event.src_ip)
        .having(func.count(func.distinct(Event.vps_id)) >= 2)
    )
    if vps_id:
        cross_ips = db.execute(
            select(func.count()).select_from(
                select(Event.src_ip)
                .where(Event.vps_id == vps_id, *cross_filters, Event.src_ip.in_(cross_base))
                .distinct()
                .subquery()
            )
        ).scalar_one()
    else:
        cross_ips = db.execute(select(func.count()).select_from(cross_base.subquery())).scalar_one()

    mal_stmt = scoped(
        select(func.count(func.distinct(Event.src_ip)))
        .select_from(Event)
        .join(ThreatIntel, ThreatIntel.ip == Event.src_ip)
        .where(ThreatIntel.raw_response["is_malicious"].as_boolean().is_(True))
    )
    known_malicious = db.execute(_with_since(mal_stmt, since)).scalar_one()

    kpi = Kpi(
        events_24h=count_since(timedelta(hours=24)),
        events_7d=count_since(timedelta(days=7)),
        events_30d=count_since(timedelta(days=30)),
        events_all=count_since(None),
        active_vps=active_vps,
        total_vps=total_vps,
        unique_ips=unique_ips,
        cross_vps_ips=cross_ips,
        known_malicious_ips=known_malicious,
    )

    # ── Timeline (stacked by VPS) ────────────────────────────────────────────
    # Group by vps_id (index-only friendly) and map to alias in Python instead
    # of joining vps_sources — the join forces a heap scan over millions of rows.
    alias_by_id = dict(db.execute(select(VpsSource.id, VpsSource.alias)).all())
    bucket = _bucket_expr(window)
    tl_rows = db.execute(
        _with_since(
            scoped(
                select(bucket.label("b"), Event.vps_id, func.count()).select_from(Event)
            ),
            since,
        ).group_by(bucket, Event.vps_id).order_by(bucket)
    ).all()
    tl: dict[datetime, dict[str, int]] = {}
    for b, vid, c in tl_rows:
        tl.setdefault(b, {})[alias_by_id.get(vid, str(vid))] = c
    timeline = [TimelinePoint(bucket=b, counts=counts) for b, counts in sorted(tl.items())]

    # ── Event types / protocols ──────────────────────────────────────────────
    def named(col, limit=12) -> list[NamedCount]:
        rows = db.execute(
            _with_since(
                scoped(select(col, func.count()).select_from(Event).where(col.isnot(None))),
                since,
            ).group_by(col).order_by(func.count().desc()).limit(limit)
        ).all()
        return [NamedCount(name=str(n), count=c) for n, c in rows]

    event_types = named(Event.event_type)
    protocols = named(Event.protocol, limit=8)

    # ── Geo ──────────────────────────────────────────────────────────────────
    # Aggregate from ip_registry (enriched at ingest/backfill) rather than
    # scanning millions of event rows. Per-sensor view uses ip_vps_sightings.
    if vps_id:
        geo_rows = db.execute(
            select(IpRegistry.country_code, func.sum(IpVpsSighting.event_count))
            .select_from(IpVpsSighting)
            .join(IpRegistry, IpRegistry.ip == IpVpsSighting.ip)
            .where(IpVpsSighting.vps_id == vps_id, IpRegistry.country_code.isnot(None))
            .group_by(IpRegistry.country_code)
            .order_by(func.sum(IpVpsSighting.event_count).desc())
            .limit(40)
        ).all()
    else:
        geo_rows = db.execute(
            select(IpRegistry.country_code, func.sum(IpRegistry.total_events))
            .where(IpRegistry.country_code.isnot(None))
            .group_by(IpRegistry.country_code)
            .order_by(func.sum(IpRegistry.total_events).desc())
            .limit(40)
        ).all()
    geo = [GeoCount(country_code=cc, count=int(c)) for cc, c in geo_rows]

    # ── Top credentials ──────────────────────────────────────────────────────
    cred_rows = db.execute(
        _with_since(
            scoped(
                select(Event.password_tried, func.count())
                .select_from(Event)
                .where(Event.password_tried.isnot(None))
            ),
            since,
        ).group_by(Event.password_tried).order_by(func.count().desc()).limit(10)
    ).all()
    top_credentials = [NamedCount(name=p, count=c) for p, c in cred_rows]

    # ── Top / priority IPs (window-scoped attack volume) ─────────────────────
    top_ip_stmt = (
        select(Event.src_ip, func.count().label("cnt"))
        .select_from(Event)
        .group_by(Event.src_ip)
        .order_by(func.count().desc())
        .limit(10)
    )
    if vps_id:
        top_ip_stmt = top_ip_stmt.where(Event.vps_id == vps_id)
    if since is not None:
        top_ip_stmt = top_ip_stmt.where(Event.occurred_at >= since)

    top_ips: list[CrossVpsIp] = []
    for src_ip, cnt in db.execute(top_ip_stmt).all():
        ip = str(src_ip)
        reg = db.get(IpRegistry, ip)
        aliases = db.execute(
            select(VpsSource.alias)
            .join(IpVpsSighting, IpVpsSighting.vps_id == VpsSource.id)
            .where(IpVpsSighting.ip == ip)
        ).scalars().all()
        ti = db.get(ThreatIntel, ip)
        top_ips.append(
            CrossVpsIp(
                ip=ip,
                vps_count=reg.vps_count if reg else len(aliases),
                vps_aliases=list(aliases),
                total_events=int(cnt),
                first_seen_at=reg.first_seen_at if reg else None,
                last_seen_at=reg.last_seen_at if reg else None,
                country_code=reg.country_code if reg else None,
                otx_pulse_count=ti.otx_pulse_count if ti else None,
                reputation_score=float(ti.reputation_score) if ti and ti.reputation_score is not None else None,
                coordination_score=coordination_score(db, ip),
            )
        )

    # ── VPS health strip ─────────────────────────────────────────────────────
    vps_health = []
    for v in db.execute(select(VpsSource).order_by(VpsSource.alias)).scalars():
        if vps_id and v.id != vps_id:
            continue
        st, secs = _vps_status(db, v)
        vps_health.append(VpsHealth(alias=v.alias, status=st, last_seen_at=v.last_seen_at, seconds_since=secs))

    return StatsOverview(
        kpi=kpi,
        timeline=timeline,
        top_ips=top_ips,
        event_types=event_types,
        protocols=protocols,
        geo=geo,
        vps_health=vps_health,
        top_credentials=top_credentials,
    )


# Aggregates over millions of rows barely change second-to-second, and the
# dashboard polls every 30s. A short fresh TTL keeps data current; a generous
# stale window means the (multi-second) recompute always happens in the
# background — a user never blocks on it. Longer windows scan more data.
_OVERVIEW_TTL = {"24h": 20.0, "7d": 30.0, "30d": 45.0, "all": 60.0}
_OVERVIEW_STALE = 900.0  # keep serving stale up to 15 min while refreshing


def _overview_producer(window: str, vps_alias: str | None):
    """No-arg producer with its own session (safe for background refresh)."""

    def run() -> StatsOverview:
        db = SessionLocal()
        try:
            return _build_overview(db, window, vps_alias=vps_alias)
        finally:
            db.close()

    return run


def overview_cache_key(window: str, vps_alias: str | None = None) -> str:
    return f"overview::{vps_alias or '_all'}::{window}"


@router.get("/overview", response_model=StatsOverview)
def stats_overview(
    window: str = Query(default="7d", pattern="^(24h|7d|30d|all)$"),
) -> StatsOverview:
    return cached(
        overview_cache_key(window),
        _OVERVIEW_TTL.get(window, 30.0),
        _overview_producer(window, None),
        stale_ttl=_OVERVIEW_STALE,
    )


@router.get("/{vps_alias}", response_model=StatsOverview)
def stats_for_vps(
    vps_alias: str,
    window: str = Query(default="7d", pattern="^(24h|7d|30d|all)$"),
) -> StatsOverview:
    return cached(
        overview_cache_key(window, vps_alias),
        _OVERVIEW_TTL.get(window, 30.0),
        _overview_producer(window, vps_alias),
        stale_ttl=_OVERVIEW_STALE,
    )
