"""Event ingestion + query endpoints."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..cache import cached
from ..database import get_db
from ..deps import enforce_rate_limit
from ..models import Event, VpsSource
from ..schemas import EventBatchIn, EventOut, IngestResponse, PagedEvents
from ..services import ingest_batch

router = APIRouter(tags=["events"])

# Above this planner-estimated row count we return the estimate instead of an
# exact COUNT(*). Exact counts over multi-million-row result sets take seconds;
# for a "X matched" display an estimate is more than accurate enough, and small
# / well-filtered result sets still get exact numbers.
_EXACT_COUNT_MAX = 100_000


def _plan_rows(db: Session, stmt) -> int | None:
    """Ask the Postgres planner how many rows a query will return (~instant)."""
    try:
        compiled = stmt.compile(
            dialect=db.bind.dialect,
            compile_kwargs={"literal_binds": True},
        )
        plan = db.execute(text(f"EXPLAIN (FORMAT JSON) {compiled}")).scalar_one()
        return int(plan[0]["Plan"]["Plan Rows"])
    except Exception:
        return None


def _events_total(db: Session, base_stmt, cache_key: str) -> tuple[int, bool]:
    """(total, is_estimate). Estimate for huge result sets, exact otherwise.

    Cached per filter-set so paging through results never re-runs the count.
    """

    def compute() -> tuple[int, bool]:
        est = _plan_rows(db, base_stmt)
        if est is not None and est > _EXACT_COUNT_MAX:
            return est, True
        total = db.execute(select(func.count()).select_from(base_stmt.subquery())).scalar_one()
        return total, False

    return cached(cache_key, 20.0, compute)


@router.post("/events", response_model=IngestResponse, status_code=202)
def ingest_events(
    payload: EventBatchIn,
    vps: VpsSource = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> IngestResponse:
    """Bulk, idempotent event ingestion. Auth: per-VPS bearer key."""
    return ingest_batch(db, vps, payload.events)


@router.get("/events", response_model=PagedEvents)
def list_events(
    db: Session = Depends(get_db),
    vps: str | None = Query(default=None, description="VPS alias filter"),
    type: str | None = Query(default=None, description="event_type filter"),
    protocol: str | None = None,
    ip: str | None = None,
    min_severity: int | None = Query(default=None, ge=0, le=4),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    q: str | None = Query(default=None, description="search username/password/payload"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> PagedEvents:
    stmt = select(Event, VpsSource.alias).join(VpsSource, Event.vps_id == VpsSource.id)

    if vps:
        stmt = stmt.where(VpsSource.alias == vps)
    if type:
        stmt = stmt.where(Event.event_type == type)
    if protocol:
        stmt = stmt.where(Event.protocol == protocol)
    if ip:
        stmt = stmt.where(Event.src_ip == ip)
    if min_severity is not None:
        stmt = stmt.where(Event.severity >= min_severity)
    if from_:
        stmt = stmt.where(Event.occurred_at >= from_)
    if to:
        stmt = stmt.where(Event.occurred_at <= to)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            Event.username_tried.ilike(like)
            | Event.password_tried.ilike(like)
            | Event.payload_excerpt.ilike(like)
        )

    cache_key = "events::count::" + "|".join(
        str(x) for x in (vps, type, protocol, ip, min_severity, from_, to, q)
    )
    total, is_estimate = _events_total(db, stmt, cache_key)

    rows = db.execute(
        stmt.order_by(Event.occurred_at.desc(), Event.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    items = []
    for ev, alias in rows:
        out = EventOut.model_validate(ev)
        out.src_ip = str(ev.src_ip)
        out.vps_alias = alias
        items.append(out)

    return PagedEvents(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
        is_estimate=is_estimate,
    )
