"""VPS source management: register, list, health heartbeat."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..cache import cached
from ..database import SessionLocal, get_db
from ..deps import get_current_vps, require_admin
from ..models import Event, VpsSource
from ..schemas import VpsHealth, VpsOut, VpsRegisterIn, VpsRegisterOut
from ..security import encrypt_secret, generate_api_key, hash_api_key
from ..vps_health import effective_last_contact, vps_status

router = APIRouter(prefix="/vps", tags=["vps"])


@router.post("/register", response_model=VpsRegisterOut, dependencies=[Depends(require_admin)])
def register_vps(payload: VpsRegisterIn, db: Session = Depends(get_db)) -> VpsRegisterOut:
    """Admin-only. Creates a source and returns its API key exactly once."""
    exists = db.execute(select(VpsSource).where(VpsSource.alias == payload.alias)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail=f"VPS alias '{payload.alias}' already registered")

    api_key = generate_api_key()
    vps = VpsSource(
        alias=payload.alias,
        display_name=payload.display_name,
        base_url=payload.base_url,
        stack_type=payload.stack_type,
        region=payload.region,
        lat=payload.lat,
        lon=payload.lon,
        api_key_hash=hash_api_key(api_key),
        alienvault_key_encrypted=encrypt_secret(payload.alienvault_key) if payload.alienvault_key else None,
    )
    db.add(vps)
    db.commit()
    db.refresh(vps)
    return VpsRegisterOut(id=vps.id, alias=vps.alias, api_key=api_key)


def _count_events_by_vps() -> dict:
    db = SessionLocal()
    try:
        return dict(db.execute(select(Event.vps_id, func.count()).group_by(Event.vps_id)).all())
    finally:
        db.close()


def _event_counts() -> dict:
    """Per-VPS event totals. Full GROUP BY over millions of rows is costly and
    the sidebar polls every 10s — cache with stale-while-revalidate so a caller
    never blocks on the recompute (counts drift slowly)."""
    return cached("vps::event_counts", 30.0, _count_events_by_vps, stale_ttl=600.0)


@router.get("", response_model=list[VpsOut])
def list_vps(db: Session = Depends(get_db)) -> list[VpsOut]:
    counts = _event_counts()
    out: list[VpsOut] = []
    for vps in db.execute(select(VpsSource).order_by(VpsSource.alias)).scalars():
        status, _ = vps_status(db, vps)
        model = VpsOut.model_validate(vps)
        model.has_otx_key = vps.alienvault_key_encrypted is not None
        model.status = status
        model.last_seen_at = effective_last_contact(db, vps) or vps.last_seen_at
        model.event_count = counts.get(vps.id, 0)
        out.append(model)
    return out


@router.get("/{alias}/health", response_model=VpsHealth)
def vps_health(alias: str, db: Session = Depends(get_db)) -> VpsHealth:
    vps = db.execute(select(VpsSource).where(VpsSource.alias == alias)).scalar_one_or_none()
    if vps is None:
        raise HTTPException(status_code=404, detail="VPS not found")
    status, secs = vps_status(db, vps)
    last = effective_last_contact(db, vps) or vps.last_seen_at
    return VpsHealth(alias=alias, status=status, last_seen_at=last, seconds_since=secs)


@router.post("/heartbeat", response_model=VpsHealth)
def heartbeat(vps: VpsSource = Depends(get_current_vps), db: Session = Depends(get_db)) -> VpsHealth:
    """Shipper agents ping here between event batches. Auth: per-VPS key."""
    vps.last_seen_at = datetime.now(timezone.utc)
    db.commit()
    status, secs = vps_status(db, vps)
    last = effective_last_contact(db, vps) or vps.last_seen_at
    return VpsHealth(alias=vps.alias, status=status, last_seen_at=last, seconds_since=secs)
