"""IP intelligence: cross-VPS list + single-IP deep-dive profile."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Event, IpRegistry, IpVpsSighting, ThreatIntel, VpsSource
from ..schemas import CrossVpsIp, EventOut, IpProfile, ThreatIntelOut
from ..services import coordination_score

router = APIRouter(prefix="/ips", tags=["ips"])


@router.get("/cross-vps", response_model=list[CrossVpsIp])
def cross_vps_ips(
    db: Session = Depends(get_db),
    min_vps: int = Query(default=2, ge=1),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[CrossVpsIp]:
    rows = db.execute(
        select(IpRegistry)
        .where(IpRegistry.vps_count >= min_vps)
        .order_by(IpRegistry.total_events.desc())
        .limit(limit)
    ).scalars().all()

    result: list[CrossVpsIp] = []
    for reg in rows:
        ip = str(reg.ip)
        aliases = db.execute(
            select(VpsSource.alias)
            .join(IpVpsSighting, IpVpsSighting.vps_id == VpsSource.id)
            .where(IpVpsSighting.ip == reg.ip)
            .order_by(VpsSource.alias)
        ).scalars().all()
        ti = db.get(ThreatIntel, reg.ip)
        result.append(
            CrossVpsIp(
                ip=ip,
                vps_count=reg.vps_count,
                vps_aliases=aliases,
                total_events=reg.total_events,
                first_seen_at=reg.first_seen_at,
                last_seen_at=reg.last_seen_at,
                country_code=reg.country_code,
                otx_pulse_count=ti.otx_pulse_count if ti else None,
                reputation_score=float(ti.reputation_score) if ti and ti.reputation_score is not None else None,
                coordination_score=coordination_score(db, ip),
            )
        )
    return result


@router.get("/{ip}", response_model=IpProfile)
def ip_profile(ip: str, db: Session = Depends(get_db)) -> IpProfile:
    reg = db.get(IpRegistry, ip)
    if reg is None:
        raise HTTPException(status_code=404, detail="IP not seen on any source")

    breakdown = []
    rows = db.execute(
        select(
            VpsSource.alias,
            VpsSource.display_name,
            IpVpsSighting.event_count,
            IpVpsSighting.first_seen_at,
            IpVpsSighting.last_seen_at,
        )
        .join(IpVpsSighting, IpVpsSighting.vps_id == VpsSource.id)
        .where(IpVpsSighting.ip == ip)
        .order_by(IpVpsSighting.event_count.desc())
    ).all()
    for alias, name, cnt, first, last in rows:
        protos = db.execute(
            select(Event.protocol, func.count())
            .join(VpsSource, Event.vps_id == VpsSource.id)
            .where(Event.src_ip == ip, VpsSource.alias == alias)
            .group_by(Event.protocol)
        ).all()
        breakdown.append(
            {
                "vps_alias": alias,
                "display_name": name,
                "event_count": cnt,
                "first_seen_at": first.isoformat() if first else None,
                "last_seen_at": last.isoformat() if last else None,
                "protocols": {p or "?": c for p, c in protos},
            }
        )

    ti = db.get(ThreatIntel, ip)
    ti_out = ThreatIntelOut.model_validate(ti) if ti else None

    recent_rows = db.execute(
        select(Event, VpsSource.alias)
        .join(VpsSource, Event.vps_id == VpsSource.id)
        .where(Event.src_ip == ip)
        .order_by(Event.occurred_at.desc())
        .limit(40)
    ).all()
    recent = []
    for ev, alias in recent_rows:
        out = EventOut.model_validate(ev)
        out.src_ip = str(ev.src_ip)
        out.vps_alias = alias
        recent.append(out)

    return IpProfile(
        ip=str(reg.ip),
        first_seen_at=reg.first_seen_at,
        last_seen_at=reg.last_seen_at,
        total_events=reg.total_events,
        vps_count=reg.vps_count,
        is_cross_vps=reg.is_cross_vps,
        country_code=reg.country_code,
        asn=reg.asn,
        vps_breakdown=breakdown,
        threat_intel=ti_out,
        coordination_score=coordination_score(db, str(reg.ip)),
        recent_events=recent,
    )
