"""Domain services: event ingestion, IP-registry linking, coordination scoring."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from .models import Event, IpRegistry, IpVpsSighting, VpsSource
from .schemas import EventAck, EventIn, IngestResponse

# Free-text sensor "Description" → controlled event-type vocabulary.
_TYPE_MAP = {
    "ssh": "ssh_login_attempt",
    "http": "http_scan",
    "telnet": "telnet_login_attempt",
    "ftp": "ftp_login_attempt",
    "smtp": "smtp_probe",
    "tcp": "tcp_connect",
}


def normalize_event_type(raw_type: str | None, protocol: str | None) -> str:
    if raw_type:
        low = raw_type.lower()
        for key, canon in _TYPE_MAP.items():
            if key in low:
                return canon
        return raw_type
    if protocol:
        return _TYPE_MAP.get(protocol.lower(), f"{protocol.lower()}_event")
    return "unknown"


def ingest_batch(db: Session, vps: VpsSource, events: list[EventIn]) -> IngestResponse:
    """Idempotent bulk ingest keyed on event_uuid, with IP-registry linking."""
    results: list[EventAck] = []
    accepted = duplicates = rejected = 0

    incoming_uuids = [e.event_uuid for e in events]
    existing = set(
        db.execute(
            select(Event.event_uuid).where(Event.event_uuid.in_(incoming_uuids))
        ).scalars()
    )

    # Track per-IP roll-ups within this batch to minimise UPSERT round-trips.
    ip_touch: dict[str, dict] = {}

    for ev in events:
        if ev.event_uuid in existing:
            duplicates += 1
            results.append(EventAck(event_uuid=ev.event_uuid, status="duplicate"))
            continue
        try:
            src_ip = str(ev.src_ip)
            row = Event(
                event_uuid=ev.event_uuid,
                vps_id=vps.id,
                occurred_at=ev.occurred_at,
                src_ip=src_ip,
                dst_port=ev.dst_port,
                protocol=ev.protocol,
                event_type=normalize_event_type(ev.event_type, ev.protocol),
                severity=ev.severity,
                username_tried=ev.username_tried,
                password_tried=ev.password_tried,
                payload_excerpt=ev.payload_excerpt,
                raw_payload=ev.raw or {},
                country_code=ev.country_code,
            )
            db.add(row)
            existing.add(ev.event_uuid)  # guard against in-batch dup
            accepted += 1
            results.append(EventAck(event_uuid=ev.event_uuid, status="accepted"))

            t = ip_touch.setdefault(
                src_ip,
                {"count": 0, "first": ev.occurred_at, "last": ev.occurred_at, "cc": ev.country_code},
            )
            t["count"] += 1
            t["first"] = min(t["first"], ev.occurred_at)
            t["last"] = max(t["last"], ev.occurred_at)
            if ev.country_code:
                t["cc"] = ev.country_code
        except Exception as exc:  # pragma: no cover - defensive
            rejected += 1
            results.append(EventAck(event_uuid=ev.event_uuid, status="rejected", detail=str(exc)))

    now = datetime.now(timezone.utc)
    if accepted:
        db.flush()
        _link_ips(db, vps.id, ip_touch)

    # Any shipper POST (new or duplicate events) counts as liveness for status dots.
    if events:
        vps.last_seen_at = now

    db.commit()
    return IngestResponse(
        received=len(events),
        accepted=accepted,
        duplicates=duplicates,
        rejected=rejected,
        results=results,
    )


def _link_ips(db: Session, vps_id: uuid.UUID, ip_touch: dict[str, dict]) -> None:
    """Section 5: UPSERT ip_registry + ip_vps_sightings, recompute cross-VPS flags."""
    for ip, t in ip_touch.items():
        # ip_registry upsert
        db.execute(
            pg_insert(IpRegistry)
            .values(
                ip=ip,
                first_seen_at=t["first"],
                last_seen_at=t["last"],
                total_events=t["count"],
                country_code=t["cc"],
            )
            .on_conflict_do_update(
                index_elements=[IpRegistry.ip],
                set_={
                    "last_seen_at": func.greatest(IpRegistry.last_seen_at, t["last"]),
                    "first_seen_at": func.least(IpRegistry.first_seen_at, t["first"]),
                    "total_events": IpRegistry.total_events + t["count"],
                    "country_code": func.coalesce(IpRegistry.country_code, t["cc"]),
                },
            )
        )
        # ip_vps_sightings upsert
        db.execute(
            pg_insert(IpVpsSighting)
            .values(
                ip=ip,
                vps_id=vps_id,
                first_seen_at=t["first"],
                last_seen_at=t["last"],
                event_count=t["count"],
            )
            .on_conflict_do_update(
                index_elements=[IpVpsSighting.ip, IpVpsSighting.vps_id],
                set_={
                    "last_seen_at": func.greatest(IpVpsSighting.last_seen_at, t["last"]),
                    "first_seen_at": func.least(IpVpsSighting.first_seen_at, t["first"]),
                    "event_count": IpVpsSighting.event_count + t["count"],
                },
            )
        )

    # Recompute vps_count / is_cross_vps for touched IPs.
    for ip in ip_touch:
        cnt = db.execute(
            select(func.count(func.distinct(IpVpsSighting.vps_id))).where(IpVpsSighting.ip == ip)
        ).scalar_one()
        db.execute(
            IpRegistry.__table__.update()
            .where(IpRegistry.ip == ip)
            .values(vps_count=cnt, is_cross_vps=cnt > 1)
        )


def coordination_score(db: Session, ip: str) -> int:
    """
    0-100 heuristic (architecure.md §5): high when an IP hits multiple VPS
    inside a tight window (scripted/coordinated recon) vs. spread over months.
    """
    sightings = db.execute(
        select(IpVpsSighting.first_seen_at, IpVpsSighting.last_seen_at, IpVpsSighting.event_count)
        .where(IpVpsSighting.ip == ip)
    ).all()
    if len(sightings) < 2:
        return 0

    firsts = [s.first_seen_at for s in sightings if s.first_seen_at]
    if len(firsts) < 2:
        return 0
    spread = max(firsts) - min(firsts)

    # VPS breadth: more distinct VPS => more coordinated.
    breadth = min(len(sightings) / 3.0, 1.0) * 40

    # Temporal tightness: <1h across VPS => very coordinated; >30d => scanner noise.
    if spread <= timedelta(hours=1):
        temporal = 45
    elif spread <= timedelta(hours=24):
        temporal = 35
    elif spread <= timedelta(days=7):
        temporal = 20
    elif spread <= timedelta(days=30):
        temporal = 8
    else:
        temporal = 0

    # Volume signal.
    total = sum(s.event_count or 0 for s in sightings)
    volume = min(total / 200.0, 1.0) * 15

    return int(min(breadth + temporal + volume, 100))


def ingest_threat_intel_batch(db, vps, reports) -> "ThreatIntelIngestResponse":
    """Ingest OTX verdicts already computed on a VPS (no central OTX calls)."""
    from datetime import datetime, timezone
    from sqlalchemy.dialects.postgresql import insert as pg_insert
    from .models import IpRegistry, ThreatIntel
    from .schemas import ThreatIntelIngestResponse

    accepted = updated = 0
    now = datetime.now(timezone.utc)

    for report in reports:
        ip = str(report.ip)
        db.execute(
            pg_insert(IpRegistry)
            .values(ip=ip, first_seen_at=now, last_seen_at=now, total_events=0)
            .on_conflict_do_nothing(index_elements=[IpRegistry.ip])
        )

        existing = db.get(ThreatIntel, ip)
        tags = report.tags or []
        families = report.malware_families or []
        pulse_count = int(report.otx_pulse_count or 0)
        if report.is_malicious and pulse_count == 0:
            pulse_count = 1

        raw = {
            "is_malicious": report.is_malicious,
            "malicious_status": report.malicious_status,
            "ip_type": report.ip_type,
            "malware_sample_count": report.malware_sample_count,
            "asn": report.asn,
            "country_name": report.country_name,
            "attack_count": report.attack_count,
            "top_protocol": report.top_protocol,
            "protocols": report.protocols,
            "pulse_names": report.pulse_names,
            "bot_tag_matches": report.bot_tag_matches,
            "classification_notes": report.classification_notes,
            "whitelisted": report.whitelisted,
            "vps_alias": vps.alias,
        }

        if existing is None:
            db.add(ThreatIntel(
                ip=ip,
                otx_pulse_count=pulse_count,
                reputation_score=report.reputation_score,
                tags=tags or None,
                malware_families=families or None,
                last_checked_at=report.checked_at or now,
                checked_via_vps=vps.id,
                raw_response=raw,
            ))
            accepted += 1
        else:
            existing.otx_pulse_count = pulse_count
            existing.reputation_score = report.reputation_score
            existing.tags = tags or None
            existing.malware_families = families or None
            existing.last_checked_at = report.checked_at or now
            existing.checked_via_vps = vps.id
            existing.raw_response = raw
            updated += 1

        if report.asn:
            db.execute(
                IpRegistry.__table__.update().where(IpRegistry.ip == ip).values(asn=report.asn)
            )

    if accepted or updated:
        vps.last_seen_at = now
    db.commit()
    return ThreatIntelIngestResponse(received=len(reports), accepted=accepted, updated=updated)
