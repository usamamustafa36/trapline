"""Pydantic v2 request/response models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


# ── Ingestion ───────────────────────────────────────────────────────────────
class EventIn(BaseModel):
    event_uuid: uuid.UUID
    occurred_at: datetime
    src_ip: IPvAnyAddress
    dst_port: int | None = None
    protocol: str | None = None
    event_type: str | None = None
    severity: int = Field(default=0, ge=0, le=4)
    username_tried: str | None = None
    password_tried: str | None = None
    payload_excerpt: str | None = None
    country_code: str | None = Field(default=None, max_length=2)
    raw: dict[str, Any] = Field(default_factory=dict)


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)


class EventAck(BaseModel):
    event_uuid: uuid.UUID
    status: str  # accepted | duplicate | rejected
    detail: str | None = None


class IngestResponse(BaseModel):
    received: int
    accepted: int
    duplicates: int
    rejected: int
    results: list[EventAck]


# ── VPS sources ─────────────────────────────────────────────────────────────
class VpsRegisterIn(BaseModel):
    alias: str = Field(min_length=1, max_length=32)
    display_name: str
    base_url: str | None = None
    stack_type: str | None = None
    region: str | None = None
    lat: float | None = None
    lon: float | None = None
    alienvault_key: str | None = None


class VpsRegisterOut(BaseModel):
    id: uuid.UUID
    alias: str
    api_key: str  # shown ONCE
    message: str = "Store this key now — it is not retrievable later."


class VpsHealth(BaseModel):
    alias: str
    status: str  # online | stale | offline
    last_seen_at: datetime | None
    seconds_since: float | None


class VpsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    alias: str
    display_name: str
    base_url: str | None
    stack_type: str | None
    region: str | None
    lat: float | None
    lon: float | None
    is_active: bool
    last_seen_at: datetime | None
    has_otx_key: bool = False
    status: str = "offline"
    event_count: int = 0


# ── Query / read models ─────────────────────────────────────────────────────
class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    event_uuid: uuid.UUID
    vps_id: uuid.UUID
    vps_alias: str | None = None
    occurred_at: datetime
    received_at: datetime
    src_ip: str
    dst_port: int | None
    protocol: str | None
    event_type: str | None
    severity: int
    username_tried: str | None
    password_tried: str | None
    payload_excerpt: str | None
    country_code: str | None

    # psycopg3 returns INET columns as ipaddress objects — coerce to str.
    @field_validator("src_ip", mode="before")
    @classmethod
    def _ip_to_str(cls, v: object) -> str:
        return str(v)


class PagedEvents(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[EventOut]
    is_estimate: bool = False  # total is a planner estimate for very large result sets


class ThreatIntelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    otx_pulse_count: int
    reputation_score: float | None
    tags: list[str] | None
    malware_families: list[str] | None
    last_checked_at: datetime | None


class IpProfile(BaseModel):
    ip: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    total_events: int
    vps_count: int
    is_cross_vps: bool
    country_code: str | None
    asn: str | None
    vps_breakdown: list[dict[str, Any]]
    threat_intel: ThreatIntelOut | None
    coordination_score: int  # 0-100 heuristic
    recent_events: list[EventOut]


class CrossVpsIp(BaseModel):
    ip: str
    vps_count: int
    vps_aliases: list[str]
    total_events: int
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    country_code: str | None
    otx_pulse_count: int | None
    reputation_score: float | None
    coordination_score: int


# ── Stats ───────────────────────────────────────────────────────────────────
class Kpi(BaseModel):
    events_24h: int
    events_7d: int
    events_30d: int
    events_all: int
    active_vps: int
    total_vps: int
    unique_ips: int
    cross_vps_ips: int
    known_malicious_ips: int


class TimelinePoint(BaseModel):
    bucket: datetime
    counts: dict[str, int]  # alias -> count


class NamedCount(BaseModel):
    name: str
    count: int


class GeoCount(BaseModel):
    country_code: str
    count: int


class StatsOverview(BaseModel):
    kpi: Kpi
    timeline: list[TimelinePoint]
    top_ips: list[CrossVpsIp]
    event_types: list[NamedCount]
    protocols: list[NamedCount]
    geo: list[GeoCount]
    vps_health: list[VpsHealth]
    top_credentials: list[NamedCount]
# Append to backend/app/schemas.py

class ThreatIntelReportIn(BaseModel):
    ip: IPvAnyAddress
    is_malicious: bool = False
    malicious_status: str | None = None
    ip_type: str | None = None
    otx_pulse_count: int = Field(default=0, ge=0)
    reputation_score: float | None = None
    malware_sample_count: int = 0
    tags: list[str] | None = None
    malware_families: list[str] | None = None
    asn: str | None = None
    country_name: str | None = None
    checked_at: datetime | None = None
    attack_count: int = 0
    top_protocol: str | None = None
    protocols: str | None = None
    pulse_names: str | None = None
    bot_tag_matches: str | None = None
    classification_notes: str | None = None
    whitelisted: bool = False


class ThreatIntelBatchIn(BaseModel):
    reports: list[ThreatIntelReportIn] = Field(min_length=1, max_length=200)


class ThreatIntelIngestResponse(BaseModel):
    received: int
    accepted: int
    updated: int
