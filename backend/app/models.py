"""SQLAlchemy ORM models — mirrors the schema in architecure.md §3."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _ts():
    return mapped_column(TIMESTAMP(timezone=True))


class VpsSource(Base):
    __tablename__ = "vps_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alias: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text)
    stack_type: Mapped[str | None] = mapped_column(Text)  # react_pg | html_fastapi | ...
    region: Mapped[str | None] = mapped_column(Text)      # human label, e.g. "Jakarta, ID"
    lat: Mapped[float | None] = mapped_column(Numeric)
    lon: Mapped[float | None] = mapped_column(Numeric)
    api_key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    alienvault_key_encrypted: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=text("TRUE"))
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=text("now()"))
    last_seen_at: Mapped[datetime | None] = _ts()

    events: Mapped[list["Event"]] = relationship(back_populates="vps")


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_uuid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, nullable=False)
    vps_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vps_sources.id"), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=text("now()"))
    src_ip: Mapped[str] = mapped_column(INET, nullable=False)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(Text)
    event_type: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[int] = mapped_column(SmallInteger, server_default=text("0"))
    username_tried: Mapped[str | None] = mapped_column(Text)
    password_tried: Mapped[str | None] = mapped_column(Text)
    payload_excerpt: Mapped[str | None] = mapped_column(Text)
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    country_code: Mapped[str | None] = mapped_column(String(2))
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=text("now()"))

    vps: Mapped["VpsSource"] = relationship(back_populates="events")

    __table_args__ = (
        Index("idx_events_vps_time", "vps_id", text("occurred_at DESC")),
        Index("idx_events_src_ip", "src_ip"),
        Index("idx_events_type", "event_type"),
        Index("idx_events_raw_payload_gin", "raw_payload", postgresql_using="gin"),
        # Default listing order (occurred_at DESC) across all sensors.
        Index("idx_events_occurred_at", text("occurred_at DESC"), text("id DESC")),
        # Fast MAX(received_at) per sensor for health / last-contact checks.
        Index("idx_events_vps_received", "vps_id", text("received_at DESC")),
        # Per-IP recent-activity lookups (IP profile page).
        Index("idx_events_src_ip_time", "src_ip", text("occurred_at DESC")),
        # Index-only scans for the dashboard's top-N aggregate panels.
        Index("idx_events_protocol", "protocol", postgresql_where=text("protocol IS NOT NULL")),
        Index("idx_events_country", "country_code", postgresql_where=text("country_code IS NOT NULL")),
        Index("idx_events_password", "password_tried", postgresql_where=text("password_tried IS NOT NULL")),
    )


class IpRegistry(Base):
    __tablename__ = "ip_registry"

    ip: Mapped[str] = mapped_column(INET, primary_key=True)
    first_seen_at: Mapped[datetime | None] = _ts()
    last_seen_at: Mapped[datetime | None] = _ts()
    total_events: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    vps_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    country_code: Mapped[str | None] = mapped_column(String(2))
    asn: Mapped[str | None] = mapped_column(Text)
    is_cross_vps: Mapped[bool] = mapped_column(Boolean, server_default=text("FALSE"))


class IpVpsSighting(Base):
    __tablename__ = "ip_vps_sightings"

    ip: Mapped[str] = mapped_column(INET, ForeignKey("ip_registry.ip"), primary_key=True)
    vps_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vps_sources.id"), primary_key=True)
    first_seen_at: Mapped[datetime | None] = _ts()
    last_seen_at: Mapped[datetime | None] = _ts()
    event_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    ip: Mapped[str] = mapped_column(INET, ForeignKey("ip_registry.ip"), primary_key=True)
    otx_pulse_count: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    reputation_score: Mapped[float | None] = mapped_column(Numeric)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    malware_families: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    last_checked_at: Mapped[datetime | None] = _ts()
    checked_via_vps: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("vps_sources.id"))
    raw_response: Mapped[dict | None] = mapped_column(JSONB)
