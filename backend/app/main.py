"""Trapline Command & Control — API entrypoint."""
from __future__ import annotations

import asyncio
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import text

from . import __version__
from .cache import prime
from .config import settings
from .database import SessionLocal, engine
from .geoip import geo_enrich_loop
from .routers import events, export, ips, stats, threat_intel, vps
from .routers.stats import _overview_producer, overview_cache_key
from .vps_health import health_monitor_loop, repair_last_seen_from_events


def _prewarm_overviews() -> None:
    """Populate the overview cache (global + per-sensor) at boot so the first
    visitor never waits on a multi-second aggregate. Runs in a background thread."""
    from sqlalchemy import select as _select

    from .models import VpsSource

    windows = ("24h", "7d", "30d", "all")
    for window in windows:
        prime(overview_cache_key(window), _overview_producer(window, None))

    db = SessionLocal()
    try:
        aliases = list(db.execute(_select(VpsSource.alias)).scalars())
    finally:
        db.close()
    for alias in aliases:
        for window in windows:
            prime(overview_cache_key(window, alias), _overview_producer(window, alias))

# Performance indexes for the events table. Kept idempotent so both fresh and
# already-populated deployments converge to the same optimized schema. These
# mirror the definitions in models.py; declared here too so existing databases
# (where create_all is a no-op for the table) still pick them up on boot.
_PERF_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON events (occurred_at DESC, id DESC)",
    "CREATE INDEX IF NOT EXISTS idx_events_vps_received ON events (vps_id, received_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_events_src_ip_time ON events (src_ip, occurred_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_events_protocol ON events (protocol) WHERE protocol IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_events_country ON events (country_code) WHERE country_code IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_events_password ON events (password_tried) WHERE password_tried IS NOT NULL",
)


def _ensure_perf_indexes() -> None:
    try:
        with engine.begin() as conn:
            for ddl in _PERF_INDEXES:
                conn.execute(text(ddl))
    except Exception as exc:  # noqa: BLE001
        print(f"[startup] perf index check skipped: {exc!r}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Never block request serving on DDL — indexes may wait behind long writes.
    threading.Thread(target=_ensure_perf_indexes, name="perf-indexes", daemon=True).start()

    db = SessionLocal()
    try:
        n = repair_last_seen_from_events(db)
        if n:
            print(f"[health] repaired last_seen_at for {n} sensor(s) from event stream")
    finally:
        db.close()

    # Warm the expensive dashboard aggregates in the background so the first
    # visitor after a restart doesn't wait on a multi-second full-table scan.
    threading.Thread(target=_prewarm_overviews, name="prewarm", daemon=True).start()

    monitor = asyncio.create_task(health_monitor_loop())
    geo = asyncio.create_task(geo_enrich_loop())
    yield
    for task in (monitor, geo):
        task.cancel()
    for task in (monitor, geo):
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="Trapline // Command & Control API",
    description="Central ingestion + threat-intelligence API for distributed honeypot sensors.",
    version=__version__,
    docs_url="/docs",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API = "/api/v1"
app.include_router(events.router, prefix=API)
app.include_router(export.router, prefix=API)
app.include_router(vps.router, prefix=API)
app.include_router(ips.router, prefix=API)
app.include_router(stats.router, prefix=API)
app.include_router(threat_intel.router, prefix=API)


@app.get(f"{API}/health", tags=["ops"])
def health() -> dict:
    return {"status": "operational", "service": "trapline-api", "version": __version__}


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {"service": "Trapline Command & Control", "docs": "/docs", "api": API}
