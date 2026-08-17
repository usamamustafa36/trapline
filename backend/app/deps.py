"""FastAPI dependencies: shipper-key auth, admin auth, rate limiting."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import VpsSource
from .security import hash_api_key, verify_admin_token


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.split(" ", 1)[1].strip()


def get_current_vps(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> VpsSource:
    """Resolve the VPS source from its per-node shipper API key."""
    token = _bearer(authorization)
    key_hash = hash_api_key(token)
    vps = db.execute(
        select(VpsSource).where(VpsSource.api_key_hash == key_hash)
    ).scalar_one_or_none()
    if vps is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    if not vps.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="VPS source is disabled")
    return vps


def require_admin(authorization: str | None = Header(default=None)) -> None:
    token = _bearer(authorization)
    if not verify_admin_token(token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")


# ── Simple sliding-window rate limiter (per-VPS key) ────────────────────────
# In-memory; swap for Redis when running >1 API replica (architecure.md §8).
_WINDOW = 60.0
_hits: dict[str, deque[float]] = defaultdict(deque)


def enforce_rate_limit(vps: VpsSource = Depends(get_current_vps)) -> VpsSource:
    now = time.monotonic()
    bucket = _hits[str(vps.id)]
    while bucket and now - bucket[0] > _WINDOW:
        bucket.popleft()
    if len(bucket) >= settings.ingest_rate_limit_per_min:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Ingestion rate limit exceeded for this VPS key",
        )
    bucket.append(now)
    return vps
