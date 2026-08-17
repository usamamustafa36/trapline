"""
Analysis and detection-content endpoints.

Read-only. The heavy aggregations are cached briefly, because they scan the whole
events table and the answers only change when new telemetry lands.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from .. import analytics, detections
from ..database import get_db

router = APIRouter(tags=["analysis"])

_CACHE: dict[str, tuple[float, Any]] = {}
_TTL = 300.0


def _cached(key: str, producer):
    hit = _CACHE.get(key)
    now = time.time()
    if hit and now - hit[0] < _TTL:
        return hit[1]
    value = producer()
    _CACHE[key] = (now, value)
    return value


@router.get("/analysis/overview")
def analysis_overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Headline counts and the real per-sensor deployment window."""
    return _cached("overview", lambda: analytics.overview(db))


@router.get("/analysis/coordination")
def analysis_coordination(
    db: Session = Depends(get_db),
    limit: int = Query(40, ge=1, le=2000),
) -> dict[str, Any]:
    """Cross-sensor addresses classified by the shape of their inter-sensor lag."""
    return _cached(f"coord:{limit}", lambda: analytics.coordination(db, limit=limit))


@router.get("/analysis/clients")
def analysis_clients(db: Session = Depends(get_db)) -> dict[str, Any]:
    """SSH client banners grouped into automation, interactive, and other."""
    return _cached("clients", lambda: analytics.client_fingerprints(db))


@router.get("/analysis/credentials")
def analysis_credentials(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Credential ladders, and the groups of sources that share one."""
    return _cached("creds", lambda: analytics.credential_ladders(db))


@router.get("/analysis/guessing")
def analysis_guessing(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Guessing versus spraying versus stuffing, by account/password fan-out."""
    return _cached("guess", lambda: analytics.guessing_style(db))


@router.get("/analysis/commands")
def analysis_commands(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Observed shell commands mapped to lifecycle phases and ATT&CK techniques."""
    return _cached("cmds", lambda: analytics.command_phases(db))


@router.get("/analysis/rhythm")
def analysis_rhythm(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Hour-of-day activity and a flatness measure."""
    return _cached("rhythm", lambda: analytics.rhythm(db))


@router.get("/analysis/http")
def analysis_http(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Which application paths and user agents the HTTP probes used."""
    return _cached("http", lambda: analytics.http_surface(db))


@router.get("/analysis/report")
def analysis_report(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Everything at once, for the analysis view's first paint."""
    return _cached("report", lambda: analytics.full_report(db))


# ── Detection content ───────────────────────────────────────────────────────────


@router.get("/detections/sigma")
def sigma_rules(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Sigma rules derived from observed telemetry, as structured JSON."""
    rules = _cached("sigma", lambda: detections.build_rules(db))
    return {"count": len(rules), "rules": rules}


@router.get("/detections/sigma.yml", response_class=PlainTextResponse)
def sigma_rules_yaml(db: Session = Depends(get_db)) -> PlainTextResponse:
    """The same rules as a multi-document Sigma YAML file, ready to drop in a repo."""
    rules = _cached("sigma", lambda: detections.build_rules(db))
    body = (
        f"# {len(rules)} Sigma rule(s) generated from honeypot telemetry.\n"
        "# Each rule carries a trapline_evidence block recording what it was derived from.\n\n"
        + detections.rules_as_yaml(rules)
    )
    return PlainTextResponse(
        body,
        media_type="text/yaml",
        headers={"Content-Disposition": 'attachment; filename="trapline-sigma.yml"'},
    )


@router.get("/detections/stix")
def stix(db: Session = Depends(get_db)) -> dict[str, Any]:
    """STIX 2.1 bundle of indicators and attack patterns."""
    return _cached("stix", lambda: detections.stix_bundle(db))


@router.get("/detections/blocklist")
def blocklist(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Scored blocklist from cross-sensor coordination, with nftables output."""
    return _cached("blocklist", lambda: detections.blocklist(db))
