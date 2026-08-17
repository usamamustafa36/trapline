"""Threat intelligence ingestion from VPS OTX verdicts."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import enforce_rate_limit
from ..models import VpsSource
from ..schemas import ThreatIntelBatchIn, ThreatIntelIngestResponse
from ..services import ingest_threat_intel_batch

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.post("", response_model=ThreatIntelIngestResponse, status_code=202)
def ingest_threat_intel(
    payload: ThreatIntelBatchIn,
    vps: VpsSource = Depends(enforce_rate_limit),
    db: Session = Depends(get_db),
) -> ThreatIntelIngestResponse:
    """Bulk ingest OTX verdicts already computed on a VPS. Auth: per-VPS bearer key."""
    return ingest_threat_intel_batch(db, vps, payload.reports)
