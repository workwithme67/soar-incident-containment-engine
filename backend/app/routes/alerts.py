"""
Alert router – HTTP layer for alert management endpoints.

Endpoints
---------
POST   /alerts                      Create a new security alert.
GET    /alerts                      List all alerts (filters & pagination).
GET    /alerts/{alert_id}           Retrieve a single alert by integer ID.
PATCH  /alerts/{alert_id}/status    Update alert workflow status.
GET    /alerts/{alert_id}/enrich    Get threat intelligence for an alert's IP.
"""

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.alert import AlertStatus, SeverityLevel
from app.models.schemas import (
    AlertCreate,
    AlertListResponse,
    AlertResponse,
    AlertStatusUpdate,
)
from app.services import alert_service, threat_intelligence
from app.services.risk_scoring import score_summary
from app.utils.helpers import get_logger

router = APIRouter()
logger = get_logger(__name__)


# ── POST /alerts ─────────────────────────────────────────────────────────────
@router.post(
    "/",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new security alert",
    description=(
        "Creates a new security alert. The system automatically:\n"
        "1. Validates the source IPv4 address and severity.\n"
        "2. Runs mock threat intelligence enrichment (AbuseIPDB + VirusTotal).\n"
        "3. Computes a risk score (0-100) from severity, type, and TI data.\n"
        "4. Persists the alert and returns the full record."
    ),
)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Ingest and persist a new security alert with automatic risk scoring."""
    return alert_service.create_alert(db=db, payload=payload)


# ── GET /alerts ───────────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List security alerts",
    description=(
        "Returns a paginated list of security alerts. "
        "Supports filtering by severity and status."
    ),
)
def list_alerts(
    skip: int = Query(default=0, ge=0, description="Records to skip (offset)"),
    limit: int = Query(default=50, ge=1, le=100, description="Max records to return"),
    severity: Optional[SeverityLevel] = Query(
        default=None, description="Filter by severity (Low | Medium | High | Critical)"
    ),
    alert_status: Optional[AlertStatus] = Query(
        default=None,
        alias="status",
        description="Filter by status (Open | Investigating | Resolved)",
    ),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """Retrieve a paginated list of security alerts with optional filters."""
    alerts = alert_service.get_alerts(
        db=db, skip=skip, limit=limit, severity=severity, status=alert_status
    )
    total = alert_service.count_alerts(db=db)
    return AlertListResponse(total=total, alerts=alerts)


# ── GET /alerts/{alert_id} ────────────────────────────────────────────────────
@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get a single alert by ID",
    description="Retrieve a specific security alert by its integer primary key.",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Retrieve a specific security alert by its numeric ID."""
    return alert_service.get_alert_by_id(db=db, alert_id=alert_id)


# ── PATCH /alerts/{alert_id}/status ──────────────────────────────────────────
@router.patch(
    "/{alert_id}/status",
    response_model=AlertResponse,
    summary="Update alert workflow status",
    description=(
        "Update the workflow status of an alert.\n\n"
        "**Allowed status values:** Open | Investigating | Resolved\n\n"
        "The `updated_at` timestamp is automatically refreshed."
    ),
)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """
    Transition the alert's workflow status.

    - **Open** → initial state after alert ingestion.
    - **Investigating** → analyst is actively working the alert.
    - **Resolved** → alert has been closed / remediated.
    """
    return alert_service.update_alert_status(db=db, alert_id=alert_id, payload=payload)


# ── GET /alerts/{alert_id}/enrich ────────────────────────────────────────────
@router.get(
    "/{alert_id}/enrich",
    summary="Threat intelligence enrichment for an alert",
    description=(
        "Returns AbuseIPDB and VirusTotal threat intelligence data for the "
        "source IP of the specified alert, plus risk score details."
    ),
)
def enrich_alert(
    alert_id: int,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Return threat intelligence enrichment and risk score summary for an alert.
    """
    alert = alert_service.get_alert_by_id(db=db, alert_id=alert_id)
    ti_data   = threat_intelligence.enrich_ip(alert.source_ip)
    risk_info = score_summary(alert.risk_score)

    return {
        "alert_id":            alert.alert_id,
        "source_ip":           alert.source_ip,
        "risk_info":           risk_info,
        "threat_intelligence": ti_data,
    }
