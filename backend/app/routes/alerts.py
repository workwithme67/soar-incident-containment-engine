"""
Alert router – HTTP layer for alert management endpoints.

Endpoints
---------
POST /alerts         Create a new security alert.
GET  /alerts         List all alerts (with optional filters & pagination).
GET  /alerts/{id}    Retrieve a single alert by ID.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database.db import get_db
from app.models.alert import SeverityLevel, AlertStatus
from app.models.schemas import AlertCreate, AlertResponse, AlertListResponse
from app.services import alert_service

router = APIRouter()


# ── POST /alerts ─────────────────────────────────────────────────────────────
@router.post(
    "/",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new security alert",
)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """
    Ingest and persist a new security alert.

    - **alert_type**: Type / category of the alert.
    - **source_ip**: IPv4 or IPv6 address that triggered the alert.
    - **severity**: Severity level (LOW | MEDIUM | HIGH | CRITICAL).
    - **description**: Optional free-text context.
    - **status**: Initial workflow state (defaults to OPEN).
    """
    return alert_service.create_alert(db=db, payload=payload)


# ── GET /alerts ───────────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List security alerts",
)
def list_alerts(
    skip: int = Query(default=0, ge=0, description="Number of records to skip"),
    limit: int = Query(default=50, ge=1, le=100, description="Max records to return"),
    severity: Optional[SeverityLevel] = Query(default=None, description="Filter by severity"),
    alert_status: Optional[AlertStatus] = Query(
        default=None, alias="status", description="Filter by workflow status"
    ),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    """
    Retrieve a paginated list of security alerts.

    Supports optional filtering by **severity** and **status**.
    """
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
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """Retrieve a specific security alert by its ID."""
    return alert_service.get_alert_by_id(db=db, alert_id=alert_id)
