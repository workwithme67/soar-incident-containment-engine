"""
Alert service layer – all database operations for the Alert entity.

Responsibilities
----------------
- CRUD operations on Alert rows.
- Orchestrates risk scoring on alert creation.
- Orchestrates threat intelligence enrichment on alert creation.
- Status transition validation.
- Structured logging for all mutating operations.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus, SeverityLevel
from app.models.schemas import AlertCreate, AlertStatusUpdate
from app.services import risk_scoring, threat_intelligence
from app.utils.helpers import get_logger

logger = get_logger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_alert_id() -> str:
    """Generate a human-readable unique alert identifier."""
    return f"ALERT-{uuid.uuid4().hex[:8].upper()}"


# ── Create ────────────────────────────────────────────────────────────────────

def create_alert(db: Session, payload: AlertCreate) -> Alert:
    """
    Persist a new alert to the database.

    Steps:
      1. Fetch TI data for source_ip (mock).
      2. Compute risk score from severity + alert_type + TI confidence.
      3. Persist alert with computed risk_score.
      4. Return the fully-populated ORM instance.

    Parameters
    ----------
    db      : Active SQLAlchemy session.
    payload : Validated Pydantic payload from the request body.

    Returns
    -------
    Alert : The newly created ORM instance with a populated id and alert_id.
    """
    # Step 1: Threat intelligence enrichment
    try:
        ti_data = threat_intelligence.enrich_ip(payload.source_ip)
        ti_score = ti_data["aggregate_confidence"] / 100.0  # normalise to [0,1]
        threat_verdict = ti_data["threat_verdict"]
    except Exception as exc:
        logger.warning("TI enrichment failed for %s: %s", payload.source_ip, exc)
        ti_score = 0.0
        threat_verdict = "Unknown"

    # Step 2: Risk scoring
    risk_score = risk_scoring.calculate_risk_score(
        severity=payload.severity,
        alert_type=payload.alert_type,
        ti_score=ti_score,
    )

    # Step 3: Build ORM instance
    alert = Alert(
        alert_id=_generate_alert_id(),
        alert_type=payload.alert_type,
        source_ip=payload.source_ip,
        severity=payload.severity,
        description=payload.description,
        status=payload.status,
        risk_score=risk_score,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    logger.info(
        "Alert created | alert_id=%s type=%s ip=%s severity=%s "
        "risk_score=%.2f ti_verdict=%s",
        alert.alert_id,
        alert.alert_type,
        alert.source_ip,
        alert.severity,
        alert.risk_score,
        threat_verdict,
    )
    return alert


# ── Read (list) ───────────────────────────────────────────────────────────────

def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[SeverityLevel] = None,
    status: Optional[AlertStatus] = None,
) -> List[Alert]:
    """
    Retrieve a paginated, optionally filtered list of alerts.

    Parameters
    ----------
    db       : Active SQLAlchemy session.
    skip     : Number of records to skip (offset).
    limit    : Maximum records to return (capped at 100 per call).
    severity : Optional filter by severity level.
    status   : Optional filter by workflow status.
    """
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)

    return query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()


# ── Read (single by int id) ───────────────────────────────────────────────────

def get_alert_by_id(db: Session, alert_id: int) -> Alert:
    """
    Fetch a single alert by its integer primary key.

    Raises 404 if not found.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return alert


# ── Read (single by alert_id string) ─────────────────────────────────────────

def get_alert_by_alert_id(db: Session, alert_id: str) -> Alert:
    """
    Fetch a single alert by its human-readable alert_id (e.g. "ALERT-A3F80001").

    Raises 404 if not found.
    """
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    return alert


# ── Update status ─────────────────────────────────────────────────────────────

def update_alert_status(
    db: Session,
    alert_id: int,
    payload: AlertStatusUpdate,
) -> Alert:
    """
    Update the workflow status of an alert.

    Allowed transitions:
      Open → Investigating → Resolved
      Any status → Open  (re-open)

    Parameters
    ----------
    db       : Active SQLAlchemy session.
    alert_id : Integer primary key of the alert to update.
    payload  : Validated status update payload.

    Returns
    -------
    Alert : The updated ORM instance.

    Raises
    ------
    HTTPException 404 : Alert not found.
    """
    alert = get_alert_by_id(db=db, alert_id=alert_id)
    old_status = alert.status

    alert.status = payload.status
    alert.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(alert)

    logger.info(
        "Alert status updated | alert_id=%s %s → %s",
        alert.alert_id,
        old_status,
        alert.status,
    )
    return alert


# ── Count (helper) ────────────────────────────────────────────────────────────

def count_alerts(db: Session) -> int:
    """Return the total number of alerts in the database."""
    return db.query(Alert).count()
