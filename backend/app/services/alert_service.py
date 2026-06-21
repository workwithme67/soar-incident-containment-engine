"""
Alert service layer – all database operations for the Alert entity.

Keeping business logic here (rather than in the route handlers) ensures
routes stay thin, services stay testable, and the codebase scales cleanly.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.alert import Alert, SeverityLevel, AlertStatus
from app.models.schemas import AlertCreate


# ── Create ───────────────────────────────────────────────────────────────────
def create_alert(db: Session, payload: AlertCreate) -> Alert:
    """
    Persist a new alert to the database.

    Parameters
    ----------
    db      : Active SQLAlchemy session (injected via FastAPI dependency).
    payload : Validated Pydantic payload from the request body.

    Returns
    -------
    Alert : The newly created ORM instance with a populated ``id``.
    """
    alert = Alert(
        alert_type=payload.alert_type,
        source_ip=payload.source_ip,
        severity=payload.severity,
        description=payload.description,
        status=payload.status,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


# ── Read (list) ───────────────────────────────────────────────────────────────
def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
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

    return query.order_by(Alert.timestamp.desc()).offset(skip).limit(limit).all()


# ── Read (single) ─────────────────────────────────────────────────────────────
def get_alert_by_id(db: Session, alert_id: int) -> Alert:
    """
    Fetch a single alert by its primary key.

    Raises 404 if not found.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with id={alert_id} not found.",
        )
    return alert


# ── Count (helper) ────────────────────────────────────────────────────────────
def count_alerts(db: Session) -> int:
    """Return the total number of alerts in the database."""
    return db.query(Alert).count()
