"""
SQLAlchemy ORM model for security alerts.

Fields
------
id          : Auto-incrementing integer primary key.
alert_id    : Human-readable unique identifier (UUID4-based, e.g. "ALERT-a3f8…").
alert_type  : Category of the alert (e.g. "Brute Force", "Port Scan").
source_ip   : IPv4 address that triggered the alert.
severity    : Enumerated severity level – Low | Medium | High | Critical.
status      : Workflow state – Open | Investigating | Resolved.
description : Optional free-text context provided by the detection source.
risk_score  : Numeric risk score 0-100 computed by the risk scoring module.
created_at  : UTC datetime when the alert was first persisted.
updated_at  : UTC datetime of the last status/field change.
"""

import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, Integer, String, DateTime, Float, Enum as SAEnum
from app.database.db import Base


# ── Severity Enum ────────────────────────────────────────────────────────────
class SeverityLevel(str, enum.Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"


# ── Status Enum ──────────────────────────────────────────────────────────────
class AlertStatus(str, enum.Enum):
    Open = "Open"
    Investigating = "Investigating"
    Resolved = "Resolved"


# ── ORM Model ────────────────────────────────────────────────────────────────
class Alert(Base):
    """ORM representation of a security alert stored in the database."""

    __tablename__ = "alerts"

    id: int = Column(Integer, primary_key=True, index=True, autoincrement=True)

    alert_id: str = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True,
        default=lambda: f"ALERT-{uuid.uuid4().hex[:8].upper()}",
    )

    alert_type: str = Column(String(100), nullable=False, index=True)
    source_ip: str = Column(String(45), nullable=False)  # 45 chars covers IPv6

    severity: str = Column(
        SAEnum(SeverityLevel, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=SeverityLevel.Medium,
    )

    status: str = Column(
        SAEnum(AlertStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=AlertStatus.Open,
    )

    description: str = Column(String(500), nullable=True)

    risk_score: float = Column(Float, nullable=True, default=0.0)

    created_at: datetime = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at: datetime = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"<Alert alert_id={self.alert_id!r} type={self.alert_type!r} "
            f"severity={self.severity} status={self.status} score={self.risk_score}>"
        )
