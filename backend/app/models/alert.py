"""
SQLAlchemy ORM model for security alerts.

Fields
------
id          : Auto-incrementing primary key.
alert_type  : Category of the alert (e.g. "Brute Force", "Port Scan").
source_ip   : IPv4/IPv6 address that triggered the alert.
severity    : Enumerated severity level – LOW | MEDIUM | HIGH | CRITICAL.
timestamp   : UTC datetime when the alert was first observed.
description : Optional free-text context provided by the detection source.
status      : Workflow state – OPEN | IN_PROGRESS | RESOLVED | DISMISSED.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum as SAEnum
from app.database.db import Base
import enum


class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class Alert(Base):
    """ORM representation of a security alert stored in the database."""

    __tablename__ = "alerts"

    id: int = Column(Integer, primary_key=True, index=True, autoincrement=True)
    alert_type: str = Column(String(100), nullable=False, index=True)
    source_ip: str = Column(String(45), nullable=False)  # 45 chars covers IPv6
    severity: str = Column(
        SAEnum(SeverityLevel), nullable=False, default=SeverityLevel.MEDIUM
    )
    timestamp: datetime = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    description: str = Column(String(500), nullable=True)
    status: str = Column(
        SAEnum(AlertStatus), nullable=False, default=AlertStatus.OPEN
    )

    def __repr__(self) -> str:
        return (
            f"<Alert id={self.id} type={self.alert_type!r} "
            f"severity={self.severity} status={self.status}>"
        )
