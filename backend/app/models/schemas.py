"""
Pydantic schemas for request validation and response serialisation.

Separation of concerns:
  AlertBase       – shared fields used by both create and response schemas.
  AlertCreate     – request body for POST /alerts (no id / timestamp needed).
  AlertResponse   – full alert object returned to the client.
  AlertListResponse – paginated list wrapper.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import ipaddress

from app.models.alert import SeverityLevel, AlertStatus


# ── Base schema (shared fields) ──────────────────────────────────────────────
class AlertBase(BaseModel):
    alert_type: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Category of the security alert",
        examples=["Brute Force", "Port Scan", "SQL Injection"],
    )
    source_ip: str = Field(
        ...,
        description="IPv4 or IPv6 address that triggered the alert",
        examples=["192.168.1.100"],
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.MEDIUM,
        description="Severity level of the alert",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable context",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Ensure source_ip is a valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{v}' is not a valid IP address.")
        return v


# ── Create schema (inbound request) ─────────────────────────────────────────
class AlertCreate(AlertBase):
    """Schema for creating a new alert via POST /alerts."""

    status: AlertStatus = Field(
        default=AlertStatus.OPEN,
        description="Initial workflow status of the alert",
    )


# ── Response schema (outbound) ───────────────────────────────────────────────
class AlertResponse(AlertBase):
    """Schema returned to the client after creating or fetching an alert."""

    id: int
    timestamp: datetime
    status: AlertStatus

    model_config = {"from_attributes": True}


# ── List response wrapper ────────────────────────────────────────────────────
class AlertListResponse(BaseModel):
    """Wrapper for paginated alert listings."""

    total: int = Field(..., description="Total number of matching alerts")
    alerts: List[AlertResponse]
