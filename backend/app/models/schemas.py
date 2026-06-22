"""
Pydantic schemas for request validation and response serialisation.

Separation of concerns:
  AlertBase         – shared fields used by both create and response schemas.
  AlertCreate       – request body for POST /alerts.
  AlertStatusUpdate – request body for PATCH /alerts/{alert_id}/status.
  AlertResponse     – full alert object returned to the client.
  AlertListResponse – paginated list wrapper.
"""

import ipaddress
import re
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from app.models.alert import AlertStatus, SeverityLevel


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
        description="Valid IPv4 address that triggered the alert",
        examples=["192.168.1.100", "10.0.0.1"],
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.Medium,
        description="Severity level of the alert: Low | Medium | High | Critical",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Optional human-readable context",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_ipv4(cls, v: str) -> str:
        """Ensure source_ip is a valid IPv4 address (not IPv6)."""
        # Strip surrounding whitespace
        v = v.strip()
        try:
            addr = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(
                f"'{v}' is not a valid IP address. "
                "Please provide a valid IPv4 address (e.g. 192.168.1.1)."
            )
        if not isinstance(addr, ipaddress.IPv4Address):
            raise ValueError(
                f"'{v}' is an IPv6 address. Only IPv4 addresses are accepted."
            )
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Normalise and validate severity value."""
        allowed = [e.value for e in SeverityLevel]
        # Accept case-insensitive variants (e.g. "high" → "High")
        if isinstance(v, str):
            normalised = v.strip().capitalize()
            if normalised in allowed:
                return normalised
        if v in allowed:
            return v
        raise ValueError(
            f"'{v}' is not a valid severity. Allowed values: {allowed}. "
            "Please use one of: Low, Medium, High, Critical."
        )


# ── Create schema (inbound request) ─────────────────────────────────────────
class AlertCreate(AlertBase):
    """Schema for creating a new alert via POST /alerts."""

    status: AlertStatus = Field(
        default=AlertStatus.Open,
        description="Initial workflow status (Open | Investigating | Resolved)",
    )


# ── Status update schema ─────────────────────────────────────────────────────
class AlertStatusUpdate(BaseModel):
    """Schema for PATCH /alerts/{alert_id}/status."""

    status: AlertStatus = Field(
        ...,
        description="New workflow status (Open | Investigating | Resolved)",
    )

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Normalise and validate status value."""
        allowed = [e.value for e in AlertStatus]
        if isinstance(v, str):
            normalised = v.strip().capitalize()
            if normalised in allowed:
                return normalised
        if v in allowed:
            return v
        raise ValueError(
            f"'{v}' is not a valid status. Allowed values: {allowed}. "
            "Please use one of: Open, Investigating, Resolved."
        )


# ── Response schema (outbound) ───────────────────────────────────────────────
class AlertResponse(AlertBase):
    """Schema returned to the client after creating or fetching an alert."""

    id: int
    alert_id: str
    status: AlertStatus
    risk_score: float
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── List response wrapper ────────────────────────────────────────────────────
class AlertListResponse(BaseModel):
    """Wrapper for paginated alert listings."""

    total: int = Field(..., description="Total number of matching alerts")
    alerts: List[AlertResponse]
