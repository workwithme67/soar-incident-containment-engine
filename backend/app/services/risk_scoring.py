"""
Risk Scoring Module
===================
Calculates a numeric risk score (0-100) for a security alert based on
multiple weighted factors and maps it to a risk level label.

Risk Level Bands
----------------
  0  – 25  → Low
  26 – 50  → Medium
  51 – 75  → High
  76 – 100 → Critical

Scoring Factors (sum → normalised to 0-100)
-------------------------------------------
  1. Severity weight        (max 40 pts)
  2. Alert type weight      (max 30 pts)
  3. Threat intelligence    (max 20 pts)
  4. Time-of-day penalty    (max 10 pts)

Usage
-----
  from app.services.risk_scoring import calculate_risk_score, get_risk_level

  score = calculate_risk_score(severity="High", alert_type="Brute Force",
                               ti_score=0.8, is_off_hours=True)
  level = get_risk_level(score)   # → "High"
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.utils.helpers import get_logger

logger = get_logger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

# Severity → base score contribution (out of 40)
SEVERITY_WEIGHTS: dict[str, float] = {
    "Low":      10.0,
    "Medium":   20.0,
    "High":     30.0,
    "Critical": 40.0,
}

# Alert type → additional score contribution (out of 30)
ALERT_TYPE_WEIGHTS: dict[str, float] = {
    "Brute Force":          20.0,
    "Credential Stuffing":  22.0,
    "SQL Injection":        25.0,
    "Command Injection":    28.0,
    "Privilege Escalation": 28.0,
    "Ransomware":           30.0,
    "Malware Detected":     25.0,
    "Malware Detection":    25.0,
    "Data Exfiltration":    28.0,
    "DDoS":                 22.0,
    "Port Scan":            12.0,
    "Reconnaissance":        8.0,
    "Phishing":             18.0,
    "Suspicious Login":     15.0,
    "Insider Threat":       24.0,
    "Zero-Day Exploit":     30.0,
    "Lateral Movement":     26.0,
    "C2 Communication":     27.0,
}

# Risk level thresholds
RISK_BANDS: list[tuple[int, int, str]] = [
    (0,  25,  "Low"),
    (26, 50,  "Medium"),
    (51, 75,  "High"),
    (76, 100, "Critical"),
]

# Off-hours: 00:00 – 06:00 UTC (max 10 pts)
OFF_HOURS_BONUS: float = 10.0
OFF_HOURS_RANGE: tuple[int, int] = (0, 6)   # UTC hours


# ── Public API ───────────────────────────────────────────────────────────────

def calculate_risk_score(
    severity: str,
    alert_type: str,
    ti_score: float = 0.0,          # Threat intelligence confidence 0.0–1.0
    is_off_hours: Optional[bool] = None,
) -> float:
    """
    Compute a risk score in the range [0.0, 100.0].

    Parameters
    ----------
    severity     : Severity label (Low | Medium | High | Critical).
    alert_type   : Category of the security alert.
    ti_score     : Threat intelligence abuse confidence (0.0 = clean, 1.0 = confirmed malicious).
    is_off_hours : Override for off-hours flag; auto-detected from UTC clock if None.

    Returns
    -------
    float : Clamped risk score in [0.0, 100.0].
    """
    # 1. Severity component (0-40)
    sev_pts = SEVERITY_WEIGHTS.get(severity, SEVERITY_WEIGHTS["Medium"])

    # 2. Alert-type component (0-30); default to 15 for unknown types
    type_pts = ALERT_TYPE_WEIGHTS.get(alert_type, 15.0)

    # 3. Threat intelligence component (0-20)
    ti_pts = ti_score * 20.0

    # 4. Off-hours penalty (0-10)
    if is_off_hours is None:
        current_hour = datetime.now(timezone.utc).hour
        is_off_hours = OFF_HOURS_RANGE[0] <= current_hour < OFF_HOURS_RANGE[1]
    off_pts = OFF_HOURS_BONUS if is_off_hours else 0.0

    raw_score = sev_pts + type_pts + ti_pts + off_pts
    clamped = round(min(max(raw_score, 0.0), 100.0), 2)

    logger.info(
        "Risk score computed | alert_type=%s severity=%s ti_score=%.2f "
        "off_hours=%s -> score=%.2f",
        alert_type, severity, ti_score, is_off_hours, clamped,
    )
    return clamped


def get_risk_level(score: float) -> str:
    """
    Map a numeric risk score to a risk level label.

    Parameters
    ----------
    score : Numeric risk score in [0, 100].

    Returns
    -------
    str : One of 'Low', 'Medium', 'High', 'Critical'.
    """
    for low, high, label in RISK_BANDS:
        if low <= score <= high:
            return label
    return "Critical"   # Fallback for scores exactly at 100


def score_summary(score: float) -> dict:
    """
    Return a full scoring summary dictionary.

    Useful for API responses that want to expose the risk breakdown.
    """
    level = get_risk_level(score)
    return {
        "risk_score": score,
        "risk_level": level,
        "bands": {
            "Low":      "0–25",
            "Medium":   "26–50",
            "High":     "51–75",
            "Critical": "76–100",
        },
    }
