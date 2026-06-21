"""
Seed script – populates the database with realistic sample security alerts.

Usage (from the backend/ directory):
    python -m tests.seed_data
"""

import sys
import os

# Allow running from the backend/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.database.db import engine, Base, SessionLocal
from app.models.alert import Alert, SeverityLevel, AlertStatus
from datetime import datetime, timezone, timedelta


SAMPLE_ALERTS = [
    {
        "alert_type": "Brute Force",
        "source_ip": "203.0.113.42",
        "severity": SeverityLevel.HIGH,
        "description": "348 failed SSH login attempts in 60 seconds against auth-server-01.",
        "status": AlertStatus.OPEN,
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
    },
    {
        "alert_type": "Port Scan",
        "source_ip": "198.51.100.17",
        "severity": SeverityLevel.MEDIUM,
        "description": "Nmap-style scan detected across 1024 ports on DMZ subnet.",
        "status": AlertStatus.IN_PROGRESS,
        "timestamp": datetime.now(timezone.utc) - timedelta(minutes=30),
    },
    {
        "alert_type": "SQL Injection",
        "source_ip": "192.0.2.88",
        "severity": SeverityLevel.CRITICAL,
        "description": "UNION-based SQL injection payload detected in /api/users query parameter.",
        "status": AlertStatus.OPEN,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=1),
    },
    {
        "alert_type": "DDoS",
        "source_ip": "45.33.32.156",
        "severity": SeverityLevel.CRITICAL,
        "description": "SYN flood attack – 85,000 packets/sec targeting load balancer on port 443.",
        "status": AlertStatus.IN_PROGRESS,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=2),
    },
    {
        "alert_type": "Malware Detected",
        "source_ip": "10.0.1.55",
        "severity": SeverityLevel.HIGH,
        "description": "Ransomware binary (SHA256: a3f8...) detected on endpoint WIN-DESK-055.",
        "status": AlertStatus.OPEN,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=3),
    },
    {
        "alert_type": "Phishing",
        "source_ip": "185.220.101.9",
        "severity": SeverityLevel.MEDIUM,
        "description": "Phishing email with malicious macro-enabled attachment blocked by email gateway.",
        "status": AlertStatus.RESOLVED,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=6),
    },
    {
        "alert_type": "Privilege Escalation",
        "source_ip": "10.0.0.201",
        "severity": SeverityLevel.CRITICAL,
        "description": "sudo -l abuse detected; user 'jdoe' gained root on prod-db-02 without MFA.",
        "status": AlertStatus.OPEN,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=8),
    },
    {
        "alert_type": "Data Exfiltration",
        "source_ip": "10.0.5.23",
        "severity": SeverityLevel.HIGH,
        "description": "Unusual outbound transfer of 4.2 GB to external IP over port 22.",
        "status": AlertStatus.IN_PROGRESS,
        "timestamp": datetime.now(timezone.utc) - timedelta(hours=12),
    },
    {
        "alert_type": "Insider Threat",
        "source_ip": "10.10.0.88",
        "severity": SeverityLevel.HIGH,
        "description": "Employee accessed 1,200+ sensitive records outside normal working hours.",
        "status": AlertStatus.OPEN,
        "timestamp": datetime.now(timezone.utc) - timedelta(days=1),
    },
    {
        "alert_type": "Reconnaissance",
        "source_ip": "198.18.0.7",
        "severity": SeverityLevel.LOW,
        "description": "OSINT-level DNS enumeration and WHOIS lookups detected for company domain.",
        "status": AlertStatus.DISMISSED,
        "timestamp": datetime.now(timezone.utc) - timedelta(days=2),
    },
]


def seed() -> None:
    """Create tables (if needed) and insert sample alerts."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing = db.query(Alert).count()
        if existing > 0:
            print(f"[seed] Database already contains {existing} alerts. Skipping.")
            return

        for data in SAMPLE_ALERTS:
            db.add(Alert(**data))
        db.commit()
        print(f"[seed] OK - Inserted {len(SAMPLE_ALERTS)} sample alerts.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
