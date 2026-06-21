"""
Test suite for alert API endpoints.

Run with:  pytest tests/ -v
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.db import Base, get_db

# ── In-memory SQLite for tests (isolated from development DB) ────────────────
TEST_DATABASE_URL = "sqlite:///./test_soar.db"

test_engine = create_engine(
    TEST_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop them after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


client = TestClient(app)


# ── Health check ─────────────────────────────────────────────────────────────
class TestHealthCheck:
    def test_health_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200

    def test_health_response_structure(self):
        response = client.get("/")
        data = response.json()
        assert data["status"] == "running"
        assert data["project"] == "SOAR Incident Containment Engine"


# ── Alert creation ────────────────────────────────────────────────────────────
class TestCreateAlert:
    VALID_PAYLOAD = {
        "alert_type": "Brute Force",
        "source_ip": "192.168.1.100",
        "severity": "HIGH",
        "description": "Multiple failed SSH login attempts detected.",
        "status": "OPEN",
    }

    def test_create_alert_returns_201(self):
        response = client.post("/alerts/", json=self.VALID_PAYLOAD)
        assert response.status_code == 201

    def test_create_alert_response_contains_id(self):
        response = client.post("/alerts/", json=self.VALID_PAYLOAD)
        data = response.json()
        assert "id" in data
        assert data["id"] == 1

    def test_create_alert_preserves_fields(self):
        response = client.post("/alerts/", json=self.VALID_PAYLOAD)
        data = response.json()
        assert data["alert_type"] == "Brute Force"
        assert data["source_ip"] == "192.168.1.100"
        assert data["severity"] == "HIGH"

    def test_create_alert_invalid_ip_returns_422(self):
        payload = {**self.VALID_PAYLOAD, "source_ip": "not-an-ip"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_create_alert_invalid_severity_returns_422(self):
        payload = {**self.VALID_PAYLOAD, "severity": "EXTREME"}
        response = client.post("/alerts/", json=payload)
        assert response.status_code == 422

    def test_create_alert_missing_required_fields_returns_422(self):
        response = client.post("/alerts/", json={})
        assert response.status_code == 422


# ── Alert listing ─────────────────────────────────────────────────────────────
class TestListAlerts:
    def _seed_alerts(self):
        payloads = [
            {"alert_type": "Port Scan", "source_ip": "10.0.0.1", "severity": "LOW"},
            {"alert_type": "SQL Injection", "source_ip": "10.0.0.2", "severity": "CRITICAL"},
            {"alert_type": "DDoS", "source_ip": "10.0.0.3", "severity": "HIGH"},
        ]
        for p in payloads:
            client.post("/alerts/", json=p)

    def test_list_alerts_returns_200(self):
        response = client.get("/alerts/")
        assert response.status_code == 200

    def test_list_alerts_response_structure(self):
        response = client.get("/alerts/")
        data = response.json()
        assert "total" in data
        assert "alerts" in data

    def test_list_alerts_returns_seeded_data(self):
        self._seed_alerts()
        response = client.get("/alerts/")
        data = response.json()
        assert data["total"] == 3
        assert len(data["alerts"]) == 3

    def test_filter_by_severity(self):
        self._seed_alerts()
        response = client.get("/alerts/?severity=CRITICAL")
        data = response.json()
        assert all(a["severity"] == "CRITICAL" for a in data["alerts"])


# ── Get single alert ──────────────────────────────────────────────────────────
class TestGetAlert:
    def test_get_existing_alert(self):
        client.post("/alerts/", json={
            "alert_type": "Malware", "source_ip": "172.16.0.1", "severity": "HIGH"
        })
        response = client.get("/alerts/1")
        assert response.status_code == 200
        assert response.json()["id"] == 1

    def test_get_nonexistent_alert_returns_404(self):
        response = client.get("/alerts/9999")
        assert response.status_code == 404
