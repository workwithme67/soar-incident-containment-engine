# SOAR Incident Containment Engine

> **Security Orchestration, Automation, and Response (SOAR) Platform**
> Internship Project — Infotact | Day 2: Alert Workflow Validation & Risk Scoring

---

## Project Overview

A production-grade FastAPI backend for ingesting, enriching, scoring, and triaging security incidents. The engine automates the first-response workflow by validating incoming alerts, running threat intelligence enrichment (mock), computing risk scores, and maintaining a full audit trail.

---

## Technology Stack

| Layer         | Technology                          |
|---------------|-------------------------------------|
| Framework     | FastAPI 0.111                       |
| ORM           | SQLAlchemy 2.0                      |
| Database      | SQLite (development) / PostgreSQL   |
| Validation    | Pydantic v2                         |
| Server        | Uvicorn                             |
| Testing       | Pytest + FastAPI TestClient         |

---

## Project Structure

```
backend/
├── app/
│   ├── main.py                    # FastAPI app factory & lifespan
│   ├── database/
│   │   └── db.py                  # SQLAlchemy engine + session + Base
│   ├── models/
│   │   ├── alert.py               # Alert ORM model (SeverityLevel, AlertStatus enums)
│   │   └── schemas.py             # Pydantic request/response schemas
│   ├── routes/
│   │   └── alerts.py              # HTTP route handlers
│   ├── services/
│   │   ├── alert_service.py       # Business logic (CRUD + orchestration)
│   │   ├── risk_scoring.py        # Risk score calculation engine
│   │   └── threat_intelligence.py # Mock AbuseIPDB & VirusTotal lookups
│   └── utils/
│       └── helpers.py             # Shared logger factory
├── tests/
│   ├── seed_data.py               # Sample alert seeder script
│   └── test_alerts.py             # Pytest unit tests
├── requirements.txt
└── README.md
```

---

## Database Schema

### Table: `alerts`

| Column       | Type         | Constraints                          | Description                              |
|--------------|--------------|--------------------------------------|------------------------------------------|
| id           | INTEGER      | PRIMARY KEY, AUTOINCREMENT           | Auto-incrementing integer ID             |
| alert_id     | VARCHAR(50)  | UNIQUE, NOT NULL, INDEX              | Human-readable ID (e.g. `ALERT-A3F80001`)|
| alert_type   | VARCHAR(100) | NOT NULL, INDEX                      | Category (Brute Force, Port Scan, etc.)  |
| source_ip    | VARCHAR(45)  | NOT NULL                             | IPv4 address that triggered the alert    |
| severity     | ENUM         | NOT NULL, DEFAULT Medium             | Low \| Medium \| High \| Critical        |
| status       | ENUM         | NOT NULL, DEFAULT Open               | Open \| Investigating \| Resolved        |
| description  | VARCHAR(500) | NULLABLE                             | Optional free-text context               |
| risk_score   | FLOAT        | NOT NULL, DEFAULT 0.0                | Computed risk score (0-100)              |
| created_at   | DATETIME     | NOT NULL                             | UTC creation timestamp                   |
| updated_at   | DATETIME     | NOT NULL                             | UTC last-modified timestamp              |

---

## API Endpoints

### Base URL: `http://localhost:8000`

| Method  | Endpoint                        | Description                                        |
|---------|---------------------------------|----------------------------------------------------|
| GET     | `/`                             | Health check                                       |
| POST    | `/alerts/`                      | Create a new security alert                        |
| GET     | `/alerts/`                      | List alerts (filter by severity/status, paginate)  |
| GET     | `/alerts/{id}`                  | Retrieve a single alert by integer ID              |
| PATCH   | `/alerts/{id}/status`           | Update alert workflow status                       |
| GET     | `/alerts/{id}/enrich`           | Get TI enrichment for an alert's IP               |

### Interactive API Docs: `http://localhost:8000/docs`

---

### POST `/alerts/`

**Request Body:**
```json
{
  "alert_type":  "Brute Force",
  "source_ip":   "203.0.113.42",
  "severity":    "High",
  "description": "348 failed SSH logins in 60 seconds.",
  "status":      "Open"
}
```

**Response (201 Created):**
```json
{
  "id":          1,
  "alert_id":    "ALERT-A3F80001",
  "alert_type":  "Brute Force",
  "source_ip":   "203.0.113.42",
  "severity":    "High",
  "status":      "Open",
  "description": "348 failed SSH logins in 60 seconds.",
  "risk_score":  72.5,
  "created_at":  "2026-06-22T12:00:00Z",
  "updated_at":  "2026-06-22T12:00:00Z"
}
```

### PATCH `/alerts/{id}/status`

**Request Body:**
```json
{ "status": "Investigating" }
```
Allowed values: `Open` | `Investigating` | `Resolved`

### GET `/alerts/{id}/enrich`

**Response:**
```json
{
  "alert_id": "ALERT-A3F80001",
  "source_ip": "203.0.113.42",
  "risk_info": {
    "risk_score": 72.5,
    "risk_level": "High",
    "bands": { "Low": "0–25", "Medium": "26–50", "High": "51–75", "Critical": "76–100" }
  },
  "threat_intelligence": {
    "ip_address": "203.0.113.42",
    "abuseipdb": { ... },
    "virustotal": { ... },
    "aggregate_confidence": 78.4,
    "threat_verdict": "Malicious"
  }
}
```

---

## Input Validation

| Field      | Rule                                                                 |
|------------|----------------------------------------------------------------------|
| source_ip  | Valid **IPv4** address only (IPv6 and hostnames rejected → 422)      |
| severity   | `Low` \| `Medium` \| `High` \| `Critical` (case-insensitive)        |
| status     | `Open` \| `Investigating` \| `Resolved` (case-insensitive)          |
| alert_type | 2-100 characters, required                                           |
| description| Max 500 characters, optional                                         |

---

## Risk Scoring Logic

The risk score is a weighted sum of four factors, clamped to **[0, 100]**:

```
risk_score = severity_pts + alert_type_pts + (ti_score × 20) + off_hours_pts
```

| Factor             | Weight    | Details                                                          |
|--------------------|-----------|------------------------------------------------------------------|
| Severity           | 0–40 pts  | Low=10, Medium=20, High=30, Critical=40                          |
| Alert Type         | 0–30 pts  | Ransomware/Command Injection=30, Reconnaissance=8, etc.          |
| Threat Intelligence| 0–20 pts  | TI aggregate confidence (0.0–1.0) × 20                          |
| Off-Hours          | 0–10 pts  | +10 pts if alert occurs between 00:00–06:00 UTC                 |

### Risk Level Bands

| Score Range | Risk Level |
|-------------|------------|
| 0 – 25      | 🟢 Low      |
| 26 – 50     | 🟡 Medium   |
| 51 – 75     | 🟠 High     |
| 76 – 100    | 🔴 Critical |

---

## Threat Intelligence Service

Mock implementations of real TI APIs (deterministic — same IP always returns same data):

### `check_abuseipdb(ip: str) → dict`
Returns: `ip_address`, `abuse_confidence_score` (0–100), `country_code`, `isp`, `total_reports`, `last_reported_at`, `usage_type`, ...

### `check_virustotal(ip: str) → dict`
Returns: `ip_address`, `malicious_count`, `suspicious_count`, `harmless_count`, `total_engines`, `reputation`, `tags`, `as_owner`, ...

### `enrich_ip(ip: str) → dict`
Runs both lookups and returns a combined report with:
- `aggregate_confidence`: weighted average of both sources
- `threat_verdict`: `Clean` | `Suspicious` | `Malicious`

---

## Alert Workflow

```
POST /alerts  →  [Open]  →  [Investigating]  →  [Resolved]
                    ↑______________↑
                  (re-open allowed at any step)
```

---

## Sample Security Alerts (Day 2)

| Alert Type           | Source IP       | Severity | Status        |
|----------------------|-----------------|----------|---------------|
| Brute Force          | 203.0.113.42    | High     | Open          |
| Malware Detection    | 10.0.1.55       | Critical | Investigating |
| Suspicious Login     | 185.220.101.9   | Medium   | Open          |
| Port Scan            | 198.51.100.17   | Low      | Resolved      |
| Credential Stuffing  | 45.33.32.156    | High     | Investigating |

Seed the database:
```bash
python -m tests.seed_data
```

---

## Running the Application

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the server
```bash
uvicorn app.main:app --reload
```

### 3. View API documentation
Open: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## Running Tests

```bash
# From the backend/ directory
pytest tests/ -v
```

### Test Coverage (Day 2)
- ✅ Alert creation (all 5 required types)
- ✅ Alert retrieval (GET by ID)
- ✅ Alert listing (with filters & pagination)
- ✅ Status update (PATCH + transition validation)
- ✅ Invalid IPv4 → 422
- ✅ IPv6 address → 422
- ✅ Invalid severity → 422
- ✅ Case-insensitive severity/status normalisation
- ✅ Risk scoring boundary tests (Low/Medium/High/Critical bands)
- ✅ Threat intelligence determinism and response structure

---

## Logging

All mutating operations are logged with structured fields:

```
2026-06-22 12:00:00 | INFO     | soar | Alert created | alert_id=ALERT-A3F80001 type=Brute Force ip=203.0.113.42 severity=High risk_score=72.50 ti_verdict=Malicious
2026-06-22 12:05:00 | INFO     | soar | Alert status updated | alert_id=ALERT-A3F80001 Open → Investigating
```

---

## Git Commit Message

```
feat: implement alert workflow validation and risk scoring system

- Add alert_id, created_at, updated_at fields to Alert model
- Enforce IPv4-only validation with descriptive error messages
- Add case-insensitive severity (Low/Medium/High/Critical) validation
- Create risk_scoring.py with weighted 0-100 scoring engine
- Create threat_intelligence.py with mock AbuseIPDB + VirusTotal
- Add PATCH /alerts/{id}/status endpoint (Open|Investigating|Resolved)
- Add GET /alerts/{id}/enrich endpoint for TI + risk enrichment
- Wire TI enrichment and risk scoring into alert creation pipeline
- Seed database with 10 realistic sample security alerts
- Expand test suite to 50+ tests across 8 test classes
```
