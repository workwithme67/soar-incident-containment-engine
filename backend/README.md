# 🛡️ SOAR Incident Containment Engine

> **Security Orchestration, Automation, and Response (SOAR) platform**  
> Built during the Infotact Internship Program · Day 1 Foundation

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python)](https://python.org)
[![SQLite](https://img.shields.io/badge/Database-SQLite%20%2F%20PostgreSQL-003B57?logo=sqlite)](https://sqlite.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Project Overview

The **SOAR Incident Containment Engine** is a backend platform designed to ingest, triage, enrich, and automatically respond to security incidents. It serves as the nerve centre of a SOC (Security Operations Centre), replacing manual analyst workflows with intelligent automation.

---

## 🔥 Problem Statement

Modern organisations face hundreds to thousands of security alerts per day. Security analysts suffer from **alert fatigue** — they are overwhelmed by volume, miss critical incidents buried in noise, and spend valuable time on repetitive triage tasks.

**SOAR platforms solve this by:**
- Centralising alert ingestion from disparate sources (SIEM, EDR, firewall, IDS).
- Automatically enriching alerts with threat intelligence (VirusTotal, AbuseIPDB, Shodan).
- Calculating dynamic risk scores to prioritise analyst attention.
- Executing automated response playbooks (isolate host, block IP, revoke credentials).
- Reducing Mean Time To Respond (MTTR) from hours to minutes.

---

## ✨ Features (Day 1 – Foundation)

| Feature | Status |
|---|---|
| FastAPI backend with interactive docs | ✅ |
| SQLite database via SQLAlchemy ORM | ✅ |
| Alert ingestion (`POST /alerts`) | ✅ |
| Alert retrieval with filters (`GET /alerts`) | ✅ |
| Pydantic v2 validation (IP, severity, status) | ✅ |
| Modular clean architecture | ✅ |
| Health check endpoint | ✅ |
| Sample seed data (10 realistic alerts) | ✅ |
| Pytest test suite | ✅ |

---

## 🏗️ Architecture

```
backend/
├── app/
│   ├── database/
│   │   ├── __init__.py
│   │   └── db.py             # SQLAlchemy engine, session, Base
│   ├── models/
│   │   ├── __init__.py
│   │   ├── alert.py          # ORM model (Alert table)
│   │   └── schemas.py        # Pydantic request/response schemas
│   ├── routes/
│   │   ├── __init__.py
│   │   └── alerts.py         # HTTP route handlers
│   ├── services/
│   │   ├── __init__.py
│   │   └── alert_service.py  # Business logic layer
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py        # Shared utilities (logger, etc.)
│   └── main.py               # FastAPI app factory + startup
├── tests/
│   ├── __init__.py
│   ├── seed_data.py          # Sample alert seed script
│   └── test_alerts.py        # Pytest test suite
├── docs/                     # API documentation & diagrams
├── screenshots/              # UI / Swagger screenshots
├── .env.example              # Environment variable template
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Framework** | FastAPI 0.111 |
| **Language** | Python 3.11+ |
| **ORM** | SQLAlchemy 2.0 |
| **Database** | SQLite (dev) / PostgreSQL (prod) |
| **Validation** | Pydantic v2 |
| **Server** | Uvicorn (ASGI) |
| **Testing** | Pytest + FastAPI TestClient |
| **Migration** | Alembic (Day 2+) |

---

## 🚀 Installation Guide

### Prerequisites

- Python 3.11 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/your-username/soar-incident-containment-engine.git
cd "SOAR Incident Containment Engine/backend"
```

### 2. Create and activate a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

```bash
cp .env.example .env
# Edit .env and fill in your values
```

### 5. Seed the database with sample data (optional)

```bash
python -m tests.seed_data
```

### 6. Start the development server

```bash
uvicorn app.main:app --reload
```

The API is now running at **http://127.0.0.1:8000**

### 7. Explore the interactive API docs

| Interface | URL |
|---|---|
| Swagger UI | http://127.0.0.1:8000/docs |
| ReDoc | http://127.0.0.1:8000/redoc |

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/alerts/` | Ingest a new security alert |
| `GET` | `/alerts/` | List alerts (with filters & pagination) |
| `GET` | `/alerts/{id}` | Get a single alert by ID |

### Example: Create an Alert

```bash
curl -X POST http://127.0.0.1:8000/alerts/ \
  -H "Content-Type: application/json" \
  -d '{
    "alert_type": "Brute Force",
    "source_ip": "203.0.113.42",
    "severity": "HIGH",
    "description": "348 failed SSH login attempts in 60 seconds."
  }'
```

### Example: Get alerts filtered by severity

```bash
curl "http://127.0.0.1:8000/alerts/?severity=CRITICAL&limit=10"
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

---

## 🔮 Future Scope

| Day | Feature |
|---|---|
| **Day 2** | Alembic migrations · Alert update/delete endpoints |
| **Day 3** | Threat intelligence enrichment (VirusTotal, AbuseIPDB) |
| **Day 4** | Dynamic risk score calculator |
| **Day 5** | Automated response playbook engine |
| **Day 6** | SIEM integration (Splunk / Elastic) |
| **Day 7** | Real-time WebSocket alerts dashboard |
| **Week 2** | React.js frontend with live alert dashboard |
| **Week 3** | ML-based anomaly detection |
| **Week 4** | Docker containerization & CI/CD pipeline |

---

## 👨‍💻 Author

**Infotact Internship Program**  
SOAR Incident Containment Engine – Day 1

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
