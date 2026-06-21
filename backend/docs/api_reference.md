# SOAR Incident Containment Engine – API Documentation

## Base URL

```
http://127.0.0.1:8000
```

## Authentication

Day 1: No authentication required.  
Day 6+: JWT Bearer token authentication will be added.

---

## Endpoints

### `GET /`

**Health Check**

```json
{
  "status": "running",
  "project": "SOAR Incident Containment Engine"
}
```

---

### `POST /alerts/`

**Ingest a new security alert**

**Request Body**

| Field | Type | Required | Description |
|---|---|---|---|
| `alert_type` | string | ✅ | Category (e.g., "Brute Force") |
| `source_ip` | string | ✅ | Valid IPv4 or IPv6 address |
| `severity` | enum | ✅ | LOW \| MEDIUM \| HIGH \| CRITICAL |
| `description` | string | ❌ | Optional context (max 500 chars) |
| `status` | enum | ❌ | OPEN (default) \| IN_PROGRESS \| RESOLVED \| DISMISSED |

**Response** `201 Created`

```json
{
  "id": 1,
  "alert_type": "Brute Force",
  "source_ip": "203.0.113.42",
  "severity": "HIGH",
  "description": "348 failed SSH login attempts in 60 seconds.",
  "status": "OPEN",
  "timestamp": "2026-06-21T04:30:00+00:00"
}
```

---

### `GET /alerts/`

**List security alerts with pagination and optional filters**

**Query Parameters**

| Parameter | Type | Default | Description |
|---|---|---|---|
| `skip` | int | 0 | Records to skip |
| `limit` | int | 50 | Max records (1–100) |
| `severity` | enum | — | Filter by severity |
| `status` | enum | — | Filter by workflow status |

**Response** `200 OK`

```json
{
  "total": 42,
  "alerts": [...]
}
```

---

### `GET /alerts/{id}`

**Get a single alert by ID**

**Response** `200 OK` – Alert object  
**Response** `404 Not Found` – `{"detail": "Alert with id=99 not found."}`

---

## Error Codes

| Code | Meaning |
|---|---|
| 201 | Alert created successfully |
| 200 | Request successful |
| 404 | Resource not found |
| 422 | Validation error (check request body) |
| 500 | Internal server error |
