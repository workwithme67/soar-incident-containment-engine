"""
SOAR Incident Containment Engine - Main Application Entry Point
===============================================================
Day 1 Foundation: FastAPI backend setup with health check,
alert ingestion, and database initialization.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database.db import engine, Base
from app.routes import alerts


# ── Lifespan: create tables on startup ─────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables when the application starts."""
    Base.metadata.create_all(bind=engine)
    print("[SOAR] Database tables initialized OK")
    yield
    print("[SOAR] Application shutdown.")


# ── Application factory ─────────────────────────────────────────────────────
app = FastAPI(
    title="SOAR Incident Containment Engine",
    description=(
        "Security Orchestration, Automation, and Response platform. "
        "Ingests security alerts, enriches them with threat intelligence, "
        "calculates risk scores, and executes automated response playbooks."
    ),
    version="0.1.0",
    contact={
        "name": "Infotact Internship",
    },
    license_info={"name": "MIT"},
    lifespan=lifespan,
)

# ── CORS middleware ─────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])


# ── Health-check endpoint ────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def health_check() -> dict:
    """Root health-check endpoint."""
    return {
        "status": "running",
        "project": "SOAR Incident Containment Engine",
    }
