"""
SOAR Incident Containment Engine – Main Application Entry Point
===============================================================
Day 2: Alert workflow validation, risk scoring, and threat intelligence layer.
"""

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database.db import Base, engine
from app.routes import alerts
from app.utils.helpers import get_logger

# Root application logger
logger = get_logger("soar")

# Suppress noisy SQLAlchemy engine logs in development
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# ── Lifespan: create tables on startup ─────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables when the application starts."""
    Base.metadata.create_all(bind=engine)
    logger.info("SOAR Engine starting – database tables initialised.")
    yield
    logger.info("SOAR Engine shut down gracefully.")


# ── Application factory ─────────────────────────────────────────────────────
app = FastAPI(
    title="SOAR Incident Containment Engine",
    description=(
        "## Security Orchestration, Automation, and Response Platform\n\n"
        "Ingests security alerts, enriches them with threat intelligence (mock), "
        "calculates risk scores (0-100), and manages the alert workflow.\n\n"
        "### Risk Score Bands\n"
        "| Range | Level    |\n"
        "|-------|----------|\n"
        "| 0-25  | Low      |\n"
        "| 26-50 | Medium   |\n"
        "| 51-75 | High     |\n"
        "| 76-100| Critical |\n\n"
        "### Alert Workflow\n"
        "`Open` → `Investigating` → `Resolved`"
    ),
    version="0.2.0",
    contact={"name": "Infotact Internship"},
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
        "version": "0.2.0",
        "project": "SOAR Incident Containment Engine",
        "docs": "/docs",
    }
