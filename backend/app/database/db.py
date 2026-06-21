"""
Database configuration and session management.
Uses SQLite for Day-1 development; swap DATABASE_URL for
PostgreSQL/MySQL in production via the .env file.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# ── Database URL ─────────────────────────────────────────────────────────────
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./soar.db")

# ── SQLAlchemy engine ────────────────────────────────────────────────────────
# check_same_thread=False is required for SQLite + FastAPI's async handlers
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
)

# ── Session factory ──────────────────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ── Declarative base for ORM models ─────────────────────────────────────────
Base = declarative_base()


# ── Dependency: yields a DB session per request ──────────────────────────────
def get_db():
    """FastAPI dependency that provides a SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
