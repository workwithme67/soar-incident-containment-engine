"""
Utility helpers shared across the SOAR application.

Currently contains:
  - logger     : Structured logging configuration.
  - validators : Extra validation helpers beyond Pydantic.
"""

import logging
import sys


def get_logger(name: str = "soar") -> logging.Logger:
    """
    Return a configured logger with a consistent format.

    Usage
    -----
    from app.utils.helpers import get_logger
    logger = get_logger(__name__)
    logger.info("Alert ingested", extra={"alert_id": 42})
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)

    return logger
