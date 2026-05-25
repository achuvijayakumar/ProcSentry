"""Logging setup for daemon, web, and terminal commands."""

from __future__ import annotations

import logging
import logging.config

from app.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure structured-enough console and rotating-file friendly logging."""

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    log_path = settings.data_dir / "procsentry.log"
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {
                "format": "%(asctime)s %(levelname)s [%(name)s] %(message)s",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "standard",
                "level": settings.log_level,
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "standard",
                "filename": str(log_path),
                "maxBytes": 5_000_000,
                "backupCount": 3,
                "level": settings.log_level,
            },
        },
        "root": {
            "handlers": ["console", "file"],
            "level": settings.log_level,
        },
    }
    logging.config.dictConfig(config)
    logging.getLogger(__name__).debug("Logging configured at %s", log_path)
