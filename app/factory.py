"""Application factory helpers."""

from __future__ import annotations

from app.config import Settings, load_settings
from app.collectors.common.capabilities import detect_capabilities
from app.database.repository import ProcessRepository
from app.database.session import create_db_engine, create_session_factory, init_db
from app.diagnostics import log_startup_diagnostics
from app.logging_config import configure_logging


def build_repository(settings: Settings) -> ProcessRepository:
    """Initialize storage and return a repository."""

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    engine = create_db_engine(settings)
    init_db(engine)
    return ProcessRepository(create_session_factory(engine))


def bootstrap(config_path: str | None = None) -> tuple[Settings, ProcessRepository]:
    """Load settings, configure logging, initialize storage."""

    settings = load_settings(config_path)
    configure_logging(settings)
    log_startup_diagnostics(settings, detect_capabilities())
    repository = build_repository(settings)
    return settings, repository
