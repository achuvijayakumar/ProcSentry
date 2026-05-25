"""Database engine and session helpers."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

import logging
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.database.models import Base

logger = logging.getLogger(__name__)


def create_db_engine(settings: Settings) -> Engine:
    """Create a SQLAlchemy engine tuned for SQLite and future PostgreSQL URLs."""

    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    return create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)


def init_db(engine: Engine) -> None:
    """Create database tables for the initial SQLite deployment."""

    if engine.dialect.name == "sqlite":
        _configure_sqlite(engine)
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "sqlite":
        _run_lightweight_migrations(engine)


def _configure_sqlite(engine: Engine) -> None:
    """Enable SQLite pragmas that improve agent reliability."""

    with engine.begin() as connection:
        connection.execute(text("PRAGMA journal_mode=WAL"))
        connection.execute(text("PRAGMA synchronous=NORMAL"))
        connection.execute(text("PRAGMA temp_store=MEMORY"))
        connection.execute(text("PRAGMA busy_timeout=5000"))
        integrity = connection.execute(text("PRAGMA quick_check")).scalar()
        if integrity != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {integrity}")


def _run_lightweight_migrations(engine: Engine) -> None:
    """Apply SQL migration files once using a tiny migration table."""

    migrations_dir = Path(__file__).parent / "migrations"
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_migrations "
                "(version VARCHAR(255) PRIMARY KEY, applied_at DATETIME DEFAULT CURRENT_TIMESTAMP)"
            )
        )
        applied = {
            row[0]
            for row in connection.execute(text("SELECT version FROM schema_migrations")).fetchall()
        }
        for path in sorted(migrations_dir.glob("*.sql")):
            if path.name in applied:
                continue
            sql = path.read_text(encoding="utf-8")
            for statement in [chunk.strip() for chunk in sql.split(";") if chunk.strip()]:
                try:
                    connection.execute(text(statement))
                except Exception as exc:
                    if "duplicate column name" in str(exc).lower() or "already exists" in str(exc).lower():
                        logger.debug("Ignoring idempotent migration statement in %s: %s", path.name, exc)
                        continue
                    raise
            connection.execute(
                text("INSERT INTO schema_migrations(version) VALUES (:version)"),
                {"version": path.name},
            )


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a session factory."""

    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Generator[Session, None, None]:
    """Provide a transactional session scope."""

    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
