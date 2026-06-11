"""SQLAlchemy models for ProcSentry persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Base model class."""


class ProcessRecord(Base):
    """Current process state keyed by PID."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    ppid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    fuzzy_fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    cmdline: Mapped[str] = mapped_column(Text)
    executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwd: Mapped[str | None] = mapped_column(Text, nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0)
    memory_mb: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    threads: Mapped[int] = mapped_column(Integer, default=0)
    start_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ports_json: Mapped[str] = mapped_column(Text, default="[]")
    service_manager: Mapped[str | None] = mapped_column(String(64), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    systemd_unit: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    ancestry_json: Mapped[str] = mapped_column(Text, default="[]")
    is_zombie: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    is_orphan: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    executable_deleted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    executable_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outbound_connections: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_score: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_score: Mapped[int] = mapped_column(Integer, default=0)
    restart_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    history: Mapped[list["ProcessHistoryRecord"]] = relationship(
        back_populates="process", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("pid", "start_time", name="uq_process_pid_start"),)


class ProcessHistoryRecord(Base):
    """Rolling process resource history."""

    __tablename__ = "process_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process_id: Mapped[int] = mapped_column(ForeignKey("processes.id", ondelete="CASCADE"), index=True)
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_mb: Mapped[float] = mapped_column(Float)
    thread_count: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    process: Mapped[ProcessRecord] = relationship(back_populates="history")


class DuplicateGroupRecord(Base):
    """Persisted duplicate group observation."""

    __tablename__ = "duplicate_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    process_pids: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    explanations_json: Mapped[str] = mapped_column(Text, default="[]")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class AlertRecord(Base):
    """Alert emitted by resource, duplicate, or security services."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(32), index=True)
    category: Mapped[str] = mapped_column(String(64), default="general", index=True)
    message: Mapped[str] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class KillRecord(Base):
    """One row per process kill issued through ProcSentry. Powers /roast."""

    __tablename__ = "kill_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255), index=True)
    cmdline: Mapped[str] = mapped_column(Text, default="")
    friendly_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    project: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float, default=0)
    memory_mb: Mapped[float] = mapped_column(Float, default=0)
    killed_via: Mapped[str] = mapped_column(String(32), default="single")
    killed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ServiceActionRecord(Base):
    """One row per systemd unit action issued through the dashboard."""

    __tablename__ = "service_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    unit: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(32))
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class ProcessNoteRecord(Base):
    """Operator note/tag attached to a process fingerprint or PID."""

    __tablename__ = "process_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    tag: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
