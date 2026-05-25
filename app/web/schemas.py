"""Typed API response schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ProcessResponse(BaseModel):
    """Process API response."""

    pid: int
    name: str
    cmdline: str
    cpu_percent: float
    memory_mb: float
    ports: list[int]
    duplicate_score: int
    suspicious_score: int
    is_zombie: bool
    is_orphan: bool
    service_manager: str | None = None
    systemd_unit: str | None = None
    container_id: str | None = None
    outbound_connections: int = 0
    restart_count: int = 0


class HealthResponse(BaseModel):
    """Health response."""

    status: str = "ok"
    database: str = "ok"


class StatsResponse(BaseModel):
    """Aggregate stats response."""

    processes: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    alerts: int = Field(ge=0)
    suspicious: int = Field(ge=0)
