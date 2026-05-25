"""Health, stats, and metrics routes."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.services.metrics_service import MetricsService
from app.services.runtime_registry import get_runtime_metrics
from app.web.schemas import HealthResponse, StatsResponse

router = APIRouter(tags=["system"])
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return process health."""

    return HealthResponse()


@router.get("/stats", response_model=StatsResponse)
def stats(request: Request) -> StatsResponse:
    """Return aggregate repository stats."""

    return StatsResponse(**request.app.state.repository.stats())


@router.get("/metrics")
def metrics(request: Request) -> dict[str, Any]:
    """Return lightweight host metrics."""

    runtime = get_runtime_metrics()
    data = dict(MetricsService().snapshot())
    data.update(
        {
            "scan_count": runtime.scan_count,
            "last_scan_ms": runtime.last_scan_ms,
            "scan_collect_ms": runtime.scan_collect_ms,
            "scan_ports_ms": runtime.scan_ports_ms,
            "scan_socket_enum_ms": runtime.scan_socket_enum_ms,
            "scan_enrich_ms": runtime.scan_enrich_ms,
            "scan_fingerprint_ms": runtime.scan_fingerprint_ms,
            "process_count": runtime.process_count,
            "duplicate_count": runtime.duplicate_count,
            "security_finding_count": runtime.security_finding_count,
            "db_write_ms": runtime.db_write_ms,
            "maintenance_ms": runtime.maintenance_ms,
            "scanner_cache_hits": runtime.scanner_cache_hits,
            "scanner_cache_misses": runtime.scanner_cache_misses,
            "scanner_fingerprint_cache_hits": runtime.scanner_fingerprint_cache_hits,
            "scanner_fingerprint_cache_misses": runtime.scanner_fingerprint_cache_misses,
        }
    )
    data.update(request.app.state.repository.storage_metrics())
    return data


@router.get("/capabilities")
def capabilities(request: Request) -> dict[str, object]:
    """Return platform capability flags."""

    return asdict(request.app.state.capabilities)


@router.get("/health/score")
def health_score(request: Request) -> dict[str, object]:
    """Return simple degraded-mode health score."""

    capabilities_data = asdict(request.app.state.capabilities)
    supported = [
        bool(capabilities_data["supports_procfs"]),
        bool(capabilities_data["supports_cgroups"]),
        bool(capabilities_data["supports_systemd"]),
        bool(capabilities_data["supports_deleted_exe"]),
        bool(capabilities_data["supports_zombie_state"]),
    ]
    score = 100 - (supported.count(False) * 12)
    return {
        "score": max(0, score),
        "degraded": not all(supported),
        "capabilities": capabilities_data,
    }


@router.get("/capabilities/view", response_class=HTMLResponse)
def capabilities_page(request: Request) -> HTMLResponse:
    """Render capability overview."""

    return templates.TemplateResponse(
        request,
        "capabilities.html",
        {"capabilities": asdict(request.app.state.capabilities)},
    )
