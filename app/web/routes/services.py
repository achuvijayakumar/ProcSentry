"""Systemd services, timers, and cron dashboard routes."""

from __future__ import annotations

import html

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.services import host_services

router = APIRouter(tags=["services"])
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/services", response_class=HTMLResponse)
def services_page(request: Request) -> HTMLResponse:
    snapshot = host_services.snapshot()
    actions = request.app.state.repository.list_service_actions(limit=20)
    failed = [s for s in snapshot.services if s.active == "failed"]
    return templates.TemplateResponse(
        request,
        "services.html",
        {
            "services": snapshot.services,
            "timers": snapshot.timers,
            "cron": snapshot.cron,
            "errors": snapshot.errors,
            "recent_actions": actions,
            "failed_count": len(failed),
        },
    )


@router.get("/api/services/{unit}/journal", response_class=PlainTextResponse)
def service_journal(unit: str, lines: int = Query(default=50, ge=1, le=500)) -> PlainTextResponse:
    return PlainTextResponse(host_services.unit_journal(unit, lines))


@router.post("/api/services/{unit}/{action}", response_class=HTMLResponse)
def service_action(
    request: Request,
    unit: str,
    action: str,
    force: bool = Query(default=False),
) -> HTMLResponse:
    result = host_services.control_unit(unit, action, force=force)
    repository = request.app.state.repository
    try:
        repository.record_service_action(unit=unit, action=action, ok=result.ok, detail=result.detail)
    except Exception:  # pragma: no cover - audit failure must not block the action result
        pass
    detail = html.escape(result.detail)
    if result.ok:
        body = f'<span class="font-mono text-xs text-green-400">✓ {detail}</span>'
        status = 200
    else:
        body = f'<span class="font-mono text-xs text-red-400">✗ {detail}</span>'
        # 200 so htmx swaps the error message into the result target.
        status = 200
    return HTMLResponse(body, status_code=status)
