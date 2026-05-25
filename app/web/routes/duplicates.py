"""Duplicate process routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/duplicates", response_class=HTMLResponse)
def duplicate_page(request: Request) -> HTMLResponse:
    groups = request.app.state.repository.list_duplicate_groups(limit=200)
    return templates.TemplateResponse(request, "duplicates.html", {"groups": groups})


@router.get("/api/duplicates")
def api_duplicates(request: Request) -> list[dict[str, object]]:
    return [
        {
            "fingerprint": group.fingerprint,
            "confidence": group.confidence,
            "process_pids": group.process_pids,
            "reason": group.reason,
            "detected_at": group.detected_at.isoformat(),
        }
        for group in request.app.state.repository.list_duplicate_groups(limit=200)
    ]


@router.post("/api/duplicates/ignore")
def ignore_duplicate() -> dict[str, bool]:
    return {"ok": True}


@router.post("/api/duplicates/{group_id}/resolve")
def resolve_duplicate(request: Request, group_id: int) -> dict[str, bool]:
    if not request.app.state.repository.resolve_duplicate_group(group_id):
        raise HTTPException(status_code=404, detail="Duplicate group not found")
    return {"ok": True}
