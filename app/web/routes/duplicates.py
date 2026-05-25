"""Duplicate process routes."""

from __future__ import annotations

import json
import os
import signal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def _resolve_group_members(repository, group) -> tuple[list[dict], dict | None]:
    """Return (members, keep_member). keep_member is the oldest still-alive process."""
    from app.web.routes.processes import _friendly_label, _detect_project, _tokens

    try:
        pids = json.loads(group.process_pids)
    except (ValueError, TypeError):
        pids = []
    members: list[dict] = []
    for pid in pids:
        proc = repository.get_process_by_pid(int(pid))
        if not proc:
            continue
        toks = _tokens(proc.cmdline)
        members.append({
            "pid": proc.pid,
            "name": proc.name,
            "cmdline": (proc.cmdline or "").replace("\0", " ").strip(),
            "cpu_percent": proc.cpu_percent,
            "memory_mb": proc.memory_mb,
            "start_time": proc.start_time,
            "user": proc.user,
            "project": _detect_project(toks, proc.cwd, proc.systemd_unit, proc.name),
            "friendly_label": _friendly_label(proc.name, proc.cmdline),
        })
    members.sort(key=lambda m: (m["start_time"] is None, m["start_time"] or 0))
    keep = members[0] if members else None
    return members, keep


@router.get("/duplicates", response_class=HTMLResponse)
def duplicate_page(request: Request) -> HTMLResponse:
    raw_groups = request.app.state.repository.list_duplicate_groups(limit=200)
    repository = request.app.state.repository
    groups = []
    for g in raw_groups:
        members, keep = _resolve_group_members(repository, g)
        groups.append({
            "id": g.id,
            "confidence": g.confidence,
            "reason": g.reason,
            "members": members,
            "keep_pid": keep["pid"] if keep else None,
            "kill_count": max(0, len(members) - 1),
        })
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


@router.post("/api/duplicates/{group_id}/kill-extras", response_class=HTMLResponse)
def kill_extras(request: Request, group_id: int) -> HTMLResponse:
    """Kill all duplicates in a group except the oldest. Returns HTML snippet for HTMX."""
    repository = request.app.state.repository
    groups = repository.list_duplicate_groups(limit=500)
    group = next((g for g in groups if g.id == group_id), None)
    if group is None:
        raise HTTPException(status_code=404, detail="Duplicate group not found")
    members, keep = _resolve_group_members(repository, group)
    if not keep or len(members) < 2:
        return HTMLResponse(
            '<span class="font-mono text-xs text-zinc-500">— nothing to kill —</span>',
        )
    killed: list[int] = []
    failed: list[tuple[int, str]] = []
    for m in members:
        if m["pid"] == keep["pid"]:
            continue
        try:
            os.kill(m["pid"], signal.SIGTERM)
            killed.append(m["pid"])
        except PermissionError:
            failed.append((m["pid"], "perm"))
        except ProcessLookupError:
            failed.append((m["pid"], "gone"))
    repository.resolve_duplicate_group(group_id)
    parts = [f'<span class="font-mono text-xs text-green-400">SIGTERM → {len(killed)} pid(s), kept PID {keep["pid"]}</span>']
    if failed:
        parts.append(f'<span class="font-mono text-xs text-amber-400 ml-2">{len(failed)} failed</span>')
    return HTMLResponse(" ".join(parts))
