"""Process dashboard and API routes."""

from __future__ import annotations

import os
import signal
from dataclasses import asdict

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database.repository import ports_from_record
from app.services.metrics_service import MetricsService
from app.services.runtime_registry import get_runtime_metrics
from app.web.schemas import ProcessResponse

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    repository = request.app.state.repository
    processes = repository.list_processes(limit=500)
    alerts = repository.list_alerts(limit=50)
    duplicates = repository.list_duplicate_groups(limit=50)
    metrics = MetricsService().snapshot()
    return templates.TemplateResponse(
        "overview.html",
        {
            "request": request,
            "processes": processes[:10],
            "alerts": alerts[:10],
            "duplicates": duplicates,
            "metrics": metrics,
            "ports_count": sum(len(ports_from_record(proc)) for proc in processes),
        },
    )


@router.get("/processes", response_class=HTMLResponse)
def process_page(
    request: Request,
    q: str | None = None,
    suspicious: bool = False,
    duplicates: bool = False,
) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(
        limit=1000, query=q, suspicious=suspicious or None, duplicates=duplicates or None
    )
    return templates.TemplateResponse(
        "processes.html",
        {
            "request": request,
            "processes": processes,
            "q": q or "",
            "suspicious": suspicious,
            "duplicates": duplicates,
        },
    )


@router.get("/suspicious", response_class=HTMLResponse)
def suspicious_page(request: Request) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(limit=500, suspicious=True)
    return templates.TemplateResponse(
        "suspicious.html", {"request": request, "processes": processes}
    )


@router.get("/processes/{pid}", response_class=HTMLResponse)
def process_detail(request: Request, pid: int) -> HTMLResponse:
    proc = request.app.state.repository.get_process_by_pid(pid)
    if not proc:
        raise HTTPException(status_code=404, detail="Process not found")
    notes = request.app.state.repository.list_process_notes(pid=pid, fingerprint=proc.fingerprint)
    return templates.TemplateResponse(
        "process_detail.html",
        {"request": request, "proc": proc, "ports": ports_from_record(proc), "notes": notes},
    )


@router.post("/processes/{pid}/notes", response_class=HTMLResponse)
def add_process_note(
    request: Request,
    pid: int,
    note: str = Form(...),
    tag: str | None = Form(default=None),
) -> HTMLResponse:
    proc = request.app.state.repository.get_process_by_pid(pid)
    if not proc:
        raise HTTPException(status_code=404, detail="Process not found")
    request.app.state.repository.add_process_note(note=note, tag=tag, pid=pid, fingerprint=proc.fingerprint)
    notes = request.app.state.repository.list_process_notes(pid=pid, fingerprint=proc.fingerprint)
    return templates.TemplateResponse("partials/process_notes.html", {"request": request, "notes": notes, "proc": proc})


@router.get("/partials/process-table", response_class=HTMLResponse)
def process_table(request: Request) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(limit=200)
    return templates.TemplateResponse("partials/process_table.html", {"request": request, "processes": processes})


@router.get("/partials/stats-cards", response_class=HTMLResponse)
def stats_cards(request: Request) -> HTMLResponse:
    runtime = get_runtime_metrics()
    metrics = {
        "last_scan_ms": runtime.last_scan_ms,
        "db_write_ms": runtime.db_write_ms,
        **request.app.state.repository.storage_metrics(),
    }
    return templates.TemplateResponse("partials/stats_cards.html", {"request": request, "metrics": metrics})


@router.get("/api/processes")
def api_processes(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    q: str | None = None,
    suspicious: bool = False,
    duplicates: bool = False,
) -> list[ProcessResponse]:
    return [
        ProcessResponse(
            pid=proc.pid,
            name=proc.name,
            cmdline=proc.cmdline.replace("\0", " "),
            cpu_percent=proc.cpu_percent,
            memory_mb=proc.memory_mb,
            ports=[port.port for port in ports_from_record(proc)],
            duplicate_score=proc.duplicate_score,
            suspicious_score=proc.suspicious_score,
            is_zombie=proc.is_zombie,
            is_orphan=proc.is_orphan,
            service_manager=proc.service_manager,
            systemd_unit=proc.systemd_unit,
            container_id=proc.container_id,
            outbound_connections=proc.outbound_connections,
            restart_count=proc.restart_count,
        )
        for proc in request.app.state.repository.list_processes(
            limit=limit,
            offset=offset,
            query=q,
            suspicious=suspicious or None,
            duplicates=duplicates or None,
        )
    ]


@router.get("/api/processes/{pid}")
def api_process_detail(request: Request, pid: int) -> dict[str, object]:
    proc = request.app.state.repository.get_process_by_pid(pid)
    if not proc:
        raise HTTPException(status_code=404, detail="Process not found")
    return {
        "pid": proc.pid,
        "name": proc.name,
        "cmdline": proc.cmdline.replace("\0", " "),
        "cwd": proc.cwd,
        "executable": proc.executable,
        "ports": [asdict(port) for port in ports_from_record(proc)],
        "outbound_connections": proc.outbound_connections,
        "restart_count": proc.restart_count,
        "ancestry": proc.ancestry_json,
    }


@router.get("/api/process-tree")
def api_process_tree(request: Request) -> list[dict[str, object]]:
    processes = request.app.state.repository.list_processes(limit=5000)
    nodes = {
        proc.pid: {
            "pid": proc.pid,
            "name": proc.name,
            "ppid": proc.ppid,
            "cpu_percent": proc.cpu_percent,
            "memory_mb": proc.memory_mb,
            "duplicate_score": proc.duplicate_score,
            "suspicious_score": proc.suspicious_score,
            "children": [],
        }
        for proc in processes
    }
    roots: list[dict[str, object]] = []
    for proc in processes:
        node = nodes[proc.pid]
        parent = nodes.get(proc.ppid or -1)
        if parent is None or parent is node:
            roots.append(node)
        else:
            children = parent["children"]
            if isinstance(children, list):
                children.append(node)
    return roots


@router.post("/api/processes/{pid}/kill")
def kill_process(pid: int) -> dict[str, object]:
    try:
        os.kill(pid, signal.SIGTERM)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail="Permission denied") from exc
    except ProcessLookupError as exc:
        raise HTTPException(status_code=404, detail="Process not found") from exc
    return {"ok": True, "pid": pid}
