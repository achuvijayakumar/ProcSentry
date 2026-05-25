"""Port explorer routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database.repository import ports_from_record

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/ports", response_class=HTMLResponse)
def ports_page(request: Request) -> HTMLResponse:
    rows = _port_rows(request)
    return templates.TemplateResponse("ports.html", {"request": request, "rows": rows})


@router.get("/api/ports")
def api_ports(request: Request) -> list[dict[str, object]]:
    return _port_rows(request)


def _port_rows(request: Request) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for proc in request.app.state.repository.list_processes(limit=1000):
        for port in ports_from_record(proc):
            rows.append(
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "address": port.address,
                    "pid": proc.pid,
                    "process": proc.name,
                    "public": port.address in {"0.0.0.0", "::", ""},
                }
            )
    return sorted(rows, key=lambda item: (int(str(item["port"])), str(item["protocol"])))
