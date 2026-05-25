"""Alert routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request) -> HTMLResponse:
    alerts = request.app.state.repository.list_alerts(limit=500)
    return templates.TemplateResponse("alerts.html", {"request": request, "alerts": alerts})


@router.get("/api/alerts")
def api_alerts(request: Request) -> list[dict[str, object]]:
    return [
        {
            "type": alert.type,
            "severity": alert.severity,
            "message": alert.message,
            "pid": alert.pid,
            "created_at": alert.created_at.isoformat(),
        }
        for alert in request.app.state.repository.list_alerts(limit=500)
    ]


@router.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(request: Request, alert_id: int) -> dict[str, bool]:
    if not request.app.state.repository.resolve_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"ok": True}
