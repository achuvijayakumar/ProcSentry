"""The /roast page — a Wrapped-style shame card for processes you keep killing."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def _label_for(rec) -> str:
    return rec.friendly_label or rec.name or "?"


def _build_roast(records: list) -> dict:
    """Compute the roast payload from a list of KillRecord rows."""

    total_kills = len(records)
    if not total_kills:
        return {"empty": True, "total_kills": 0}

    by_label: dict[str, list] = defaultdict(list)
    for rec in records:
        by_label[_label_for(rec)].append(rec)

    # Top hog: most cumulative memory-MB at kill time.
    top_hog_label, top_hog_recs = max(
        by_label.items(),
        key=lambda kv: sum((r.memory_mb or 0) for r in kv[1]),
    )
    top_hog_ram_gb = sum((r.memory_mb or 0) for r in top_hog_recs) / 1024.0

    # Most killed: highest kill count.
    most_killed_label, most_killed_recs = max(by_label.items(), key=lambda kv: len(kv[1]))
    most_killed_count = len(most_killed_recs)

    # Stockholm syndrome: anything killed >= 5 times, ordered by count, exclude
    # the most_killed entry so we don't repeat it.
    stockholm = [
        {"label": label, "count": len(recs)}
        for label, recs in sorted(by_label.items(), key=lambda kv: -len(kv[1]))
        if len(recs) >= 5 and label != most_killed_label
    ][:3]

    # Funniest crime: biggest single-kill RAM hit.
    funniest = max(records, key=lambda r: r.memory_mb or 0)

    # Project leaderboard.
    by_project: Counter = Counter()
    for rec in records:
        by_project[rec.project or "unknown"] += 1
    top_projects = by_project.most_common(5)

    # Aggregate "reclaimed" numbers — framed as observed-at-kill-time, not as
    # extrapolated savings. See the conversation that produced this feature.
    total_ram_gb_at_kill = sum((r.memory_mb or 0) for r in records) / 1024.0
    total_cpu_pct_at_kill = sum((r.cpu_percent or 0) for r in records)

    # Headline leaderboard rows (top 5 by kill count).
    leaderboard = [
        {
            "label": label,
            "count": len(recs),
            "ram_gb": sum((r.memory_mb or 0) for r in recs) / 1024.0,
            "last_killed_at": max(r.killed_at for r in recs),
        }
        for label, recs in sorted(by_label.items(), key=lambda kv: -len(kv[1]))[:10]
    ]

    return {
        "empty": False,
        "total_kills": total_kills,
        "unique_offenders": len(by_label),
        "top_hog": {"label": top_hog_label, "ram_gb": top_hog_ram_gb, "count": len(top_hog_recs)},
        "most_killed": {"label": most_killed_label, "count": most_killed_count},
        "funniest_crime": {
            "label": _label_for(funniest),
            "ram_gb": (funniest.memory_mb or 0) / 1024.0,
            "killed_at": funniest.killed_at,
        },
        "stockholm": stockholm,
        "top_projects": top_projects,
        "total_ram_gb_at_kill": total_ram_gb_at_kill,
        "total_cpu_pct_at_kill": total_cpu_pct_at_kill,
        "leaderboard": leaderboard,
    }


@router.get("/roast", response_class=HTMLResponse)
def roast(request: Request, days: int = Query(default=30, ge=1, le=365)) -> HTMLResponse:
    repository = request.app.state.repository
    since = datetime.now(timezone.utc) - timedelta(days=days)
    records = repository.list_kills(since=since, limit=5000)
    payload = _build_roast(records)
    payload["days"] = days
    return templates.TemplateResponse(request, "roast.html", payload)
