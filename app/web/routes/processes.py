"""Process dashboard and API routes."""

from __future__ import annotations

import json
import os
import re
import signal
from dataclasses import asdict
from pathlib import PurePosixPath

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database.repository import ports_from_record
from app.services.metrics_service import MetricsService
from app.services.runtime_registry import get_runtime_metrics
from app.web.schemas import ProcessResponse
from app.web.suggestions import build_suggestions, current_username

router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")

# Interpreters whose name tells us nothing — the *next* token is the real program.
_INTERPRETERS = {
    "python", "python2", "python3", "python3.9", "python3.10", "python3.11", "python3.12",
    "node", "nodejs", "deno", "bun",
    "ruby", "perl", "php", "php-fpm",
    "java", "bash", "sh", "zsh", "dash",
    "sudo", "env",
}

# Known framework/tool tokens that should win as the label if present in the cmdline.
_KNOWN_TOOLS = {
    "uvicorn", "gunicorn", "hypercorn", "daphne", "streamlit",
    "celery", "flask", "fastapi", "django",
    "next", "vite", "webpack", "nuxt",
    "pytest", "jupyter", "ipython",
    "nginx", "apache2", "httpd", "redis-server", "postgres", "mysqld", "mongod",
    "docker", "containerd",
}


def _tokens(cmdline: str | None) -> list[str]:
    if not cmdline:
        return []
    return [t for t in cmdline.replace("\0", " ").split() if t]


# Path patterns where projects/apps typically live. The captured group is the
# project name. Order matters: more specific first.
_PROJECT_PATH_PATTERNS = [
    re.compile(r"/home/[^/]+/apps/([^/]+)"),
    re.compile(r"/home/[^/]+/projects/([^/]+)"),
    re.compile(r"/home/[^/]+/src/([^/]+)"),
    re.compile(r"/home/[^/]+/code/([^/]+)"),
    re.compile(r"/home/[^/]+/repos/([^/]+)"),
    re.compile(r"/srv/([^/]+)"),
    re.compile(r"/var/www/([^/]+)"),
    re.compile(r"/opt/([^/]+)"),
]

# Well-known service binaries — the kernel comm or first cmdline token directly
# names the service. These map a comm/basename -> friendly group label.
_WELL_KNOWN_SERVICES = {
    "nginx": "nginx",
    "apache2": "apache",
    "httpd": "apache",
    "caddy": "caddy",
    "haproxy": "haproxy",
    "redis-server": "redis",
    "redis-sentinel": "redis",
    "memcached": "memcached",
    "postgres": "postgres",
    "postmaster": "postgres",
    "mysqld": "mysql",
    "mariadbd": "mariadb",
    "mongod": "mongodb",
    "rabbitmq-server": "rabbitmq",
    "ollama": "ollama",
    "questdb": "questdb",
    "java": None,  # too generic; only label if path tells us more
    "dockerd": "docker",
    "containerd": "docker",
    "docker-proxy": "docker",
    "containerd-shim": "docker",
    "sshd": "sshd",
    "systemd": "systemd",
    "cron": "cron",
    "crond": "cron",
    "rsyslogd": "rsyslog",
    "fail2ban-server": "fail2ban",
    "ufw": "ufw",
    "snapd": "snap",
    "kernel": "kernel",
}


def _project_name_from_path(path: str | None) -> str | None:
    """Extract a project name from any well-known directory pattern."""
    if not path:
        return None
    for pat in _PROJECT_PATH_PATTERNS:
        m = pat.search(path)
        if m:
            return m.group(1)
    return None


_UNIT_ALIASES = {"ssh": "sshd"}


def _systemd_unit_label(unit: str | None) -> str | None:
    """Turn 'nginx.service' into 'nginx'. Skip generic units."""
    if not unit:
        return None
    base = unit.rsplit(".", 1)[0]
    # Skip user@<uid>, session-*, init.scope, system.slice, user.slice, etc.
    if base.startswith(("user@", "session-", "user-")) or base in {
        "init", "system", "user", "init.scope", "system.slice", "user.slice"
    }:
        return None
    # Strip per-instance suffixes from template units (foo@bar -> foo).
    if "@" in base:
        base = base.split("@", 1)[0]
    return _UNIT_ALIASES.get(base, base)


def _detect_project(
    cmdline_tokens: list[str],
    cwd: str | None,
    systemd_unit: str | None = None,
    comm: str | None = None,
) -> str | None:
    """Discover the 'app/service' a process belongs to.

    Priority:
      1. project name from cwd or cmdline path (your repos in /apps/, /opt/, etc.)
      2. systemd unit name (when not a generic system slice)
      3. well-known service name from comm or first cmdline token
    """
    # 1) Project directories.
    project = _project_name_from_path(cwd)
    if project:
        return project
    for t in cmdline_tokens:
        project = _project_name_from_path(t)
        if project:
            return project

    # 2) systemd unit.
    unit = _systemd_unit_label(systemd_unit)
    if unit:
        return unit

    # 3) Well-known service name from kernel comm or first cmdline token.
    if comm:
        svc = _WELL_KNOWN_SERVICES.get(comm)
        if svc:
            return svc
    if cmdline_tokens:
        first_base = PurePosixPath(cmdline_tokens[0]).name if "/" in cmdline_tokens[0] else cmdline_tokens[0]
        svc = _WELL_KNOWN_SERVICES.get(first_base)
        if svc:
            return svc

    return None


def _friendly_label(name: str, cmdline: str | None) -> str:
    """Return just the program/command label (no project prefix).

    Examples:
      uvicorn web.app:app --host 0.0.0.0  -> uvicorn (web.app:app)
      gunicorn run:app -w 4               -> gunicorn (run:app)
      python3 manage.py runserver         -> python3 manage.py
      streamlit run app.py                -> streamlit (app.py)
      /usr/sbin/nginx -g daemon off       -> nginx
    """
    toks = _tokens(cmdline)
    if not toks:
        return name

    def basename(t: str) -> str:
        return PurePosixPath(t).name if "/" in t else t

    # 1) Known framework/tool anywhere in the cmdline.
    for t in toks:
        b = basename(t)
        if b in _KNOWN_TOOLS:
            try:
                idx = toks.index(t)
            except ValueError:
                idx = -1
            arg = next(
                (a for a in toks[idx + 1:]
                 if not a.startswith("-") and (":" in a or "." in a or "/" in a)),
                None,
            )
            return f"{b} ({basename(arg)})" if arg else b

    # 2) Interpreter + script.
    first = basename(toks[0]).split(".")[0]
    if first in _INTERPRETERS:
        script = next((a for a in toks[1:] if not a.startswith("-")), None)
        if script:
            return f"{first} {basename(script)}"
        return first

    # 3) Fallback.
    return basename(toks[0]) or name


def _decorate(procs):
    """Attach friendly_label and project attributes to each process record."""
    for p in procs:
        try:
            toks = _tokens(p.cmdline)
            setattr(
                p,
                "project",
                _detect_project(
                    toks,
                    getattr(p, "cwd", None),
                    getattr(p, "systemd_unit", None),
                    p.name,
                ),
            )
            setattr(p, "friendly_label", _friendly_label(p.name, p.cmdline))
        except Exception:
            setattr(p, "project", None)
            setattr(p, "friendly_label", p.name)
    return procs


@router.get("/", response_class=HTMLResponse)
def overview(request: Request) -> HTMLResponse:
    repository = request.app.state.repository
    processes = _decorate(repository.list_processes(limit=5000))
    duplicate_pids: set[int] = set()
    for group in repository.list_duplicate_groups(limit=200):
        try:
            duplicate_pids.update(int(p) for p in json.loads(group.process_pids))
        except (ValueError, TypeError):
            continue
    # Bucket every process by detected project/service. Unknown ones go under
    # the literal label "unknown" — they remain visible just like any group.
    buckets: dict[str, list] = {}
    for proc in processes:
        setattr(proc, "is_duplicate", proc.pid in duplicate_pids)
        key = proc.project or "unknown"
        buckets.setdefault(key, []).append(proc)

    def _is_user_app(name: str) -> bool:
        """Heuristic: user apps come from /home/*/apps/ or /opt etc. — i.e., not
        a well-known system service name and not 'unknown'."""
        return name != "unknown" and name not in _WELL_KNOWN_SERVICES.values()

    groups = []
    for name, procs in buckets.items():
        groups.append({
            "name": name,
            "procs": sorted(procs, key=lambda p: -p.cpu_percent),
            "total_cpu": sum(p.cpu_percent for p in procs),
            "total_mem_mb": sum(p.memory_mb for p in procs),
            "duplicate_count": sum(1 for p in procs if p.is_duplicate),
            "is_user_app": _is_user_app(name),
        })
    # Sort: user apps first (alphabetical), then system services (alphabetical),
    # then "unknown" at the very end.
    def _sort_key(g):
        tier = 0 if g["is_user_app"] else (1 if g["name"] != "unknown" else 2)
        return (tier, g["name"].lower())
    groups.sort(key=_sort_key)

    # Top resource users — quick-glance cards on the dashboard.
    top_cpu = sorted(processes, key=lambda p: -p.cpu_percent)[:5]
    top_ram = sorted(processes, key=lambda p: -p.memory_mb)[:5]
    top_out = sorted(processes, key=lambda p: -(p.outbound_connections or 0))[:5]
    top_out = [p for p in top_out if (p.outbound_connections or 0) > 0]

    metrics = MetricsService().snapshot()
    return templates.TemplateResponse(
        request,
        "overview.html",
        {
            "groups": groups,
            "metrics": metrics,
            "total_procs": len(processes),
            "total_groups": len(groups),
            "top_cpu": top_cpu,
            "top_ram": top_ram,
            "top_out": top_out,
        },
    )


@router.get("/processes", response_class=HTMLResponse)
def process_page(
    request: Request,
    q: str | None = None,
    suspicious: bool = False,
    duplicates: bool = False,
    group_by_app: bool = False,
) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(
        limit=1000, query=q, suspicious=suspicious or None, duplicates=duplicates or None
    )
    decorated = _decorate(processes)
    if group_by_app:
        # Sort: real apps first (alphabetically), unidentified at the end; within
        # an app, keep the original risk-score ordering by using a stable sort.
        decorated = sorted(
            decorated,
            key=lambda p: (p.project is None, (p.project or "").lower()),
        )
    # Build app summary (top apps by count).
    counts: dict[str, int] = {}
    for p in decorated:
        if p.project:
            counts[p.project] = counts.get(p.project, 0) + 1
    app_summary = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return templates.TemplateResponse(
        request,
        "processes.html",
        {
            "processes": decorated,
            "q": q or "",
            "suspicious": suspicious,
            "duplicates": duplicates,
            "group_by_app": group_by_app,
            "app_summary": app_summary,
        },
    )


@router.get("/top", response_class=HTMLResponse)
def top_page(
    request: Request,
    sort: str = "cpu",
    limit: int = 50,
) -> HTMLResponse:
    """Resource leaderboard — htop-style focused view."""
    valid_sorts = {"cpu", "ram", "out", "rst", "susp"}
    if sort not in valid_sorts:
        sort = "cpu"
    procs = _decorate(request.app.state.repository.list_processes(limit=5000))
    key = {
        "cpu": lambda p: -p.cpu_percent,
        "ram": lambda p: -p.memory_mb,
        "out": lambda p: -(p.outbound_connections or 0),
        "rst": lambda p: -(p.restart_count or 0),
        "susp": lambda p: -(p.suspicious_score or 0),
    }[sort]
    procs = sorted(procs, key=key)[: max(1, min(limit, 500))]
    return templates.TemplateResponse(
        request,
        "top.html",
        {"processes": procs, "sort": sort, "limit": limit},
    )


@router.get("/partials/top-table", response_class=HTMLResponse)
def top_table_partial(
    request: Request,
    sort: str = "cpu",
    limit: int = 50,
) -> HTMLResponse:
    """Just the table body, for HTMX auto-refresh."""
    valid_sorts = {"cpu", "ram", "out", "rst", "susp"}
    if sort not in valid_sorts:
        sort = "cpu"
    procs = _decorate(request.app.state.repository.list_processes(limit=5000))
    key = {
        "cpu": lambda p: -p.cpu_percent,
        "ram": lambda p: -p.memory_mb,
        "out": lambda p: -(p.outbound_connections or 0),
        "rst": lambda p: -(p.restart_count or 0),
        "susp": lambda p: -(p.suspicious_score or 0),
    }[sort]
    procs = sorted(procs, key=key)[: max(1, min(limit, 500))]
    return templates.TemplateResponse(
        request,
        "partials/top_rows.html",
        {"processes": procs, "sort": sort},
    )


@router.get("/suspicious", response_class=HTMLResponse)
def suspicious_page(request: Request) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(limit=500, suspicious=True)
    return templates.TemplateResponse(
        request, "suspicious.html", {"processes": _decorate(processes)}
    )


@router.get("/suggestions", response_class=HTMLResponse)
def suggestions_page(request: Request) -> HTMLResponse:
    repository = request.app.state.repository
    processes = _decorate(repository.list_processes(limit=5000))
    duplicate_pids: set[int] = set()
    for group in repository.list_duplicate_groups(limit=200):
        try:
            duplicate_pids.update(int(p) for p in json.loads(group.process_pids))
        except (ValueError, TypeError):
            continue
    user = current_username()
    suggestions = build_suggestions(
        processes,
        duplicate_pids=duplicate_pids,
        current_user=user,
    )
    tier1 = [s for s in suggestions if s.tier == 1]
    tier2 = [s for s in suggestions if s.tier == 2]
    return templates.TemplateResponse(
        request,
        "suggestions.html",
        {
            "tier1": tier1,
            "tier2": tier2,
            "current_user": user,
            "duplicate_count": len(duplicate_pids),
        },
    )


@router.get("/processes/{pid}", response_class=HTMLResponse)
def process_detail(request: Request, pid: int) -> HTMLResponse:
    proc = request.app.state.repository.get_process_by_pid(pid)
    if not proc:
        raise HTTPException(status_code=404, detail="Process not found")
    notes = request.app.state.repository.list_process_notes(pid=pid, fingerprint=proc.fingerprint)
    try:
        ancestry_pids: list[int] = json.loads(proc.ancestry_json) if proc.ancestry_json else []
    except (ValueError, TypeError):
        ancestry_pids = []
    toks = _tokens(proc.cmdline)
    project = _detect_project(toks, proc.cwd)
    friendly_label = _friendly_label(proc.name, proc.cmdline)
    return templates.TemplateResponse(
        request,
        "process_detail.html",
        {
            "proc": proc,
            "ports": ports_from_record(proc),
            "notes": notes,
            "ancestry_pids": ancestry_pids,
            "project": project,
            "friendly_label": friendly_label,
        },
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
    return templates.TemplateResponse(request, "partials/process_notes.html", {"notes": notes, "proc": proc})


@router.get("/partials/process-table", response_class=HTMLResponse)
def process_table(request: Request) -> HTMLResponse:
    processes = request.app.state.repository.list_processes(limit=200)
    return templates.TemplateResponse(request, "partials/process_table.html", {"processes": _decorate(processes)})


@router.get("/partials/stats-cards", response_class=HTMLResponse)
def stats_cards(request: Request) -> HTMLResponse:
    runtime = get_runtime_metrics()
    metrics = {
        "last_scan_ms": runtime.last_scan_ms,
        "db_write_ms": runtime.db_write_ms,
        **request.app.state.repository.storage_metrics(),
    }
    return templates.TemplateResponse(request, "partials/stats_cards.html", {"metrics": metrics})


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


@router.post("/api/apps/{app_name}/kill", response_class=HTMLResponse)
def kill_app(request: Request, app_name: str) -> HTMLResponse:
    """SIGTERM all processes belonging to the named app/project."""
    processes = _decorate(request.app.state.repository.list_processes(limit=2000))
    targets = [p for p in processes if p.project == app_name]
    if not targets:
        return HTMLResponse('<span class="font-mono text-xs text-zinc-500">— no processes —</span>')
    killed, failed = 0, 0
    for p in targets:
        try:
            os.kill(p.pid, signal.SIGTERM)
            killed += 1
        except (PermissionError, ProcessLookupError):
            failed += 1
    msg = f'<span class="font-mono text-xs text-green-400">SIGTERM → {killed} pid(s)</span>'
    if failed:
        msg += f' <span class="font-mono text-xs text-amber-400">· {failed} failed</span>'
    return HTMLResponse(msg)
