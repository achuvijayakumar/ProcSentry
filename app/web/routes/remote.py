"""Remote SSH hosts: settings CRUD and live process views."""

from __future__ import annotations

import html
import re
from pathlib import Path

import yaml
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import RemoteHostConfig
from app.services import remote_ssh

router = APIRouter(tags=["remote"])
templates = Jinja2Templates(directory="app/web/templates")

_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")


def _result(text: str, ok: bool) -> HTMLResponse:
    color = "text-green-400" if ok else "text-red-400"
    mark = "✓" if ok else "✗"
    return HTMLResponse(f'<span class="font-mono text-xs {color}">{mark} {html.escape(text)}</span>')


def _get_host(request: Request, name: str) -> RemoteHostConfig:
    host = next((h for h in request.app.state.settings.remote_hosts if h.name == name), None)
    if host is None:
        raise HTTPException(status_code=404, detail="Unknown remote host")
    return host


def _save_hosts(request: Request, hosts: tuple[RemoteHostConfig, ...]) -> str | None:
    """Persist hosts to the YAML config and apply in memory. Returns an error string on failure."""

    config_path = Path(getattr(request.app.state, "config_path", "config/vpswatch.yml"))
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        data = {}
    except (OSError, yaml.YAMLError) as exc:
        return f"could not read config: {exc}"
    if not isinstance(data, dict):
        return "config file is not a YAML mapping"
    data["remote_hosts"] = [h.model_dump(exclude_none=True) for h in hosts]
    try:
        config_path.write_text(
            yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config_path.chmod(0o600)
    except OSError as exc:
        return f"could not write config: {exc}"
    request.app.state.settings.remote_hosts = hosts
    return None


def _hosts_partial(request: Request, message: str | None = None, ok: bool = True) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "partials/remote_hosts.html",
        {
            "hosts": request.app.state.settings.remote_hosts,
            "message": message,
            "message_ok": ok,
        },
    )


@router.post("/settings/remote-hosts", response_class=HTMLResponse)
def add_remote_host(
    request: Request,
    name: str = Form(default=""),
    host: str = Form(default=""),
    port: int = Form(default=22),
    username: str = Form(default=""),
    password: str = Form(default=""),
) -> HTMLResponse:
    name, host, username = name.strip(), host.strip(), username.strip()
    if not _NAME_RE.match(name):
        return _hosts_partial(request, "name must be 1-40 chars: letters, digits, . _ -", ok=False)
    if not host or not username:
        return _hosts_partial(request, "host and username are required", ok=False)
    if not 1 <= port <= 65535:
        return _hosts_partial(request, "port must be 1-65535", ok=False)
    settings = request.app.state.settings
    if any(h.name == name for h in settings.remote_hosts):
        return _hosts_partial(request, f"host '{name}' already exists — delete it first", ok=False)
    new = RemoteHostConfig(
        name=name, host=host, port=port, username=username, password=password or None
    )
    error = _save_hosts(request, settings.remote_hosts + (new,))
    if error:
        return _hosts_partial(request, error, ok=False)
    return _hosts_partial(request, f"added '{name}'", ok=True)


@router.post("/settings/remote-hosts/{name}/delete", response_class=HTMLResponse)
def delete_remote_host(request: Request, name: str) -> HTMLResponse:
    settings = request.app.state.settings
    remaining = tuple(h for h in settings.remote_hosts if h.name != name)
    if len(remaining) == len(settings.remote_hosts):
        return _hosts_partial(request, "host not found", ok=False)
    error = _save_hosts(request, remaining)
    if error:
        return _hosts_partial(request, error, ok=False)
    return _hosts_partial(request, f"deleted '{name}'", ok=True)


@router.post("/settings/remote-hosts/{name}/test", response_class=HTMLResponse)
def test_remote_host(request: Request, name: str) -> HTMLResponse:
    host = _get_host(request, name)
    try:
        hostname = remote_ssh.test_connection(host)
    except remote_ssh.RemoteError as exc:
        return _result(str(exc), False)
    return _result(f"connected — remote hostname: {hostname}", True)


@router.get("/remote", response_class=HTMLResponse)
def remote_page(request: Request, host: str | None = None) -> HTMLResponse:
    hosts = request.app.state.settings.remote_hosts
    selected = host if host and any(h.name == host for h in hosts) else None
    if selected is None and hosts:
        selected = hosts[0].name
    return templates.TemplateResponse(
        request,
        "remote.html",
        {"hosts": hosts, "selected": selected},
    )


@router.get("/remote/{name}/partials/processes", response_class=HTMLResponse)
def remote_process_table(request: Request, name: str) -> HTMLResponse:
    host = _get_host(request, name)
    error = None
    procs: list[remote_ssh.RemoteProcess] = []
    try:
        procs = remote_ssh.list_processes(host)
    except remote_ssh.RemoteError as exc:
        error = str(exc)
    return templates.TemplateResponse(
        request,
        "partials/remote_process_table.html",
        {"host": host, "processes": procs, "error": error},
    )


@router.post("/remote/{name}/kill/{pid}")
def remote_kill(request: Request, name: str, pid: int) -> dict[str, object]:
    host = _get_host(request, name)
    try:
        outcome = remote_ssh.kill_process(host, pid)
    except remote_ssh.RemoteError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if outcome == "gone":
        raise HTTPException(status_code=404, detail="Process already gone")
    if outcome == "denied":
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied — '{host.username}' cannot signal this process",
        )
    return {"ok": True, "pid": pid, "outcome": outcome}
