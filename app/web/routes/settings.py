"""Dashboard settings routes: password change."""

from __future__ import annotations

import hmac
import html
from pathlib import Path

import yaml
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["settings"])
templates = Jinja2Templates(directory="app/web/templates")

MIN_PASSWORD_LENGTH = 10


def _result(text: str, ok: bool) -> HTMLResponse:
    color = "text-green-400" if ok else "text-red-400"
    mark = "✓" if ok else "✗"
    return HTMLResponse(f'<span class="font-mono text-xs {color}">{mark} {html.escape(text)}</span>')


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request) -> HTMLResponse:
    settings = request.app.state.settings
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "auth_enabled": settings.web.auth_enabled,
            "auth_username": settings.web.auth_username,
            "min_length": MIN_PASSWORD_LENGTH,
        },
    )


@router.post("/settings/password", response_class=HTMLResponse)
def change_password(
    request: Request,
    current_password: str = Form(default=""),
    new_password: str = Form(default=""),
    confirm_password: str = Form(default=""),
) -> HTMLResponse:
    settings = request.app.state.settings
    web = settings.web
    if not web.auth_enabled:
        return _result("auth is disabled — enable web.auth_enabled in the config first", False)
    if not hmac.compare_digest(current_password, web.auth_password or ""):
        return _result("current password is incorrect", False)
    if len(new_password) < MIN_PASSWORD_LENGTH:
        return _result(f"new password must be at least {MIN_PASSWORD_LENGTH} characters", False)
    if new_password == current_password:
        return _result("new password must differ from the current one", False)
    if not hmac.compare_digest(new_password, confirm_password):
        return _result("new passwords do not match", False)

    config_path = Path(getattr(request.app.state, "config_path", "config/vpswatch.yml"))
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return _result(f"could not read config: {exc}", False)
    if not isinstance(data, dict):
        return _result("config file is not a YAML mapping", False)
    data.setdefault("web", {})["auth_password"] = new_password
    try:
        config_path.write_text(
            yaml.safe_dump(data, default_flow_style=False, sort_keys=False), encoding="utf-8"
        )
        config_path.chmod(0o600)
    except OSError as exc:
        return _result(f"could not write config: {exc}", False)

    # Apply immediately — next login uses the new password. Existing
    # sessions stay valid because they are signed with session_secret.
    web.auth_password = new_password
    return _result("password changed — use it on next login", True)
