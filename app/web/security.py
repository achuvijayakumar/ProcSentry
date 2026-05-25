"""Lightweight dashboard authentication and CSRF protection."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import Response

from app.config import Settings

templates = Jinja2Templates(directory="app/web/templates")

SESSION_COOKIE = "procsentry_session"
CSRF_COOKIE = "procsentry_csrf"
PUBLIC_PATHS = {"/login", "/health", "/stats", "/metrics", "/capabilities", "/health/score"}


def install_security(app: FastAPI, settings: Settings) -> None:
    """Install optional auth and CSRF middleware plus login routes."""

    @app.middleware("http")
    async def dashboard_security(request: Request, call_next):
        request.state.csrf_token = _ensure_csrf_cookie(request)
        if request.url.path.startswith("/static"):
            return await call_next(request)
        if settings.web.auth_enabled and not _is_public(request.url.path):
            if not _valid_session(request, settings):
                if request.url.path.startswith("/api/") or request.headers.get("hx-request"):
                    return Response("authentication required", status_code=401)
                return RedirectResponse("/login", status_code=303)
        if settings.web.csrf_enabled and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.url.path not in {"/login", "/logout"} and not _valid_csrf(request):
                return Response("csrf token invalid", status_code=403)
        response = await call_next(request)
        if not request.cookies.get(CSRF_COOKIE):
            response.set_cookie(
                CSRF_COOKIE,
                request.state.csrf_token,
                httponly=False,
                secure=settings.web.secure_cookies,
                samesite="lax",
            )
        return response

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "login.html", {"error": None})

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        if not _credentials_match(username, password, settings):
            return templates.TemplateResponse(
                request, "login.html", {"error": "Invalid credentials"}, status_code=401
            )
        token = _sign_session(username, settings)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            secure=settings.web.secure_cookies,
            samesite="lax",
        )
        return response

    @app.post("/logout")
    def logout() -> Response:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE)
        return response


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS


def _ensure_csrf_cookie(request: Request) -> str:
    return request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(24)


def _valid_csrf(request: Request) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("x-csrf-token")
    return bool(cookie and header and hmac.compare_digest(cookie, header))


def _credentials_match(username: str, password: str, settings: Settings) -> bool:
    expected_password = settings.web.auth_password or ""
    return hmac.compare_digest(username, settings.web.auth_username) and hmac.compare_digest(
        password, expected_password
    )


def _sign_session(username: str, settings: Settings) -> str:
    secret = _session_secret(settings)
    issued = str(int(time.time()))
    payload = f"{username}:{issued}"
    signature = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload.encode() + b"." + signature).decode()


def _valid_session(request: Request, settings: Settings) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    try:
        raw = base64.urlsafe_b64decode(token.encode())
        payload, signature = raw.rsplit(b".", 1)
        expected = hmac.new(_session_secret(settings), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return False
        username, issued = payload.decode().split(":", 1)
        if username != settings.web.auth_username:
            return False
        return time.time() - int(issued) < 86400
    except Exception:
        return False


def _session_secret(settings: Settings) -> bytes:
    return (settings.web.session_secret or settings.web.auth_password or "dev-only-secret").encode()
