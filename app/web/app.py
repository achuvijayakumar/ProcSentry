"""FastAPI application factory."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import time

from app.config import Settings
from app.collectors.common.capabilities import detect_capabilities
from app.database.repository import ProcessRepository
from app.web.routes import alerts, duplicates, ports, processes, roast, system
from app.web.security import install_security


def create_app(settings: Settings, repository: ProcessRepository) -> FastAPI:
    """Create the web dashboard app."""

    app = FastAPI(title=settings.app_name)
    app.state.settings = settings
    app.state.repository = repository
    app.state.capabilities = detect_capabilities()
    app.mount("/static", StaticFiles(directory="app/web/static"), name="static")
    _install_rate_limit(app)
    install_security(app, settings)
    app.include_router(processes.router)
    app.include_router(duplicates.router)
    app.include_router(ports.router)
    app.include_router(alerts.router)
    app.include_router(roast.router)
    app.include_router(system.router)
    return app


def _install_rate_limit(app: FastAPI) -> None:
    """Install a tiny in-memory per-IP rate limiter."""

    buckets: dict[str, list[float]] = {}

    @app.middleware("http")
    async def rate_limit(request: Request, call_next):
        client = request.client.host if request.client else "local"
        now = time.monotonic()
        bucket = [stamp for stamp in buckets.get(client, []) if now - stamp < 60]
        if len(bucket) > 300:
            return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
        bucket.append(now)
        buckets[client] = bucket
        return await call_next(request)
