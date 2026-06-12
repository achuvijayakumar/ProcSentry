"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.collectors.common.capabilities import detect_capabilities
from app.database.repository import ProcessRepository
from app.services.process_service import ProcessService
from app.web.routes import alerts, duplicates, ports, processes, remote, roast, services, settings as settings_routes, system
from app.web.security import install_security
from app.web.url_prefix import prefixed_url

logger = logging.getLogger(__name__)


def create_app(settings: Settings, repository: ProcessRepository) -> FastAPI:
    """Create the web dashboard app.

    Runs the scan loop as a background task so the dashboard always serves
    live process data, even when the standalone daemon is not installed.
    """

    service = ProcessService(settings, repository)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(_run_scanner(service))
        yield
        service.stop()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    app = FastAPI(title=settings.app_name, lifespan=lifespan)
    app.state.settings = settings
    app.state.repository = repository
    app.state.capabilities = detect_capabilities()
    app.mount("/static", StaticFiles(directory="app/web/static"), name="static")
    _register_url_helper()
    _install_rate_limit(app)
    install_security(app, settings)
    app.include_router(processes.router)
    app.include_router(duplicates.router)
    app.include_router(ports.router)
    app.include_router(alerts.router)
    app.include_router(roast.router)
    app.include_router(services.router)
    app.include_router(remote.router)
    app.include_router(settings_routes.router)
    app.include_router(system.router)
    return app


async def _run_scanner(service: ProcessService) -> None:
    """Keep the scan loop alive; restart it if a scan cycle crashes."""

    while True:
        try:
            await service.run_forever()
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scan loop crashed; restarting in 10s")
            await asyncio.sleep(10)


def _register_url_helper() -> None:
    """Expose ``url(request, path)`` to every Jinja environment in use.

    Each route module owns its own ``Jinja2Templates`` instance, so register
    the prefix-aware helper on all of them from one place.
    """

    from app.web import security
    from app.web.routes import alerts, duplicates, ports, processes, remote, roast, services, system
    from app.web.routes import settings as settings_routes

    modules = (security, alerts, duplicates, ports, processes, remote, roast, services, settings_routes, system)
    for module in modules:
        env = module.templates.env
        env.globals["url"] = prefixed_url


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
