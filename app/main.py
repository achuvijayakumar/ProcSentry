"""Command line entrypoint for ProcSentry."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal

from app.factory import bootstrap
from app.services.process_service import ProcessService

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""

    parser = argparse.ArgumentParser(prog="procsentry", description="Linux VPS process monitor")
    parser.add_argument("--config", help="Path to YAML config file")
    sub = parser.add_subparsers(dest="command", required=False)
    sub.add_parser("scan-once", help="Run one scan cycle")
    sub.add_parser("daemon", help="Run the monitoring daemon")
    sub.add_parser("tui", help="Run terminal UI")
    sub.add_parser("web", help="Run FastAPI web dashboard")
    return parser


async def _run_daemon(config_path: str | None) -> None:
    settings, repository = bootstrap(config_path)
    service = ProcessService(settings, repository)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, service.stop)
        except NotImplementedError:
            pass
    await service.run_forever()


async def _scan_once(config_path: str | None) -> None:
    settings, repository = bootstrap(config_path)
    await ProcessService(settings, repository).scan_once()


def main() -> None:
    """Run the selected command."""

    args = build_parser().parse_args()
    command = args.command or "tui"
    if command == "daemon":
        asyncio.run(_run_daemon(args.config))
    elif command == "scan-once":
        asyncio.run(_scan_once(args.config))
    elif command == "web":
        import uvicorn

        from app.web.app import create_app

        settings, repository = bootstrap(args.config)
        app = create_app(settings, repository)
        if args.config:
            app.state.config_path = args.config
        uvicorn.run(app, host=settings.web.host, port=settings.web.port)
    elif command == "tui":
        from app.tui.dashboard import run_tui

        settings, repository = bootstrap(args.config)
        run_tui(settings, repository)
    else:
        raise SystemExit(f"Unknown command: {command}")


if __name__ == "__main__":
    main()
