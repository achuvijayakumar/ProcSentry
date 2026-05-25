"""Startup diagnostics and production configuration validation."""

from __future__ import annotations

import logging

from app.collectors.common.capabilities import PlatformCapabilities
from app.config import Settings

logger = logging.getLogger(__name__)


def validate_startup(settings: Settings, capabilities: PlatformCapabilities) -> list[str]:
    """Return startup warnings for unsafe or degraded production operation."""

    warnings: list[str] = []
    if settings.scan_interval < 2:
        warnings.append("scan_interval below 2s can raise idle CPU on small VPS instances")
    if settings.web.host == "0.0.0.0" and not settings.web.auth_enabled:
        warnings.append("web dashboard binds publicly without built-in authentication")
    if settings.web.auth_enabled:
        if not settings.web.auth_password or settings.web.auth_password == "change-me":
            warnings.append("web authentication enabled with missing/default password")
        if not settings.web.session_secret or settings.web.session_secret == "change-me-long-random-secret":
            warnings.append("web authentication enabled with missing/default session_secret")
    if not capabilities.is_linux:
        warnings.append("running outside Linux; production procfs/cgroup/systemd intelligence is disabled")
    if capabilities.is_linux and not capabilities.supports_procfs:
        warnings.append("Linux detected but /proc is unavailable; scanner will be degraded")
    if capabilities.is_linux and not capabilities.supports_cgroups:
        warnings.append("cgroup support unavailable; container/systemd attribution will be limited")
    if settings.healing.enabled and not settings.healing.dry_run:
        warnings.append("auto-healing is enabled and not dry-run; process termination may occur")
    return warnings


def log_startup_diagnostics(settings: Settings, capabilities: PlatformCapabilities) -> list[str]:
    """Log startup diagnostics and return warnings."""

    logger.info(
        "Startup capabilities: system=%s procfs=%s cgroups=%s systemd=%s deleted_exe=%s zombie=%s",
        capabilities.system,
        capabilities.supports_procfs,
        capabilities.supports_cgroups,
        capabilities.supports_systemd,
        capabilities.supports_deleted_exe,
        capabilities.supports_zombie_state,
    )
    warnings = validate_startup(settings, capabilities)
    for warning in warnings:
        logger.warning("Startup warning: %s", warning)
    return warnings
