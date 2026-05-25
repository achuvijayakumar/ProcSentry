"""Backward-compatible Linux systemd imports."""

from app.collectors.linux.systemd import detect_service_manager, detect_systemd_unit

__all__ = ["detect_service_manager", "detect_systemd_unit"]
