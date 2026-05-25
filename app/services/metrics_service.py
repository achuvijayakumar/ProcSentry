"""System-level metric helpers."""

from __future__ import annotations

import os

import psutil


class MetricsService:
    """Expose lightweight host metrics for UIs."""

    def snapshot(self) -> dict[str, float | tuple[float, float, float]]:
        """Return current host metrics."""

        memory = psutil.virtual_memory()
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": memory.percent,
            "memory_used_mb": memory.used / 1024 / 1024,
            "memory_total_mb": memory.total / 1024 / 1024,
            "load_average": os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0),
        }

