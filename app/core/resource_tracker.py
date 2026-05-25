"""Resource threshold evaluation."""

from __future__ import annotations

from app.config import AlertConfig
from app.schemas import ProcessSnapshot


class ResourceTracker:
    """Evaluate process resource usage against configured thresholds."""

    def __init__(self, config: AlertConfig) -> None:
        self._config = config

    def high_usage(self, snapshots: list[ProcessSnapshot]) -> list[tuple[ProcessSnapshot, str, str]]:
        """Return processes breaching CPU or RAM thresholds."""

        findings: list[tuple[ProcessSnapshot, str, str]] = []
        for proc in snapshots:
            if proc.cpu_percent >= self._config.cpu_threshold_percent:
                findings.append((proc, "warning", f"PID {proc.pid} CPU usage is {proc.cpu_percent:.1f}%"))
            if proc.memory_mb >= self._config.ram_threshold_mb:
                findings.append((proc, "warning", f"PID {proc.pid} RAM usage is {proc.memory_mb:.1f} MB"))
        return findings

