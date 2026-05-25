"""Cross-platform psutil-backed process collector."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import psutil

from app.schemas import ProcessSnapshot

logger = logging.getLogger(__name__)


class PsutilProcessCollector:
    """Collect process metadata with permission-aware cross-platform fallbacks."""

    attrs = [
        "pid",
        "ppid",
        "name",
        "cmdline",
        "exe",
        "cwd",
        "username",
        "cpu_percent",
        "memory_info",
        "status",
        "num_threads",
        "create_time",
    ]

    def prime_cpu_counters(self) -> None:
        """Prime psutil CPU counters so later samples are meaningful."""

        for proc in psutil.process_iter(["pid"]):
            try:
                proc.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def collect(self) -> list[ProcessSnapshot]:
        """Collect one snapshot of visible processes."""

        snapshots: list[ProcessSnapshot] = []
        for proc in psutil.process_iter(self.attrs):
            try:
                info = proc.info
                memory = info.get("memory_info")
                start = info.get("create_time")
                snapshots.append(
                    ProcessSnapshot(
                        pid=int(info["pid"]),
                        ppid=info.get("ppid"),
                        name=info.get("name") or f"pid-{info['pid']}",
                        cmdline=tuple(info.get("cmdline") or ()),
                        executable=info.get("exe"),
                        cwd=info.get("cwd"),
                        user=info.get("username"),
                        cpu_percent=float(info.get("cpu_percent") or 0.0),
                        memory_mb=(float(memory.rss) / 1024 / 1024) if memory else 0.0,
                        status=info.get("status"),
                        threads=int(info.get("num_threads") or 0),
                        start_time=(
                            datetime.fromtimestamp(float(start), tz=timezone.utc) if start else None
                        ),
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug("Skipping process %s due to collector error: %s", proc, exc)
        return snapshots

