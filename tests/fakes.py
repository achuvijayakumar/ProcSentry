"""Fake process snapshots for tests."""

from __future__ import annotations

from datetime import datetime, timezone

from app.schemas import ProcessSnapshot


def proc(
    pid: int,
    name: str = "python",
    cmdline: tuple[str, ...] = ("python3", "app.py"),
    executable: str = "/usr/bin/python3",
    cwd: str = "/srv/app",
    cpu_percent: float = 1.0,
) -> ProcessSnapshot:
    """Create a test process snapshot."""

    return ProcessSnapshot(
        pid=pid,
        ppid=1,
        name=name,
        cmdline=cmdline,
        executable=executable,
        cwd=cwd,
        user="ubuntu",
        cpu_percent=cpu_percent,
        memory_mb=128,
        status="sleeping",
        threads=2,
        start_time=datetime.fromtimestamp(1_700_000_000 + pid, tz=timezone.utc),
    )

