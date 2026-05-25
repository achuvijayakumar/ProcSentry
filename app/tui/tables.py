"""Rich table builders for terminal output."""

from __future__ import annotations

from rich.table import Table

from app.database.models import ProcessRecord


def process_table(processes: list[ProcessRecord]) -> Table:
    """Build a live process table."""

    table = Table(title="Processes")
    for column in ("PID", "Name", "CPU", "RAM MB", "Dup", "Susp", "Status"):
        table.add_column(column)
    for proc in processes[:40]:
        table.add_row(
            str(proc.pid),
            proc.name[:28],
            f"{proc.cpu_percent:.1f}",
            f"{proc.memory_mb:.1f}",
            str(proc.duplicate_score),
            str(proc.suspicious_score),
            proc.status or "",
        )
    return table

