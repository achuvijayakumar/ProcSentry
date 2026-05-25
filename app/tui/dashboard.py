"""Textual terminal dashboard."""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Static

from app.config import Settings
from app.database.repository import ProcessRepository
from app.services.metrics_service import MetricsService


class ProcSentryApp(App[None]):
    """Live terminal UI for process intelligence."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("i", "inspect", "Inspect"),
        ("k", "kill", "Kill"),
        ("/", "toggle_filter", "Filter"),
    ]

    def __init__(self, settings: Settings, repository: ProcessRepository) -> None:
        super().__init__()
        self.settings = settings
        self.repository = repository
        self.metrics = MetricsService()
        self.table: DataTable[str] = DataTable()
        self.summary = Static()
        self.alerts = Static()
        self.only_suspicious = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield self.summary
            yield self.alerts
        yield self.table
        yield Footer()

    def on_mount(self) -> None:
        self.table.add_columns("PID", "Name", "CPU", "RAM MB", "Ports", "Dup", "Susp", "Status")
        self.set_interval(self.settings.scan_interval, self.refresh_data)
        self.refresh_data()

    def action_refresh(self) -> None:
        self.refresh_data()

    def action_inspect(self) -> None:
        row = self.table.cursor_row
        if row is not None and row >= 0:
            self.notify(f"Inspect PID {self.table.get_row_at(row)[0]}")

    def action_kill(self) -> None:
        row = self.table.cursor_row
        if row is not None and row >= 0:
            self.notify(f"Kill is guarded by auto-healing settings for PID {self.table.get_row_at(row)[0]}")

    def action_toggle_filter(self) -> None:
        self.only_suspicious = not self.only_suspicious
        self.refresh_data()

    def refresh_data(self) -> None:
        metrics = self.metrics.snapshot()
        alerts = self.repository.list_alerts(limit=20)
        processes = self.repository.list_processes(limit=200, suspicious=self.only_suspicious or None)
        duplicates = self.repository.list_duplicate_groups(limit=20)
        self.summary.update(
            f"CPU {metrics['cpu_percent']:.1f}% | RAM {metrics['memory_percent']:.1f}% | "
            f"Processes {len(processes)} | Duplicates {len(duplicates)} | Alerts {len(alerts)} | "
            f"Filter {'suspicious' if self.only_suspicious else 'all'}"
        )
        self.alerts.update("\n".join(f"{alert.severity}: {alert.message[:80]}" for alert in alerts[:5]))
        self.table.clear()
        for proc in processes:
            self.table.add_row(
                str(proc.pid),
                proc.name[:36],
                f"{proc.cpu_percent:.1f}",
                f"{proc.memory_mb:.1f}",
                proc.ports_json,
                str(proc.duplicate_score),
                str(proc.suspicious_score),
                proc.status or "",
            )


def run_tui(settings: Settings, repository: ProcessRepository) -> None:
    """Run the terminal UI."""

    ProcSentryApp(settings, repository).run()
