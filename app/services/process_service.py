"""Daemon orchestration service."""

from __future__ import annotations

import asyncio
import logging
import time

from app.config import Settings
from app.core.duplicate_detector import DuplicateDetector
from app.core.resource_tracker import ResourceTracker
from app.core.scanner import ProcessScanner
from app.core.security_engine import SecurityEngine
from app.database.repository import ProcessRepository
from app.services import host_services
from app.services.alert_service import AlertService
from app.services.runtime_registry import get_runtime_metrics

logger = logging.getLogger(__name__)


class ProcessService:
    """Coordinate scanning, detection, alerting, and persistence."""

    def __init__(
        self,
        settings: Settings,
        repository: ProcessRepository,
        scanner: ProcessScanner | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._scanner = scanner or ProcessScanner()
        self._duplicates = DuplicateDetector(config=settings.duplicate_detection)
        self._resources = ResourceTracker(settings.alerts)
        self._security = SecurityEngine(settings.security)
        self._alerts = AlertService(repository)
        self._stop = asyncio.Event()
        self.metrics = get_runtime_metrics()
        self._last_cleanup_at = 0.0
        self._last_checkpoint_at = 0.0
        self._last_vacuum_at = 0.0
        self._last_unit_check_at = 0.0
        self._known_failed_units: set[str] = set()

    def stop(self) -> None:
        """Request daemon shutdown."""

        self._stop.set()

    async def run_forever(self) -> None:
        """Run the process intelligence loop until stopped."""

        logger.info("Starting ProcSentry scan loop")
        self._scanner.prime()
        while not self._stop.is_set():
            await self.scan_once()
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._settings.scan_interval)
            except TimeoutError:
                continue

    def _check_failed_units(self) -> None:
        """Alert on units that newly entered the failed state; note recoveries."""

        failed = host_services.list_failed_units()
        if failed is None:  # systemctl unavailable or probe error — skip cycle
            return
        current = set(failed)
        for unit in sorted(current - self._known_failed_units):
            self._alerts.emit(
                "systemd",
                "CRITICAL",
                f"systemd unit failed: {unit} — check /services for logs and restart",
                fingerprint=unit,
                category="systemd",
            )
        for unit in sorted(self._known_failed_units - current):
            self._alerts.emit(
                "systemd",
                "INFO",
                f"systemd unit recovered: {unit}",
                fingerprint=unit,
                category="systemd",
            )
        self._known_failed_units = current

    async def scan_once(self) -> None:
        """Run one full scan and detection cycle."""

        started = time.perf_counter()
        snapshots = await self._scanner.scan()
        scan_elapsed_ms = (time.perf_counter() - started) * 1000
        detect_started = time.perf_counter()
        groups = self._duplicates.detect(snapshots) if self._settings.duplicate_detection.enabled else []
        security_findings = self._security.scan(snapshots)
        db_started = time.perf_counter()
        self._repository.upsert_processes(
            snapshots,
            history_sample_interval_seconds=self._settings.storage.history_sample_interval_seconds,
        )
        db_write_ms = (time.perf_counter() - db_started) * 1000
        self._repository.add_duplicate_groups(groups)
        now = time.monotonic()
        maintenance_ms = 0.0
        if now - self._last_cleanup_at > self._settings.storage.maintenance_interval_seconds:
            maintenance_started = time.perf_counter()
            checkpoint = now - self._last_checkpoint_at > self._settings.storage.wal_checkpoint_interval_seconds
            vacuum = now - self._last_vacuum_at > self._settings.storage.vacuum_interval_seconds
            self._repository.run_maintenance(self._settings.history_retention_days, checkpoint, vacuum)
            maintenance_ms = (time.perf_counter() - maintenance_started) * 1000
            self._last_cleanup_at = now
            if checkpoint:
                self._last_checkpoint_at = now
            if vacuum:
                self._last_vacuum_at = now

        for group in groups:
            self._alerts.emit(
                "duplicate",
                "WARNING" if group.confidence < 90 else "CRITICAL",
                f"{len(group.processes)} duplicate processes detected ({group.confidence}%): "
                f"{', '.join(str(proc.pid) for proc in group.processes)}",
                fingerprint=group.fingerprint,
            )
        if time.monotonic() - self._last_unit_check_at > 30:
            self._last_unit_check_at = time.monotonic()
            self._check_failed_units()
        for proc, severity, message in self._resources.high_usage(snapshots):
            self._alerts.emit("resource", severity, message, pid=proc.pid, fingerprint=proc.fingerprint)
        for finding in security_findings:
            self._alerts.emit(
                "security", finding.severity, finding.message, pid=finding.pid, category=finding.category
            )
        self.metrics.scan_count += 1
        self.metrics.last_scan_ms = scan_elapsed_ms
        profile = getattr(self._scanner, "last_profile", {})
        self.metrics.scan_collect_ms = float(profile.get("collect_ms", 0.0))
        self.metrics.scan_ports_ms = float(profile.get("ports_ms", 0.0))
        self.metrics.scan_socket_enum_ms = float(profile.get("socket_enum_ms", 0.0))
        self.metrics.scan_enrich_ms = float(profile.get("enrich_ms", 0.0))
        self.metrics.scan_fingerprint_ms = float(profile.get("fingerprint_ms", 0.0))
        self.metrics.process_count = len(snapshots)
        self.metrics.duplicate_count = len(groups)
        self.metrics.security_finding_count = len(security_findings)
        self.metrics.db_write_ms = db_write_ms
        self.metrics.maintenance_ms = maintenance_ms
        self.metrics.scanner_cache_hits = getattr(self._scanner, "cache_hits", 0)
        self.metrics.scanner_cache_misses = getattr(self._scanner, "cache_misses", 0)
        self.metrics.scanner_fingerprint_cache_hits = getattr(
            self._scanner, "fingerprint_cache_hits", 0
        )
        self.metrics.scanner_fingerprint_cache_misses = getattr(
            self._scanner, "fingerprint_cache_misses", 0
        )
        elapsed_ms = (time.perf_counter() - detect_started) * 1000
        logger.info(
            "Scan complete: processes=%d duplicates=%d security_findings=%d scan_ms=%.1f db_ms=%.1f maintenance_ms=%.1f detect_persist_ms=%.1f scan=%d",
            len(snapshots),
            len(groups),
            len(security_findings),
            scan_elapsed_ms,
            db_write_ms,
            maintenance_ms,
            elapsed_ms,
            self.metrics.scan_count,
        )
