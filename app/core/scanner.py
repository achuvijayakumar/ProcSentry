"""Coordinated process scanner."""

from __future__ import annotations

import asyncio
import logging
import time

from app.collectors.common.enricher import ProcessEnricher
from app.collectors.common.factory import create_process_collector, create_process_enricher
from app.collectors.common.psutil_collector import PsutilProcessCollector
from app.core.fingerprint import FingerprintEngine
from app.core.port_mapper import PortMapper
from app.core.process_tree import trace_ancestry
from app.schemas import ProcessSnapshot

logger = logging.getLogger(__name__)


class ProcessScanner:
    """Collect, enrich, and fingerprint Linux processes."""

    def __init__(
        self,
        collector: PsutilProcessCollector | None = None,
        enricher: ProcessEnricher | None = None,
        port_mapper: PortMapper | None = None,
        fingerprint_engine: FingerprintEngine | None = None,
        min_scan_interval: float = 1.0,
    ) -> None:
        self._collector = collector or create_process_collector()
        self._enricher = enricher or create_process_enricher()
        self._port_mapper = port_mapper or PortMapper()
        self._fingerprints = fingerprint_engine or FingerprintEngine()
        self._min_scan_interval = min_scan_interval
        self._last_scan_at = 0.0
        self._last_snapshots: list[ProcessSnapshot] = []
        self._pid_hash_cache: dict[tuple[int, str | None], str | None] = {}
        self._fingerprint_cache: dict[
            tuple[int, object, str | None, str | None, tuple[str, ...]], tuple[str | None, str | None]
        ] = {}
        self.cache_hits = 0
        self.cache_misses = 0
        self.fingerprint_cache_hits = 0
        self.fingerprint_cache_misses = 0
        self.last_profile: dict[str, float] = {
            "total_ms": 0.0,
            "collect_ms": 0.0,
            "ports_ms": 0.0,
            "socket_enum_ms": 0.0,
            "enrich_ms": 0.0,
            "fingerprint_ms": 0.0,
        }

    def prime(self) -> None:
        """Prime CPU counters before the daemon scan loop starts."""

        self._collector.prime_cpu_counters()

    async def scan(self) -> list[ProcessSnapshot]:
        """Run one process scan off the event loop."""

        return await asyncio.to_thread(self._scan_sync)

    def _scan_sync(self) -> list[ProcessSnapshot]:
        now = time.monotonic()
        if self._last_snapshots and now - self._last_scan_at < self._min_scan_interval:
            logger.debug("Debounced process scan")
            self.cache_hits += 1
            self.last_profile = {
                "total_ms": 0.0,
                "collect_ms": 0.0,
                "ports_ms": 0.0,
                "socket_enum_ms": 0.0,
                "enrich_ms": 0.0,
                "fingerprint_ms": 0.0,
            }
            return self._last_snapshots
        self.cache_misses += 1
        scan_started = time.perf_counter()
        stage_started = time.perf_counter()
        snapshots = self._collector.collect()
        collect_ms = (time.perf_counter() - stage_started) * 1000
        stage_started = time.perf_counter()
        self._port_mapper.attach(snapshots)
        ports_ms = (time.perf_counter() - stage_started) * 1000
        enrich_ms = 0.0
        fingerprint_ms = 0.0
        parents = {snapshot.pid: snapshot.ppid for snapshot in snapshots}
        for snapshot in snapshots:
            stage_started = time.perf_counter()
            self._enricher.enrich(snapshot)
            enrich_ms += (time.perf_counter() - stage_started) * 1000
            hash_key = (snapshot.pid, snapshot.executable)
            if hash_key not in self._pid_hash_cache:
                self._pid_hash_cache[hash_key] = (
                    self._enricher.hash_executable(snapshot.executable, max_bytes=256_000)
                    if self._should_hash(snapshot.executable, snapshot.executable_deleted)
                    else None
                )
                if len(self._pid_hash_cache) > 4096:
                    self._pid_hash_cache.clear()
            snapshot.executable_hash = self._pid_hash_cache[hash_key]
            snapshot.ancestry = trace_ancestry(snapshot.pid, parents)
            stage_started = time.perf_counter()
            fingerprint_key = (
                snapshot.pid,
                snapshot.start_time,
                snapshot.executable,
                snapshot.cwd,
                snapshot.cmdline,
            )
            cached_fingerprint = self._fingerprint_cache.get(fingerprint_key)
            if cached_fingerprint:
                self.fingerprint_cache_hits += 1
                snapshot.fingerprint, snapshot.fuzzy_fingerprint = cached_fingerprint
            else:
                self.fingerprint_cache_misses += 1
                self._fingerprints.apply(snapshot)
                self._fingerprint_cache[fingerprint_key] = (
                    snapshot.fingerprint,
                    snapshot.fuzzy_fingerprint,
                )
                if len(self._fingerprint_cache) > 8192:
                    self._fingerprint_cache.clear()
            fingerprint_ms += (time.perf_counter() - stage_started) * 1000
        self._last_snapshots = snapshots
        self._last_scan_at = time.monotonic()
        self.last_profile = {
            "total_ms": (time.perf_counter() - scan_started) * 1000,
            "collect_ms": collect_ms,
            "ports_ms": ports_ms,
            "socket_enum_ms": self._port_mapper.last_socket_enum_ms,
            "enrich_ms": enrich_ms,
            "fingerprint_ms": fingerprint_ms,
        }
        logger.debug("Scanned %d processes", len(snapshots))
        return snapshots

    def _should_hash(self, executable: str | None, deleted: bool) -> bool:
        if not executable:
            return False
        return deleted or executable.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/usr/bin/", "/usr/local/bin/"))
