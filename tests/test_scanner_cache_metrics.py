"""Scanner cache metric tests."""

import asyncio

from app.collectors.common.capabilities import PlatformCapabilities
from app.collectors.common.factory import create_process_enricher
from app.core.scanner import ProcessScanner
from tests.fakes import proc


class StaticCollector:
    def prime_cpu_counters(self) -> None:
        return None

    def collect(self):
        return [proc(10)]


def test_scanner_debounce_and_fingerprint_cache_metrics() -> None:
    capabilities = PlatformCapabilities(
        system="Windows",
        is_linux=False,
        is_windows=True,
        supports_procfs=False,
        supports_systemd=False,
        supports_cgroups=False,
        supports_deleted_exe=False,
        supports_zombie_state=False,
    )
    scanner = ProcessScanner(
        collector=StaticCollector(),
        enricher=create_process_enricher(capabilities),
        min_scan_interval=60,
    )

    asyncio.run(scanner.scan())
    asyncio.run(scanner.scan())

    assert scanner.cache_misses == 1
    assert scanner.cache_hits == 1
    assert scanner.fingerprint_cache_misses == 1
