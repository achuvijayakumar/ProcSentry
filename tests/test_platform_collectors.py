"""Platform-aware collector tests."""

import asyncio

from app.collectors.common.capabilities import PlatformCapabilities
from app.collectors.common.factory import create_process_enricher
from app.collectors.linux.enricher import LinuxProcessEnricher
from app.collectors.windows.enricher import WindowsProcessEnricher
from app.core.scanner import ProcessScanner
from tests.fakes import proc


class FakeCollector:
    """Small scanner collector fixture."""

    def prime_cpu_counters(self) -> None:
        return None

    def collect(self):
        return [proc(10, executable="C:/Python/python.exe", cwd="C:/app")]


def test_windows_capabilities_select_fallback_enricher() -> None:
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

    enricher = create_process_enricher(capabilities)

    assert isinstance(enricher, WindowsProcessEnricher)


def test_linux_capabilities_select_linux_enricher() -> None:
    capabilities = PlatformCapabilities(
        system="Linux",
        is_linux=True,
        is_windows=False,
        supports_procfs=True,
        supports_systemd=True,
        supports_cgroups=True,
        supports_deleted_exe=True,
        supports_zombie_state=True,
    )

    enricher = create_process_enricher(capabilities)

    assert isinstance(enricher, LinuxProcessEnricher)


def test_scanner_runs_with_windows_fallback_enricher() -> None:
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
        collector=FakeCollector(),
        enricher=create_process_enricher(capabilities),
        min_scan_interval=0,
    )

    snapshots = asyncio.run(scanner.scan())

    assert len(snapshots) == 1
    assert snapshots[0].container_id is None
    assert snapshots[0].executable_deleted is False
    assert snapshots[0].fingerprint is not None
