"""Platform-aware collector factory."""

from __future__ import annotations

from app.collectors.common.capabilities import PlatformCapabilities, detect_capabilities
from app.collectors.common.enricher import ProcessEnricher
from app.collectors.common.psutil_collector import PsutilProcessCollector
from app.collectors.linux.enricher import LinuxProcessEnricher
from app.collectors.windows.enricher import WindowsProcessEnricher


def create_process_collector() -> PsutilProcessCollector:
    """Create the baseline cross-platform process collector."""

    return PsutilProcessCollector()


def create_process_enricher(
    capabilities: PlatformCapabilities | None = None,
) -> ProcessEnricher:
    """Create a platform-specific process enricher."""

    detected = capabilities or detect_capabilities()
    if detected.is_linux:
        return LinuxProcessEnricher(detected)
    return WindowsProcessEnricher(detected)

