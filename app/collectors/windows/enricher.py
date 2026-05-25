"""Windows development fallback process enrichment."""

from __future__ import annotations

from app.collectors.common.capabilities import PlatformCapabilities
from app.schemas import ProcessSnapshot


class WindowsProcessEnricher:
    """No-op enrichment for Windows local development."""

    def __init__(self, capabilities: PlatformCapabilities) -> None:
        self.capabilities = capabilities

    def enrich(self, snapshot: ProcessSnapshot) -> None:
        """Populate safe fallback values only."""

        snapshot.service_manager = None
        snapshot.systemd_unit = None
        snapshot.container_id = None
        snapshot.executable_deleted = False
        snapshot.is_zombie = snapshot.status == "zombie"
        snapshot.is_orphan = False

    def hash_executable(self, executable: str | None, max_bytes: int = 256_000) -> str | None:
        """Skip executable hashing on Windows development by default."""

        return None

