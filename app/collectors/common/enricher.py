"""Platform-specific process enrichment interface."""

from __future__ import annotations

from typing import Protocol

from app.collectors.common.capabilities import PlatformCapabilities
from app.schemas import ProcessSnapshot


class ProcessEnricher(Protocol):
    """Interface implemented by platform-specific enrichers."""

    capabilities: PlatformCapabilities

    def enrich(self, snapshot: ProcessSnapshot) -> None:
        """Mutate a process snapshot with platform-specific metadata."""

    def hash_executable(self, executable: str | None, max_bytes: int = 256_000) -> str | None:
        """Return executable hash when supported."""
