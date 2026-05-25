"""Alert creation service with simple de-duplication."""

from __future__ import annotations

import hashlib
import time

from app.database.repository import ProcessRepository


class AlertService:
    """Create alerts while suppressing tight-loop duplicates."""

    def __init__(self, repository: ProcessRepository, cooldown_seconds: int = 300) -> None:
        self._repository = repository
        self._cooldown_seconds = cooldown_seconds
        self._last_emitted: dict[str, float] = {}

    def emit(
        self,
        alert_type: str,
        severity: str,
        message: str,
        pid: int | None = None,
        fingerprint: str | None = None,
        category: str = "general",
    ) -> None:
        """Persist an alert unless an equivalent alert is cooling down."""

        key = hashlib.sha1(f"{alert_type}:{severity}:{pid}:{fingerprint}:{message}".encode()).hexdigest()
        now = time.monotonic()
        if now - self._last_emitted.get(key, 0) < self._cooldown_seconds:
            return
        self._last_emitted[key] = now
        self._repository.add_alert(
            alert_type, severity, message, pid=pid, fingerprint=fingerprint, category=category
        )
