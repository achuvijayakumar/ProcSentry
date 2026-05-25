"""Terminal action helpers."""

from __future__ import annotations

from app.services.healing_service import HealingService


def request_kill(healing: HealingService, pid: int) -> bool:
    """Request process termination through the healing guardrail."""

    return healing.kill_process(pid)

