"""Auto-healing framework disabled by default."""

from __future__ import annotations

import logging
import os
import signal

from app.config import HealingConfig

logger = logging.getLogger(__name__)


class HealingService:
    """Framework for future remediation actions."""

    def __init__(self, config: HealingConfig) -> None:
        self._config = config

    def kill_process(self, pid: int) -> bool:
        """Kill a process only when healing is explicitly enabled."""

        if not self._config.enabled:
            logger.info("Auto-healing disabled; refusing to kill PID %s", pid)
            return False
        if self._config.dry_run:
            logger.info("Auto-healing dry-run; would kill PID %s", pid)
            return False
        os.kill(pid, signal.SIGTERM)
        return True

