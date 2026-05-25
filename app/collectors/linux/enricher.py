"""Linux process metadata enrichment."""

from __future__ import annotations

from pathlib import Path

from app.collectors.common.capabilities import PlatformCapabilities
from app.collectors.linux.procfs import (
    hash_executable,
    read_container_id,
    read_executable_link,
    read_process_state,
)
from app.collectors.linux.systemd import detect_service_manager, detect_systemd_unit
from app.schemas import ProcessSnapshot


class LinuxProcessEnricher:
    """Add Linux-only metadata while gracefully handling permission races."""

    def __init__(self, capabilities: PlatformCapabilities, proc_root: Path = Path("/proc")) -> None:
        self.capabilities = capabilities
        self.proc_root = proc_root

    def enrich(self, snapshot: ProcessSnapshot) -> None:
        """Enrich a process snapshot using procfs, cgroups, and systemd hints."""

        if self.capabilities.supports_cgroups:
            snapshot.service_manager = detect_service_manager(snapshot.pid, self.proc_root)
            snapshot.systemd_unit = detect_systemd_unit(snapshot.pid, self.proc_root)
            snapshot.container_id = read_container_id(snapshot.pid, self.proc_root)
        if self.capabilities.supports_deleted_exe:
            exe_link, deleted = read_executable_link(snapshot.pid, self.proc_root)
            if exe_link and not snapshot.executable:
                snapshot.executable = exe_link
            snapshot.executable_deleted = deleted
        if self.capabilities.supports_zombie_state:
            state = read_process_state(snapshot.pid, self.proc_root)
            snapshot.is_zombie = state == "Z" or snapshot.status == "zombie"
        snapshot.is_orphan = snapshot.ppid == 1 and snapshot.service_manager is None

    def hash_executable(self, executable: str | None, max_bytes: int = 256_000) -> str | None:
        """Hash an executable when Linux capability is available."""

        return hash_executable(executable, max_bytes=max_bytes)
