"""Runtime platform and collector capability detection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import platform


@dataclass(frozen=True, slots=True)
class PlatformCapabilities:
    """Feature flags for the current runtime platform."""

    system: str
    is_linux: bool
    is_windows: bool
    supports_procfs: bool
    supports_systemd: bool
    supports_cgroups: bool
    supports_deleted_exe: bool
    supports_zombie_state: bool


def detect_capabilities() -> PlatformCapabilities:
    """Detect runtime capabilities without assuming Linux paths exist."""

    system = platform.system()
    is_linux = system == "Linux"
    is_windows = system == "Windows"
    proc_root = Path("/proc")
    supports_procfs = is_linux and proc_root.exists()
    supports_cgroups = supports_procfs and (
        Path("/proc/self/cgroup").exists() or Path("/sys/fs/cgroup").exists()
    )
    supports_systemd = is_linux and (
        Path("/run/systemd/system").exists() or Path("/proc/1/comm").exists()
    )
    return PlatformCapabilities(
        system=system,
        is_linux=is_linux,
        is_windows=is_windows,
        supports_procfs=supports_procfs,
        supports_systemd=supports_systemd,
        supports_cgroups=supports_cgroups,
        supports_deleted_exe=supports_procfs,
        supports_zombie_state=supports_procfs,
    )

