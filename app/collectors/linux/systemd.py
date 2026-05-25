"""Linux systemd/cgroup process attribution."""

from __future__ import annotations

from pathlib import Path


def read_cgroup(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Read cgroup content for a process."""

    try:
        return (proc_root / str(pid) / "cgroup").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def detect_service_manager(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Detect systemd/docker/podman process ownership from cgroups."""

    text = read_cgroup(pid, proc_root)
    if not text:
        return None
    if ".service" in text:
        return "systemd"
    if "docker" in text:
        return "docker"
    if "podman" in text:
        return "podman"
    return None


def detect_systemd_unit(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Return systemd unit/scope name from cgroups when available."""

    text = read_cgroup(pid, proc_root)
    if not text:
        return None
    for segment in text.replace("\\", "/").replace("\n", "/").split("/"):
        if segment.endswith(".service") or segment.endswith(".scope"):
            return segment
    return None
