"""Linux procfs helpers."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

_HASH_CACHE: dict[tuple[str, int, int], str] = {}


def proc_path(pid: int, name: str, proc_root: Path = Path("/proc")) -> Path:
    """Return a path below a procfs root."""

    return proc_root / str(pid) / name


def read_container_id(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Return a Docker/Podman-style container id from Linux cgroups."""

    cgroup = proc_path(pid, "cgroup", proc_root)
    try:
        text = cgroup.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    for token in text.replace("\\", "/").split("/"):
        token = token.strip()
        if len(token) >= 12 and all(char.isalnum() or char in "-_" for char in token):
            if token.endswith(".scope"):
                token = token.removesuffix(".scope")
            return token[:64]
    return None


def read_executable_link(pid: int, proc_root: Path = Path("/proc")) -> tuple[str | None, bool]:
    """Return Linux /proc executable symlink target and deleted marker."""

    try:
        exe_path = proc_path(pid, "exe", proc_root)
        if exe_path.is_symlink():
            target = os.readlink(exe_path)
        else:
            target = exe_path.read_text(encoding="utf-8", errors="ignore").strip()
    except OSError:
        return None, False
    deleted = target.endswith(" (deleted)")
    return target.removesuffix(" (deleted)"), deleted


def hash_executable(path: str | None, max_bytes: int = 2_000_000) -> str | None:
    """Hash an executable with a stat-keyed cache."""

    if not path:
        return None
    try:
        stat = os.stat(path)
        if not stat.st_mode or stat.st_size > 128 * 1024 * 1024:
            return None
        key = (path, int(stat.st_mtime_ns), int(stat.st_size))
        cached = _HASH_CACHE.get(key)
        if cached:
            return cached
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            remaining = max_bytes
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
        value = digest.hexdigest()
        if len(_HASH_CACHE) > 2048:
            _HASH_CACHE.clear()
        _HASH_CACHE[key] = value
        return value
    except OSError:
        return None


def read_process_state(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """Read the one-letter Linux process state from /proc/<pid>/stat."""

    try:
        text = proc_path(pid, "stat", proc_root).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    suffix = text.rsplit(")", 1)[-1].strip().split()
    return suffix[0] if suffix else None
