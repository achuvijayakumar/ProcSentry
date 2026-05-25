"""Safety-classified kill suggestions.

Two tiers:
  Tier 1 — Almost-zero false-positive risk.
           * Confirmed duplicates (extras can go, oldest stays)
           * Zombies / orphans with no children and no listening ports

  Tier 2 — Likely safe, but the user must read the reason.
           * Idle user-owned processes: same uid as the running ProcSentry user,
             0% CPU, no listening port, no outbound connections, no recent
             restarts, idle for at least the configured threshold.

Anything matching the protect list is never suggested, regardless of tier.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone

# System processes / well-known services we MUST NEVER suggest closing.
_PROTECT_COMMS = {
    "systemd", "init", "kthreadd", "kworker", "ksoftirqd", "migration",
    "rcu_sched", "rcu_bh", "rcu_preempt", "watchdog", "kdevtmpfs",
    "kauditd", "khungtaskd", "oom_reaper", "writeback", "kcompactd",
    "ksmd", "khugepaged", "kintegrityd", "kblockd", "ata_sff", "md",
    "edac-poller", "devfreq_wq", "scsi_eh_", "scsi_tmf_", "kswapd",
    "fsnotify_mark", "ecryptfs-kthrea", "irq/", "card0-",
    "sshd", "agetty", "login", "getty",
    "dbus-daemon", "polkitd", "rsyslogd", "systemd-journald",
    "systemd-logind", "systemd-udevd", "systemd-timesyncd",
    "systemd-network", "systemd-resolve", "cron", "crond",
    "snapd", "packagekitd", "unattended-upgr", "fail2ban-server",
    "vmtoolsd", "VGAuthService", "vgauth", "open-vm-tools",
    "(sd-pam)",
}

# Project names (from our detector) that are system-managed.
_PROTECT_PROJECTS = {
    "sshd", "ssh", "systemd", "cron", "dbus", "polkit", "rsyslog",
    "snap", "ufw", "fail2ban", "kernel", "systemd-journald",
    "systemd-logind", "systemd-udevd", "systemd-timesyncd",
    "open-vm-tools", "vgauth", "packagekit", "unattended-upgrades",
    "getty",
}

# Users whose processes we never suggest killing.
_PROTECT_USERS = {"root", "systemd+", "systemd-network", "systemd-resolve",
                  "messagebus", "syslog", "_apt", "polkitd", "snapd"}


@dataclass
class Suggestion:
    pid: int
    name: str
    friendly_label: str
    project: str | None
    user: str | None
    cpu_percent: float
    memory_mb: float
    tier: int            # 1 = very safe, 2 = probably safe
    reason: str          # human-readable explanation
    confidence: str      # 'high', 'medium'


def _is_protected(proc) -> tuple[bool, str | None]:
    """Return (is_protected, reason)."""
    if proc.pid <= 2:
        return True, "PID 1 / kernel scheduler"
    if proc.name in _PROTECT_COMMS:
        return True, f"system process ({proc.name})"
    if (proc.user or "") in _PROTECT_USERS:
        return True, f"running as {proc.user}"
    project = getattr(proc, "project", None)
    if project in _PROTECT_PROJECTS:
        return True, f"managed service ({project})"
    # Kernel threads have no cmdline.
    if not (proc.cmdline or "").strip():
        return True, "kernel thread (no cmdline)"
    return False, None


def _has_listening_port(proc) -> bool:
    try:
        ports = json.loads(proc.ports_json or "[]")
        return any(isinstance(p, dict) and p.get("port") for p in ports)
    except (ValueError, TypeError):
        return False


def _seconds_since(ts: datetime | None) -> float | None:
    if not ts:
        return None
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds()


def build_suggestions(
    processes,
    duplicate_pids: set[int],
    *,
    idle_seconds_threshold: int = 1800,  # 30 minutes
    current_uid: int | None = None,
    current_user: str | None = None,
) -> list[Suggestion]:
    """Classify a sorted list of suggestions. Conservative by design."""

    suggestions: list[Suggestion] = []

    for proc in processes:
        protected, _why = _is_protected(proc)
        if protected:
            continue

        label = getattr(proc, "friendly_label", proc.name) or proc.name
        project = getattr(proc, "project", None)

        # --- Tier 1: zombies / orphans (no listening port, no children) ---
        if proc.is_zombie:
            suggestions.append(Suggestion(
                pid=proc.pid, name=proc.name, friendly_label=label,
                project=project, user=proc.user,
                cpu_percent=proc.cpu_percent, memory_mb=proc.memory_mb,
                tier=1, confidence="high",
                reason="zombie — already terminated, just consuming a PID slot",
            ))
            continue

        if proc.is_orphan and not _has_listening_port(proc):
            suggestions.append(Suggestion(
                pid=proc.pid, name=proc.name, friendly_label=label,
                project=project, user=proc.user,
                cpu_percent=proc.cpu_percent, memory_mb=proc.memory_mb,
                tier=1, confidence="high",
                reason="orphan with no listening port — parent died, no traffic served",
            ))
            continue

        # --- Tier 2: idle YOUR-user process ---
        if current_user and (proc.user or "") != current_user:
            continue  # only suggest things owned by the same user as ProcSentry
        if proc.cpu_percent and proc.cpu_percent > 0.5:
            continue  # actively doing work
        if _has_listening_port(proc):
            continue  # serving traffic
        if (proc.outbound_connections or 0) > 0:
            continue  # has open outbound conns
        if (proc.restart_count or 0) > 0:
            continue  # was crashing — leave it
        if proc.suspicious_score and proc.suspicious_score > 0:
            continue  # let the user look at it before killing

        idle_for = _seconds_since(proc.last_seen_at)
        # Use start_time as a proxy for "how long has this been alive" so a
        # process needs to have actually existed for the threshold to qualify.
        alive_for = _seconds_since(proc.start_time) or 0
        if alive_for < idle_seconds_threshold:
            continue

        suggestions.append(Suggestion(
            pid=proc.pid, name=proc.name, friendly_label=label,
            project=project, user=proc.user,
            cpu_percent=proc.cpu_percent, memory_mb=proc.memory_mb,
            tier=2, confidence="medium",
            reason=(
                f"idle ≥{idle_seconds_threshold // 60}min · "
                "0% cpu · no listening port · no outbound conns"
            ),
        ))

    # Sort: tier 1 first, then by RAM saved (descending).
    suggestions.sort(key=lambda s: (s.tier, -s.memory_mb))
    return suggestions


def current_username() -> str | None:
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return None
