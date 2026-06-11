"""Read and control host systemd services, timers, and cron entries.

All shell-outs use argument lists (no shell) with strict unit-name
validation, so nothing user-controlled can reach sudo unsanitised.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_UNIT_RE = re.compile(r"^[A-Za-z0-9_.@\\:-]{1,256}\.(service|timer)$")
_COMMAND_TIMEOUT = 15

ALLOWED_ACTIONS = {"start", "stop", "restart"}

# Units that can lock you out of a remote VPS. "stop" is always refused;
# "restart" requires an explicit force flag (double confirm in the UI).
CRITICAL_UNITS = {
    "ssh.service",
    "sshd.service",
    "networking.service",
    "systemd-networkd.service",
    "systemd-resolved.service",
    "ufw.service",
    "dbus.service",
    "systemd-journald.service",
    "systemd-logind.service",
    "cron.service",
}

# Acting on our own unit kills this process (and any child in our cgroup)
# before the HTTP response leaves, so the UI would always show an error.
SELF_UNIT = "procsentry.service"


@dataclass
class ServiceUnit:
    name: str
    load: str
    active: str
    sub: str
    description: str
    enabled: str = "unknown"
    is_critical: bool = False


@dataclass
class TimerUnit:
    name: str
    activates: str
    next_run: str
    last_run: str
    active: str
    description: str


@dataclass
class CronEntry:
    source: str
    line: str


@dataclass
class ControlResult:
    ok: bool
    detail: str


@dataclass
class HostServicesSnapshot:
    services: list[ServiceUnit] = field(default_factory=list)
    timers: list[TimerUnit] = field(default_factory=list)
    cron: list[CronEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _run(argv: list[str], timeout: int = _COMMAND_TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def valid_unit(name: str) -> bool:
    return bool(_UNIT_RE.match(name))


def list_services() -> tuple[list[ServiceUnit], list[str]]:
    """Return all service units with their enablement state."""

    errors: list[str] = []
    enabled_map: dict[str, str] = {}
    try:
        proc = _run(["systemctl", "list-unit-files", "--type=service", "--plain", "--no-legend", "--no-pager"])
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                enabled_map[parts[0]] = parts[1]
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"list-unit-files failed: {exc}")

    services: list[ServiceUnit] = []
    try:
        proc = _run(["systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager"])
        for line in proc.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 4 or not parts[0].endswith(".service"):
                continue
            name = parts[0]
            services.append(
                ServiceUnit(
                    name=name,
                    load=parts[1],
                    active=parts[2],
                    sub=parts[3],
                    description=parts[4] if len(parts) > 4 else "",
                    enabled=enabled_map.get(name, "unknown"),
                    is_critical=name in CRITICAL_UNITS,
                )
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"list-units failed: {exc}")

    order = {"failed": 0, "activating": 1, "deactivating": 1, "active": 2}
    services.sort(key=lambda s: (order.get(s.active, 3), s.name))
    return services, errors


def list_timers() -> tuple[list[TimerUnit], list[str]]:
    """Return timer units with next/last trigger times."""

    errors: list[str] = []
    timers: list[TimerUnit] = []
    try:
        proc = _run(["systemctl", "list-units", "--type=timer", "--all", "--plain", "--no-legend", "--no-pager"])
        names = [line.split(None, 1)[0] for line in proc.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"list timers failed: {exc}"]

    for name in names:
        if not name.endswith(".timer"):
            continue
        try:
            proc = _run(
                [
                    "systemctl", "show", name, "--no-pager",
                    "--property=Unit,NextElapseUSecRealtime,LastTriggerUSec,ActiveState,Description",
                ]
            )
            props = dict(
                line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line
            )
            timers.append(
                TimerUnit(
                    name=name,
                    activates=props.get("Unit", ""),
                    next_run=props.get("NextElapseUSecRealtime", "") or "n/a",
                    last_run=props.get("LastTriggerUSec", "") or "never",
                    active=props.get("ActiveState", "unknown"),
                    description=props.get("Description", ""),
                )
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"show {name} failed: {exc}")
    timers.sort(key=lambda t: t.name)
    return timers, errors


def _cron_lines(text: str, source: str) -> list[CronEntry]:
    entries = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(CronEntry(source=source, line=stripped))
    return entries


def list_cron() -> tuple[list[CronEntry], list[str]]:
    """Collect cron entries from system files and user crontabs."""

    errors: list[str] = []
    entries: list[CronEntry] = []

    for path in [Path("/etc/crontab"), *sorted(Path("/etc/cron.d").glob("*"))]:
        try:
            entries.extend(_cron_lines(path.read_text(encoding="utf-8", errors="replace"), str(path)))
        except OSError as exc:
            errors.append(f"{path}: {exc}")

    spool = Path("/var/spool/cron/crontabs")
    try:
        proc = _run(["sudo", "-n", "ls", "-1", str(spool)])
        users = [u for u in proc.stdout.split() if u] if proc.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired):
        users = []
    for user in users:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            continue
        try:
            proc = _run(["sudo", "-n", "cat", str(spool / user)])
            if proc.returncode == 0:
                entries.extend(_cron_lines(proc.stdout, f"crontab:{user}"))
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"crontab {user}: {exc}")
    return entries, errors


def list_failed_units() -> list[str] | None:
    """Return failed service unit names, or None when the probe itself fails."""

    try:
        proc = _run(["systemctl", "--failed", "--type=service", "--plain", "--no-legend", "--no-pager"])
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    units = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            units.append(parts[0])
    return units


def unit_journal(unit: str, lines: int = 50) -> str:
    """Return the last journal lines for a unit."""

    if not valid_unit(unit):
        return "invalid unit name"
    try:
        proc = _run(["sudo", "-n", "journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"])
        return proc.stdout or proc.stderr or "(no journal output)"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"journalctl failed: {exc}"


def control_unit(unit: str, action: str, *, force: bool = False) -> ControlResult:
    """Run systemctl start/stop/restart on a unit, with critical-unit guard."""

    if action not in ALLOWED_ACTIONS:
        return ControlResult(False, f"action '{action}' not allowed")
    if not valid_unit(unit) or not unit.endswith(".service"):
        return ControlResult(False, "invalid unit name")
    if unit in CRITICAL_UNITS:
        if action == "stop":
            return ControlResult(False, f"{unit} is critical — stop refused (would risk losing access)")
        if not force:
            return ControlResult(False, f"{unit} is critical — confirm again to {action}")
    if unit == SELF_UNIT and action in {"restart", "stop"}:
        # Schedule via a transient systemd-run unit outside our cgroup so
        # the HTTP reply gets out before this process dies.
        try:
            proc = _run(["sudo", "-n", "/usr/bin/systemd-run", "--on-active=2", "/usr/bin/systemctl", action, unit])
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ControlResult(False, f"could not schedule self-{action}: {exc}")
        if proc.returncode != 0:
            return ControlResult(False, (proc.stderr or "could not schedule self-restart").strip()[:500])
        return ControlResult(True, f"{action} scheduled in 2s — dashboard will reconnect")
    try:
        proc = _run(["sudo", "-n", "systemctl", action, unit], timeout=30)
    except subprocess.TimeoutExpired:
        return ControlResult(False, f"systemctl {action} {unit} timed out")
    except OSError as exc:
        return ControlResult(False, f"systemctl failed: {exc}")
    if proc.returncode != 0:
        return ControlResult(False, (proc.stderr or proc.stdout or "unknown error").strip()[:500])
    return ControlResult(True, f"{action} ok")


def snapshot() -> HostServicesSnapshot:
    """Gather services, timers, and cron in one call for the dashboard page."""

    services, err1 = list_services()
    timers, err2 = list_timers()
    cron, err3 = list_cron()
    return HostServicesSnapshot(
        services=services, timers=timers, cron=cron, errors=[*err1, *err2, *err3]
    )
