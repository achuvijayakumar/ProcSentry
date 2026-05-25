"""Command-line normalization helpers for fingerprinting and duplicate scoring."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
import shlex

_PID_LIKE = re.compile(r"^\d{2,}$")
_TIMESTAMP_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}|^\d{10,}$")
_HEX_LIKE = re.compile(r"^[a-f0-9]{16,}$", re.IGNORECASE)
_HOST_PORT = re.compile(r"^(?:(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::\]|::):)?\d{2,5}$")
_ASSIGNMENT = re.compile(r"^(--?[a-z0-9][a-z0-9_.-]*)(?:=(.*))?$", re.IGNORECASE)

PYTHON_ALIASES = {"python", "python3", "python3.12", "python3.11", "python3.10", "pypy3"}
NODE_ALIASES = {"node", "nodejs"}
VOLATILE_FLAGS = {
    "--pid",
    "--pidfile",
    "--worker-id",
    "--reload-dir",
    "--fd",
    "--bind-fd",
    "--port",
    "-p",
    "--host",
    "-b",
}
HARMLESS_FLAGS = {"--reload", "--color=auto", "--no-color", "--log-level=info"}


@dataclass(frozen=True, slots=True)
class NormalizedCommand:
    """Normalized command profile used by fingerprints and duplicate scoring."""

    executable: str
    cwd: str
    stable_args: tuple[str, ...]
    stable_flags: tuple[str, ...]
    script_or_module: str | None

    @property
    def arg_text(self) -> str:
        """Return normalized command text for similarity scoring."""

        return " ".join((*self.stable_args, *self.stable_flags))


@lru_cache(maxsize=16384)
def normalize_command(
    executable: str | None,
    cwd: str | None,
    cmdline: tuple[str, ...],
    fuzzy: bool = True,
) -> NormalizedCommand:
    """Normalize executable, cwd, and arguments with an LRU cache."""

    normalized_executable = normalize_executable(executable or (cmdline[0] if cmdline else ""), fuzzy=fuzzy)
    normalized_cwd = normalize_path(cwd, fuzzy=fuzzy)
    args = tuple(_clean_arg(arg) for arg in cmdline if arg and arg.strip())
    stable_args: list[str] = []
    stable_flags: list[str] = []
    script_or_module: str | None = None
    skip_next = False

    for index, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if index == 0 and normalize_executable(arg, fuzzy=True) == normalized_executable:
            continue
        if fuzzy and _is_dynamic_value(arg):
            continue
        if arg in HARMLESS_FLAGS:
            continue

        assignment = _ASSIGNMENT.match(arg)
        if assignment:
            key = assignment.group(1)
            value = assignment.group(2)
            if fuzzy and key in VOLATILE_FLAGS:
                if value is None and index + 1 < len(args):
                    skip_next = True
                stable_flags.append(key)
                continue
            if fuzzy and value is not None and _is_dynamic_value(value):
                stable_flags.append(f"{key}=<dynamic>")
                continue
            stable_flags.append(arg.lower() if fuzzy else arg)
            continue

        normalized_arg = normalize_executable(arg, fuzzy=fuzzy) if _looks_exec(arg) else arg
        if script_or_module is None and _looks_application_entry(arg):
            script_or_module = normalized_arg
        stable_args.append(normalized_arg.lower() if fuzzy else normalized_arg)

    if fuzzy:
        stable_flags.sort()
    return NormalizedCommand(
        executable=normalized_executable,
        cwd=normalized_cwd,
        stable_args=tuple(stable_args),
        stable_flags=tuple(stable_flags),
        script_or_module=script_or_module,
    )


def normalize_executable(value: str, *, fuzzy: bool) -> str:
    """Normalize executable aliases and common runtime paths."""

    path = Path(value)
    name = path.name.lower()
    if fuzzy:
        if name in PYTHON_ALIASES:
            return "python"
        if name in NODE_ALIASES:
            return "node"
        parts = tuple(part.lower() for part in path.parts)
        if "node_modules" in parts:
            return str(path).replace("\\", "/").lower().split("node_modules/")[-1]
        if name.startswith("python3."):
            return "python"
    return str(path).replace("\\", "/").lower()


def normalize_path(value: str | None, *, fuzzy: bool) -> str:
    """Normalize cwd/deploy paths while retaining project identity."""

    if not value:
        return ""
    path = str(Path(value)).replace("\\", "/").rstrip("/").lower()
    if fuzzy:
        path = re.sub(r"/releases/[0-9a-f_.-]+", "/releases/<release>", path)
        path = re.sub(r"/tmp/[a-z0-9_.-]+", "/tmp/<tmp>", path)
        path = re.sub(r"/run/user/\d+", "/run/user/<uid>", path)
    return path


def _clean_arg(value: str) -> str:
    try:
        return shlex.quote(value).strip("'") if any(char.isspace() for char in value) else value.strip()
    except ValueError:
        return value.strip()


def _is_dynamic_value(value: str) -> bool:
    return bool(
        _PID_LIKE.match(value)
        or _TIMESTAMP_LIKE.match(value)
        or _HEX_LIKE.match(value)
        or _HOST_PORT.match(value)
    )


def _looks_exec(value: str) -> bool:
    return "/" in value or value.lower() in PYTHON_ALIASES | NODE_ALIASES


def _looks_application_entry(value: str) -> bool:
    lower = value.lower()
    return lower.endswith((".py", ".js", ".mjs", ".cjs")) or ":" in lower or lower in {"-m", "module"}
