"""Remote host process inspection over SSH.

Connects with username/password (or the local SSH agent/keys when no
password is configured), runs `ps`, and parses the output into lightweight
records. Every call opens a fresh connection — remote views are on-demand,
not part of the scan loop, so there is no pooling to manage.
"""

from __future__ import annotations

from dataclasses import dataclass

import paramiko

from app.config import RemoteHostConfig

_CONNECT_TIMEOUT = 10.0
_EXEC_TIMEOUT = 20.0
# Headerless, wide output; args last so everything after the 7th field is
# the full command line regardless of embedded spaces.
_PS_COMMAND = "ps -eo pid=,ppid=,user:32=,pcpu=,rss=,etimes=,stat=,args= -ww"


class RemoteError(RuntimeError):
    """SSH operation failed; the message is safe to show in the UI."""


@dataclass(slots=True)
class RemoteProcess:
    """Single observation of a process on a remote host."""

    pid: int
    ppid: int
    user: str
    cpu_percent: float
    memory_mb: float
    elapsed_seconds: int
    status: str
    cmdline: str

    @property
    def name(self) -> str:
        first = self.cmdline.split()[0] if self.cmdline.strip() else ""
        return first.rsplit("/", 1)[-1] or "?"

    @property
    def elapsed_human(self) -> str:
        s = self.elapsed_seconds
        if s >= 86400:
            return f"{s // 86400}d {s % 86400 // 3600}h"
        if s >= 3600:
            return f"{s // 3600}h {s % 3600 // 60}m"
        if s >= 60:
            return f"{s // 60}m"
        return f"{s}s"


def _connect(host: RemoteHostConfig) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    use_keys = host.password is None
    try:
        client.connect(
            hostname=host.host,
            port=host.port,
            username=host.username,
            password=host.password,
            timeout=_CONNECT_TIMEOUT,
            auth_timeout=_CONNECT_TIMEOUT,
            banner_timeout=_CONNECT_TIMEOUT,
            allow_agent=use_keys,
            look_for_keys=use_keys,
        )
    except Exception as exc:
        client.close()
        raise RemoteError(f"connect to {host.host}:{host.port} failed: {exc}") from exc
    return client


def _run(client: paramiko.SSHClient, command: str) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=_EXEC_TIMEOUT)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out, err


def parse_ps_output(output: str) -> list[RemoteProcess]:
    """Parse `_PS_COMMAND` output. Malformed lines are skipped."""

    procs: list[RemoteProcess] = []
    for line in output.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        try:
            procs.append(
                RemoteProcess(
                    pid=int(parts[0]),
                    ppid=int(parts[1]),
                    user=parts[2],
                    cpu_percent=float(parts[3]),
                    memory_mb=int(parts[4]) / 1024.0,
                    elapsed_seconds=int(parts[5]),
                    status=parts[6],
                    cmdline=parts[7].strip(),
                )
            )
        except ValueError:
            continue
    procs.sort(key=lambda p: -p.cpu_percent)
    return procs


def list_processes(host: RemoteHostConfig) -> list[RemoteProcess]:
    """Fetch the live process list from a remote host."""

    client = _connect(host)
    try:
        code, out, err = _run(client, _PS_COMMAND)
    except Exception as exc:
        raise RemoteError(f"ps failed: {exc}") from exc
    finally:
        client.close()
    if code != 0:
        raise RemoteError(f"ps exited {code}: {err.strip() or out.strip() or 'no output'}")
    return parse_ps_output(out)


def kill_process(host: RemoteHostConfig, pid: int) -> str:
    """SIGTERM a remote pid, escalate to SIGKILL after a grace period.

    Returns "terminated", "killed", "gone", or "denied".
    """

    pid = int(pid)  # hard guarantee: only a number reaches the shell
    script = (
        f"if ! kill -TERM {pid} 2>/dev/null; then "
        f"  if kill -0 {pid} 2>/dev/null; then echo DENIED; else echo GONE; fi; "
        f"else "
        f"  sleep 2; "
        f"  if kill -0 {pid} 2>/dev/null; then "
        f"    kill -KILL {pid} 2>/dev/null && echo KILLED || echo DENIED; "
        f"  else echo TERMINATED; fi; "
        f"fi"
    )
    client = _connect(host)
    try:
        code, out, err = _run(client, script)
    except Exception as exc:
        raise RemoteError(f"kill failed: {exc}") from exc
    finally:
        client.close()
    outcome = out.strip().upper()
    mapping = {"TERMINATED": "terminated", "KILLED": "killed", "GONE": "gone", "DENIED": "denied"}
    if outcome not in mapping:
        raise RemoteError(f"unexpected kill result: {err.strip() or out.strip() or f'exit {code}'}")
    return mapping[outcome]


def test_connection(host: RemoteHostConfig) -> str:
    """Connect and return the remote hostname, raising RemoteError on failure."""

    client = _connect(host)
    try:
        code, out, err = _run(client, "uname -n")
    except Exception as exc:
        raise RemoteError(f"command failed: {exc}") from exc
    finally:
        client.close()
    if code != 0:
        raise RemoteError(f"uname exited {code}: {err.strip()}")
    return out.strip() or host.host
