"""Tests for remote SSH ps parsing and host config plumbing."""

from __future__ import annotations

from app.config import RemoteHostConfig, Settings
from app.services.remote_ssh import RemoteProcess, parse_ps_output

PS_OUTPUT = """\
      1       0 root              0.0  11264     98765 Ss   /sbin/init
    742       1 www-data          2.5 524288     86400 Ssl  /usr/sbin/nginx -g daemon off;
   9001     742 deploy           55.0 2097152      3600 Rl   python3 /srv/app/worker.py --queue high priority
 garbage line that does not parse
"""


def test_parse_ps_output_basic() -> None:
    procs = parse_ps_output(PS_OUTPUT)
    assert len(procs) == 3
    # Sorted by cpu desc.
    assert [p.pid for p in procs] == [9001, 742, 1]
    worker = procs[0]
    assert worker.user == "deploy"
    assert worker.cpu_percent == 55.0
    assert worker.memory_mb == 2048.0
    assert worker.status == "Rl"
    # Args with spaces survive intact.
    assert worker.cmdline == "python3 /srv/app/worker.py --queue high priority"
    assert worker.name == "python3"


def test_parse_ps_output_skips_garbage_and_empty() -> None:
    assert parse_ps_output("") == []
    assert parse_ps_output("not a process line\n") == []


def test_remote_process_helpers() -> None:
    p = RemoteProcess(
        pid=1, ppid=0, user="root", cpu_percent=0.0, memory_mb=1.0,
        elapsed_seconds=90061, status="S", cmdline="/usr/bin/foo --bar",
    )
    assert p.name == "foo"
    assert p.elapsed_human == "1d 1h"
    short = RemoteProcess(
        pid=2, ppid=1, user="root", cpu_percent=0.0, memory_mb=1.0,
        elapsed_seconds=42, status="S", cmdline="",
    )
    assert short.elapsed_human == "42s"
    assert short.name == "?"


def test_settings_remote_hosts_roundtrip() -> None:
    settings = Settings(
        remote_hosts=[
            {"name": "web-1", "host": "203.0.113.10", "username": "root", "password": "secret"},
            {"name": "db-1", "host": "203.0.113.11", "port": 2222, "username": "deploy"},
        ]
    )
    assert isinstance(settings.remote_hosts[0], RemoteHostConfig)
    assert settings.remote_hosts[0].port == 22
    assert settings.remote_hosts[1].port == 2222
    assert settings.remote_hosts[1].password is None
