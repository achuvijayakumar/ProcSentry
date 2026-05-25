"""Security heuristics for suspicious process detection."""

from __future__ import annotations

import math
import re
from pathlib import Path

from app.config import SecurityConfig
from app.schemas import ProcessSnapshot, SecurityFinding

_SUSPICIOUS_COMMAND_PATTERNS = (
    re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE),
    re.compile(r"base64\s+-d", re.IGNORECASE),
    re.compile(r"\bnc\s+.*\s-e\s", re.IGNORECASE),
    re.compile(r"\bbash\s+-i\b", re.IGNORECASE),
    re.compile(r"/dev/tcp/", re.IGNORECASE),
    re.compile(r"xmrig|kinsing|kdevtmpfsi|watchdogd", re.IGNORECASE),
    re.compile(r"python\s+-c\s+.*socket", re.IGNORECASE),
    re.compile(r"perl\s+-e\s+.*socket", re.IGNORECASE),
)
_MINER_NAMES = {"xmrig", "minerd", "kinsing", "kdevtmpfsi", "kthreaddi", "watchdogd"}
_SUSPICIOUS_PORTS = {4444, 5555, 6666, 1337, 31337, 3333, 4443, 5555, 7777}


class SecurityEngine:
    """Score suspicious process behavior using transparent heuristics."""

    def __init__(self, config: SecurityConfig) -> None:
        self._config = config

    def scan(self, snapshots: list[ProcessSnapshot]) -> list[SecurityFinding]:
        """Return suspicious process findings."""

        if not self._config.enabled:
            return []
        findings: list[SecurityFinding] = []
        for proc in snapshots:
            score, signals, category = self._score(proc)
            proc.suspicious_score = score
            if score >= 40:
                severity = "CRITICAL" if score >= 80 else "WARNING"
                findings.append(
                    SecurityFinding(
                        pid=proc.pid,
                        severity=severity,
                        category=category,
                        confidence=min(100, score + 10 if len(signals) > 1 else score),
                        score=score,
                        message=f"PID {proc.pid} ({proc.name}) looks suspicious: {', '.join(signals)}",
                        signals=tuple(signals),
                    )
                )
        return findings

    def _score(self, proc: ProcessSnapshot) -> tuple[int, list[str], str]:
        signals: list[str] = []
        score = 0
        category = "INFO"
        executable = proc.executable or ""
        cmd = " ".join(proc.cmdline)
        name = Path(executable or proc.name).name

        if executable.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            score += 30
            category = "WARNING"
            signals.append("temp directory executable")
        if proc.executable_deleted or " (deleted)" in executable:
            score += 45
            category = "WARNING"
            signals.append("deleted executable still running")
        if name.startswith("."):
            score += 20
            signals.append("hidden binary name")
        if self._entropy(name) >= self._config.random_name_entropy_threshold and len(name) >= 10:
            score += 15
            signals.append("random-looking binary name")
        if name.lower() in _MINER_NAMES:
            score += 60
            category = "CRITICAL"
            signals.append("known crypto miner process name")
        if proc.cpu_percent >= self._config.excessive_cpu_percent:
            score += 20
            signals.append("excessive CPU")
        for pattern in _SUSPICIOUS_COMMAND_PATTERNS:
            if pattern.search(cmd):
                score += 45
                category = "CRITICAL"
                signals.append(f"suspicious command pattern: {pattern.pattern}")
                break
        if any(port.port in _SUSPICIOUS_PORTS for port in proc.ports):
            score += 15
            signals.append("suspicious listener port")
        if len(proc.ports) >= 25:
            score += 10
            signals.append("unusually many listening sockets")
        if proc.outbound_connections >= 50:
            score += 40
            signals.append("excessive outbound connections")
        elif proc.outbound_connections >= 15 and proc.cpu_percent >= 50:
            score += 40
            signals.append("high CPU with many outbound connections")
        return min(score, 100), signals, category if score else "INFO"

    def _entropy(self, value: str) -> float:
        if not value:
            return 0.0
        counts = {char: value.count(char) for char in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())
