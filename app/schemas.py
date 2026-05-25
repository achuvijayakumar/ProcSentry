"""Typed data contracts shared by collectors, services, and UI layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class PortInfo:
    """A listening socket mapped to a process."""

    port: int
    protocol: str
    address: str
    pid: int | None = None
    process_name: str | None = None


@dataclass(slots=True)
class ProcessSnapshot:
    """Single observation of a Linux process."""

    pid: int
    ppid: int | None
    name: str
    cmdline: tuple[str, ...]
    executable: str | None
    cwd: str | None
    user: str | None
    cpu_percent: float
    memory_mb: float
    status: str | None
    threads: int
    start_time: datetime | None
    ports: tuple[PortInfo, ...] = field(default_factory=tuple)
    service_manager: str | None = None
    container_id: str | None = None
    systemd_unit: str | None = None
    ancestry: tuple[int, ...] = field(default_factory=tuple)
    is_zombie: bool = False
    is_orphan: bool = False
    executable_deleted: bool = False
    executable_hash: str | None = None
    outbound_connections: int = 0
    fingerprint: str | None = None
    fuzzy_fingerprint: str | None = None
    duplicate_score: int = 0
    suspicious_score: int = 0


@dataclass(slots=True)
class DuplicateGroup:
    """A group of processes believed to be accidental duplicates."""

    fingerprint: str
    confidence: int
    reason: str
    processes: tuple[ProcessSnapshot, ...]
    explanations: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DuplicateDecisionReason:
    """Structured duplicate decision reason for UI/API/debugging."""

    code: str
    message: str
    weight: int


@dataclass(slots=True)
class RuntimeMetrics:
    """Bounded in-memory daemon metrics."""

    scan_count: int = 0
    last_scan_ms: float = 0.0
    scan_collect_ms: float = 0.0
    scan_ports_ms: float = 0.0
    scan_enrich_ms: float = 0.0
    scan_fingerprint_ms: float = 0.0
    scan_socket_enum_ms: float = 0.0
    last_scan_started_at: datetime | None = None
    process_count: int = 0
    duplicate_count: int = 0
    security_finding_count: int = 0
    scanner_cache_hits: int = 0
    scanner_cache_misses: int = 0
    scanner_fingerprint_cache_hits: int = 0
    scanner_fingerprint_cache_misses: int = 0
    db_write_ms: float = 0.0
    maintenance_ms: float = 0.0


@dataclass(slots=True)
class SecurityFinding:
    """Suspicious process finding emitted by the security engine."""

    pid: int
    severity: str
    category: str
    confidence: int
    score: int
    message: str
    signals: tuple[str, ...]
