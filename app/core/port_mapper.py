"""Map listening sockets to processes."""

from __future__ import annotations

import logging
import time

import psutil

from app.schemas import PortInfo, ProcessSnapshot

logger = logging.getLogger(__name__)


class PortMapper:
    """Collect and attach TCP/UDP listening ports to process snapshots."""

    def __init__(self, refresh_interval: float = 5.0) -> None:
        self._refresh_interval = refresh_interval
        self._last_collect_at = 0.0
        self._cached_ports: dict[int, list[PortInfo]] = {}
        self._cached_outbound: dict[int, int] = {}
        self.last_socket_enum_ms = 0.0
        self.cache_hits = 0
        self.cache_misses = 0

    def collect_ports(self) -> dict[int, list[PortInfo]]:
        """Return listening ports keyed by PID."""

        now = time.monotonic()
        if self._cached_ports and now - self._last_collect_at < self._refresh_interval:
            self.cache_hits += 1
            self.last_socket_enum_ms = 0.0
            return self._cached_ports
        self.cache_misses += 1
        started = time.perf_counter()
        ports_by_pid: dict[int, list[PortInfo]] = {}
        outbound_by_pid: dict[int, int] = {}
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            logger.warning("Unable to collect full port ownership: %s", exc)
            self.last_socket_enum_ms = (time.perf_counter() - started) * 1000
            return ports_by_pid

        for conn in connections:
            if conn.pid is None or not conn.laddr:
                continue
            if conn.type.name == "SOCK_STREAM" and conn.status != psutil.CONN_LISTEN:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    outbound_by_pid[conn.pid] = outbound_by_pid.get(conn.pid, 0) + 1
                continue
            protocol = "tcp" if conn.type.name == "SOCK_STREAM" else "udp"
            ports_by_pid.setdefault(conn.pid, []).append(
                PortInfo(
                    port=int(conn.laddr.port),
                    protocol=protocol,
                    address=str(conn.laddr.ip),
                    pid=conn.pid,
                )
            )
        self._cached_ports = ports_by_pid
        self._cached_outbound = outbound_by_pid
        self._last_collect_at = now
        self.last_socket_enum_ms = (time.perf_counter() - started) * 1000
        return ports_by_pid

    def attach(self, snapshots: list[ProcessSnapshot]) -> list[ProcessSnapshot]:
        """Attach listening port metadata to each process snapshot."""

        by_pid = self.collect_ports()
        for snapshot in snapshots:
            ports = by_pid.get(snapshot.pid, [])
            for port in ports:
                port.process_name = snapshot.name
            snapshot.ports = tuple(ports)
            snapshot.outbound_connections = self._cached_outbound.get(snapshot.pid, 0)
        return snapshots
