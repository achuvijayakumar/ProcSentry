"""Repository abstraction over persistence."""

from __future__ import annotations

import json
from dataclasses import asdict
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time

from sqlalchemy import delete, desc, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.database.models import (
    AlertRecord,
    DuplicateGroupRecord,
    KillRecord,
    ProcessNoteRecord,
    ProcessHistoryRecord,
    ProcessRecord,
    utcnow,
)
from app.database.session import session_scope
from app.schemas import DuplicateGroup, PortInfo, ProcessSnapshot


class ProcessRepository:
    """Repository for process, history, duplicate, and alert records."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def upsert_processes(
        self, snapshots: Sequence[ProcessSnapshot], history_sample_interval_seconds: int = 15
    ) -> None:
        """Persist current process snapshots and append resource history."""

        now = utcnow()
        history_cutoff = now - timedelta(seconds=history_sample_interval_seconds)
        with session_scope(self._session_factory) as session:
            existing: dict[int, ProcessRecord] = {}
            if snapshots:
                pids = {snapshot.pid for snapshot in snapshots}
                for existing_record in session.scalars(
                    select(ProcessRecord).where(ProcessRecord.pid.in_(pids))
                ):
                    existing[existing_record.pid] = existing_record
            for snapshot in snapshots:
                record: ProcessRecord | None = existing.get(snapshot.pid)
                if record is None:
                    record = ProcessRecord(
                        pid=snapshot.pid,
                        ppid=snapshot.ppid,
                        name=snapshot.name,
                        cmdline="\0".join(snapshot.cmdline),
                        executable=snapshot.executable,
                        cwd=snapshot.cwd,
                        start_time=snapshot.start_time,
                        fingerprint=snapshot.fingerprint,
                        fuzzy_fingerprint=snapshot.fuzzy_fingerprint,
                    )
                    session.add(record)
                    session.flush()
                else:
                    if record.start_time != snapshot.start_time:
                        record.restart_count += 1
                    record.start_time = snapshot.start_time

                record.ppid = snapshot.ppid
                record.name = snapshot.name
                record.cmdline = "\0".join(snapshot.cmdline)
                record.executable = snapshot.executable
                record.cwd = snapshot.cwd
                record.cpu_percent = snapshot.cpu_percent
                record.memory_mb = snapshot.memory_mb
                record.status = snapshot.status
                record.user = snapshot.user
                record.threads = snapshot.threads
                record.ports_json = json.dumps([asdict(port) for port in snapshot.ports])
                record.service_manager = snapshot.service_manager
                record.container_id = snapshot.container_id
                record.systemd_unit = snapshot.systemd_unit
                record.ancestry_json = json.dumps(snapshot.ancestry)
                record.is_zombie = snapshot.is_zombie
                record.is_orphan = snapshot.is_orphan
                record.executable_deleted = snapshot.executable_deleted
                record.executable_hash = snapshot.executable_hash
                record.outbound_connections = snapshot.outbound_connections
                record.fingerprint = snapshot.fingerprint
                record.fuzzy_fingerprint = snapshot.fuzzy_fingerprint
                record.duplicate_score = snapshot.duplicate_score
                record.suspicious_score = snapshot.suspicious_score
                record.last_seen_at = now
                last_history = session.scalar(
                    select(func.max(ProcessHistoryRecord.timestamp)).where(
                        ProcessHistoryRecord.process_id == record.id
                    )
                )
                if last_history is not None and last_history.tzinfo is None:
                    last_history = last_history.replace(tzinfo=timezone.utc)
                if last_history is None or last_history < history_cutoff:
                    session.add(
                        ProcessHistoryRecord(
                            process_id=record.id,
                            cpu_percent=snapshot.cpu_percent,
                            memory_mb=snapshot.memory_mb,
                            thread_count=snapshot.threads,
                            timestamp=now,
                        )
                    )

            stale_cutoff = now - timedelta(seconds=30)
            session.flush()
            session.execute(delete(ProcessRecord).where(ProcessRecord.last_seen_at < stale_cutoff))

    def list_processes(
        self,
        limit: int = 500,
        offset: int = 0,
        query: str | None = None,
        suspicious: bool | None = None,
        duplicates: bool | None = None,
    ) -> list[ProcessRecord]:
        """Return recent current process records."""

        risk_score = (
            ProcessRecord.suspicious_score
            + ProcessRecord.duplicate_score
            + (ProcessRecord.restart_count * 10)
            + ProcessRecord.cpu_percent
        )
        statement = select(ProcessRecord)
        if query:
            like = f"%{query}%"
            statement = statement.where(
                ProcessRecord.name.like(like) | ProcessRecord.cmdline.like(like)
            )
        if suspicious:
            statement = statement.where(ProcessRecord.suspicious_score > 0)
        if duplicates:
            statement = statement.where(ProcessRecord.duplicate_score > 0)
        statement = statement.order_by(desc(risk_score), desc(ProcessRecord.cpu_percent)).offset(offset).limit(limit)
        with session_scope(self._session_factory) as session:
            return list(session.scalars(statement))

    def count_processes(self) -> int:
        """Return current process count."""

        with session_scope(self._session_factory) as session:
            return int(session.scalar(select(func.count(ProcessRecord.id))) or 0)

    def get_process_by_pid(self, pid: int) -> ProcessRecord | None:
        """Return one process by PID."""

        with session_scope(self._session_factory) as session:
            return session.scalar(select(ProcessRecord).where(ProcessRecord.pid == pid))

    def add_duplicate_groups(self, groups: Sequence[DuplicateGroup]) -> None:
        """Persist duplicate groups for audit/history."""

        with session_scope(self._session_factory) as session:
            for group in groups:
                session.add(
                    DuplicateGroupRecord(
                        fingerprint=group.fingerprint,
                        confidence=group.confidence,
                        process_pids=json.dumps([proc.pid for proc in group.processes]),
                        reason=group.reason,
                        explanations_json=json.dumps(group.explanations),
                    )
                )

    def list_duplicate_groups(self, limit: int = 100) -> list[DuplicateGroupRecord]:
        """Return latest duplicate group observations."""

        with session_scope(self._session_factory) as session:
            return list(
                session.scalars(
                    select(DuplicateGroupRecord)
                    .where(DuplicateGroupRecord.resolved.is_(False))
                    .order_by(desc(DuplicateGroupRecord.detected_at))
                    .limit(limit)
                )
            )

    def resolve_duplicate_group(self, group_id: int) -> bool:
        """Mark a duplicate group resolved after operator review."""

        with session_scope(self._session_factory) as session:
            group = session.get(DuplicateGroupRecord, group_id)
            if group is None:
                return False
            group.resolved = True
            return True

    def add_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        pid: int | None = None,
        fingerprint: str | None = None,
        category: str = "general",
    ) -> None:
        """Persist an alert."""

        with session_scope(self._session_factory) as session:
            session.add(
                AlertRecord(
                    type=alert_type,
                    severity=severity,
                    category=category,
                    message=message,
                    pid=pid,
                    fingerprint=fingerprint,
                )
            )

    def list_alerts(self, limit: int = 200) -> list[AlertRecord]:
        """Return active alerts."""

        with session_scope(self._session_factory) as session:
            return list(
                session.scalars(
                    select(AlertRecord)
                    .where(AlertRecord.resolved.is_(False))
                    .order_by(desc(AlertRecord.created_at))
                    .limit(limit)
                )
            )

    def resolve_alert(self, alert_id: int) -> bool:
        """Mark an alert resolved/acknowledged."""

        with session_scope(self._session_factory) as session:
            alert = session.get(AlertRecord, alert_id)
            if alert is None:
                return False
            alert.resolved = True
            return True

    def add_process_note(
        self,
        note: str,
        pid: int | None = None,
        fingerprint: str | None = None,
        tag: str | None = None,
    ) -> None:
        """Persist an operator note or tag."""

        with session_scope(self._session_factory) as session:
            session.add(ProcessNoteRecord(pid=pid, fingerprint=fingerprint, tag=tag, note=note))

    def list_process_notes(
        self, pid: int | None = None, fingerprint: str | None = None, limit: int = 50
    ) -> list[ProcessNoteRecord]:
        """List operator notes for a process."""

        statement = select(ProcessNoteRecord).order_by(desc(ProcessNoteRecord.created_at)).limit(limit)
        if pid is not None:
            statement = statement.where(ProcessNoteRecord.pid == pid)
        if fingerprint is not None:
            statement = statement.where(ProcessNoteRecord.fingerprint == fingerprint)
        with session_scope(self._session_factory) as session:
            return list(session.scalars(statement))

    def purge_old_history(self, retention_days: int) -> None:
        """Delete process history older than the retention window."""

        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        with session_scope(self._session_factory) as session:
            session.execute(delete(ProcessHistoryRecord).where(ProcessHistoryRecord.timestamp < cutoff))

    def sqlite_checkpoint(self) -> None:
        """Checkpoint SQLite WAL when using SQLite."""

        bind = self._session_factory.kw["bind"]
        if getattr(bind, "dialect", None) and bind.dialect.name == "sqlite":
            with bind.begin() as connection:
                connection.execute(text("PRAGMA wal_checkpoint(TRUNCATE)"))

    def sqlite_vacuum(self) -> None:
        """Run SQLite VACUUM outside active transaction."""

        bind = self._session_factory.kw["bind"]
        if getattr(bind, "dialect", None) and bind.dialect.name == "sqlite":
            with bind.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
                connection.execute(text("VACUUM"))

    def storage_metrics(self) -> dict[str, int]:
        """Return storage metrics for observability."""

        bind = self._session_factory.kw["bind"]
        db_size = 0
        wal_size = 0
        if getattr(bind, "url", None) and bind.dialect.name == "sqlite":
            database = bind.url.database
            if database:
                path = Path(database)
                if path.exists():
                    db_size = path.stat().st_size
                wal_path = Path(f"{database}-wal")
                if wal_path.exists():
                    wal_size = wal_path.stat().st_size
        with session_scope(self._session_factory) as session:
            history_rows = int(session.scalar(select(func.count(ProcessHistoryRecord.id))) or 0)
        return {"db_size_bytes": db_size, "wal_size_bytes": wal_size, "history_rows": history_rows}

    def stats(self) -> dict[str, int]:
        """Return lightweight aggregate stats."""

        with session_scope(self._session_factory) as session:
            return {
                "processes": int(session.scalar(select(func.count(ProcessRecord.id))) or 0),
                "duplicates": int(
                    session.scalar(
                        select(func.count(DuplicateGroupRecord.id)).where(
                            DuplicateGroupRecord.resolved.is_(False)
                        )
                    )
                    or 0
                ),
                "alerts": int(
                    session.scalar(
                        select(func.count(AlertRecord.id)).where(AlertRecord.resolved.is_(False))
                    )
                    or 0
                ),
                "suspicious": int(
                    session.scalar(
                        select(func.count(ProcessRecord.id)).where(ProcessRecord.suspicious_score > 0)
                    )
                    or 0
                ),
            }

    def run_maintenance(
        self,
        retention_days: int,
        checkpoint: bool,
        vacuum: bool,
    ) -> dict[str, float]:
        """Run bounded storage maintenance and return timings."""

        timings: dict[str, float] = {}
        started = time.perf_counter()
        self.purge_old_history(retention_days)
        timings["prune_ms"] = (time.perf_counter() - started) * 1000
        if checkpoint:
            started = time.perf_counter()
            self.sqlite_checkpoint()
            timings["checkpoint_ms"] = (time.perf_counter() - started) * 1000
        if vacuum:
            started = time.perf_counter()
            self.sqlite_vacuum()
            timings["vacuum_ms"] = (time.perf_counter() - started) * 1000
        return timings


    def record_kill(
        self,
        *,
        pid: int,
        name: str,
        cmdline: str = "",
        friendly_label: str | None = None,
        project: str | None = None,
        user: str | None = None,
        cpu_percent: float = 0.0,
        memory_mb: float = 0.0,
        killed_via: str = "single",
    ) -> None:
        """Persist a single kill event for /roast aggregation."""

        with session_scope(self._session_factory) as session:
            session.add(
                KillRecord(
                    pid=pid,
                    name=name,
                    cmdline=cmdline,
                    friendly_label=friendly_label,
                    project=project,
                    user=user,
                    cpu_percent=cpu_percent,
                    memory_mb=memory_mb,
                    killed_via=killed_via,
                )
            )

    def list_kills(self, since: datetime | None = None, limit: int = 5000) -> list[KillRecord]:
        """Return kill records, optionally restricted to those after ``since``."""

        with session_scope(self._session_factory) as session:
            stmt = select(KillRecord)
            if since is not None:
                stmt = stmt.where(KillRecord.killed_at >= since)
            stmt = stmt.order_by(desc(KillRecord.killed_at)).limit(limit)
            records = list(session.scalars(stmt))
            for record in records:
                session.expunge(record)
            return records


def ports_from_record(record: ProcessRecord) -> list[PortInfo]:
    """Decode port information stored on a process record."""

    try:
        payload = json.loads(record.ports_json or "[]")
    except json.JSONDecodeError:
        return []
    ports: list[PortInfo] = []
    for item in payload:
        if isinstance(item, dict):
            ports.append(
                PortInfo(
                    port=int(item.get("port", 0)),
                    protocol=str(item.get("protocol", "tcp")),
                    address=str(item.get("address", "")),
                    pid=item.get("pid"),
                    process_name=item.get("process_name"),
                )
            )
    return ports
