"""Duplicate process detection with exclusions and confidence scoring."""

from __future__ import annotations

from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

from app.config import DuplicateDetectionConfig
from app.core.command_normalizer import normalize_command
from app.core.runtime_state import RestartTracker, TTLSet
from app.schemas import DuplicateDecisionReason, DuplicateGroup, ProcessSnapshot

_WORKER_PATTERNS = (
    "nginx: worker",
    "postgres:",
    "postgres ",
    "apache2 -k",
    "php-fpm: pool",
    "docker-proxy",
    "containerd-shim",
)
_CLUSTER_MASTERS = {"gunicorn", "celery", "pm2", "nginx", "postgres", "node"}
_SUPERVISOR_MARKERS = (
    "celery worker",
    "gunicorn: worker",
    "gunicorn worker",
    "uvicorn subprocess",
    "multiprocessing.spawn",
    "pm2:",
    "node cluster",
)


class DuplicateDetector:
    """Detect exact and probable duplicate processes with low-noise defaults."""

    def __init__(
        self,
        confidence_threshold: int = 75,
        config: DuplicateDetectionConfig | None = None,
    ) -> None:
        self._config = config or DuplicateDetectionConfig(confidence_threshold=confidence_threshold)
        self.confidence_threshold = self._config.confidence_threshold
        self._suppressed = TTLSet()
        self._restart_tracker = RestartTracker()

    def detect(self, snapshots: list[ProcessSnapshot]) -> list[DuplicateGroup]:
        """Return duplicate process groups above the configured threshold."""

        parent_map = {proc.pid: proc for proc in snapshots}
        restart_loop_fingerprints = self._restart_loop_fingerprints(snapshots)
        candidates = [
            proc
            for proc in snapshots
            if not self._is_intentional_worker(proc, parent_map)
            and not self._is_allowlisted(proc)
            and proc.fingerprint not in restart_loop_fingerprints
        ]
        groups: list[DuplicateGroup] = []
        seen_pids: set[int] = set()

        exact_buckets: dict[str, list[ProcessSnapshot]] = defaultdict(list)
        for proc in candidates:
            if proc.fingerprint:
                exact_buckets[proc.fingerprint].append(proc)

        for fingerprint, bucket in exact_buckets.items():
            if len(bucket) > 1:
                if self._mixed_containers(bucket):
                    continue
                if self._contains_parent_child(bucket):
                    continue
                for proc in bucket:
                    seen_pids.add(proc.pid)
                suppression_key = self._suppression_key(fingerprint, bucket)
                if self._suppressed.seen_recently(
                    suppression_key, self._config.suppression_window_seconds
                ):
                    continue
                for proc in bucket:
                    proc.duplicate_score = 99
                groups.append(
                    DuplicateGroup(
                        fingerprint=fingerprint,
                        confidence=99,
                        reason="same executable, cwd, and normalized arguments",
                        processes=tuple(bucket),
                        explanations=self._messages(
                            [
                                DuplicateDecisionReason("same_exec", "same normalized executable", 30),
                                DuplicateDecisionReason("same_cwd", "same working directory", 25),
                                DuplicateDecisionReason("same_args", "same normalized arguments", 44),
                            ]
                        ),
                    )
                )

        fuzzy_buckets: dict[str, list[ProcessSnapshot]] = defaultdict(list)
        for proc in candidates:
            if proc.pid not in seen_pids and proc.fuzzy_fingerprint:
                fuzzy_buckets[proc.fuzzy_fingerprint].append(proc)

        for fingerprint, bucket in fuzzy_buckets.items():
            if len(bucket) < 2:
                continue
            scored = [self._pair_score(left, right) for left in bucket for right in bucket if left != right]
            confidence, reasons = max(scored, key=lambda item: item[0])
            if confidence >= self.confidence_threshold:
                suppression_key = self._suppression_key(fingerprint, bucket)
                if self._suppressed.seen_recently(
                    suppression_key, self._config.suppression_window_seconds
                ):
                    continue
                for proc in bucket:
                    proc.duplicate_score = max(proc.duplicate_score, confidence)
                groups.append(
                    DuplicateGroup(
                        fingerprint=fingerprint,
                        confidence=confidence,
                        reason="; ".join(self._messages(reasons)),
                        processes=tuple(bucket),
                        explanations=self._messages(reasons),
                    )
                )

        pairwise_groups = self._detect_near_duplicates(candidates, seen_pids, groups)
        groups.extend(pairwise_groups)
        return groups

    def _detect_near_duplicates(
        self,
        candidates: list[ProcessSnapshot],
        seen_pids: set[int],
        emitted_groups: list[DuplicateGroup],
    ) -> list[DuplicateGroup]:
        emitted_pids = {proc.pid for group in emitted_groups for proc in group.processes}
        buckets: dict[tuple[str, str, str | None], list[ProcessSnapshot]] = defaultdict(list)
        for proc in candidates:
            if proc.pid in seen_pids or proc.pid in emitted_pids:
                continue
            profile = normalize_command(proc.executable or proc.name, proc.cwd, proc.cmdline, fuzzy=True)
            key = (profile.executable, profile.cwd, profile.script_or_module)
            buckets[key].append(proc)

        groups: list[DuplicateGroup] = []
        consumed: set[int] = set()
        for bucket in buckets.values():
            if len(bucket) < 2:
                continue
            for left_index, left in enumerate(bucket):
                if left.pid in consumed:
                    continue
                members = [left]
                best_score = 0
                best_reasons: list[DuplicateDecisionReason] = []
                for right in bucket[left_index + 1 :]:
                    if right.pid in consumed or self._has_ancestor_relationship(left, right):
                        continue
                    confidence, reasons = self._pair_score(left, right)
                    if confidence >= self.confidence_threshold:
                        members.append(right)
                        best_score = max(best_score, confidence)
                        if confidence >= best_score:
                            best_reasons = reasons
                if len(members) > 1 and not self._mixed_containers(members):
                    suppression_key = self._suppression_key(members[0].fuzzy_fingerprint or "", members)
                    if self._suppressed.seen_recently(
                        suppression_key, self._config.suppression_window_seconds
                    ):
                        continue
                    for member in members:
                        member.duplicate_score = max(member.duplicate_score, best_score)
                        consumed.add(member.pid)
                    fingerprint = members[0].fuzzy_fingerprint or members[0].fingerprint or str(members[0].pid)
                    groups.append(
                        DuplicateGroup(
                            fingerprint=fingerprint,
                            confidence=best_score,
                            reason="; ".join(self._messages(best_reasons)),
                            processes=tuple(members),
                            explanations=self._messages(best_reasons),
                        )
                    )
        return groups

    def _pair_score(
        self, left: ProcessSnapshot, right: ProcessSnapshot
    ) -> tuple[int, list[DuplicateDecisionReason]]:
        score = 0
        reasons: list[DuplicateDecisionReason] = []
        if self._exec_name(left) == self._exec_name(right):
            score += 30
            reasons.append(DuplicateDecisionReason("same_exec", "same executable alias", 30))
        if left.cwd and right.cwd and self._similarity(left.cwd, right.cwd) > 0.88:
            score += 25
            reasons.append(DuplicateDecisionReason("similar_cwd", "same or highly similar cwd", 25))
        left_profile = normalize_command(left.executable or left.name, left.cwd, left.cmdline, fuzzy=True)
        right_profile = normalize_command(right.executable or right.name, right.cwd, right.cmdline, fuzzy=True)
        arg_similarity = self._similarity(left_profile.arg_text, right_profile.arg_text)
        if arg_similarity > 0.75:
            points = 25 if arg_similarity >= 0.9 else 18
            score += points
            reasons.append(
                DuplicateDecisionReason(
                    "similar_args", f"{arg_similarity:.0%} argument similarity", points
                )
            )
        if {port.port for port in left.ports} & {port.port for port in right.ports}:
            score += 10
            reasons.append(DuplicateDecisionReason("same_port", "same listening port", 10))
        if left.ppid and left.ppid == right.ppid:
            score += 10
            reasons.append(DuplicateDecisionReason("same_parent", "same parent process", 10))
        if left_profile.script_or_module and left_profile.script_or_module == right_profile.script_or_module:
            score += 10
            reasons.append(DuplicateDecisionReason("same_entrypoint", "same application entrypoint", 10))
        if self._has_ancestor_relationship(left, right):
            score -= 45
            reasons.append(
                DuplicateDecisionReason(
                    "ancestor_penalty", "parent-child relationship lowers duplicate confidence", -45
                )
            )
        if left.systemd_unit and left.systemd_unit == right.systemd_unit:
            score -= 20
            reasons.append(
                DuplicateDecisionReason(
                    "same_systemd_unit", "same systemd unit lowers duplicate confidence", -20
                )
            )
        if left.container_id and right.container_id and left.container_id != right.container_id:
            score -= 30
            reasons.append(
                DuplicateDecisionReason(
                    "different_container", "different containers lower duplicate confidence", -30
                )
            )
        age_delta = self._start_delta_seconds(left, right)
        if age_delta is not None and age_delta <= 10:
            score += 5
            reasons.append(DuplicateDecisionReason("same_start_window", "started within 10 seconds", 5))
        elif age_delta is not None and age_delta > 3600:
            score -= 10
            reasons.append(DuplicateDecisionReason("distant_start", "start times far apart", -10))
        return max(0, min(score, 99)), reasons

    def _exec_name(self, proc: ProcessSnapshot) -> str:
        value = proc.executable or proc.name
        name = Path(value).name.lower()
        return {"python3": "python", "python3.12": "python", "nodejs": "node"}.get(name, name)

    def _similarity(self, left: str, right: str) -> float:
        return SequenceMatcher(None, left.lower(), right.lower()).ratio()

    def _is_intentional_worker(
        self, proc: ProcessSnapshot, parent_map: dict[int, ProcessSnapshot] | None = None
    ) -> bool:
        cmd = " ".join(proc.cmdline).lower()
        name = proc.name.lower()
        if any(pattern in cmd or pattern in name for pattern in _WORKER_PATTERNS):
            return True
        if any(marker in cmd for marker in _SUPERVISOR_MARKERS):
            return True
        if proc.service_manager in {"docker", "podman"} and name in {"docker-proxy", "containerd-shim"}:
            return True
        if "--reload" in cmd and ("uvicorn" in cmd or name == "uvicorn"):
            return True
        if "node" in name and ("cluster" in cmd or "pm2" in cmd):
            return True
        if name in {"celery", "gunicorn", "pm2"}:
            return True
        parent = parent_map.get(proc.ppid) if parent_map and proc.ppid else None
        if parent and self._exec_name(parent) in _CLUSTER_MASTERS:
            return True
        if parent and any(marker in " ".join(parent.cmdline).lower() for marker in _SUPERVISOR_MARKERS):
            return True
        if proc.ppid == 1 and name in {"nginx", "postgres", "mysqld"}:
            return True
        return False

    def _mixed_containers(self, bucket: list[ProcessSnapshot]) -> bool:
        containers = {proc.container_id for proc in bucket if proc.container_id}
        return len(containers) > 1

    def _has_ancestor_relationship(self, left: ProcessSnapshot, right: ProcessSnapshot) -> bool:
        return left.pid in right.ancestry or right.pid in left.ancestry or left.ppid == right.pid or right.ppid == left.pid

    def _contains_parent_child(self, bucket: list[ProcessSnapshot]) -> bool:
        for left in bucket:
            for right in bucket:
                if left.pid != right.pid and self._has_ancestor_relationship(left, right):
                    return True
        return False

    def _messages(self, reasons: list[DuplicateDecisionReason]) -> tuple[str, ...]:
        return tuple(reason.message for reason in reasons)

    def _is_allowlisted(self, proc: ProcessSnapshot) -> bool:
        if proc.fingerprint and proc.fingerprint in self._config.allowlist_fingerprints:
            return True
        cmd = " ".join(proc.cmdline).lower()
        return any(pattern.lower() in cmd for pattern in self._config.allowlist_commands)

    def _suppression_key(self, fingerprint: str, bucket: list[ProcessSnapshot]) -> str:
        pids = ",".join(str(proc.pid) for proc in sorted(bucket, key=lambda item: item.pid))
        return f"{fingerprint}:{pids}"

    def _restart_loop_fingerprints(self, snapshots: list[ProcessSnapshot]) -> set[str]:
        restart_loops: set[str] = set()
        for proc in snapshots:
            count = self._restart_tracker.observe(
                proc.fingerprint,
                proc.start_time,
                self._config.restart_loop_window_seconds,
            )
            if count >= self._config.restart_loop_threshold and proc.fingerprint:
                restart_loops.add(proc.fingerprint)
        return restart_loops

    def _start_delta_seconds(self, left: ProcessSnapshot, right: ProcessSnapshot) -> float | None:
        if left.start_time is None or right.start_time is None:
            return None
        return abs((left.start_time - right.start_time).total_seconds())
