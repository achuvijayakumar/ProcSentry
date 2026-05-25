"""Process tree construction and ancestry helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.schemas import ProcessSnapshot


@dataclass(slots=True)
class ProcessTreeNode:
    """A process tree node for API/UI rendering."""

    pid: int
    name: str
    ppid: int | None
    cpu_percent: float
    memory_mb: float
    duplicate_score: int
    suspicious_score: int
    children: list["ProcessTreeNode"] = field(default_factory=list)


def build_process_tree(snapshots: list[ProcessSnapshot]) -> list[ProcessTreeNode]:
    """Build a forest from process snapshots in O(n)."""

    nodes = {
        proc.pid: ProcessTreeNode(
            pid=proc.pid,
            name=proc.name,
            ppid=proc.ppid,
            cpu_percent=proc.cpu_percent,
            memory_mb=proc.memory_mb,
            duplicate_score=proc.duplicate_score,
            suspicious_score=proc.suspicious_score,
        )
        for proc in snapshots
    }
    roots: list[ProcessTreeNode] = []
    for proc in snapshots:
        node = nodes[proc.pid]
        parent = nodes.get(proc.ppid or -1)
        if parent is None or parent.pid == node.pid:
            roots.append(node)
        else:
            parent.children.append(node)
    return roots


def trace_ancestry(pid: int, parents: dict[int, int | None]) -> tuple[int, ...]:
    """Trace process ancestry without looping on malformed process tables."""

    lineage: list[int] = []
    seen = {pid}
    current = parents.get(pid)
    while current and current not in seen:
        lineage.append(current)
        seen.add(current)
        current = parents.get(current)
    return tuple(lineage)
