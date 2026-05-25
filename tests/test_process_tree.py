"""Process tree helper tests."""

from app.core.process_tree import build_process_tree, trace_ancestry
from tests.fakes import proc


def test_trace_ancestry_handles_cycles() -> None:
    assert trace_ancestry(10, {10: 11, 11: 10}) == (11,)


def test_build_process_tree_attaches_children() -> None:
    parent = proc(10)
    child = proc(11)
    child.ppid = 10

    roots = build_process_tree([parent, child])

    assert len(roots) == 1
    assert roots[0].children[0].pid == 11
