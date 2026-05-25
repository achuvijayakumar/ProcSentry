"""Duplicate detection heuristics tests."""

from app.core.duplicate_detector import DuplicateDetector
from app.core.fingerprint import FingerprintEngine
from tests.fakes import proc


def _fingerprinted(*processes):
    engine = FingerprintEngine()
    return [engine.apply(process) for process in processes]


def test_exact_duplicate_detection() -> None:
    processes = _fingerprinted(proc(100), proc(101))

    groups = DuplicateDetector(confidence_threshold=75).detect(processes)

    assert len(groups) == 1
    assert groups[0].confidence == 99
    assert {process.pid for process in groups[0].processes} == {100, 101}


def test_worker_group_exclusion_for_gunicorn() -> None:
    processes = _fingerprinted(
        proc(100, name="gunicorn", cmdline=("gunicorn", "app:app", "worker")),
        proc(101, name="gunicorn", cmdline=("gunicorn", "app:app", "worker")),
    )

    assert DuplicateDetector().detect(processes) == []


def test_uvicorn_reload_mode_is_excluded() -> None:
    processes = _fingerprinted(
        proc(100, name="uvicorn", cmdline=("uvicorn", "app:app", "--reload")),
        proc(101, name="uvicorn", cmdline=("uvicorn", "app:app", "--reload")),
    )

    assert DuplicateDetector().detect(processes) == []


def test_different_containers_lower_confidence() -> None:
    left, right = _fingerprinted(proc(100), proc(101))
    left.container_id = "container-a"
    right.container_id = "container-b"

    groups = DuplicateDetector(confidence_threshold=80).detect([left, right])

    assert groups == []


def test_probable_duplicate_normalizes_python_aliases() -> None:
    processes = _fingerprinted(
        proc(100, cmdline=("python", "bot.py"), executable="/usr/bin/python"),
        proc(101, cmdline=("python3", "bot.py"), executable="/usr/bin/python3"),
    )

    groups = DuplicateDetector(confidence_threshold=70).detect(processes)

    assert groups
    assert groups[0].confidence >= 70
    assert groups[0].explanations


def test_near_duplicate_with_different_ports_is_detected() -> None:
    processes = _fingerprinted(
        proc(100, cmdline=("python3", "app.py", "--port", "8000")),
        proc(101, cmdline=("python3", "app.py", "--port", "8001")),
    )

    groups = DuplicateDetector(confidence_threshold=70).detect(processes)

    assert groups
    assert "same application entrypoint" in groups[0].explanations


def test_parent_child_relationship_is_not_duplicate() -> None:
    parent, child = _fingerprinted(
        proc(100, cmdline=("python3", "app.py")),
        proc(101, cmdline=("python3", "app.py")),
    )
    child.ppid = 100
    child.ancestry = (100, 1)

    assert DuplicateDetector(confidence_threshold=70).detect([parent, child]) == []


def test_celery_child_is_excluded_by_parent_supervisor() -> None:
    parent, child = _fingerprinted(
        proc(100, name="celery", cmdline=("celery", "-A", "proj", "worker")),
        proc(101, name="python", cmdline=("python3", "-m", "celery.concurrency.prefork")),
    )
    child.ppid = 100
    child.ancestry = (100, 1)

    assert DuplicateDetector(confidence_threshold=70).detect([parent, child]) == []
