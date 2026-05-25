"""Fingerprinting tests."""

from app.core.fingerprint import FingerprintEngine
from tests.fakes import proc


def test_fuzzy_fingerprint_normalizes_python_aliases() -> None:
    engine = FingerprintEngine()
    left = engine.apply(proc(100, cmdline=("python", "bot.py"), executable="/usr/bin/python"))
    right = engine.apply(proc(101, cmdline=("python3", "bot.py"), executable="/usr/bin/python3"))

    assert left.fuzzy_fingerprint == right.fuzzy_fingerprint
    assert left.fingerprint != right.fingerprint


def test_fingerprint_ignores_pid_like_dynamic_args() -> None:
    engine = FingerprintEngine()
    left = engine.apply(proc(100, cmdline=("python3", "worker.py", "--pid=12345")))
    right = engine.apply(proc(101, cmdline=("python3", "worker.py", "--pid=98765")))

    assert left.fuzzy_fingerprint == right.fuzzy_fingerprint

