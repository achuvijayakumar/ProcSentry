"""Command normalization tests."""

from app.core.command_normalizer import normalize_command


def test_normalizer_collapses_dynamic_ports_and_flag_order() -> None:
    left = normalize_command(
        "/usr/bin/python3",
        "/srv/app",
        ("python3", "app.py", "--host", "0.0.0.0", "--port", "8000", "--workers=2"),
    )
    right = normalize_command(
        "/usr/bin/python",
        "/srv/app",
        ("python", "app.py", "--workers=2", "--port", "9000", "--host", "127.0.0.1"),
    )

    assert left.executable == right.executable == "python"
    assert left.script_or_module == right.script_or_module == "app.py"
    assert left.stable_flags == right.stable_flags

