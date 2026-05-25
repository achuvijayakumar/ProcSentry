"""Realistic VPS duplicate-detection scenario tests."""

from app.config import DuplicateDetectionConfig
from app.core.duplicate_detector import DuplicateDetector
from tests import scenarios


def test_common_worker_pools_do_not_alert_as_duplicates() -> None:
    detector = DuplicateDetector(config=DuplicateDetectionConfig(confidence_threshold=75))
    for processes in (
        scenarios.uvicorn_reload(),
        scenarios.gunicorn_pool(),
        scenarios.celery_prefork(),
        scenarios.nginx_master_worker(),
        scenarios.postgres_workers(),
        scenarios.node_cluster(),
        scenarios.docker_shim_tree(),
    ):
        assert detector.detect(processes) == []


def test_accidental_duplicate_is_detected_with_reasons() -> None:
    groups = DuplicateDetector(config=DuplicateDetectionConfig(confidence_threshold=75)).detect(
        scenarios.accidental_duplicate()
    )

    assert len(groups) == 1
    assert groups[0].confidence >= 90
    assert groups[0].explanations


def test_duplicate_suppression_window_prevents_repeated_alerts() -> None:
    detector = DuplicateDetector(
        config=DuplicateDetectionConfig(confidence_threshold=75, suppression_window_seconds=300)
    )
    processes = scenarios.accidental_duplicate()

    assert detector.detect(processes)
    assert detector.detect(processes) == []


def test_restart_loop_is_suppressed_as_duplicate_signal() -> None:
    detector = DuplicateDetector(
        config=DuplicateDetectionConfig(
            confidence_threshold=75,
            restart_loop_window_seconds=120,
            restart_loop_threshold=3,
        )
    )
    for batch in scenarios.restart_loop():
        groups = detector.detect(batch)
    assert groups == []

