"""Small process-local runtime metrics registry."""

from __future__ import annotations

from app.schemas import RuntimeMetrics

_metrics = RuntimeMetrics()


def get_runtime_metrics() -> RuntimeMetrics:
    """Return mutable process-local runtime metrics."""

    return _metrics

