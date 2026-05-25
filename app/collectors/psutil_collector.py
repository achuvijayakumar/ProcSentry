"""Backward-compatible import for the shared psutil collector."""

from app.collectors.common.psutil_collector import PsutilProcessCollector

__all__ = ["PsutilProcessCollector"]
