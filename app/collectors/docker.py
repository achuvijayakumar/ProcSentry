"""Container awareness hooks."""

from __future__ import annotations

from app.collectors.linux.procfs import read_container_id

__all__ = ["read_container_id"]
