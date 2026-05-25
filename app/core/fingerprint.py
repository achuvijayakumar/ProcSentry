"""Process fingerprinting and command normalization."""

from __future__ import annotations

import hashlib

from app.core.command_normalizer import normalize_command
from app.schemas import ProcessSnapshot


class FingerprintEngine:
    """Create exact and fuzzy process fingerprints."""

    def apply(self, snapshot: ProcessSnapshot) -> ProcessSnapshot:
        """Return a snapshot with fingerprint fields populated."""

        exact = normalize_command(snapshot.executable or snapshot.name, snapshot.cwd, snapshot.cmdline, fuzzy=False)
        fuzzy = normalize_command(snapshot.executable or snapshot.name, snapshot.cwd, snapshot.cmdline, fuzzy=True)
        exact_parts = [exact.executable, exact.cwd, exact.arg_text]
        fuzzy_parts = [fuzzy.executable, fuzzy.cwd, fuzzy.arg_text]
        snapshot.fingerprint = self._hash_parts(exact_parts)
        snapshot.fuzzy_fingerprint = self._hash_parts(fuzzy_parts)
        return snapshot

    def _hash_parts(self, parts: list[str]) -> str:
        data = "\0".join(parts).encode("utf-8", errors="ignore")
        return hashlib.sha256(data).hexdigest()
