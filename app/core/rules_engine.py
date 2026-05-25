"""YAML rule engine for alerts and future healing actions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.schemas import ProcessSnapshot


class RuleEngine:
    """Evaluate simple YAML process rules."""

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self._rules = self._load_rules(rules_path) if rules_path else []

    def evaluate(self, snapshots: list[ProcessSnapshot]) -> list[tuple[str, ProcessSnapshot, str]]:
        """Return matching rules as action tuples."""

        matches: list[tuple[str, ProcessSnapshot, str]] = []
        for rule in self._rules:
            condition = rule.get("condition", {})
            action = rule.get("action", "notify")
            name = str(rule.get("name", "unnamed_rule"))
            for proc in snapshots:
                if self._matches(proc, condition):
                    matches.append((name, proc, str(action)))
        return matches

    def _load_rules(self, rules_path: str | Path) -> list[dict[str, Any]]:
        path = Path(rules_path)
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = data.get("rules", [])
        return rules if isinstance(rules, list) else []

    def _matches(self, proc: ProcessSnapshot, condition: dict[str, Any]) -> bool:
        for key, expected in condition.items():
            actual: Any = getattr(proc, key, None)
            if key == "process_name":
                actual = proc.name
            if isinstance(expected, str) and expected[:1] in {">", "<"}:
                if not self._compare(float(actual or 0), expected):
                    return False
            elif str(actual) != str(expected):
                return False
        return True

    def _compare(self, actual: float, expression: str) -> bool:
        operator = expression[0]
        target = float(expression[1:])
        return actual > target if operator == ">" else actual < target

