"""Deterministic lookup over AntiFine's local AI knowledge catalog."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.models.finding import Finding

KNOWLEDGE_PATH = Path(__file__).resolve().parent / "knowledge" / "rules.json"


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    technology: str
    title: str
    match_terms: tuple[str, ...]
    severity: str
    description: str
    frameworks: tuple[str, ...]
    remediation: str
    source: str
    deterministic_remediation: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuleMetadata":
        return cls(
            rule_id=str(value["rule_id"]),
            technology=str(value["technology"]),
            title=str(value["title"]),
            match_terms=tuple(str(item).lower() for item in value.get("match_terms", [])),
            severity=str(value["severity"]),
            description=str(value["description"]),
            frameworks=tuple(str(item) for item in value.get("frameworks", [])),
            remediation=str(value["remediation"]),
            source=str(value["source"]),
            deterministic_remediation=value.get("deterministic_remediation"),
        )

    def as_prompt_context(self) -> str:
        frameworks = ", ".join(self.frameworks) or "None supplied"
        return (
            f"Rule ID: {self.rule_id}\n"
            f"Technology: {self.technology}\n"
            f"Title: {self.title}\n"
            f"Severity: {self.severity}\n"
            f"Detection: {self.description}\n"
            f"Frameworks: {frameworks}\n"
            f"Remediation guidance: {self.remediation}\n"
            f"Source: {self.source}"
        )


class KnowledgeService:
    """Loads the immutable rule catalog and provides read-only lookups."""

    def __init__(self, path: Path = KNOWLEDGE_PATH) -> None:
        with path.open(encoding="utf-8") as handle:
            raw_rules = json.load(handle)
        if not isinstance(raw_rules, list):
            raise ValueError("AntiFine knowledge catalog must contain a list")
        self._rules = tuple(RuleMetadata.from_dict(item) for item in raw_rules)
        self._by_id = {rule.rule_id: rule for rule in self._rules}

    def get_rule(self, rule_id: str) -> RuleMetadata | None:
        return self._by_id.get(rule_id)

    @property
    def rules(self) -> tuple[RuleMetadata, ...]:
        """Return the immutable catalog entries for index builders."""
        return self._rules

    def search_rules(self, query: str) -> list[RuleMetadata]:
        terms = {part for part in query.lower().split() if part}
        if not terms:
            return []
        return [
            rule for rule in self._rules
            if any(term in " ".join((rule.rule_id, rule.title, *rule.match_terms)).lower() for term in terms)
        ]

    def get_framework(self, framework: str) -> list[RuleMetadata]:
        needle = framework.lower()
        return [rule for rule in self._rules if any(needle in item.lower() for item in rule.frameworks)]

    def get_remediation(self, rule_id: str) -> str | None:
        rule = self.get_rule(rule_id)
        return rule.remediation if rule else None

    def find_for_finding(self, finding: Finding) -> RuleMetadata | None:
        name = finding.rule_name.lower()
        matches = [
            rule for rule in self._rules
            if any(term in name for term in rule.match_terms)
        ]
        for rule in matches:
            if rule.severity == finding.severity:
                return rule
        return matches[0] if matches else None


_SERVICE = KnowledgeService()


def get_rule(rule_id: str) -> RuleMetadata | None:
    return _SERVICE.get_rule(rule_id)


def search_rules(query: str) -> list[RuleMetadata]:
    return _SERVICE.search_rules(query)


def get_framework(framework: str) -> list[RuleMetadata]:
    return _SERVICE.get_framework(framework)


def get_remediation(rule_id: str) -> str | None:
    return _SERVICE.get_remediation(rule_id)


def find_rule_for_finding(finding: Finding) -> RuleMetadata | None:
    return _SERVICE.find_for_finding(finding)
