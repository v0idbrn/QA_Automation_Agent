# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Small shared contracts for the Workhorse Edition engines.

The autonomous agent's ``core.models`` remains untouched. These models are a
lightweight bridge so the new engines, reporter, and CLI speak the same
language without importing the heavier orchestration layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)


def normalize_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


@dataclass(frozen=True)
class Finding:
    title: str
    severity: Severity | str
    category: str
    description: str = ""
    url: str = ""
    evidence: str = ""
    reproduction: str = ""
    recommendation: str = ""
    confidence: str = "MEDIUM"
    finding_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", normalize_severity(self.severity))

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "reproduction": self.reproduction,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "finding_id": self.finding_id,
            "metadata": dict(self.metadata),
        }


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[normalize_severity(finding.severity).value] += 1
    return counts


def sort_findings(findings: list[Finding]) -> list[Finding]:
    rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda item: (rank[normalize_severity(item.severity)], item.category, item.title),
    )
