# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Failure analyzer for QA Automation Agent.

The analyzer classifies failures using evidence rather than guessing root
causes. If the evidence is insufficient, it reports UNKNOWN with low
confidence instead of inventing a cause.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from core.models import Finding, FindingCategory, Severity


class FailureType(str, Enum):
    APPLICATION_FAILURE = "APPLICATION_FAILURE"
    TEST_FAILURE = "TEST_FAILURE"
    ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    TIMEOUT = "TIMEOUT"
    SELECTOR_FAILURE = "SELECTOR_FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass
class FailureClassification:
    failure_type: FailureType
    confidence: float
    evidence_summary: str
    note: str = ""


class FailureAnalyzer:
    def classify(self, finding: Finding) -> FailureClassification:
        evidence = (finding.evidence or "").lower()
        category = finding.category.value
        description = finding.description.lower()
        actual = (finding.actual or "").lower()

        if finding.confidence < 0.4:
            return FailureClassification(
                failure_type=FailureType.UNKNOWN,
                confidence=finding.confidence,
                evidence_summary=self._summarize(evidence or description),
                note="insufficient evidence to classify",
            )

        if self._looks_like_timeout(finding, evidence, description, actual):
            return FailureClassification(
                failure_type=FailureType.TIMEOUT,
                confidence=self._timeout_confidence(evidence, description),
                evidence_summary=self._summarize(evidence or description),
            )

        if self._looks_like_network_failure(finding, evidence, description, actual):
            return FailureClassification(
                failure_type=FailureType.NETWORK_FAILURE,
                confidence=self._network_confidence(evidence, description),
                evidence_summary=self._summarize(evidence or description),
            )

        if self._looks_like_environment_failure(finding, evidence, description, actual):
            return FailureClassification(
                failure_type=FailureType.ENVIRONMENT_FAILURE,
                confidence=self._environment_confidence(evidence, description),
                evidence_summary=self._summarize(evidence or description),
            )

        if self._looks_like_selector_failure(finding, evidence, description):
            return FailureClassification(
                failure_type=FailureType.SELECTOR_FAILURE,
                confidence=self._selector_confidence(evidence, description),
                evidence_summary=self._summarize(evidence or description),
            )

        if self._looks_like_application_failure(finding, evidence, description, actual):
            return FailureClassification(
                failure_type=FailureType.APPLICATION_FAILURE,
                confidence=self._application_confidence(evidence, description, actual),
                evidence_summary=self._summarize(evidence or description),
            )

        if self._looks_like_test_failure(finding, evidence, description):
            return FailureClassification(
                failure_type=FailureType.TEST_FAILURE,
                confidence=self._test_confidence(evidence, description),
                evidence_summary=self._summarize(evidence or description),
            )

        return FailureClassification(
            failure_type=FailureType.UNKNOWN,
            confidence=0.2,
            evidence_summary=self._summarize(evidence or description),
            note="no matching failure pattern found",
        )

    def _summarize(self, text: str, max_len: int = 220) -> str:
        text = text.strip()
        if len(text) <= max_len:
            return text
        return text[: max_len - 3].rstrip() + "..."

    def _looks_like_timeout(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        combined = f"{evidence} {description} {actual} {finding.title.lower()}"
        return "timeout" in combined or "timed out" in combined or "deadline" in combined

    def _timeout_confidence(self, evidence: str, description: str) -> float:
        combined = f"{evidence} {description}"
        if "timeout" in combined:
            return 0.9
        return 0.6

    def _looks_like_network_failure(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        combined = f"{evidence} {description} {actual}"
        return any(token in combined for token in ("connection", "networkerror", "dns", "refused", "unreachable", "econnrefused", "enotfound", "503", "gateway"))

    def _network_confidence(self, evidence: str, description: str) -> float:
        combined = f"{evidence} {description}"
        if "connection refused" in combined or "econnrefused" in combined:
            return 0.9
        if "timeout" in combined:
            return 0.7
        return 0.5

    def _looks_like_environment_failure(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        combined = f"{evidence} {description} {actual}"
        return any(token in combined for token in ("environment", "browser", "driver", "playwright", "version", "not installed", "launch", "unsupported"))

    def _environment_confidence(self, evidence: str, description: str) -> float:
        combined = f"{evidence} {description}"
        if "not installed" in combined or "launch" in combined:
            return 0.8
        return 0.5

    def _looks_like_selector_failure(self, finding: Finding, evidence: str, description: str) -> bool:
        combined = f"{evidence} {description}".lower()
        return any(token in combined for token in ("selector", "queryselector", "not found", "no element", " detached", "stale"))

    def _selector_confidence(self, evidence: str, description: str) -> float:
        combined = f"{evidence} {description}".lower()
        if "no element" in combined or "not found" in combined:
            return 0.8
        return 0.5

    def _looks_like_application_failure(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        combined = f"{evidence} {description} {actual}"
        return any(token in combined for token in ("500", "502", "503", "exception", "error in", "failed to", "internal server", "application error"))

    def _application_confidence(self, evidence: str, description: str, actual: str) -> float:
        combined = f"{evidence} {description} {actual}"
        if "500" in combined or "internal server" in combined:
            return 0.8
        if "exception" in combined:
            return 0.7
        return 0.5

    def _looks_like_test_failure(self, finding: Finding, evidence: str, description: str) -> bool:
        combined = f"{evidence} {description}".lower()
        return any(token in combined for token in ("assertion", "assert", "expected", "actual", "test failed", "assertionerror"))

    def _test_confidence(self, evidence: str, description: str) -> float:
        combined = f"{evidence} {description}".lower()
        if "assertion" in combined:
            return 0.85
        return 0.5
