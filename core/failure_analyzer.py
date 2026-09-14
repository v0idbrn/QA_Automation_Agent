# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Failure Analyzer — 12-type taxonomy + RetryController + FlakyDetector.

Taxonomy (FailureType):
  PRODUCT_BUG
  TEST_BUG
  ENVIRONMENT_FAILURE
  NETWORK_FAILURE
  TIMEOUT
  DEPENDENCY_FAILURE
  AUTH_FAILURE
  CONFIGURATION_FAILURE
  DATA_PROBLEM
  BROWSER_FAILURE
  INFRASTRUCTURE_FAILURE
  UNKNOWN

Classification considers:
  * expected vs actual
  * stack trace
  * console errors
  * network metadata
  * timing
  * environment signals

Retry rules:
  * Only TRANSIENT failures allowed: TIMEOUT, NETWORK_FAILURE, BROWSER_FAILURE,
    INFRASTRUCTURE_FAILURE, probable flaky behavior.
  * NEVER auto-retry: PRODUCT_BUG, AUTH_FAILURE, CONFIGURATION_FAILURE,
    scope violations, destructive situations.
  * Max 3 retries globally per failure signature.

Flaky detection: register N runs per test_id; any [PASS, FAIL] pair → FLAKY,
never auto-promote to confirmed bug.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.actions import Action
from core.models import Finding, FindingCategory, Confidence

ConfidenceLevel = Confidence  # backward-compat alias for downstream imports


class FailureType(str, Enum):
    PRODUCT_BUG = "PRODUCT_BUG"
    TEST_BUG = "TEST_BUG"
    ENVIRONMENT_FAILURE = "ENVIRONMENT_FAILURE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    TIMEOUT = "TIMEOUT"
    DEPENDENCY_FAILURE = "DEPENDENCY_FAILURE"
    AUTH_FAILURE = "AUTH_FAILURE"
    CONFIGURATION_FAILURE = "CONFIGURATION_FAILURE"
    DATA_PROBLEM = "DATA_PROBLEM"
    BROWSER_FAILURE = "BROWSER_FAILURE"
    INFRASTRUCTURE_FAILURE = "INFRASTRUCTURE_FAILURE"
    UNKNOWN = "UNKNOWN"


TRANSIENT_FAILURES = {
    FailureType.TIMEOUT,
    FailureType.NETWORK_FAILURE,
    FailureType.BROWSER_FAILURE,
    FailureType.INFRASTRUCTURE_FAILURE,
}

NON_RETRYABLE = {
    FailureType.PRODUCT_BUG,
    FailureType.AUTH_FAILURE,
    FailureType.CONFIGURATION_FAILURE,
    FailureType.TEST_BUG,
    FailureType.DATA_PROBLEM,
}

MAX_GLOBAL_RETRIES = 3
MAX_SIGNATURE_RETRIES = 3


@dataclass
class FailureClassification:
    failure_type: FailureType
    confidence: float
    evidence_summary: str
    note: str = ""
    retryable: bool = False


@dataclass
class RetryDecision:
    should_retry: bool
    reason: str
    retry_count_so_far: int = 0
    global_count_so_far: int = 0


class RetryController:
    """Decide whether a classified failure merits a retry.

    Idempotent and signature-bounded. Uses MAX_GLOBAL_RETRIES total and
    MAX_SIGNATURE_RETRIES per failure_signature (normalized error text).
    """

    def __init__(self, *, max_global: int = MAX_GLOBAL_RETRIES, max_per_signature: int = MAX_SIGNATURE_RETRIES) -> None:
        self.max_global = max_global
        self.max_per_signature = max_per_signature
        self.global_retries = 0
        self._signature_retries: dict[str, int] = {}

    def evaluate(self, classification: FailureClassification, action: Action, signature: str | None) -> RetryDecision:
        sig = signature or _signature_from(action, classification)
        sig_count = self._signature_retries.get(sig, 0)
        if self.global_retries >= self.max_global:
            return RetryDecision(False, "max global retries exhausted", sig_count, self.global_retries)
        if sig_count >= self.max_per_signature:
            return RetryDecision(False, f"max retries exhausted for signature {sig[:12]}", sig_count, self.global_retries)
        if not action.idempotent or action.destructive:
            return RetryDecision(False, f"action not idempotent={not action.idempotent} or destructive={action.destructive}", sig_count, self.global_retries)
        if classification.failure_type in NON_RETRYABLE:
            return RetryDecision(False, f"{classification.failure_type.value} is never auto-retryable", sig_count, self.global_retries)
        if classification.failure_type not in TRANSIENT_FAILURES and not classification.retryable:
            return RetryDecision(False, "failure not classified transient", sig_count, self.global_retries)
        return RetryDecision(True, f"transient {classification.failure_type.value}", sig_count, self.global_retries)

    def consume(self, sig: str) -> None:
        self.global_retries += 1
        self._signature_retries[sig] = self._signature_retries.get(sig, 0) + 1


@dataclass
class FlakyDetector:
    """Distinguish PASS/FAIL/FLAKY/BLOCKED/ERROR per test_id.

    A [PASS, FAIL] or [FAIL, PASS] pair for the same test_id → status FLAKY.
    FLAKY findings are NEVER automatically promoted to confirmed bug status.
    They should flow into Quality Gate as WARNING, not FAIL — unless confirmed
    via human review or 3+ consistent failures.
    """

    _runs: dict[str, list[str]] = field(default_factory=dict)

    def register_run(self, test_id: str, status: str) -> None:
        status_norm = (status or "UNKNOWN").upper()
        self._runs.setdefault(test_id, []).append(status_norm)

    def status_for(self, test_id: str) -> str:
        runs = self._runs.get(test_id, [])
        if not runs:
            return "UNKNOWN"
        distinct = set(runs)
        if "BLOCKED" in distinct:
            return "BLOCKED"
        if "ERROR" in distinct and {"PASS", "FAIL"}.isdisjoint(distinct):
            return "ERROR"
        if "PASS" in distinct and "FAIL" in distinct:
            return "FLAKY"
        if len(distinct) == 1:
            return next(iter(distinct))
        if "FAIL" in distinct:
            return "FAIL"
        if "PASS" in distinct:
            return "PASS"
        return "UNKNOWN"

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {"PASS": 0, "FAIL": 0, "FLAKY": 0, "BLOCKED": 0, "ERROR": 0, "UNKNOWN": 0}
        for test_id in self._runs:
            out[self.status_for(test_id)] = out.get(self.status_for(test_id), 0) + 1
        return out


def _signature_from(action: Action, cls: FailureClassification) -> str:
    raw = f"{action.test_id or action.name}|{cls.failure_type.value}|{cls.evidence_summary[:240]}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class FailureAnalyzer:
    def __init__(self) -> None:
        self.global_retries = 0
        self.retry_controller = RetryController()
        self.flaky = FlakyDetector()

    # ------------------------------------------------------------------
    def classify(self, finding: Finding) -> FailureClassification:
        evidence = (finding.evidence or "").lower()
        try:
            category = finding.category.value
        except Exception:
            category = str(finding.category)
        description = (finding.description or "").lower()
        actual = (finding.actual or "").lower()
        try:
            sev_val = finding.severity.value
        except Exception:
            sev_val = str(finding.severity)

        conf = finding.confidence if hasattr(finding, "confidence") else Confidence.MEDIUM
        if isinstance(conf, Confidence):
            conf_val = {"low": 0.3, "medium": 0.6, "high": 0.9}.get(conf.value.lower(), 0.6)
        else:
            conf_val = float(conf) if isinstance(conf, (int, float)) else 0.6

        if conf_val < 0.4:
            return FailureClassification(FailureType.UNKNOWN, conf_val, _summarize(evidence or description), "insufficient evidence to classify")

        # TIMEOUT
        if self._looks_like_timeout(finding, evidence, description, actual):
            score = self._timeout_confidence(evidence, description)
            return FailureClassification(FailureType.TIMEOUT, score, _summarize(evidence or description), "", True)
        # NETWORK
        if self._looks_like_network(finding, evidence, description, actual):
            score = self._network_confidence(evidence, description)
            return FailureClassification(FailureType.NETWORK_FAILURE, score, _summarize(evidence or description), "", True)
        # AUTH
        if self._looks_like_auth(finding, evidence, description, actual):
            return FailureClassification(FailureType.AUTH_FAILURE, self._auth_confidence(evidence, description), _summarize(evidence or description), "not retryable")
        # CONFIGURATION
        if self._looks_like_config(finding, evidence, description):
            return FailureClassification(FailureType.CONFIGURATION_FAILURE, 0.85, _summarize(evidence or description), "not retryable")
        # BROWSER
        if self._looks_like_browser(finding, evidence, description):
            return FailureClassification(FailureType.BROWSER_FAILURE, 0.8, _summarize(evidence or description), "", True)
        # INFRASTRUCTURE (502/503/504, connection reset)
        if self._looks_like_infra(finding, evidence, description):
            return FailureClassification(FailureType.INFRASTRUCTURE_FAILURE, 0.75, _summarize(evidence or description), "", True)
        # ENVIRONMENT (missing binary, playwright not installed)
        if self._looks_like_env(finding, evidence, description):
            return FailureClassification(FailureType.ENVIRONMENT_FAILURE, 0.8, _summarize(evidence or description), "", True)
        # TEST_BUG (selector/attribute error, playwright TestExpect)
        if self._looks_like_test_bug(finding, evidence, description):
            return FailureClassification(FailureType.TEST_BUG, 0.75, _summarize(evidence or description), "not retryable")
        # DEPENDENCY
        if self._looks_like_dep(finding, evidence, description):
            return FailureClassification(FailureType.DEPENDENCY_FAILURE, 0.7, _summarize(evidence or description), "", True)
        # DATA
        if self._looks_like_data(finding, evidence, description):
            return FailureClassification(FailureType.DATA_PROBLEM, 0.7, _summarize(evidence or description), "not retryable")

        # Product bug heuristic: high/medium functional finding with solid evidence
        if category in {"functional", "ui", "api", "accessibility", "performance", "form"} or sev_val in {"critical", "high", "medium"}:
            return FailureClassification(FailureType.PRODUCT_BUG, max(conf_val, 0.5), _summarize(evidence or description))
        return FailureClassification(FailureType.UNKNOWN, conf_val, _summarize(evidence or description), "unclassified")

    # ------------------------------------------------------------------
    # Token-based heuristics
    # ------------------------------------------------------------------

    def _looks_like_timeout(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        joined = f"{evidence} {description} {actual}"
        category = str(getattr(finding.category, "value", finding.category))
        return any(tok in joined for tok in ("timeout", "timed out", "exceeded", "deadline exceeded", "ETIMEDOUT")) or category == "timeout"

    def _timeout_confidence(self, evidence: str, description: str) -> float:
        if "timeout" in evidence or "timeout" in description:
            return 0.92
        return 0.65

    def _looks_like_network(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        joined = f"{evidence} {description} {actual}"
        return any(tok in joined for tok in ("econnrefused", "enotfound", "econnreset", "dns", "network error", "connection refused", "connection reset", "getaddrinfo")) or "http" in joined and any(str(c) in joined for c in ("502", "503", "504"))

    def _network_confidence(self, evidence: str, description: str) -> float:
        joined = f"{evidence} {description}"
        if any(tok in joined for tok in ("econnrefused", "econnreset", "enotfound")):
            return 0.95
        return 0.7

    def _looks_like_auth(self, finding: Finding, evidence: str, description: str, actual: str) -> bool:
        joined = f"{evidence} {description} {actual}"
        return any(tok in joined for tok in ("401", "403", "unauthorized", "forbidden", "invalid credentials", "expired session", "bad credentials", "login failed", "auth failed"))

    def _auth_confidence(self, evidence: str, description: str) -> float:
        joined = f"{evidence} {description}"
        if "401" in joined or "403" in joined:
            return 0.9
        return 0.75

    def _looks_like_config(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        config_tokens = ("invalid config", "missing config", "misconfigur", "env var missing", "no such file or directory", "validationerror", "valueerror")
        context_tokens = ("config", "env", ".env", "setting")
        return any(tok in joined for tok in config_tokens) and any(s in joined for s in context_tokens)

    def _looks_like_browser(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("page crashed", "target closed", "browser closed", "playwright error", "context was destroyed", "page.goto", "browser_context", "chromium", "firefox", "webkit"))

    def _looks_like_infra(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("502 bad gateway", "503 service unavailable", "504 gateway timeout", "service unavailable", "bad gateway", "gateway timeout", "server overloaded"))

    def _looks_like_env(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("playwright install", "executable not found", "no such file or directory: 'chromium'", "missing playwright browser", "command not found"))

    def _looks_like_test_bug(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("locator resolved to 0 elements", "element not visible", "selector error", "no node found for selector", "assertionerror", "assertion error", "locator.click", "attributeerror"))

    def _looks_like_dep(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("importerror", "modulenotfound", "cannot import", "dependency missing", "version conflict"))

    def _looks_like_data(self, finding: Finding, evidence: str, description: str) -> bool:
        joined = f"{evidence} {description}"
        return any(tok in joined for tok in ("jsondecodeerror", "malformed json", "invalid content type", "schema validation", "integrity error", "unexpected null"))

    # ------------------------------------------------------------------
    def should_retry(self, classification: FailureClassification, action: Action, signature: str | None = None) -> bool:
        """Backwards-compat wrapper: uses RetryController under the hood."""
        decision = self.retry_controller.evaluate(classification, action, signature)
        if decision.should_retry:
            sig = signature or _signature_from(action, classification)
            self.retry_controller.consume(sig)
            self.global_retries = self.retry_controller.global_retries
            return True
        return False


def _summarize(text: str, *, limit: int = 240) -> str:
    clean = " ".join(text.split())
    return clean if len(clean) <= limit else clean[:limit] + "…"
