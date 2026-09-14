# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Observability helpers.

The QA agent must be able to explain:
  * what it is doing
  * why it is doing it
  * how much budget remains
  * which test ran and what happened
  * why a retry happened
  * why something was omitted
  * why a human escalation was triggered

Each function returns structured data (dict/str) that callers can
directly pass to the structured logger or attach to evidence metadata.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from core.scope import Budget, OmitRecord, Scope
from core.failure_analyzer import FailureClassification, RetryDecision
from core.models import Escalation
from core.quality_gate import QualityGateResult


@dataclass
class WhyOmit:
    url: str
    reason: str
    category: str = "scope"

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "reason": self.reason, "category": self.category}


@dataclass
class BudgetRemaining:
    pages: int | None = None
    requests: int | None = None
    tests: int | None = None
    retries: int | None = None
    artifacts: int | None = None
    runtime_seconds: float | None = None
    exhausted: bool = False
    exhausted_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WhyRetry:
    failure_type: str
    reason: str
    signature: str | None
    global_retries_used: int
    signature_retries_used: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WhyEscalate:
    why: str
    what_was_attempted: str
    what_evidence_exists: str
    what_human_input_is_required: str
    halt: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def why_omit_list(scope: Scope) -> list[dict[str, str]]:
    """Return latest URL-omission reasons from Scope. Call after a crawl."""
    out: list[dict[str, str]] = []
    for rec in scope.omits()[-256:]:
        out.append(WhyOmit(url=rec.url, reason=rec.reason, category=rec.category).as_dict())
    return out


def budget_remaining(budget: Budget) -> BudgetRemaining:
    rem = budget.remaining()
    exhausted = budget.is_exhausted()
    return BudgetRemaining(
        pages=rem.get("pages"),
        requests=rem.get("requests"),
        tests=rem.get("tests"),
        retries=rem.get("retries"),
        artifacts=rem.get("artifacts"),
        runtime_seconds=rem.get("runtime_seconds"),
        exhausted=exhausted,
        exhausted_reason=budget.exhausted_reason,
    )


def why_retry(
    classification: FailureClassification,
    decision: RetryDecision,
    *,
    signature: str | None = None,
) -> WhyRetry:
    return WhyRetry(
        failure_type=str(classification.failure_type.value if hasattr(classification.failure_type, "value") else classification.failure_type),
        reason=decision.reason,
        signature=signature,
        global_retries_used=decision.global_count_so_far,
        signature_retries_used=decision.retry_count_so_far,
    )


def why_escalate_from_escalation(e: Escalation, *, what_was_attempted: str = "", what_evidence_exists: str = "", what_human_input_is_required: str = "") -> WhyEscalate:
    return WhyEscalate(
        why=e.reason or "Escalation fired.",
        what_was_attempted=what_was_attempted or "Agent completed DISCOVER→PLAN→EXECUTE→ANALYZE path.",
        what_evidence_exists=what_evidence_exists or "Evidence folder structure initialized; see run_evidence.json.",
        what_human_input_is_required=what_human_input_is_required or "Human must confirm scope, credentials, or destructive-action permission.",
        halt=bool(e.halt),
    )


def test_execution_summary(
    *,
    tests_planned: int = 0,
    tests_executed: int = 0,
    passed: int = 0,
    failed: int = 0,
    blocked: int = 0,
    flaky: int = 0,
    skipped: int = 0,
    errored: int = 0,
) -> dict[str, int]:
    return {
        "tests_planned": tests_planned,
        "tests_executed": tests_executed,
        "passed": passed,
        "failed": failed,
        "blocked": blocked,
        "flaky": flaky,
        "skipped": skipped,
        "errored": errored,
    }


def gate_summary_text(gate: QualityGateResult) -> str:
    status = gate.status.value if hasattr(gate.status, "value") else str(gate.status)
    if gate.reasons:
        return f"QualityGate {status}. Reasons: {' | '.join(gate.reasons)}"
    return f"QualityGate {status}."
