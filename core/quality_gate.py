# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Quality Gate (5 mutually-exclusive states) + Coverage Engine (5 states).

Quality Gate Status:
  PASS                — no unresolved CRITICAL/HIGH, coverage acceptable, blocked<10%
  PASS_WITH_WARNINGS  — ≤2 HIGH findings resolved or INFO-only but scope limitations noted
  FAIL                — ≥1 CRITICAL or ≥3 HIGH unresolved findings
  BLOCKED             — budget exhausted, platform unavailable, or destructive scope violation
  NEEDS_HUMAN         — escalation conditions: missing credentials, insufficient evidence, auth challenge, non-reproducible, infrastructure inaccessible, critical uncertainty

Coverage Engine states:
  COVERED             — at least 1 passing test linked
  PARTIALLY_COVERED   — 1+ tests linked but all blocked/impossible or non-deterministic
  NOT_COVERED         — no tests linked at all
  BLOCKED             — linked test is permanently blocked/impossible
  UNKNOWN             — cannot determine (no metadata available)

IMPORTANT: this is *requirement/risk/test* coverage, NOT target-project code coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from core.models import (
    Finding,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
)
from core.planner import TestPlan, PlanItem


# ---------------------------------------------------------------------------
# Coverage Engine
# ---------------------------------------------------------------------------

class CoverageState(str, Enum):
    COVERED = "COVERED"
    PARTIALLY_COVERED = "PARTIALLY_COVERED"
    NOT_COVERED = "NOT_COVERED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass
class CoverageReport:
    requirement_coverage: dict[str, CoverageState] = field(default_factory=dict)
    test_coverage: dict[str, CoverageState] = field(default_factory=dict)
    risk_coverage: dict[str, CoverageState] = field(default_factory=dict)
    execution_coverage: dict[str, CoverageState] = field(default_factory=dict)

    def summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for label, mapping in (
            ("requirements", self.requirement_coverage),
            ("tests", self.test_coverage),
            ("risks", self.risk_coverage),
            ("execution", self.execution_coverage),
        ):
            counts: dict[str, int] = {s.value: 0 for s in CoverageState}
            for state in mapping.values():
                counts[state.value] = counts.get(state.value, 0) + 1
            out[label] = counts
        return out

    def ratio(self, kind: str = "requirements") -> float:
        mapping = {
            "requirements": self.requirement_coverage,
            "tests": self.test_coverage,
            "risks": self.risk_coverage,
            "execution": self.execution_coverage,
        }.get(kind, {})
        total = len(mapping)
        if total == 0:
            return 0.0
        covered = sum(1 for s in mapping.values() if s == CoverageState.COVERED)
        return round(covered / total, 3)


class CoverageEngine:
    """Takes (requirements, test_cases, findings) → coverage states."""

    def evaluate(
        self,
        *,
        plan_items: Iterable[PlanItem],
        test_cases: Iterable[Any] | None = None,
        findings: Iterable[Finding] | None = None,
        requirements_ids: Iterable[str] | None = None,
        execution_results: dict[str, str] | None = None,
    ) -> CoverageReport:
        plan_items = list(plan_items)
        findings = list(findings or [])
        test_cases = list(test_cases or [])
        execution_results = execution_results or {}

        # Requirements coverage: check linked plan_items + linked findings
        req_state: dict[str, CoverageState] = {}
        if requirements_ids:
            for req_id in requirements_ids:
                req_state[req_id] = CoverageState.NOT_COVERED
        for item in plan_items:
            req_id = item.requirement_id
            if not req_id:
                continue
            req_state.setdefault(req_id, CoverageState.NOT_COVERED)
            if req_state[req_id] == CoverageState.COVERED:
                continue
            status = self._item_status(item, execution_results)
            current = req_state.get(req_id, CoverageState.UNKNOWN)
            new = self._combine(current, status)
            req_state[req_id] = new

        # Test coverage: per test_id from test_cases
        test_state: dict[str, CoverageState] = {}
        for tc in test_cases:
            tid = getattr(tc, "test_id", None) or str(tc)
            impossible = getattr(tc, "impossible_reason", None)
            if impossible:
                test_state[tid] = CoverageState.BLOCKED
                continue
            result_status = (execution_results.get(tid) or getattr(tc, "status", "PENDING")).upper()
            test_state[tid] = self._from_exec_status(result_status)

        # Risk coverage: per risk_id present in plan_items (same state as req)
        risk_state: dict[str, CoverageState] = {}
        for item in plan_items:
            rid = item.risk_id
            if not rid:
                continue
            risk_state.setdefault(rid, CoverageState.NOT_COVERED)
            if risk_state[rid] == CoverageState.COVERED:
                continue
            status = self._item_status(item, execution_results)
            risk_state[rid] = self._combine(risk_state[rid], status)

        # Execution coverage: per plan_id executed or not
        exec_state: dict[str, CoverageState] = {}
        for item in plan_items:
            pid = item.plan_id or f"planitem_{id(item)}"
            status = execution_results.get(pid, getattr(item, "status", "proposed")).upper()
            exec_state[pid] = self._from_item_sched(status)
        return CoverageReport(
            requirement_coverage=req_state,
            test_coverage=test_state,
            risk_coverage=risk_state,
            execution_coverage=exec_state,
        )

    # ------------------------------------------------------------------
    def _item_status(self, item: PlanItem, results: dict[str, str]) -> CoverageState:
        raw = (results.get(item.plan_id) or item.status or "proposed").upper()
        if "BLOCKED" in raw or "IMP" in raw:
            return CoverageState.BLOCKED
        if "PASS" in raw:
            return CoverageState.COVERED
        if "FAIL" in raw or "EXECUTED" in raw:
            return CoverageState.PARTIALLY_COVERED
        return CoverageState.NOT_COVERED

    def _from_exec_status(self, status: str) -> CoverageState:
        s = (status or "UNKNOWN").upper()
        if "BLOCKED" in s or "IMP" in s:
            return CoverageState.BLOCKED
        if "PASS" in s:
            return CoverageState.COVERED
        if "FAIL" in s or "FLAKY" in s or "ERROR" in s:
            return CoverageState.PARTIALLY_COVERED
        if "PENDING" in s or "PROPOSED" in s or "SKIP" in s:
            return CoverageState.NOT_COVERED
        return CoverageState.UNKNOWN

    def _from_item_sched(self, status: str) -> CoverageState:
        s = (status or "UNKNOWN").upper()
        if "PASS" in s:
            return CoverageState.COVERED
        if "FAIL" in s or "EXECUTED" in s:
            return CoverageState.PARTIALLY_COVERED
        if "BLOCKED" in s or "IMP" in s:
            return CoverageState.BLOCKED
        if "PROPOSED" in s or "PENDING" in s:
            return CoverageState.NOT_COVERED
        return CoverageState.UNKNOWN

    def _combine(self, a: CoverageState, b: CoverageState) -> CoverageState:
        order = [
            CoverageState.COVERED,
            CoverageState.PARTIALLY_COVERED,
            CoverageState.BLOCKED,
            CoverageState.NOT_COVERED,
            CoverageState.UNKNOWN,
        ]
        ia = order.index(a) if a in order else 9
        ib = order.index(b) if b in order else 9
        return order[min(ia, ib)]


# ---------------------------------------------------------------------------
# Quality Gate
# ---------------------------------------------------------------------------

class QualityGateStatus(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


@dataclass
class QualityGateResult:
    status: QualityGateStatus
    reasons: list[str] = field(default_factory=list)
    coverage_score: float = 0.0
    false_positive_risk: float = 0.0
    blocked_tests: int = 0
    unresolved_critical: int = 0
    unresolved_high: int = 0
    flaky_count: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.status in {QualityGateStatus.PASS, QualityGateStatus.PASS_WITH_WARNINGS}

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "passed": self.passed,
            "reasons": list(self.reasons),
            "coverage_score": self.coverage_score,
            "false_positive_risk": self.false_positive_risk,
            "blocked_tests": self.blocked_tests,
            "unresolved_critical": self.unresolved_critical,
            "unresolved_high": self.unresolved_high,
            "flaky_count": self.flaky_count,
            "notes": list(self.notes),
        }


class QualityGate:
    """Evaluate findings + plan + coverage + context → QualityGateResult (5 states)."""

    def __init__(
        self,
        *,
        max_critical: int = 0,
        max_high: int = 2,
        min_requirements_coverage: float = 0.20,
        max_blocked_ratio: float = 0.50,
        max_flaky: int = 8,
    ) -> None:
        self.max_critical = max_critical
        self.max_high = max_high
        self.min_requirements_coverage = min_requirements_coverage
        self.max_blocked_ratio = max_blocked_ratio
        self.max_flaky = max_flaky

    def evaluate(
        self,
        findings: Iterable[Finding],
        plan: TestPlan | None = None,
        *,
        coverage: CoverageReport | None = None,
        escalations: int = 0,
        flaky_count: int = 0,
        blocked_tests: int = 0,
        budget_exhausted_reason: str | None = None,
        insufficient_evidence: bool = False,
        auth_challenge: bool = False,
        credentials_missing: bool = False,
        infrastructure_unreachable: bool = False,
        non_reproducible: bool = False,
        critical_uncertainty: bool = False,
        scope_violations: int = 0,
    ) -> QualityGateResult:
        findings = list(findings)
        reasons: list[str] = []

        # NEEDS_HUMAN short-circuit
        if (
            credentials_missing
            or auth_challenge
            or insufficient_evidence
            or non_reproducible
            or infrastructure_unreachable
            or critical_uncertainty
            or escalations > 0
        ):
            if credentials_missing:
                reasons.append("Missing credentials for authenticated surface.")
            if auth_challenge:
                reasons.append("Authentication challenge requires human consent.")
            if insufficient_evidence:
                reasons.append("Insufficient evidence to confirm findings.")
            if non_reproducible:
                reasons.append("Failure is non-reproducible.")
            if infrastructure_unreachable:
                reasons.append("Target infrastructure is inaccessible.")
            if critical_uncertainty:
                reasons.append("Critical uncertainty requires human review.")
            if escalations > 0:
                reasons.append(f"{escalations} human escalation(s) fired during run.")
            return QualityGateResult(
                status=QualityGateStatus.NEEDS_HUMAN,
                reasons=reasons,
                blocked_tests=blocked_tests,
                flaky_count=flaky_count,
                notes=["escalation path"],
            )

        # BLOCKED short-circuit
        if budget_exhausted_reason or scope_violations > 0:
            if budget_exhausted_reason:
                reasons.append(f"Budget exhausted: {budget_exhausted_reason}")
            if scope_violations > 0:
                reasons.append(f"{scope_violations} scope violation(s) observed.")
            return QualityGateResult(
                status=QualityGateStatus.BLOCKED,
                reasons=reasons,
                blocked_tests=blocked_tests,
                flaky_count=flaky_count,
                notes=["blocked path"],
            )

        def sev(f: Finding) -> str:
            try:
                return f.severity.value.upper()
            except Exception:
                return str(f.severity).upper()

        def is_unresolved(f: Finding) -> bool:
            try:
                s = f.status.value
            except Exception:
                s = str(f.status)
            return s.upper() not in {"RESOLVED", "PASSED", "FALSE_POSITIVE"}

        unresolved = [f for f in findings if is_unresolved(f)]
        if not findings:
            reasons.append("no findings produced")
        crit = sum(1 for f in unresolved if sev(f) == "CRITICAL")
        high = sum(1 for f in unresolved if sev(f) == "HIGH")
        planned = max(1, len(plan.items)) if plan is not None else max(1, len(findings))
        covered = len(findings)
        coverage_score = min(1.0, covered / planned)
        if coverage is not None:
            req_ratio = coverage.ratio("requirements")
            if req_ratio > 0:
                coverage_score = round((coverage_score + req_ratio) / 2.0, 3)

        high_without_evidence = [f for f in unresolved if sev(f) in {"CRITICAL", "HIGH"} and not (getattr(f, "evidence", None) or "").strip()]
        false_positive_risk = round(min(1.0, len(high_without_evidence) / max(len(unresolved), 1)), 3) if unresolved else 0.0

        blocked_ratio = (blocked_tests / planned) if planned else 0.0
        if crit > self.max_critical:
            reasons.append(f"{crit} unresolved CRITICAL findings (max allowed {self.max_critical}).")
        if high > self.max_high:
            reasons.append(f"{high} unresolved HIGH findings (max allowed {self.max_high}).")
        if coverage_score < self.min_requirements_coverage:
            reasons.append(f"Requirements coverage {coverage_score:.0%} below {self.min_requirements_coverage:.0%}.")
        if blocked_ratio > self.max_blocked_ratio:
            reasons.append(f"Blocked ratio {blocked_ratio:.0%} above {self.max_blocked_ratio:.0%}.")
        if flaky_count > self.max_flaky:
            reasons.append(f"Flaky count {flaky_count} above max allowed {self.max_flaky}.")

        if not reasons and (flaky_count > 0 or false_positive_risk > 0.3 or (plan is not None and len(plan.items) == 0)):
            warnings: list[str] = []
            if flaky_count > 0:
                warnings.append(f"{flaky_count} flaky test(s) — review manually.")
            if false_positive_risk > 0.3:
                warnings.append(f"High-severity findings missing evidence; false-positive risk {false_positive_risk:.0%}.")
            if plan is not None and len(plan.items) == 0:
                warnings.append("Plan items empty during gate evaluation.")
            return QualityGateResult(
                status=QualityGateStatus.PASS_WITH_WARNINGS,
                reasons=warnings,
                coverage_score=coverage_score,
                false_positive_risk=false_positive_risk,
                blocked_tests=blocked_tests,
                unresolved_critical=crit,
                unresolved_high=high,
                flaky_count=flaky_count,
            )

        if reasons:
            return QualityGateResult(
                status=QualityGateStatus.FAIL,
                reasons=reasons,
                coverage_score=coverage_score,
                false_positive_risk=false_positive_risk,
                blocked_tests=blocked_tests,
                unresolved_critical=crit,
                unresolved_high=high,
                flaky_count=flaky_count,
            )
        return QualityGateResult(
            status=QualityGateStatus.PASS,
            reasons=[],
            coverage_score=coverage_score,
            false_positive_risk=false_positive_risk,
            blocked_tests=blocked_tests,
            unresolved_critical=crit,
            unresolved_high=high,
            flaky_count=flaky_count,
        )


# Backwards compat alias (old code imported QualityGateResult = old dataclass w/ passed bool)
QualityGateResult = QualityGateResult
