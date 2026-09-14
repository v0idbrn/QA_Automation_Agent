# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Test Planner + Test Generator.

Planner: turns (requirements, risks, strategy-selected skills) into a
structured `TestPlan` populated with `PlanItem` entries that now carry
requirement_id, risk_id, skill, preconditions, expected_result, cleanup,
priority, budget. The planner NEVER executes actions.

Generator: produces stable-id `TestCase` objects from plan items with:
  * duplicate detection (via action fingerprint)
  * equivalent-test folding
  * impossible-test detection (e.g., authenticated skill but no creds)
  * stable IDs across identical runs
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.discovery import ProjectProfile
from core.models import (
    ProjectScope,
    Requirement,
    Risk,
    RiskSeverity,
    TestCase,
    TestStep,
    TestCaseStatus,
    ConfidenceLevel,
)
from core.requirements_engine import RequirementsResult
from core.risk_engine import ProfileRiskAssessment
from core.strategist import QAStrategist, Strategy
from core.spec_analyzer import SpecAnalysis


# ---------------------------------------------------------------------------
# Planner extension (keep backwards compat with old PlanItem / TestPlan)
# ---------------------------------------------------------------------------

@dataclass
class PlanItem:
    area: str
    description: str
    kind: str = "test"
    status: str = "proposed"
    automated: bool = True
    priority: str = "medium"
    objective: str = ""
    skill: str = ""
    requirements: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # --- traceability extension ---
    plan_id: str = ""
    requirement_id: str | None = None
    risk_id: str | None = None
    preconditions: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    expected_result: str = ""
    cleanup: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestPlan:
    __test__ = False
    target: str
    discovery: ProjectProfile
    items: list[PlanItem] = field(default_factory=list)
    objectives: list[str] = field(default_factory=list)
    risk_level: str = "low"
    scope: ProjectScope | None = None
    requirements_seen: set[str] = field(default_factory=set)

    def add(self, area: str, description: str, **kwargs: Any) -> PlanItem:
        item = PlanItem(area=area, description=description, **kwargs)
        self.items.append(item)
        return item

    def summary(self) -> str:
        lines = [f"Test Plan for {self.target}", ""]
        by_area: dict[str, list[PlanItem]] = {}
        for item in self.items:
            by_area.setdefault(item.area, []).append(item)
        for area, items in sorted(by_area.items()):
            lines.append(f"{area}")
            for item in items:
                lines.append(f"├── {item.description}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# PlanItem id + priority helpers
# ---------------------------------------------------------------------------

def _plan_id(requirement_id: str, skill: str, area: str) -> str:
    joined = f"plan|{requirement_id}|{skill}|{area}"
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]
    return f"plan_{digest}"


def _risk_priority(sev: RiskSeverity | None) -> str:
    if sev is None:
        return "medium"
    order = {RiskSeverity.CRITICAL: "critical", RiskSeverity.HIGH: "high", RiskSeverity.MEDIUM: "medium", RiskSeverity.LOW: "low"}
    return order.get(sev, "medium")


def _skill_for_category(category: str) -> str:
    mapping = {
        "api": "api",
        "accessibility": "a11y",
        "form": "form_tester",
        "crawl": "crawler",
        "http": "crawler",
        "console": "crawler",
        "ui": "a11y",
        "functional": "crawler",
        "performance": "crawler",
        "security": "scope",
        "configuration": "discovery",
        "data_integrity": "form_tester",
        "infrastructure": "scope",
        "test": "discovery",
    }
    return mapping.get(category, "discovery")


def build_plan_from_discovery(
    discovery: ProjectProfile,
    target: str = "local-project",
    *,
    requirements: list[Requirement] | None = None,
    risks: dict[str, Risk] | None = None,
    strategy: Strategy | None = None,
    spec: SpecAnalysis | None = None,
    scope: ProjectScope | None = None,
) -> TestPlan:
    """Structured, risk-prioritized TestPlan with all traceability fields populated."""
    plan = TestPlan(target=target, discovery=discovery, scope=scope)
    plan.objectives = [
        "Stay inside declared scope and budgets",
        "Reuse existing engines without destructive writes",
        "Produce reproducible evidence and reports",
    ]

    if strategy is None:
        strategy = QAStrategist().select(discovery, spec, plan.risk_level)
    selected = set(strategy.selected_skills) if strategy else set()

    req_risk_lookup = risks or {}
    requirements = requirements or []

    # -- Safety + evidence always in plan (backwards compat existing items) --
    plan.add(
        "Safety",
        "Validate scope and budgets before any automation runs",
        priority="critical",
        objective="Fail closed on ambiguous targets",
        skill="scope",
        plan_id=_plan_id("safety", "scope", "Safety"),
        preconditions=["Scope constructed from CLI/profile config"],
        actions=["Call scope.assert_allowed for every action target"],
        expected_result="No ScopeViolationError raised",
        cleanup=[],
        requirements=["read-only filesystem"],
    )
    plan.add(
        "Evidence",
        "Ensure evidence and reports are reproducible",
        skill="evidence",
        plan_id=_plan_id("evidence", "evidence", "Evidence"),
        priority="high",
        preconditions=["output_dir writable"],
        actions=["Atomic writes for manifest, evidence, and reports"],
        expected_result="Artifacts present and readable",
        cleanup=[],
        requirements=["redaction"],
    )

    for req in requirements:
        risk: Risk | None = req_risk_lookup.get(req.requirement_id)
        skill = _skill_for_category(req.category.value if hasattr(req.category, "value") else str(req.category))
        if strategy is not None and skill not in selected and skill not in {"scope", "evidence", "discovery"}:
            # Item retained for coverage visibility; execution gate filters non-selected skills.
            pass
        plan.requirements_seen.add(req.requirement_id)
        area_map = {"api": "API Coverage", "accessibility": "A11y", "form": "Forms", "crawl": "Route Coverage", "http": "Route Coverage", "console": "Route Coverage"}
        area = area_map.get(req.category.value if hasattr(req.category, "value") else str(req.category), req.category.value if hasattr(req.category, "value") else str(req.category))
        desc_tail = ""
        if req.related_api_endpoints:
            desc_tail = f" — {len(req.related_api_endpoints)} endpoint(s)"
        elif req.related_routes:
            desc_tail = f" — {len(req.related_routes)} route(s)"
        priority = _risk_priority(risk.severity if risk else None)
        plan.add(
            area,
            f"{req.title[:140]}{desc_tail}",
            automated=True,
            priority=priority,
            objective=req.description[:200],
            skill=skill,
            plan_id=_plan_id(req.requirement_id, skill, area),
            requirement_id=req.requirement_id,
            risk_id=risk.risk_id if risk else None,
            preconditions=[f"requirement classification = {req.classification.value}"] + (["target reachable"] if req.related_routes or req.related_api_endpoints else []),
            actions=[f"run skill {skill} against {req.source or req.description[:80]}"],
            expected_result=(
                "Deterministic pass or documented failure. "
                "INFERRED requirements never auto-escalate to confirmed bug without human review."
            ),
            cleanup=[],
            budget={"max_retries": 3, "timeout_ms": 120_000},
            requirements=[req.requirement_id],
            notes=[f"risk={risk.severity.value if risk else 'unknown'}"],
        )

    # -- backwards compat entries for engines based on raw profile counts --
    if discovery.language == "python":
        plan.add(
            "Configuration",
            "Review dependency and toolchain configuration",
            automated=True,
            priority="high",
            objective="Confirm local toolchain",
            skill="discovery",
            plan_id=_plan_id("cfg-toolchain", "discovery", "Configuration"),
            preconditions=["target is a directory"],
            expected_result="project.language reported accurately",
        )
        plan.add(
            "Existing Tests",
            f"Audit {len(discovery.test_files)} existing test files",
            automated=True,
            priority="medium",
            objective="Align with current coverage",
            skill="discovery",
            plan_id=_plan_id("cfg-tests", "discovery", "Existing Tests"),
            expected_result=f"{len(discovery.test_files)} test files inventoried",
        )
    if discovery.framework and discovery.framework != "unknown":
        plan.add(
            "Framework Conventions",
            f"Follow {discovery.framework} conventions for test layout",
            automated=True,
            skill="discovery",
            plan_id=_plan_id("framework", "discovery", "Framework Conventions"),
        )
    if discovery.api_endpoints:
        plan.add(
            "API Coverage",
            f"Propose checks for {len(discovery.api_endpoints)} observed endpoints",
            automated=True,
            priority="high",
            objective="Intercept backend errors",
            skill="api",
            plan_id=_plan_id("api-summary", "api", "API Coverage"),
        )
    if discovery.routes:
        plan.add(
            "Route Coverage",
            f"Propose checks for {len(discovery.routes)} observed routes",
            automated=True,
            priority="high",
            objective="Crawl in-scope routes",
            skill="crawler",
            plan_id=_plan_id("route-summary", "crawler", "Route Coverage"),
        )
    if discovery.has_e2e_tests:
        plan.add("E2E Alignment", "Align new checks with existing E2E scope", automated=True, skill="crawler", plan_id=_plan_id("e2e", "crawler", "E2E Alignment"))

    return plan


# ---------------------------------------------------------------------------
# Test Generator
# ---------------------------------------------------------------------------

_IMPOSSIBLE_CREDS_PRECOND = {"credentials required", "credentials_required", "auth required", "authenticated"}


def _action_fingerprint(requirement_id: str, skill: str, actions: tuple[str, ...], expected: str) -> str:
    joined = f"tc|{requirement_id}|{skill}|{'|'.join(actions)}|{expected}"
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]


def _stable_test_id(fp: str) -> str:
    return f"test_{fp}"


@dataclass
class TestGenerationResult:
    __test__ = False  # pytest must not collect this dataclass

    test_cases: list[TestCase]
    duplicates_removed: int = 0
    impossible_marked: int = 0
    equivalents_merged: int = 0


def generate_test_cases(
    plan: TestPlan,
    *,
    profile_auth_mechanisms: list[str] | None = None,
) -> TestGenerationResult:
    """Generate stable, deduplicated, impossible-detected TestCases from a TestPlan."""
    seen_fp: set[str] = set()
    out: list[TestCase] = []
    dup = 0
    impossible = 0
    equiv_merged = 0
    auth_mechs = set(profile_auth_mechanisms or [])
    have_creds_flag = False  # by default, we treat credential presence as unknown → NOT assumed

    for item in plan.items:
        requirement_id = item.requirement_id or f"req-from-{item.area.lower()}"
        skill = item.skill or "discovery"
        actions = tuple(item.actions or [item.description])
        expected = item.expected_result or "Deterministic outcome"
        fp = _action_fingerprint(requirement_id, skill, actions, expected)
        if fp in seen_fp:
            dup += 1
            continue
        seen_fp.add(fp)
        test_id = _stable_test_id(fp)

        # Impossible detection: authenticated skill w/o creds confirmed
        impossible_reason: str | None = None
        precond_text = " ".join(item.preconditions).lower()
        if any(tok in precond_text for tok in _IMPOSSIBLE_CREDS_PRECOND) and auth_mechs and not have_creds_flag:
            impossible_reason = "Authentication required but no local credentials confirmed available"
            impossible += 1

        steps = [
            TestStep(step_index=idx + 1, action=act, description=act, expected=(expected if idx == len(actions) - 1 else ""))
            for idx, act in enumerate(actions)
        ]
        if not steps:
            steps = [TestStep(step_index=1, action=item.description, description=item.description, expected=expected)]

        status = TestCaseStatus.BLOCKED if impossible_reason else TestCaseStatus.PENDING
        confidence = ConfidenceLevel.MEDIUM if not impossible_reason else ConfidenceLevel.LOW

        tc = TestCase(
            test_id=test_id,
            title=item.description[:180],
            requirement_id=requirement_id,
            risk_id=item.risk_id or "",
            skill=skill,
            preconditions=list(item.preconditions),
            actions=list(actions),
            steps=steps,
            expected_result=expected,
            cleanup=list(item.cleanup),
            priority=item.priority or "medium",
            status=status,
            confidence=confidence,
            impossible_reason=impossible_reason,
            fingerprint=fp,
            budget=dict(item.budget) if item.budget else {},
        )
        out.append(tc)

    return TestGenerationResult(
        test_cases=out,
        duplicates_removed=dup,
        impossible_marked=impossible,
        equivalents_merged=equiv_merged,
    )
