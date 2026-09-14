# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Risk Engine — 7-axis weighted scoring.

Evaluates each requirement (or profile-wide) against:
  impact × 0.25
  likelihood × 0.20
  complexity × 0.10
  exposure × 0.10
  (+1 if auth_required) × 0.10
  data_sensitivity × 0.10
  business_criticality × 0.15

Axes range 1..5 inclusive. The weighted score S ∈ [0.0, 5.0] maps to:
  S ≥ 4.20 → CRITICAL
  S ≥ 3.00 → HIGH
  S ≥ 1.80 → MEDIUM
  else     → LOW

Auto-escalation rules:
  - If auth_required AND business_criticality ≥ 4 → severity bumped +1 level (if not already CRITICAL)
  - If impact ≥ 5 AND exposure ≥ 4 → severity bumped +1 level (if not already CRITICAL)
  - Classification UNKNOWN requirements: severity never exceeds MEDIUM, confidence capped LOW
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from core.models import (
    ProjectProfile,
    Requirement,
    RequirementClassification,
    Risk,
    RiskSeverity,
)


@dataclass
class ProfileRiskAssessment:
    """Summary profile-wide risk + per-requirement Risks."""

    profile_risk: RiskSeverity
    overall_score: float
    per_requirement: dict[str, Risk]  # requirement_id → Risk
    rules_applied: list[str]

    def critical_count(self) -> int:
        return sum(1 for r in self.per_requirement.values() if r.severity == RiskSeverity.CRITICAL)

    def high_count(self) -> int:
        return sum(1 for r in self.per_requirement.values() if r.severity == RiskSeverity.HIGH)


def _stable_risk_id(requirement_id: str) -> str:
    digest = hashlib.sha1(f"risk|{requirement_id}".encode("utf-8")).hexdigest()[:12]
    return f"risk_{digest}"


def _weighted_score(
    impact: int,
    likelihood: int,
    complexity: int,
    exposure: int,
    auth_required: bool,
    data_sensitivity: int,
    business_criticality: int,
) -> float:
    s = (
        impact * 0.25
        + likelihood * 0.20
        + complexity * 0.10
        + exposure * 0.10
        + (1.0 if auth_required else 0.0) * 5.0 * 0.10
        + data_sensitivity * 0.10
        + business_criticality * 0.15
    )
    return max(0.0, min(5.0, s))


def _severity_from_score(score: float) -> RiskSeverity:
    if score >= 4.20:
        return RiskSeverity.CRITICAL
    if score >= 3.00:
        return RiskSeverity.HIGH
    if score >= 1.80:
        return RiskSeverity.MEDIUM
    return RiskSeverity.LOW


def _bump(sev: RiskSeverity) -> RiskSeverity:
    order = [RiskSeverity.LOW, RiskSeverity.MEDIUM, RiskSeverity.HIGH, RiskSeverity.CRITICAL]
    idx = order.index(sev)
    return order[min(idx + 1, len(order) - 1)]


def _axis_for_requirement(
    req: Requirement,
    profile: ProjectProfile,
) -> dict[str, Any]:
    """Assign 1..5 axis values from requirement metadata + profile signals."""
    category_weight: dict[str, int] = {
        "security": 5,
        "api": 4,
        "functional": 3,
        "accessibility": 3,
        "performance": 3,
        "configuration": 2,
        "data_integrity": 4,
        "test": 2,
        "infrastructure": 3,
        "ui": 2,
        "crawl": 2,
        "form": 3,
        "http": 3,
        "console": 2,
        "environment": 3,
    }
    cat = req.category.value if hasattr(req.category, "value") else str(req.category)
    impact = category_weight.get(cat, 3)
    if "admin" in (req.title + " " + (req.description or "")).lower() or "/admin" in (req.description or "").lower():
        impact = max(impact, 5)

    # Likelihood: explicit requirements more likely to actually be exercised
    if req.classification == RequirementClassification.EXPLICIT:
        likelihood = 4
    elif req.classification == RequirementClassification.INFERRED:
        likelihood = 3
    else:
        likelihood = 2

    # Complexity: APIs/auth/routes more complex
    if req.related_api_endpoints:
        complexity = 4
    elif req.related_routes:
        complexity = 3
    else:
        complexity = 2

    # Exposure: inferred routes+forms → public surface
    if req.related_api_endpoints or req.related_routes:
        exposure = 4
    elif cat == "security":
        exposure = 5
    else:
        exposure = 2

    auth_required = any(
        a in ("oauth", "jwt", "basic", "session", "api_key") for a in (profile.auth_mechanisms or [])
    ) or cat == "security"

    # Data sensitivity: security + api high
    if cat == "security" or "/api/" in (req.description or ""):
        data_sensitivity = 5
    elif req.related_api_endpoints:
        data_sensitivity = 4
    else:
        data_sensitivity = 2

    # Business criticality: top 20% longest requirements (heuristic) or admin surface
    if impact >= 5 and exposure >= 4:
        business_criticality = 5
    elif cat in ("security", "api", "data_integrity"):
        business_criticality = 4
    else:
        business_criticality = 2

    return {
        "impact": impact,
        "likelihood": likelihood,
        "complexity": complexity,
        "exposure": exposure,
        "auth_required": auth_required,
        "data_sensitivity": data_sensitivity,
        "business_criticality": business_criticality,
    }


def _evaluate_requirement(
    req: Requirement,
    profile: ProjectProfile,
    rules: list[str],
) -> Risk:
    axes = _axis_for_requirement(req, profile)
    score = _weighted_score(**axes)
    severity = _severity_from_score(score)

    # UNKNOWN classification: cap severity MEDIUM
    if req.classification == RequirementClassification.UNKNOWN and severity > RiskSeverity.MEDIUM:
        severity = RiskSeverity.MEDIUM
        rules.append(f"risk/cap-unknown:{req.requirement_id}")

    # Auto-escalation: auth_required + business_criticality >= 4
    if axes["auth_required"] and axes["business_criticality"] >= 4 and severity != RiskSeverity.CRITICAL:
        severity = _bump(severity)
        rules.append(f"risk/escalate-auth-critical:{req.requirement_id}")

    # Auto-escalation: impact 5 + exposure 4+
    if axes["impact"] >= 5 and axes["exposure"] >= 4 and severity != RiskSeverity.CRITICAL:
        severity = _bump(severity)
        rules.append(f"risk/escalate-impact-exposure:{req.requirement_id}")

    return Risk(
        risk_id=_stable_risk_id(req.requirement_id),
        requirement_id=req.requirement_id,
        severity=severity,
        score=round(score, 3),
        impact=axes["impact"],
        likelihood=axes["likelihood"],
        complexity=axes["complexity"],
        exposure=axes["exposure"],
        auth_required=bool(axes["auth_required"]),
        data_sensitivity=axes["data_sensitivity"],
        business_criticality=axes["business_criticality"],
        description=(
            f"Risk derived from {req.classification.value!r} requirement "
            f"{req.category.value!r} titled {req.title[:80]!r}."
        ),
        related_routes=req.related_routes,
        related_api_endpoints=req.related_api_endpoints,
        auto_escalation_applied="escalate" in " ".join(rules[-2:]),
        notes=[],
    )


def evaluate_profile(profile: ProjectProfile) -> dict[str, Any]:
    """Top-down profile-wide risk axes (not per-requirement)."""
    high_risk_flags = 0
    total_flags = 0
    for token in profile.potential_risks or []:
        total_flags += 1
        if "secret" in token.lower() or "upload" in token.lower() or "admin" in token.lower():
            high_risk_flags += 1
    deps = len(profile.dependencies or [])
    endpoints = len(profile.api_endpoints or [])
    routes = len(profile.routes or [])
    forms = len(profile.forms_detected or [])
    auth_count = len(profile.auth_mechanisms or [])
    return {
        "complexity": min(5, 1 + (deps // 15) + forms // 3 + endpoints // 5),
        "exposure": min(5, 1 + (routes // 3) + endpoints // 5),
        "data_sensitivity": min(5, 1 + auth_count * 2),
        "business_criticality": min(5, 1 + high_risk_flags + (auth_count >= 1) + (endpoints > 0)),
        "high_risk_flags": high_risk_flags,
        "total_flags": total_flags,
    }


def assess_risks(requirements: Iterable[Requirement], profile: ProjectProfile) -> ProfileRiskAssessment:
    rules: list[str] = []
    per_req: dict[str, Risk] = {}
    total_score = 0.0
    count = 0
    for req in requirements:
        risk = _evaluate_requirement(req, profile, rules)
        per_req[req.requirement_id] = risk
        total_score += risk.score
        count += 1

    profile_signals = evaluate_profile(profile)
    profile_base_score = _weighted_score(
        impact=min(5, 2 + profile_signals["high_risk_flags"]),
        likelihood=3,
        complexity=profile_signals["complexity"],
        exposure=profile_signals["exposure"],
        auth_required=len(profile.auth_mechanisms or []) > 0,
        data_sensitivity=profile_signals["data_sensitivity"],
        business_criticality=profile_signals["business_criticality"],
    )
    avg_req_score = (total_score / count) if count else profile_base_score
    overall = (profile_base_score + avg_req_score) / 2.0
    profile_sev = _severity_from_score(overall)
    return ProfileRiskAssessment(
        profile_risk=profile_sev,
        overall_score=round(overall, 3),
        per_requirement=per_req,
        rules_applied=rules,
    )
