# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
QA strategist.

Selects relevant skill categories from discovery and specification analysis so
the executor does not run irrelevant engines.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.discovery import DiscoveredProject, ProjectProfile
from core.spec_analyzer import SpecAnalysis, SpecConfidence


@dataclass
class Strategy:
    risk_level: str
    selected_skills: list[str] = field(default_factory=list)
    skipped_skills: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)


ALL_SKILLS = ("crawler", "form_tester", "a11y", "api", "evidence", "scope")


class QAStrategist:
    def select(
        self,
        profile: DiscoveredProject | ProjectProfile,
        spec: SpecAnalysis | None = None,
        risk_level: str = "low",
    ) -> Strategy:
        selected: list[str] = ["scope", "evidence"]
        reasons = {
            "scope": "Always enforce origin and budget before execution",
            "evidence": "Every run must keep a reproducible local manifest",
        }
        looks_like_web = bool(profile.routes) or risk_level in {"medium", "high"} or self._web_from_spec(spec)
        looks_like_api = bool(profile.api_endpoints) or self._api_from_spec(spec)
        looks_like_ui = looks_like_web or profile.language in {"javascript", "typescript"}

        if looks_like_web:
            selected.append("crawler")
            reasons["crawler"] = "Observed or inferred navigable routes"
        if looks_like_ui:
            selected.append("form_tester")
            reasons["form_tester"] = "UI surface inferred; defensive form checks are in scope"
            selected.append("a11y")
            reasons["a11y"] = "UI surface inferred; WCAG checks are relevant"
        if looks_like_api or risk_level == "high":
            selected.append("api")
            reasons["api"] = "API endpoints observed/inferred or high-risk run requested"

        unique = []
        for skill in selected:
            if skill not in unique:
                unique.append(skill)
        skipped = [skill for skill in ALL_SKILLS if skill not in unique]
        for skill in skipped:
            reasons.setdefault(skill, "Skipped: no supporting evidence in discovery/spec analysis")
        return Strategy(risk_level=risk_level, selected_skills=unique, skipped_skills=skipped, reasons=reasons)

    def _web_from_spec(self, spec: SpecAnalysis | None) -> bool:
        if spec is None:
            return False
        return any(item.kind in {"docs", "auth"} and item.confidence != SpecConfidence.UNKNOWN for item in spec.statements)

    def _api_from_spec(self, spec: SpecAnalysis | None) -> bool:
        if spec is None:
            return False
        return any(item.kind == "api" and item.confidence == SpecConfidence.OBSERVED for item in spec.statements)
