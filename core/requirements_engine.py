# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Requirements Engine.

Converts the following sources into VERIFIABLE `Requirement` objects
(classified EXPLICIT / INFERRED / UNKNOWN):
  * README / docs (through spec_analyzer)
  * detected routes and endpoints
  * detected HTML forms
  * configuration entries
  * existing tests (test title → requirement mapping as INFERRED)
  * authentication surface markers

Rule: NEVER label an INFERRED requirement as EXPLICIT. The classification
field distinguishes them in every report and coverage table.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.models import (
    ProjectProfile,
    Requirement,
    RequirementClassification,
    RequirementCategory,
)
from core.spec_analyzer import SpecAnalysis, SpecConfidence, analyze_specs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SPEC_CONF_MAP: dict[SpecConfidence, RequirementClassification] = {
    SpecConfidence.OBSERVED: RequirementClassification.EXPLICIT,
    SpecConfidence.INFERRED: RequirementClassification.INFERRED,
    SpecConfidence.UNKNOWN: RequirementClassification.UNKNOWN,
}


def _stable_id(kind: str, *parts: str) -> str:
    joined = "|".join(str(p) for p in (kind, *parts))
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]
    return f"req_{kind[:3]}_{digest}"


def _from_spec_analysis(analysis: SpecAnalysis, out: list[Requirement]) -> None:
    for stmt in analysis.statements:
        classification = _SPEC_CONF_MAP.get(stmt.confidence, RequirementClassification.UNKNOWN)
        if stmt.kind in {"api", "docs", "auth", "availability", "toolchain"}:
            category_map: dict[str, RequirementCategory] = {
                "api": RequirementCategory.FUNCTIONAL,
                "docs": RequirementCategory.FUNCTIONAL,
                "auth": RequirementCategory.SECURITY,
                "availability": RequirementCategory.CONFIGURATION,
                "toolchain": RequirementCategory.CONFIGURATION,
            }
            category = category_map.get(stmt.kind, RequirementCategory.FUNCTIONAL)
            req = Requirement(
                requirement_id=_stable_id(stmt.kind, stmt.source, stmt.statement),
                statement=stmt.statement,
                title=stmt.statement[:160],
                description=stmt.statement,
                category=category,
                classification=classification,
                source=stmt.source,
                related_routes=[],
                related_api_endpoints=[],
            )
            out.append(req)


def _from_project_routes(profile: ProjectProfile, out: list[Requirement]) -> None:
    for idx, route in enumerate(profile.routes or []):
        req = Requirement(
            requirement_id=_stable_id("route", profile.path, str(idx), route[:80]),
            statement=f"Route responds: {route[:120]}",
            title=f"Route responds: {route[:120]}",
            description=f"Application declares a routable surface: {route}",
            category=RequirementCategory.FUNCTIONAL,
            classification=RequirementClassification.INFERRED,
            source=f"profile.routes[{idx}]",
            related_routes=[route[:200]],
            related_api_endpoints=[],
        )
        out.append(req)
    for idx, endpoint in enumerate(profile.api_endpoints or []):
        req = Requirement(
            requirement_id=_stable_id("api", profile.path, str(idx), endpoint),
            statement=f"API endpoint reachable: {endpoint}",
            title=f"API endpoint reachable: {endpoint}",
            description=f"Project references API endpoint {endpoint}; must return a defined status and content type.",
            category=RequirementCategory.API,
            classification=RequirementClassification.INFERRED,
            source=f"profile.api_endpoints[{idx}]",
            related_api_endpoints=[endpoint],
            related_routes=[],
        )
        out.append(req)


def _from_forms(profile: ProjectProfile, out: list[Requirement]) -> None:
    for idx, form_file in enumerate(profile.forms_detected or []):
        req = Requirement(
            requirement_id=_stable_id("form", profile.path, str(idx), form_file),
            statement=f"Form validation enforced at {form_file}",
            title=f"Form validation enforced at {form_file}",
            description=f"File {form_file} contains <form> elements; inputs must accept/decline bounded synthetic values deterministically.",
            category=RequirementCategory.FORM,
            classification=RequirementClassification.INFERRED,
            source=form_file,
            related_routes=[form_file],
        )
        out.append(req)


def _from_auth(profile: ProjectProfile, out: list[Requirement]) -> None:
    for auth in profile.auth_mechanisms or []:
        req = Requirement(
            requirement_id=_stable_id("auth", profile.path, auth),
            statement=f"Authentication surface ({auth}) present",
            title=f"Authentication surface ({auth}) present",
            description=f"Project references {auth!r} authentication mechanism. Credentials must be provided externally for authenticated runs.",
            category=RequirementCategory.SECURITY,
            classification=RequirementClassification.INFERRED,
            source=f"profile.auth_mechanisms/{auth}",
        )
        out.append(req)


def _from_configs(profile: ProjectProfile, out: list[Requirement]) -> None:
    for idx, cfg in enumerate(profile.config_files or []):
        req = Requirement(
            requirement_id=_stable_id("cfg", profile.path, str(idx), cfg),
            statement=f"Configuration loaded from {cfg}",
            title=f"Configuration loaded from {cfg}",
            description=f"Configuration file {cfg} is present; missing/invalid values should yield deterministic startup errors.",
            category=RequirementCategory.CONFIGURATION,
            classification=RequirementClassification.EXPLICIT if cfg.endswith((".py", ".json", ".yaml", ".yml")) else RequirementClassification.INFERRED,
            source=cfg,
        )
        out.append(req)


def _from_existing_tests(profile: ProjectProfile, out: list[Requirement]) -> None:
    for idx, test_file in enumerate(profile.test_files or []):
        # Grab first 8 test-like function names as inferred requirements
        try:
            text = Path(test_file).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        matches = re.findall(r"def\s+(test_[a-zA-Z0-9_]+)", text)
        for name in matches[:8]:
            req = Requirement(
                requirement_id=_stable_id("test", profile.path, test_file, name),
                statement=f"Existing test: {name}",
                title=f"Existing test: {name}",
                description=f"Test file {test_file} defines {name}; the QA agent should preserve equivalent coverage.",
                category=RequirementCategory.TEST,
                classification=RequirementClassification.INFERRED,
                source=test_file,
            )
            out.append(req)
        if len(out) > 1024:
            return


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass
class RequirementsResult:
    requirements: list[Requirement]
    spec: SpecAnalysis

    def by_classification(self, cls: RequirementClassification) -> list[Requirement]:
        return [r for r in self.requirements if r.classification == cls]

    def by_category(self, cat: RequirementCategory) -> list[Requirement]:
        return [r for r in self.requirements if r.category == cat]


def build_requirements(profile: ProjectProfile, *, spec: SpecAnalysis | None = None) -> RequirementsResult:
    """READ-ONLY. Builds classified Requirement objects from profile+specs."""
    if spec is None:
        root = Path(profile.path) if profile.path else Path(".")
        spec = analyze_specs(root)

    reqs: list[Requirement] = []
    _from_spec_analysis(spec, reqs)
    _from_project_routes(profile, reqs)
    _from_forms(profile, reqs)
    _from_auth(profile, reqs)
    _from_configs(profile, reqs)
    _from_existing_tests(profile, reqs)

    # Dedup by requirement_id (stable idempotent hashing should prevent, but belt+braces)
    seen: set[str] = set()
    unique: list[Requirement] = []
    for r in reqs:
        if r.requirement_id in seen:
            continue
        seen.add(r.requirement_id)
        unique.append(r)

    return RequirementsResult(requirements=unique, spec=spec)
