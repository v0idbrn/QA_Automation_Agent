# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Test planner for QA Automation Agent.

The planner turns discovery output and analysis hints into a structured plan.
It proposes work; it does not execute or modify the target project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.discovery import DiscoveredProject


@dataclass
class PlanItem:
    area: str
    description: str
    kind: str = "test"
    status: str = "proposed"
    automated: bool = True
    notes: list[str] = field(default_factory=list)


@dataclass
class TestPlan:
    target: str
    discovery: DiscoveredProject
    items: list[PlanItem] = field(default_factory=list)

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


def build_plan_from_discovery(discovery: DiscoveredProject, target: str = "local-project") -> TestPlan:
    plan = TestPlan(target=target, discovery=discovery)

    if discovery.language == "python":
        plan.add("Configuration", "Review dependency and toolchain configuration", automated=True)
        plan.add("Existing Tests", f"Audit {len(discovery.test_files)} existing test files", automated=True)

    if discovery.framework and discovery.framework != "unknown":
        plan.add("Framework Conventions", f"Follow {discovery.framework} conventions for test layout", automated=True)

    if discovery.api_endpoints:
        plan.add("API Coverage", f"Propose checks for {len(discovery.api_endpoints)} observed endpoints", automated=True)

    if discovery.routes:
        plan.add("Route Coverage", f"Propose checks for {len(discovery.routes)} observed routes", automated=True)

    if discovery.has_e2e_tests:
        plan.add("E2E Alignment", "Align new checks with existing E2E scope", automated=True)

    plan.add("Safety", "Validate scope and budgets before any automation runs", automated=True)
    plan.add("Evidence", "Ensure evidence and reports are reproducible", automated=True)

    return plan
