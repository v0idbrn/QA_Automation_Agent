# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Coverage Engine public facade.

Internal implementation lives in core.quality_gate (CoverageEngine +
CoverageReport + CoverageState). This module exposes a convenient facade to
avoid circular imports and clearly separates the Coverage sub-system.
"""

from __future__ import annotations

from core.quality_gate import (
    CoverageEngine,
    CoverageReport,
    CoverageState,
)

__all__ = ["CoverageEngine", "CoverageReport", "CoverageState"]


def evaluate_coverage(
    *,
    plan_items=None,
    test_cases=None,
    findings=None,
    requirements_ids=None,
    execution_results=None,
) -> CoverageReport:
    """Shortcut for CoverageEngine().evaluate(...). See quality_gate.CoverageEngine."""
    return CoverageEngine().evaluate(
        plan_items=plan_items or [],
        test_cases=test_cases or [],
        findings=findings or [],
        requirements_ids=requirements_ids or [],
        execution_results=execution_results or {},
    )
