# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Test Generator — public facade.

The core dedup / stable-id / impossible logic lives inside core.planner
(generate_test_cases). This module exists to satisfy the explicit
separation-of-concerns architecture (Planner vs Generator as distinct
modules) and to expose convenience helpers for the orchestrator.

Future: LLM proposals may flow through this module ONLY for the PROPOSE
stage; execution of generated tests remains orchestrator-bound and
authorization-gated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.planner import (
    TestPlan,
    TestGenerationResult,
    generate_test_cases as _planner_generate,
)


__all__ = [
    "TestGenerationResult",
    "generate_test_cases",
    "deduplicate_by_fingerprint",
    "summarize_generation",
]


def generate_test_cases(
    plan: TestPlan,
    *,
    profile_auth_mechanisms: list[str] | None = None,
) -> TestGenerationResult:
    """Planner-backed stable, deduplicated TestCase generation.

    This is the ONLY supported entry point. All test generation centralizes
    here to guarantee consistent fingerprints across runs.
    """
    return _planner_generate(plan, profile_auth_mechanisms=profile_auth_mechanisms)


def deduplicate_by_fingerprint(test_cases: list[Any]) -> tuple[list[Any], int]:
    """Dedup an existing list of TestCase-like objects by .fingerprint.

    Keeps the first occurrence. Returns (unique_list, removed_count).
    """
    seen: set[str] = set()
    unique: list[Any] = []
    removed = 0
    for tc in test_cases:
        fp = getattr(tc, "fingerprint", None)
        if fp is None:
            unique.append(tc)
            continue
        if fp in seen:
            removed += 1
            continue
        seen.add(fp)
        unique.append(tc)
    return unique, removed


@dataclass(frozen=True)
class GenerationSummary:
    total: int
    pending: int
    blocked: int
    impossible: int
    duplicates_removed: int

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "pending": self.pending,
            "blocked": self.blocked,
            "impossible": self.impossible,
            "duplicates_removed": self.duplicates_removed,
        }


def summarize_generation(result: TestGenerationResult) -> GenerationSummary:
    pending = 0
    blocked = 0
    impossible = 0
    for tc in result.test_cases:
        status = str(getattr(tc, "status", "PENDING"))
        if "BLOCKED" in status:
            blocked += 1
        elif "IMPOSSIBLE" in status or tc.impossible_reason:
            impossible += 1
        else:
            pending += 1
    return GenerationSummary(
        total=len(result.test_cases),
        pending=pending,
        blocked=blocked,
        impossible=impossible,
        duplicates_removed=result.duplicates_removed,
    )
