# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Action and Result contracts for deterministic execution.

Planner emits Action objects. Executor returns Result objects. The decision
loop never mixes those responsibilities.

Extended fields:
  Action.test_id / timeout_ms / resource_budget / destructive / preconditions
  Result.test_id / execution_time_ms / evidence_ids / flaky_indicator / retry_count
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from core.models import Finding


@dataclass
class Action:
    """An executable unit of work. Planner-only construct."""

    name: str
    skill: str
    idempotent: bool = True
    params: dict[str, Any] = field(default_factory=dict)
    destructive: bool = False
    # --- traceability extension ---
    test_id: str | None = None
    requirement_id: str | None = None
    risk_id: str | None = None
    timeout_ms: int = 60_000
    resource_budget: dict[str, Any] = field(default_factory=dict)
    preconditions: list[str] = field(default_factory=list)
    cleanup: list[str] = field(default_factory=list)
    priority: str = "medium"


@dataclass
class Result:
    """Outcome of a single Action execution. Executor-only construct."""

    ok: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    retryable: bool = False
    skipped: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    # --- traceability extension ---
    test_id: str | None = None
    execution_time_ms: int = 0
    started_at_epoch_ms: int | None = None
    finished_at_epoch_ms: int | None = None
    evidence_ids: list[str] = field(default_factory=list)
    flaky_indicator: str | None = None  # PASS|FAIL|FLAKY|BLOCKED|ERROR|None
    retry_count: int = 0
    failure_signature: str | None = None

    def record_timing(self, started_ms: int, finished_ms: int) -> None:
        self.started_at_epoch_ms = started_ms
        self.finished_at_epoch_ms = finished_ms
        self.execution_time_ms = max(0, int(finished_ms - started_ms))


def now_ms() -> int:
    return int(time.time() * 1000)
