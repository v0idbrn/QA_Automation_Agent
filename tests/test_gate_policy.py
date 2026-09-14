# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Quality-gate policy regression tests.

The requirement-coverage floor is a PER-PROFILE decision (QualityGatePolicy),
not a hardcoded 20%. Engine-level runs (HTTP-only skills, no live browser
sessions) legitimately cover a small fraction of discovered requirements and
must not automatically FAIL the gate because of the floor:

  safe     → 10% floor
  standard → 20% floor (unchanged default)
  deep     → 30% floor
  ci       → floor DISABLED (gate-of-record: findings/budget/scope decide)

The floor must stay tunable per run via --min-coverage, and invalid policies
must fail fast.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from core.config import (
    AgentConfig,
    QualityGatePolicy,
    ValidationError,
    load_profile,
    validate_config,
)
from core.evidence import EvidenceManager
from core.orchestrator import Orchestrator, RunContext
from core.quality_gate import CoverageReport, CoverageState
from core.scope import Budget, Scope


def _coverage(ratio_pct: int, total: int = 100) -> CoverageReport:
    """A requirement-coverage report with the given covered percentage."""
    covered = round(total * ratio_pct / 100)
    return CoverageReport(
        requirement_coverage={
            f"R{i:03d}": (CoverageState.COVERED if i < covered else CoverageState.NOT_COVERED)
            for i in range(total)
        }
    )


def _evaluate(ctx: RunContext, coverage: CoverageReport):
    orch = Orchestrator()
    ctx.escalation_registry._items = {}
    gate = orch._gate_for(ctx)
    return gate.evaluate([], None, coverage=coverage, flaky_count=0, blocked_tests=0)


def _ctx(tmp_path: Path, policy: QualityGatePolicy | None) -> RunContext:
    scope = Scope(allowed_origin="https://example.test")
    budget = Budget(scope=scope)
    budget.start()
    return RunContext(
        target=".",
        output_dir=tmp_path,
        budget=budget,
        evidence=EvidenceManager(temporary_dir=tmp_path / "tmp", final_dir=tmp_path / "final"),
        gate_policy=policy,
    )


class TestProfilePolicies:
    @pytest.mark.parametrize(
        ("profile", "expected_floor", "enabled"),
        [
            ("safe", 0.10, True),
            ("standard", 0.20, True),
            ("deep", 0.30, True),
            ("ci", 0.0, False),
        ],
    )
    def test_profile_policy_defaults(self, profile: str, expected_floor: float, enabled: bool):
        cfg = validate_config(load_profile(profile, "."))
        assert cfg.gate_policy.min_requirements_coverage == expected_floor
        assert cfg.gate_policy.floor_enabled is enabled

    def test_every_profile_carries_a_policy(self):
        for name in ("safe", "standard", "deep", "ci"):
            cfg = validate_config(load_profile(name, "."))
            assert isinstance(cfg.gate_policy, QualityGatePolicy)

    def test_effective_floor_zero_when_disabled(self):
        policy = QualityGatePolicy(min_requirements_coverage=0.0, floor_enabled=False)
        assert policy.effective_floor() == 0.0

    def test_effective_floor_value_when_enabled(self):
        policy = QualityGatePolicy(min_requirements_coverage=0.35, floor_enabled=True)
        assert policy.effective_floor() == 0.35


class TestEngineLevelRuns:
    def test_engine_level_run_passes_under_ci_policy(self, tmp_path: Path):
        """7% requirement coverage must not FAIL when the floor is disabled."""
        ctx = _ctx(
            tmp_path,
            QualityGatePolicy(min_requirements_coverage=0.0, floor_enabled=False),
        )
        result = _evaluate(ctx, _coverage(7))
        assert "below" not in " ".join(result.reasons).lower()

    def test_engine_level_run_fails_under_standard_policy(self, tmp_path: Path):
        """The standard 20% floor still applies when the profile demands it."""
        ctx = _ctx(tmp_path, QualityGatePolicy(min_requirements_coverage=0.20))
        result = _evaluate(ctx, _coverage(7))
        assert any("below 20%" in r for r in result.reasons)

    def test_no_policy_uses_backward_compatible_default(self, tmp_path: Path):
        ctx = _ctx(tmp_path, None)
        result = _evaluate(ctx, _coverage(7))
        assert any("below 20%" in r for r in result.reasons)

    def test_floor_is_satisfied_when_coverage_meets_policy(self, tmp_path: Path):
        ctx = _ctx(tmp_path, QualityGatePolicy(min_requirements_coverage=0.10))
        result = _evaluate(ctx, _coverage(30))
        assert not any("coverage" in r.lower() and "below" in r.lower() for r in result.reasons)


class TestOrchestratorGateResolution:
    def test_explicit_gate_wins_over_policy(self, tmp_path: Path):
        """Constructor-injected gate keeps priority (embedder/back-compat path)."""
        from core.quality_gate import QualityGate

        explicit = QualityGate(min_requirements_coverage=0.90)
        orch = Orchestrator(gate=explicit)
        ctx = _ctx(tmp_path, QualityGatePolicy(min_requirements_coverage=0.05))
        resolved = orch._gate_for(ctx)
        assert resolved is explicit
        assert resolved.min_requirements_coverage == 0.90

    def test_gate_built_from_ctx_policy(self, tmp_path: Path):
        orch = Orchestrator()
        ctx = _ctx(
            tmp_path,
            QualityGatePolicy(
                min_requirements_coverage=0.15,
                max_high=5,
                max_flaky=2,
                max_blocked_ratio=0.7,
            ),
        )
        resolved = orch._gate_for(ctx)
        assert resolved.min_requirements_coverage == 0.15
        assert resolved.max_high == 5
        assert resolved.max_flaky == 2
        assert resolved.max_blocked_ratio == 0.7

    def test_run_context_declares_gate_policy_field(self):
        names = {f.name for f in dataclasses.fields(RunContext)}
        assert "gate_policy" in names


class TestConfigValidation:
    def test_floor_above_one_rejected(self):
        cfg = validate_config(load_profile("standard", "."))
        cfg.gate_policy.min_requirements_coverage = 1.5
        with pytest.raises(ValidationError):
            validate_config(cfg)

    def test_negative_floor_rejected(self):
        cfg = validate_config(load_profile("standard", "."))
        cfg.gate_policy.min_requirements_coverage = -0.1
        with pytest.raises(ValidationError):
            validate_config(cfg)

    def test_disabled_floor_requires_zero(self):
        cfg = validate_config(load_profile("standard", "."))
        cfg.gate_policy.floor_enabled = False
        with pytest.raises(ValidationError):
            validate_config(cfg)

    def test_negative_thresholds_rejected(self):
        cfg = validate_config(load_profile("standard", "."))
        cfg.gate_policy.max_high = -1
        with pytest.raises(ValidationError):
            validate_config(cfg)

    def test_valid_custom_policy_accepted(self):
        cfg = validate_config(load_profile("safe", "."))
        cfg.gate_policy = QualityGatePolicy(min_requirements_coverage=0.25, max_high=1)
        validate_config(cfg)  # must not raise


class TestAgentConfigField:
    def test_agent_config_has_gate_policy_default(self):
        cfg = AgentConfig()
        assert isinstance(cfg.gate_policy, QualityGatePolicy)
        assert cfg.gate_policy.floor_enabled is True
