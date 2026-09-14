# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
CONFIGURATION PROFILES + FAIL-FAST VALIDATION.

Four profiles, all sharing the same security baselines:
  * safe       — very conservative; local-only smoke run; no network calls expected.
  * standard   — CLI default; balances coverage vs runtime.
  * deep       — expanded budgets but still non-destructive.
  * ci         — headless, INFO logging, junit-friendly, no user prompts.

Validation rules (fail-fast via ValueError):
  * All numeric budgets >= 0.
  * URL scheme must be http|https|file or empty (local project).
  * Budget combination must not be provably impossible (e.g. max_pages=0
    while max_requests > 0).
  * Unsafe combinations (allow_external=True + destructive=True +
    risk_level != "low") raise ValidationError.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from core.models import ProjectScope, BudgetConfig, ResourceBudget, ExecutionConfig, RiskLevel


class ValidationError(ValueError):
    """Raised on fail-fast config check failures. Do NOT auto-recover."""


_PROFILE_NAMES = ("safe", "standard", "deep", "ci")


@dataclass
class QualityGatePolicy:
    """Per-profile quality-gate thresholds.

    The requirement-coverage floor is deliberately a PROFILE decision, not a
    hardcoded constant: engine-level runs (HTTP-only skills, no live browser
    sessions) naturally cover a small fraction of discovered requirements,
    while deep runs with real browser execution cover far more.

    Attributes:
        min_requirements_coverage: floor for engine-level requirement
            coverage as a ratio in [0.0, 1.0].
        floor_enabled: when False the coverage floor is DISABLED entirely
            (a coverage ratio of 0.0 never fails the gate on its own).
        max_critical / max_high / max_blocked_ratio / max_flaky:
            forwarded verbatim to QualityGate.
    """

    min_requirements_coverage: float = 0.20
    max_critical: int = 0
    max_high: int = 2
    max_blocked_ratio: float = 0.50
    max_flaky: int = 8
    floor_enabled: bool = True

    def effective_floor(self) -> float:
        """The floor actually enforced by the gate (0.0 when disabled)."""
        return self.min_requirements_coverage if self.floor_enabled else 0.0


# Profile defaults. Every profile keeps the same security baseline; only the
# coverage EXPECTATION varies with how much execution the profile performs.
_PROFILE_GATE_POLICIES: dict[str, QualityGatePolicy] = {
    "safe": QualityGatePolicy(min_requirements_coverage=0.10),
    "standard": QualityGatePolicy(min_requirements_coverage=0.20),
    "deep": QualityGatePolicy(min_requirements_coverage=0.30),
    # CI runs are gate-of-record only: findings/budget/scope decide the gate,
    # not requirement-coverage ratios that depend on the target's surface.
    "ci": QualityGatePolicy(min_requirements_coverage=0.0, floor_enabled=False),
}


@dataclass
class AgentConfig:
    """Unified agent config = profile + per-run overrides merged."""

    profile: str = "standard"
    target: str = "."
    url: str | None = None
    browser: str = "chromium"
    headed: bool = False
    headless: bool | None = None
    output_dir: str = "reports"
    risk_level: str = "low"
    dry_run: bool = False
    allow_external: bool = False
    scope: ProjectScope = field(default_factory=ProjectScope)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    resources: ResourceBudget = field(default_factory=ResourceBudget)
    gate_policy: QualityGatePolicy = field(default_factory=QualityGatePolicy)
    extra: dict[str, Any] = field(default_factory=dict)

    def execution_config(self) -> ExecutionConfig:
        headless = self.headless if self.headless is not None else not self.headed
        return ExecutionConfig(
            browser=self.browser,
            headed=(not headless),
            headless=headless,
            timeout_seconds=self.budget.max_runtime_seconds or 300,
            concurrency=self.budget.max_concurrency or 3,
            output_dir=self.output_dir,
            risk_level=RiskLevel(self.risk_level) if self.risk_level in ("low", "medium", "high") else RiskLevel.LOW,
            dry_run=self.dry_run,
        )


# ---------------------------------------------------------------------------
# Profile factories
# ---------------------------------------------------------------------------


def _base_budget() -> BudgetConfig:
    return BudgetConfig(
        max_tests=None,
        max_requests=100,
        max_pages=25,
        max_depth=2,
        max_runtime_seconds=300,
        max_retries=3,
        max_concurrency=3,
        max_artifacts=256,
        max_response_size_bytes=16 * 1024 * 1024,
    )


def _base_resources() -> ResourceBudget:
    return ResourceBudget(
        max_memory_mb=None,
        max_browser_contexts=4,
        max_processes=8,
        max_temp_files=512,
        max_response_size_bytes=16 * 1024 * 1024,
        max_screenshots=128,
        max_runtime_seconds=None,
    )


def _base_scope() -> ProjectScope:
    return ProjectScope(
        allowed_origins=[],
        allowed_paths=None,
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        allowed_endpoints=None,
        blocked_paths=["/admin", "/delete", "/drop", "/reset", "/logout"],
        allow_external=False,
        allow_uploads=False,
        allow_filesystem_write=False,
        max_depth=2,
        max_pages=25,
        max_requests=100,
    )


def profile_safe(target: str = ".", *, url: str | None = None) -> AgentConfig:
    gate_policy = QualityGatePolicy(**vars(_PROFILE_GATE_POLICIES["safe"]))
    scope = _base_scope()
    scope.max_pages = 5
    scope.max_requests = 20
    scope.max_depth = 1
    budget = _base_budget()
    budget.max_pages = 5
    budget.max_requests = 20
    budget.max_depth = 1
    budget.max_runtime_seconds = 120
    budget.max_artifacts = 32
    budget.max_concurrency = 1
    resources = _base_resources()
    resources.max_screenshots = 16
    resources.max_browser_contexts = 1
    return AgentConfig(
        profile="safe",
        target=target,
        url=url,
        browser="chromium",
        headed=False,
        headless=True,
        risk_level="low",
        allow_external=False,
        scope=scope,
        budget=budget,
        resources=resources,
        gate_policy=gate_policy,
    )


def profile_standard(target: str = ".", *, url: str | None = None) -> AgentConfig:
    gate_policy = QualityGatePolicy(**vars(_PROFILE_GATE_POLICIES["standard"]))
    scope = _base_scope()
    budget = _base_budget()
    resources = _base_resources()
    return AgentConfig(
        profile="standard",
        target=target,
        url=url,
        browser="chromium",
        headed=False,
        headless=True,
        risk_level="low",
        allow_external=False,
        scope=scope,
        budget=budget,
        resources=resources,
        gate_policy=gate_policy,
    )


def profile_deep(target: str = ".", *, url: str | None = None) -> AgentConfig:
    gate_policy = QualityGatePolicy(**vars(_PROFILE_GATE_POLICIES["deep"]))
    scope = _base_scope()
    scope.max_pages = 100
    scope.max_requests = 500
    scope.max_depth = 4
    budget = _base_budget()
    budget.max_pages = 100
    budget.max_requests = 500
    budget.max_depth = 4
    budget.max_runtime_seconds = 1800
    budget.max_artifacts = 1024
    budget.max_concurrency = 5
    resources = _base_resources()
    resources.max_screenshots = 512
    resources.max_browser_contexts = 6
    resources.max_temp_files = 2048
    return AgentConfig(
        profile="deep",
        target=target,
        url=url,
        browser="chromium",
        headed=False,
        headless=True,
        risk_level="medium",
        allow_external=False,
        scope=scope,
        budget=budget,
        resources=resources,
        gate_policy=gate_policy,
    )


def profile_ci(target: str = ".", *, url: str | None = None) -> AgentConfig:
    cfg = profile_standard(target, url=url)
    cfg.profile = "ci"
    cfg.gate_policy = QualityGatePolicy(**vars(_PROFILE_GATE_POLICIES["ci"]))
    cfg.headless = True
    cfg.headed = False
    cfg.budget.max_runtime_seconds = 600
    cfg.resources.max_browser_contexts = 2
    cfg.budget.max_concurrency = 2
    cfg.extra.setdefault("log_level", "INFO")
    cfg.extra.setdefault("junit", True)
    cfg.extra.setdefault("no_interactive", True)
    return cfg


PROFILE_FACTORIES = {
    "safe": profile_safe,
    "standard": profile_standard,
    "deep": profile_deep,
    "ci": profile_ci,
}


def load_profile(name: str, target: str = ".", *, url: str | None = None) -> AgentConfig:
    if name not in PROFILE_FACTORIES:
        raise ValidationError(f"unknown profile {name!r}; choices: {sorted(PROFILE_FACTORIES)}")
    return PROFILE_FACTORIES[name](target, url=url)


# ---------------------------------------------------------------------------
# Fail-fast validation
# ---------------------------------------------------------------------------


def _validate_url(url: str) -> None:
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme not in ("http", "https", "file"):
        raise ValidationError(f"invalid URL scheme {parsed.scheme!r}; expected http/https/file or empty")
    if parsed.scheme and not parsed.netloc and parsed.scheme != "file":
        raise ValidationError(f"URL {url!r} has no host but declares scheme {parsed.scheme!r}")


def validate_config(cfg: AgentConfig, *, destructive: bool = False) -> AgentConfig:
    """Fail-fast validation. Returns the cfg object for chaining on success."""
    if cfg.profile not in PROFILE_FACTORIES:
        raise ValidationError(f"invalid profile {cfg.profile!r}; allowed: {sorted(PROFILE_FACTORIES)}")

    # URL sanity
    if cfg.url:
        _validate_url(cfg.url)
    for origin in (cfg.scope.allowed_origins or []):
        _validate_url(origin)

    # Non-negative budgets
    b = cfg.budget
    for field_name, val in (
        ("max_tests", b.max_tests),
        ("max_requests", b.max_requests),
        ("max_pages", b.max_pages),
        ("max_depth", b.max_depth),
        ("max_runtime_seconds", b.max_runtime_seconds),
        ("max_retries", b.max_retries),
        ("max_concurrency", b.max_concurrency),
        ("max_artifacts", b.max_artifacts),
        ("max_response_size_bytes", b.max_response_size_bytes),
    ):
        if val is not None and val < 0:
            raise ValidationError(f"budget.{field_name} must be >= 0 (got {val})")

    r = cfg.resources
    for field_name, val in (
        ("max_memory_mb", r.max_memory_mb),
        ("max_browser_contexts", r.max_browser_contexts),
        ("max_processes", r.max_processes),
        ("max_temp_files", r.max_temp_files),
        ("max_response_size_bytes", r.max_response_size_bytes),
        ("max_screenshots", r.max_screenshots),
        ("max_runtime_seconds", r.max_runtime_seconds),
    ):
        if val is not None and val < 0:
            raise ValidationError(f"resources.{field_name} must be >= 0 (got {val})")

    # Impossible combinations
    if b.max_pages == 0 and (b.max_requests or 0) > 0:
        raise ValidationError("max_pages=0 but max_requests>0: combination impossible")
    if (b.max_concurrency or 0) > (r.max_browser_contexts or sys.maxsize):
        raise ValidationError("budget.max_concurrency cannot exceed resources.max_browser_contexts")

    # Retry cap
    if (b.max_retries or 0) > 5:
        raise ValidationError("max_retries > 5 disallowed (prevents infinite retry storms)")

    # Quality gate policy
    g = cfg.gate_policy
    if not (0.0 <= g.min_requirements_coverage <= 1.0):
        raise ValidationError("gate_policy.min_requirements_coverage must be within [0.0, 1.0]")
    if not g.floor_enabled and g.min_requirements_coverage > 0.0:
        raise ValidationError("gate_policy.floor_enabled=False requires min_requirements_coverage=0.0")
    if g.max_critical < 0 or g.max_high < 0 or g.max_flaky < 0:
        raise ValidationError("gate_policy thresholds (max_critical/max_high/max_flaky) must be >= 0")
    if not (0.0 <= g.max_blocked_ratio <= 1.0):
        raise ValidationError("gate_policy.max_blocked_ratio must be within [0.0, 1.0]")

    # Unsafe combo: destructive + external + not low risk
    if destructive and cfg.allow_external and cfg.risk_level != "low":
        raise ValidationError(
            "Unsafe combination: destructive=True + allow_external=True + risk_level != low. "
            "Refusing to run destructive actions against out-of-origin targets."
        )

    # Risk level
    if cfg.risk_level not in ("low", "medium", "high"):
        raise ValidationError(f"risk_level must be low/medium/high (got {cfg.risk_level!r})")

    # Browser
    if cfg.browser not in ("chromium", "firefox", "webkit"):
        raise ValidationError(f"browser must be chromium/firefox/webkit (got {cfg.browser!r})")

    return cfg
