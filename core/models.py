# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Unified central models for the QA Automation Agent.

All engines, planners, orchestrators, and reporters share these typed contracts
so every piece of the pipeline can be traced from Requirement -> Risk -> TestCase
-> Execution -> Evidence -> Finding -> QualityGate.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FindingCategory(str, Enum):
    FUNCTIONAL = "functional"
    UI = "ui"
    API = "api"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    SECURITY = "security"
    DATA_INTEGRITY = "data_integrity"
    CONFIGURATION = "configuration"
    INFRASTRUCTURE = "infrastructure"
    CRAWL = "crawl"
    HTTP = "http"
    CONSOLE = "console"
    FORM = "form"
    TEST = "test"
    ENVIRONMENT = "environment"
    NETWORK = "network"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


Severity = FindingSeverity  # backward compat alias


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"
    NEEDS_HUMAN = "needs_human"
    BLOCKED = "blocked"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ESCALATED = "escalated"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


ConfidenceLevel = Confidence  # backward compat alias (analyzer, finding_manager, skills)


class TestStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    FLAKY = "flaky"
    BLOCKED = "blocked"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_RUN = "not_run"


class RiskSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def _weight(cls, v: RiskSeverity) -> int:
        return {
            RiskSeverity.LOW: 1,
            RiskSeverity.MEDIUM: 2,
            RiskSeverity.HIGH: 3,
            RiskSeverity.CRITICAL: 4,
        }[v]

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, RiskSeverity):
            return NotImplemented
        return self._weight(self) < self._weight(other)

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, RiskSeverity):
            return NotImplemented
        return self._weight(self) <= self._weight(other)

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, RiskSeverity):
            return NotImplemented
        return self._weight(self) > self._weight(other)

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, RiskSeverity):
            return NotImplemented
        return self._weight(self) >= self._weight(other)


class RequirementClassification(str, Enum):
    EXPLICIT = "explicit"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Coarse run-level risk knob (CLI --risk-level)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TestCaseStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASS = "pass"
    FAIL = "fail"
    FLAKY = "flaky"
    BLOCKED = "blocked"
    ERROR = "error"
    SKIPPED = "skipped"
    IMPOSSIBLE = "impossible"
    NOT_RUN = "not_run"


StrEnumLike = str  # kept for typing readability in downstream contracts


class RequirementCategory(str, Enum):
    FUNCTIONAL = "functional"
    API = "api"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    DATA_INTEGRITY = "data_integrity"
    UI = "ui"
    CRAWL = "crawl"
    FORM = "form"
    HTTP = "http"
    CONSOLE = "console"
    TEST = "test"
    INFRASTRUCTURE = "infrastructure"
    COMPATIBILITY = "compatibility"
    USABILITY = "usability"
    UNKNOWN = "unknown"


class QualityGateStatus(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNINGS = "PASS_WITH_WARNINGS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


class CoverageState(str, Enum):
    COVERED = "covered"
    PARTIALLY_COVERED = "partially_covered"
    NOT_COVERED = "not_covered"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stable_id(prefix: str, *parts: Any, length: int = 12) -> str:
    """Deterministic short ID built from hashed parts. Not cryptographic."""
    h = hashlib.sha1()
    for p in parts:
        if p is None:
            h.update(b"\x00")
        else:
            h.update(repr(p).encode("utf-8", errors="replace"))
    return f"{prefix}_{h.hexdigest()[:length]}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------


class ProjectScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)
    allowed_origin: str = ""
    allowed_origins: list[str] | None = None
    allowed_paths: tuple[str, ...] | None = None
    allow_external: bool = False
    allowed_methods: tuple[str, ...] | None = ("GET", "HEAD", "OPTIONS")
    allowed_endpoints: tuple[str, ...] | None = None
    blocked_paths: tuple[str, ...] | None = None
    max_depth: int = 2
    max_pages: int = 25
    max_requests: int = 100
    max_runtime_seconds: int = 300
    per_request_timeout_seconds: int = 20
    concurrency_limit: int = 3
    allow_uploads: bool = False
    max_upload_bytes: int = 0
    allow_filesystem_write: bool = False
    filesystem_roots: tuple[str, ...] = ()


class Project(BaseModel):
    model_config = ConfigDict(extra="allow")
    project_id: str = ""
    name: str = ""
    root: str = ""
    path: str = ""
    target_url: str | None = None
    language: str = "unknown"
    framework: str = "unknown"
    frontend_framework: str = "unknown"
    backend_framework: str = "unknown"
    package_manager: str = "unknown"
    created_at: datetime = Field(default_factory=_utc_now)

    @field_validator("root", "path", "name", "project_id", mode="before")
    @classmethod
    def _coerce_to_str(cls, v: Any) -> Any:
        if isinstance(v, Path):
            return str(v)
        return v

    @model_validator(mode="after")
    def _ensure_id(self) -> Project:
        if not self.project_id:
            self.project_id = _stable_id("proj", self.root, self.target_url or "")
        return self


class ProjectProfile(Project):
    entry_points: list[str] = Field(default_factory=list)
    routes: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)
    forms_detected: list[str] = Field(default_factory=list)
    test_framework: str = "unknown"
    test_files: list[str] = Field(default_factory=list)
    has_e2e_tests: bool = False
    auth_mechanisms: list[str] = Field(default_factory=list)
    spec_files: list[str] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    potential_risks: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    fingerprint: str = ""
    # Extended discovery contract (populated by core.discovery)
    frontend: str = "unknown"
    backend: str = "unknown"

    @field_validator("frontend", "backend", mode="before")
    @classmethod
    def _coerce_frontend_backend(cls, v: Any) -> Any:
        if isinstance(v, Path):
            return str(v)
        return v

    @model_validator(mode="after")
    def _ensure_fp(self) -> ProjectProfile:
        if not self.fingerprint:
            self.fingerprint = _stable_id(
                "prof",
                self.root,
                self.language,
                self.framework,
                tuple(sorted(self.routes)),
                tuple(sorted(self.api_endpoints)),
            )
        return self

    def summary(self) -> str:
        return (
            f"Project {self.project_id}\n"
            f"├── language: {self.language or 'unknown'}\n"
            f"├── framework: {self.framework or 'unknown'}\n"
            f"├── package_manager: {self.package_manager or 'unknown'}\n"
            f"├── {len(self.routes)} routes\n"
            f"├── {len(self.api_endpoints)} endpoints\n"
            f"├── {len(self.forms_detected)} forms detected\n"
            f"├── {len(self.test_files)} test files\n"
            f"├── {len(self.auth_mechanisms)} auth mechanisms: {','.join(self.auth_mechanisms) or '-'}\n"
            f"└── {'E2E' if self.has_e2e_tests else 'no E2E detected'}\n"
        )


DiscoveredProject = ProjectProfile  # backward compat alias


class Requirement(BaseModel):
    model_config = ConfigDict(extra="allow")
    requirement_id: str = ""
    project_id: str = ""
    statement: str
    title: str = ""
    description: str = ""
    category: RequirementCategory = RequirementCategory.FUNCTIONAL
    classification: RequirementClassification = RequirementClassification.UNKNOWN
    kind: str = "requirement"
    source: str = ""
    source_line: int | None = None
    related_routes: list[str] = Field(default_factory=list)
    related_api_endpoints: list[str] = Field(default_factory=list)
    testable: bool = True
    priority: str = "medium"
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="after")
    def _ensure_id(self) -> Requirement:
        if not self.requirement_id:
            self.requirement_id = _stable_id(
                "req", self.statement, self.source, self.classification.value
            )
        if not self.title:
            self.title = self.statement[:160]
        if not self.description:
            self.description = self.statement
        return self


class Risk(BaseModel):
    model_config = ConfigDict(extra="allow")
    risk_id: str = ""
    requirement_id: str = ""
    project_id: str = ""
    severity: RiskSeverity = RiskSeverity.LOW
    impact: int = Field(default=1, ge=1, le=5)
    likelihood: int = Field(default=1, ge=1, le=5)
    complexity: int = Field(default=1, ge=1, le=5)
    exposure: int = Field(default=1, ge=1, le=5)
    authentication_required: bool = False
    data_sensitivity: int = Field(default=1, ge=1, le=5)
    business_criticality: int = Field(default=1, ge=1, le=5)
    score: float = 0.0
    description: str = ""
    recommendation: str = ""
    related_routes: list[str] = Field(default_factory=list)
    related_api_endpoints: list[str] = Field(default_factory=list)
    auto_escalation_applied: bool = False
    notes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)

    @field_validator("severity", mode="before")
    @classmethod
    def _severity_from_score(cls, v: Any) -> Any:
        if isinstance(v, RiskSeverity):
            return v
        if isinstance(v, str):
            return RiskSeverity(v)
        return v

    @model_validator(mode="after")
    def _ensure_id_and_severity(self) -> Risk:
        if not self.risk_id:
            self.risk_id = _stable_id("risk", self.requirement_id, self.description)
        score = (
            self.impact * 0.25
            + self.likelihood * 0.2
            + self.complexity * 0.1
            + self.exposure * 0.1
            + (5 if self.authentication_required else 1) * 0.1
            + self.data_sensitivity * 0.1
            + self.business_criticality * 0.15
        )
        if self.severity == RiskSeverity.LOW and score >= 3.0:
            if score >= 4.2:
                self.severity = RiskSeverity.CRITICAL
            elif score >= 3.4:
                self.severity = RiskSeverity.HIGH
            else:
                self.severity = RiskSeverity.MEDIUM
        if self.authentication_required and self.business_criticality >= 4:
            if self.severity == RiskSeverity.LOW:
                self.severity = RiskSeverity.MEDIUM
        return self


class TestStep(BaseModel):
    model_config = ConfigDict(extra="allow")
    step_id: str = ""
    index: int = 0
    step_index: int = 0
    action: str = ""
    description: str = ""
    target: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    expected: str = ""
    cleanup: str = ""

    @model_validator(mode="after")
    def _ensure_id(self) -> TestStep:
        if not self.step_id:
            self.step_id = _stable_id("step", self.index, self.action, self.target)
        return self


class TestCase(BaseModel):
    model_config = ConfigDict(extra="allow")
    test_id: str = ""
    requirement_id: str = ""
    risk_id: str = ""
    risk: RiskSeverity = RiskSeverity.LOW
    skill: str = ""
    title: str = ""
    description: str = ""
    preconditions: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    expected_result: str = ""
    cleanup: list[str] = Field(default_factory=list)
    priority: str = "medium"
    budget: dict[str, Any] = Field(default_factory=dict)
    steps: list[TestStep] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source: str = "planner"
    status: TestCaseStatus = TestCaseStatus.PENDING
    confidence: Confidence = Confidence.MEDIUM
    fingerprint: str = ""
    impossible_reason: str | None = None
    created_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="after")
    def _ensure_id(self) -> TestCase:
        if not self.test_id:
            self.test_id = _stable_id(
                "tc",
                self.requirement_id,
                self.risk_id,
                self.skill,
                self.title,
                tuple(self.actions),
                self.expected_result,
            )
        if not self.fingerprint:
            self.fingerprint = self.test_id
        return self


class TestResult(BaseModel):
    test_id: str
    run_id: str = ""
    status: TestStatus = TestStatus.NOT_RUN
    execution_order: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int = 0
    expected: str = ""
    actual: str = ""
    error: str | None = None
    retries: int = 0
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    failure_signature: str = ""
    flaky_runs: list[TestStatus] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")
    finding_id: str = ""
    category: FindingCategory = FindingCategory.UNKNOWN
    severity: FindingSeverity = FindingSeverity.LOW
    confidence: Confidence = Confidence.MEDIUM
    title: str
    description: str = ""
    location: str | None = None
    evidence: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    reproduction: str | None = None
    expected: str | None = None
    actual: str | None = None
    source_skill: str = "unknown"
    source: str = ""
    status: FindingStatus = FindingStatus.OPEN
    recommendation: str | None = None
    test_id: str = ""
    requirement_id: str = ""
    run_id: str = ""
    route: str | None = None
    error_signature: str = ""
    stack_signature: str = ""
    duplicate_of: str | None = None
    timestamp: datetime = Field(default_factory=_utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, v: Any) -> Any:
        """Accept legacy numeric confidences (0..1 floats/ints) and map to the enum."""
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            f = float(v)
            if f < 0.0 or f > 1.0:
                raise ValueError("numeric confidence must be within [0.0, 1.0]")
            if f >= 0.75:
                return Confidence.HIGH
            if f >= 0.45:
                return Confidence.MEDIUM
            return Confidence.LOW
        return v

    @model_validator(mode="after")
    def _ensure_id(self) -> Finding:
        if not self.finding_id:
            self.finding_id = _stable_id(
                "f",
                self.category.value,
                self.title,
                self.location or "",
                self.error_signature,
                self.route or "",
                self.stack_signature,
            )
        return self

    def fingerprint(self) -> str:
        """Canonical 6-field dedup hash (category, location, title, error sig, route, stack)."""
        loc = (self.location or "").strip().lower()
        title_norm = re.sub(r"\s+", " ", self.title.strip().lower())
        sig = self.error_signature.strip().lower()
        route = (self.route or "").strip().lower()
        stack = self.stack_signature.strip().lower()
        raw = "|".join([self.category.value, loc, title_norm, sig, route, stack])
        return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()

    def model_dump_safe(
        self, redaction: RedactionPolicy | None = None
    ) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        if redaction is not None:
            for key in (
                "description",
                "evidence",
                "actual",
                "expected",
                "reproduction",
                "location",
                "recommendation",
                "title",
            ):
                if isinstance(data.get(key), str):
                    data[key] = redaction.redact(data[key])
            if isinstance(data.get("metadata"), dict):
                data["metadata"] = _redact_recursive(data["metadata"], redaction)
        return data


class Evidence(BaseModel):
    model_config = ConfigDict(extra="allow")
    evidence_id: str = ""
    kind: str
    path: str = ""
    description: str = ""
    content_hash: str = ""
    run_id: str = ""
    test_id: str = ""
    finding_id: str = ""
    sensitive: bool = False
    timestamp: datetime = Field(default_factory=_utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _ensure_id(self) -> Evidence:
        if not self.evidence_id:
            self.evidence_id = _stable_id(
                "ev", self.kind, self.path, self.run_id, self.test_id, self.finding_id
            )
        return self


class ExecutionConfig(BaseModel):
    model_config = ConfigDict(extra="allow")
    browser: str = "chromium"
    headless: bool = True
    headed: bool = False
    risk_level: str = "low"
    dry_run: bool = False
    allow_external: bool = False
    allow_destructive: bool = False
    profile_name: str = "standard"
    timeout_seconds: int = 300
    concurrency: int = 3
    output_dir: str = "reports"
    extras: dict[str, Any] = Field(default_factory=dict)


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_tests: int | None = 100
    max_requests: int | None = 100
    max_pages: int | None = 25
    max_depth: int | None = 2
    max_runtime_seconds: int | None = 300
    max_retries: int | None = 3
    max_concurrency: int | None = 3
    max_artifacts: int | None = 200
    max_response_size_bytes: int | None = 10 * 1024 * 1024  # 10 MB
    max_screenshots: int | None = 50
    per_request_timeout_seconds: int | None = 20

    @field_validator(
        "max_tests",
        "max_requests",
        "max_pages",
        "max_depth",
        "max_runtime_seconds",
        "max_retries",
        "max_concurrency",
        "max_artifacts",
        "max_response_size_bytes",
        "max_screenshots",
        "per_request_timeout_seconds",
    )
    @classmethod
    def _non_negative(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("budget values must be >= 0 (or None)")
        return v


class ResourceBudget(BaseModel):
    """Resource governor caps. None = uncapped (but Budget still enforces runtime)."""

    model_config = ConfigDict(extra="forbid")
    max_memory_mb: int | None = None
    max_browser_contexts: int | None = 4
    max_processes: int | None = 8
    max_temp_files: int | None = 512
    max_response_size_bytes: int | None = 16 * 1024 * 1024
    max_screenshots: int | None = 128
    max_runtime_seconds: int | None = None

    @field_validator(
        "max_memory_mb",
        "max_browser_contexts",
        "max_processes",
        "max_temp_files",
        "max_response_size_bytes",
        "max_screenshots",
        "max_runtime_seconds",
    )
    @classmethod
    def _non_negative_or_none(cls, v: int | None) -> int | None:
        if v is not None and v < 0:
            raise ValueError("resource budget values must be >= 0 (or None)")
        return v


class ExecutionRun(BaseModel):
    run_id: str = ""
    project_id: str = ""
    project_fingerprint: str = ""
    config: ExecutionConfig = Field(default_factory=ExecutionConfig)
    scope: ProjectScope = Field(default_factory=ProjectScope)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    started_at: datetime = Field(default_factory=_utc_now)
    finished_at: datetime | None = None
    status: TestStatus = TestStatus.NOT_RUN
    state_history: list[str] = Field(default_factory=list)
    tests_planned_ids: list[str] = Field(default_factory=list)
    tests_executed_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    escalation_ids: list[str] = Field(default_factory=list)
    interrupted: bool = False
    interrupt_reason: str = ""

    @model_validator(mode="after")
    def _ensure_id(self) -> ExecutionRun:
        if not self.run_id:
            import uuid

            self.run_id = f"run_{uuid.uuid4().hex[:16]}"
        return self


class RetryDecision(BaseModel):
    retry_id: str = ""
    test_id: str = ""
    run_id: str = ""
    reason: str = ""
    retryable: bool = False
    attempts: int = 0
    max_attempts: int = 3
    failure_signature: str = ""

    @model_validator(mode="after")
    def _ensure_id(self) -> RetryDecision:
        if not self.retry_id:
            self.retry_id = _stable_id(
                "retry", self.test_id, self.failure_signature, self.attempts
            )
        return self


class Escalation(BaseModel):
    escalation_id: str = ""
    run_id: str = ""
    why: str = ""
    what_was_attempted: str = ""
    what_evidence_exists: str = ""
    what_human_input_is_required: str = ""
    halt: bool = True
    created_at: datetime = Field(default_factory=_utc_now)
    resolved_by: str | None = None
    resolution: str | None = None

    @model_validator(mode="after")
    def _ensure_id(self) -> Escalation:
        if not self.escalation_id:
            self.escalation_id = _stable_id("esc", self.run_id, self.why)
        if self.why.strip() == "":
            raise ValueError("Escalation.why is required")
        return self


class QualityGateResult(BaseModel):
    status: QualityGateStatus = QualityGateStatus.FAIL
    passed: bool = False
    coverage_score: float = 0.0
    false_positive_risk: float = 0.0
    blocked: int = 0
    reasons: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _sync_passed(self) -> QualityGateResult:
        if (
            self.status == QualityGateStatus.PASS
            and not self.reasons
            or self.status in (QualityGateStatus.PASS_WITH_WARNINGS,)
        ):
            self.passed = True
        else:
            self.passed = False
        return self


QualityGate = QualityGateResult  # alias for short namespaces (backward compat)


class RunManifest(BaseModel):
    run_id: str
    agent_version: str = "1.0.0"
    timestamp: datetime = Field(default_factory=_utc_now)
    started_at: datetime = Field(default_factory=_utc_now)
    finished_at: datetime | None = None
    python_version: str = ""
    os: str = ""
    browser: str = "chromium"
    project_fingerprint: str = ""
    scope: dict[str, Any] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    tests_planned: int = 0
    tests_executed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_blocked: int = 0
    tests_flaky: int = 0
    test_errors: int = 0
    findings: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    artifacts: list[str] = Field(default_factory=list)
    quality_gate: dict[str, Any] = Field(default_factory=dict)
    retries: int = 0
    escalations: list[str] = Field(default_factory=list)
    scope_limitations: list[str] = Field(default_factory=list)
    environment: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    interrupted: bool = False
    version: str = "1.0.0"
    target: str = ""

    def to_safe_dict(self, redaction: RedactionPolicy | None = None) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        if redaction is not None:
            for key in (
                "configuration",
                "environment",
                "budget",
                "scope",
                "quality_gate",
            ):
                if isinstance(data.get(key), (dict, list, str)):
                    data[key] = _redact_recursive(data[key], redaction)
        return data

    def save(self, path: str | Any) -> Any:
        import json as _json
        from pathlib import Path as _Path

        p = _Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        payload = _json.dumps(
            self.to_safe_dict(), indent=2, default=str, ensure_ascii=False
        )
        p.write_text(payload, encoding="utf-8")
        return p


# ---------------------------------------------------------------------------
# Traceability helpers (AC-02)
# ---------------------------------------------------------------------------


class TraceabilityIndex(BaseModel):
    requirements: dict[str, Requirement] = Field(default_factory=dict)
    risks: dict[str, Risk] = Field(default_factory=dict)
    tests: dict[str, TestCase] = Field(default_factory=dict)
    findings: dict[str, Finding] = Field(default_factory=dict)
    evidences: dict[str, Evidence] = Field(default_factory=dict)

    def add_requirement(self, r: Requirement) -> None:
        self.requirements[r.requirement_id] = r

    def add_risk(self, r: Risk) -> None:
        self.risks[r.risk_id] = r

    def add_test(self, t: TestCase) -> None:
        self.tests[t.test_id] = t

    def add_finding(self, f: Finding) -> None:
        self.findings[f.finding_id] = f

    def add_evidence(self, e: Evidence) -> None:
        self.evidences[e.evidence_id] = e

    def tests_for_requirement(self, requirement_id: str) -> list[TestCase]:
        return [t for t in self.tests.values() if t.requirement_id == requirement_id]

    def findings_for_test(self, test_id: str) -> list[Finding]:
        return [f for f in self.findings.values() if f.test_id == test_id]

    def evidences_for_finding(self, finding_id: str) -> list[Evidence]:
        f = self.findings.get(finding_id)
        ids = set(f.evidence_ids) if f else set()
        ids.add(finding_id)
        return [
            e
            for e in self.evidences.values()
            if e.finding_id == finding_id or e.evidence_id in ids
        ]

    def requirement_coverage_state(self, requirement_id: str) -> CoverageState:
        tests = self.tests_for_requirement(requirement_id)
        if not tests:
            return CoverageState.NOT_COVERED
        findings_for_req = []
        for t in tests:
            findings_for_req.extend(self.findings_for_test(t.test_id))
        if any(f.status == FindingStatus.BLOCKED for f in findings_for_req):
            return CoverageState.BLOCKED
        passed = sum(
            1
            for f in findings_for_req
            if f.status == FindingStatus.PASSED or f.severity == FindingSeverity.INFO
        )
        if passed == len(findings_for_req) and findings_for_req:
            return CoverageState.COVERED
        if findings_for_req:
            return CoverageState.PARTIALLY_COVERED
        if any(t.impossible_reason for t in tests):
            return CoverageState.BLOCKED
        return CoverageState.PARTIALLY_COVERED


# ---------------------------------------------------------------------------
# Redaction (backward compat + central interface point)
# ---------------------------------------------------------------------------


def _redact_recursive(value: Any, policy: RedactionPolicy) -> Any:
    if isinstance(value, str):
        return policy.redact(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if _is_sensitive_key(k):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_recursive(v, policy)
        return out
    if isinstance(value, list):
        return [_redact_recursive(v, policy) for v in value]
    if isinstance(value, tuple):
        return tuple(_redact_recursive(v, policy) for v in value)
    return value


_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[-_ ]?key|apikey|authorization|auth|cookie|set[-_ ]?cookie|bearer|jwt|credential)"
)


def _is_sensitive_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return bool(_SENSITIVE_KEY_RE.search(key))


class RedactionPolicy:
    """Centralised redaction for sensitive values before logging or exporting."""

    marker: str = "[REDACTED]"
    _key_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(
            r"(?i)\b(authorization|cookie|set-cookie|bearer|token|api[-_ ]?key|apikey|secret|password|passwd|pwd|credential)\b"
        ),
    )
    _value_patterns: tuple[re.Pattern[str], ...] = (
        re.compile(r"(?i)(bearer\s+[A-Za-z0-9_\-\.]{5,})"),
        re.compile(r"(?i)(basic\s+[A-Za-z0-9+/=]{4,})"),
        re.compile(
            r"(?i)(^eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}$)"
        ),
        re.compile(r"(?i)([a-z][a-z0-9+.\-_]*://[^\s:\"']+:[^\s@\"']+@)"),
        re.compile(r"(?i)(password\s*[=:]\s*[\"']?[^\s\"'&,;]{3,})"),
        re.compile(r"(?i)(token\s*[=:]\s*[\"']?[^\s\"'&,;]{3,})"),
        re.compile(r"(?i)(api[-_ ]?key\s*[=:]\s*[\"']?[^\s\"'&,;]{3,})"),
        re.compile(r"(?i)(secret\s*[=:]\s*[\"']?[^\s\"'&,;]{3,})"),
    )

    def __init__(self, marker: str | None = None) -> None:
        if marker is not None:
            self.marker = marker

    def redact(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        out = value
        for pat in self._value_patterns:
            out = pat.sub(lambda m: self._replace_match(m.group(0)), out)
        lower = out.lower()
        if any(pat.search(out) for pat in self._key_patterns):
            # If a sensitive key name is present in the line, be conservative
            if any(
                tok in lower
                for tok in (
                    "authorization",
                    "cookie",
                    "set-cookie",
                    "bearer",
                    "token",
                    "api_key",
                    "apikey",
                    "secret",
                    "password",
                    "passwd",
                )
            ):
                if "=" in out or ":" in out:
                    return self.marker
        return out

    def _replace_match(self, s: str) -> str:
        # Preserve scheme prefix in URLs: postgres://user:[REDACTED]@host
        if "://" in s and "@" in s:
            m = re.match(r"^([a-zA-Z][a-zA-Z0-9+\-.]*://[^:]+:).+(@.*)$", s)
            if m:
                return f"{m.group(1)}{self.marker}{m.group(2)}"
        return self.marker


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    "BudgetConfig",
    "Confidence",
    "ConfidenceLevel",
    "CoverageState",
    "DiscoveredProject",
    "Escalation",
    "Evidence",
    "ExecutionConfig",
    "ExecutionRun",
    "Finding",
    "FindingCategory",
    "FindingSeverity",
    "FindingStatus",
    "Project",
    "ProjectProfile",
    "ProjectScope",
    "QualityGate",
    "RequirementCategory",
    "RequirementClassification",
    "ResourceBudget",
    "RiskLevel",
    "QualityGateResult",
    "QualityGateStatus",
    "RedactionPolicy",
    "Requirement",
    "RequirementClassification",
    "RetryDecision",
    "Risk",
    "RiskSeverity",
    "RunManifest",
    "Severity",
    "TestCase",
    "TestCaseStatus",
    "TestResult",
    "TestStatus",
    "TestStep",
    "TraceabilityIndex",
    "_stable_id",
    "_utc_now",
]
