# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Autonomous decision loop and deterministic executor.

State machine:
DISCOVER -> UNDERSTAND -> PLAN -> GENERATE -> EXECUTE -> OBSERVE -> ANALYZE
-> RETRY -> VERIFY -> REPORT -> ESCALATE -> DONE

Planner, Executor, and DecisionAgent are separate objects. The orchestrator
only advances state. Hard guarantees:

  * Global step cap — the loop can NEVER spin forever.
  * Retries bounded by the RetryController (max 3 per signature, global cap).
  * Escalations recorded with WHY / WHAT WAS ATTEMPTED / EVIDENCE / INPUT NEEDED.
  * Every artifact written atomically; a crash never yields a fake success.
  * Findings deduplicated by canonical fingerprint before reporting.
"""

from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from core.actions import Action, Result
from core.crash_recovery import CrashRecoveryManager, InterruptKind
from core.discovery import ProjectProfile, discover_project
from core.escalation import HumanEscalationRegistry
from core.evidence import EvidenceManager, RunManifest
from core.failure_analyzer import FailureAnalyzer
from core.finding_manager import FindingManager, score_confidence
from core.llm_boundary import LLMBoundary
from core.logger import StructuredLogger, get_logger
from core.models import (
    CoverageState,
    Finding,
    FindingCategory,
    FindingStatus,
    RedactionPolicy,
    Requirement,
    Severity,
    TestCase,
    TestCaseStatus,
    TestResult,
    TestStatus,
)
from core.planner import TestPlan, build_plan_from_discovery, generate_test_cases
from core.quality_gate import CoverageEngine, CoverageReport, QualityGate, QualityGateResult

try:  # config imports quality-gate-adjacent models; keep orchestrator importable either way
    from core.config import QualityGatePolicy
except ImportError:  # pragma: no cover - defensive: direct module execution
    QualityGatePolicy = None  # type: ignore[assignment,misc]

from core.risk_engine import ProfileRiskAssessment, assess_risks
from core.scope import Budget, Scope
from core.session_manager import SessionManager
from core.skills_registry import SkillRegistry
from core.spec_analyzer import SpecAnalysis, analyze_specs
from core.strategist import QAStrategist, Strategy


class AgentState(str, Enum):
    DISCOVER = "DISCOVER"
    UNDERSTAND = "UNDERSTAND"
    PLAN = "PLAN"
    GENERATE = "GENERATE"
    EXECUTE = "EXECUTE"
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    RETRY = "RETRY"
    VERIFY = "VERIFY"
    REPORT = "REPORT"
    ESCALATE = "ESCALATE"
    DONE = "DONE"


# Hard cap on state transitions for one run. The loop cannot exceed this.
MAX_LOOP_STEPS = 48


@dataclass
class Escalation:
    reason: str
    halt: bool = True
    details: str = ""


@dataclass
class RunContext:
    target: str
    output_dir: Path
    budget: Budget
    evidence: EvidenceManager
    risk_level: str = "low"
    browser: str = "chromium"
    run_id: str = ""
    profile: ProjectProfile | None = None
    spec: SpecAnalysis | None = None
    strategy: Strategy | None = None
    plan: TestPlan | None = None
    actions: list[Action] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    last_results: list[Result] = field(default_factory=list)
    escalation: Escalation | None = None
    gate: QualityGateResult | None = None
    history: list[str] = field(default_factory=list)
    # --- enterprise extensions ---
    requirements: list[Requirement] = field(default_factory=list)
    risk_assessment: ProfileRiskAssessment | None = None
    test_cases: list[TestCase] = field(default_factory=list)
    test_results: dict[str, TestResult] = field(default_factory=dict)
    coverage: CoverageReport | None = None
    session_public: dict | None = None
    scope_violations: int = 0
    escalation_registry: HumanEscalationRegistry = field(default_factory=HumanEscalationRegistry)
    logger: StructuredLogger | None = None
    interrupted: bool = False
    interrupt_reason: str = ""
    gate_policy: "QualityGatePolicy | None" = None  # per-profile quality-gate thresholds
    dry_run: bool = False  # when True, skills never open live browser sessions


class Planner:
    """Produces requirements, risks, a TestPlan, and Actions. Never executes skills."""

    def __init__(self, strategist: QAStrategist | None = None) -> None:
        self.strategist = strategist or QAStrategist()

    def understand(self, ctx: RunContext) -> SpecAnalysis:
        root = ctx.profile.root if ctx.profile is not None else Path(ctx.target)
        try:
            return analyze_specs(root)
        except Exception:
            return analyze_specs(Path("."))

    def plan(self, ctx: RunContext) -> tuple[Strategy, TestPlan]:
        assert ctx.profile is not None
        strategy = self.strategist.select(ctx.profile, ctx.spec, ctx.risk_level)
        risks = ctx.risk_assessment.per_requirement if ctx.risk_assessment is not None else {}
        plan = build_plan_from_discovery(
            ctx.profile,
            target=ctx.target,
            requirements=ctx.requirements,
            risks=risks,
            strategy=strategy,
            spec=ctx.spec,
            scope=ctx.budget.scope.project_scope,
        )
        plan.risk_level = ctx.risk_level
        return strategy, plan

    def generate(self, ctx: RunContext) -> list[Action]:
        """Map TestCases (preferred) or PlanItems into authorized Actions."""
        assert ctx.plan is not None
        actions: list[Action] = []
        if ctx.test_cases:
            for tc in ctx.test_cases:
                if tc.status == TestCaseStatus.BLOCKED:
                    continue  # impossible tests are never converted to actions
                actions.append(
                    Action(
                        name=f"{tc.skill or 'discovery'}:{tc.title[:60]}",
                        skill=tc.skill or "discovery",
                        idempotent=True,
                        destructive=False,
                        params={
                            "area": tc.skill or "discovery",
                            "target": ctx.target,
                            "priority": tc.priority,
                            "requirement_id": tc.requirement_id,
                        },
                        test_id=tc.test_id,
                        requirement_id=tc.requirement_id,
                        risk_id=tc.risk_id,
                        preconditions=list(tc.preconditions),
                        priority=tc.priority,
                    )
                )
            return actions
        for item in ctx.plan.items:
            skill = item.skill or "discovery"
            actions.append(
                Action(
                    name=f"{skill}:{item.area}",
                    skill=skill,
                    idempotent=True,
                    destructive=False,
                    params={"area": item.area, "target": ctx.target, "priority": item.priority},
                )
            )
        return actions


class Executor:
    """Runs Action contracts through the skill registry. Never plans."""

    def __init__(self, registry: SkillRegistry | None = None, *, analyzer: FailureAnalyzer | None = None) -> None:
        self.registry = registry or SkillRegistry()
        self.analyzer = analyzer or FailureAnalyzer()

    def execute(self, actions: list[Action], ctx: RunContext) -> list[Result]:
        results: list[Result] = []
        context = {
            "target": ctx.target,
            "budget": ctx.budget,
            "evidence": ctx.evidence,
            "profile": ctx.profile,
            "browser": ctx.browser,
            "risk_level": ctx.risk_level,
            # Live-session inputs: the scope guard, output dir, and API
            # endpoints discovered from the profile (skill handlers never
            # touch RunContext directly).
            "scope": ctx.budget.scope if ctx.budget is not None else None,
            "output_dir": str(ctx.output_dir),
            "api_endpoints": list(getattr(ctx.profile, "api_endpoints", []) or []) if ctx.profile is not None else [],
            "live_enabled": not ctx.dry_run and bool(str(ctx.target).startswith(("http://", "https://"))),
        }
        try:
            for action in actions:
                contract = self.registry.get(action.skill)
                if contract is None:
                    results.append(Result(ok=False, error=f"unknown skill {action.skill}", retryable=False, test_id=action.test_id))
                    continue
                try:
                    outcome = contract.handler(action, context)
                except Exception as exc:  # noqa: BLE001 — executor must contain skill crashes
                    classification = self.analyzer.classify(
                        Finding(
                            category=FindingCategory.ENVIRONMENT,
                            severity=Severity.HIGH,
                            title=f"skill crash: {action.skill}",
                            description=str(exc)[:300],
                        )
                    )
                    outcome = Result(
                        ok=False,
                        error=f"skill {action.skill} crashed: {exc}"[:400],
                        retryable=classification.failure_type.value
                        in {"TIMEOUT", "NETWORK_FAILURE", "BROWSER_FAILURE", "INFRASTRUCTURE_FAILURE"},
                        test_id=action.test_id,
                    )
                results.append(outcome)
        finally:
            # The shared live browser session (if any skill opened one) is
            # always torn down with the executor pass — never leaked.
            session = context.get("_session")
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001 — teardown is best-effort
                    pass
        return results


class DecisionAgent:
    """Chooses the next state. Never mutates the target and never runs skills."""

    def __init__(self, *, max_retries: int = 3) -> None:
        self.max_retries = max_retries
        self.retry_rounds = 0

    def reset(self) -> None:
        self.retry_rounds = 0

    def next_state(self, state: AgentState, ctx: RunContext, analyzer: FailureAnalyzer) -> AgentState:
        if ctx.escalation and ctx.escalation.halt:
            return AgentState.ESCALATE
        if state == AgentState.DISCOVER:
            return AgentState.UNDERSTAND
        if state == AgentState.UNDERSTAND:
            return AgentState.PLAN
        if state == AgentState.PLAN:
            return AgentState.GENERATE
        if state == AgentState.GENERATE:
            return AgentState.EXECUTE
        if state == AgentState.EXECUTE:
            return AgentState.OBSERVE
        if state == AgentState.OBSERVE:
            return AgentState.ANALYZE
        if state == AgentState.ANALYZE:
            if self._needs_retry(ctx, analyzer) and self.retry_rounds < self.max_retries:
                return AgentState.RETRY
            return AgentState.VERIFY
        if state == AgentState.RETRY:
            self.retry_rounds += 1
            return AgentState.EXECUTE
        if state == AgentState.VERIFY:
            if ctx.escalation and ctx.escalation.halt:
                return AgentState.ESCALATE
            return AgentState.REPORT
        if state == AgentState.REPORT:
            return AgentState.DONE
        if state == AgentState.ESCALATE:
            return AgentState.DONE
        return AgentState.DONE

    def _needs_retry(self, ctx: RunContext, analyzer: FailureAnalyzer) -> bool:
        for result in ctx.last_results:
            if result.ok and not result.retryable:
                continue
            if result.retryable and result.error:
                probe = Action(name="retry-probe", skill="scope", idempotent=True, test_id=result.test_id)
                classification = analyzer.classify(
                    Finding(
                        category=FindingCategory.TIMEOUT,
                        severity=Severity.MEDIUM,
                        title=result.error[:200],
                        description=result.error,
                        evidence=result.error,
                    )
                )
                if analyzer.should_retry(classification, probe):
                    return True
        return False


class Orchestrator:
    def __init__(
        self,
        planner: Planner | None = None,
        executor: Executor | None = None,
        decision: DecisionAgent | None = None,
        analyzer: FailureAnalyzer | None = None,
        gate: QualityGate | None = None,
        *,
        logger: StructuredLogger | None = None,
    ) -> None:
        self.planner = planner or Planner()
        self.executor = executor or Executor()
        self.decision = decision or DecisionAgent()
        self.analyzer = analyzer or FailureAnalyzer()
        # Default gate uses the QualityGatePolicy default floor; per-run
        # overrides come from ctx.gate_policy (see _gate_for).
        self.gate = gate or QualityGate()
        self._explicit_gate = gate
        self.logger = logger
        self.recovery = CrashRecoveryManager(logger=logger)
        self.boundary = LLMBoundary()  # LLM proposals can only ever PROPOSE

    # ------------------------------------------------------------------
    def _gate_for(self, ctx: RunContext) -> QualityGate:
        """Resolve the QualityGate for this run.

        Explicit constructor-injected gate wins (back-compat for tests and
        embedders). Otherwise the gate is built from ctx.gate_policy — the
        per-profile policy carried on AgentConfig — so the requirement-
        coverage floor is a profile decision, not a hardcoded 20%.
        """
        if self._explicit_gate is not None:
            return self._explicit_gate
        policy = getattr(ctx, "gate_policy", None)
        if policy is None:
            return QualityGate()
        return QualityGate(
            max_critical=policy.max_critical,
            max_high=policy.max_high,
            min_requirements_coverage=policy.effective_floor(),
            max_blocked_ratio=policy.max_blocked_ratio,
            max_flaky=policy.max_flaky,
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def run(self, ctx: RunContext) -> RunContext:
        self._ensure_run_setup(ctx)
        log = self._log(ctx)
        try:
            self._run_loop(ctx, log)
        except BaseException as exc:  # noqa: BLE001 — KeyboardInterrupt must be caught
            ctx.interrupted = True
            ctx.interrupt_reason = f"{type(exc).__name__}: {exc}"[:300]
            kind = self.recovery.classify_exception(exc)
            try:
                self.recovery.finalize_interrupted(
                    run_id=ctx.run_id,
                    output_dir=ctx.output_dir,
                    kind=kind if kind is not InterruptKind.UNKNOWN else InterruptKind.UNKNOWN,
                    detail=ctx.interrupt_reason,
                    manifest_payload=self._manifest_payload(ctx),
                    findings_count=len(ctx.findings),
                )
            except Exception:  # noqa: BLE001 — never mask the original error
                pass
            raise
        return ctx

    # ------------------------------------------------------------------
    def _ensure_run_setup(self, ctx: RunContext) -> None:
        if not ctx.run_id:
            ctx.run_id = f"run_{uuid4().hex[:16]}"
        if ctx.logger is None:
            ctx.logger = self.logger or get_logger(run_id=ctx.run_id, min_level="INFO")
        if ctx.evidence.manifest is None:
            ctx.evidence.manifest = RunManifest(
                run_id=ctx.run_id,
                started_at=datetime.now(timezone.utc),
                target=ctx.target,
            )
        try:
            session = SessionManager()
            ctx.session_public = session.public_info().to_dict()
        except Exception:  # noqa: BLE001 — session info is best-effort metadata
            ctx.session_public = {"state": "ANONYMOUS", "source": "none"}

    def _log(self, ctx: RunContext):
        return ctx.logger if ctx.logger is not None else self.logger

    # ------------------------------------------------------------------
    def _run_loop(self, ctx: RunContext, log) -> None:
        state = AgentState.DISCOVER
        pending_actions: list[Action] = []
        findings_manager = FindingManager()
        steps = 0
        self.decision.reset()

        while state != AgentState.DONE:
            steps += 1
            if steps > MAX_LOOP_STEPS:
                if log:
                    log.error("loop step cap reached — forcing VERIFY", steps=steps)
                state = AgentState.VERIFY
            ctx.history.append(state.value)
            if log:
                log.debug(f"state={state.value}")

            if state == AgentState.DISCOVER:
                target_path = ctx.target if Path(ctx.target).exists() else "."
                ctx.profile = discover_project(target_path)
                if log:
                    log.info("discovery complete", language=ctx.profile.language, framework=ctx.profile.framework)

            elif state == AgentState.UNDERSTAND:
                ctx.spec = self.planner.understand(ctx)
                from core.requirements_engine import build_requirements

                req_result = build_requirements(ctx.profile, spec=ctx.spec)
                ctx.requirements = req_result.requirements
                ctx.risk_assessment = assess_risks(ctx.requirements, ctx.profile)
                if log:
                    log.info(
                        "requirements and risks assessed",
                        requirements=len(ctx.requirements),
                        profile_risk=str(ctx.risk_assessment.profile_risk.value),
                    )

            elif state == AgentState.PLAN:
                ctx.strategy, ctx.plan = self.planner.plan(ctx)
                if log:
                    log.info("plan built", items=len(ctx.plan.items), skills=ctx.strategy.selected_skills)

            elif state == AgentState.GENERATE:
                generation = generate_test_cases(ctx.plan, profile_auth_mechanisms=ctx.profile.auth_mechanisms if ctx.profile else None)
                ctx.test_cases = generation.test_cases
                ctx.actions = self.planner.generate(ctx)
                pending_actions = list(ctx.actions)
                if log:
                    log.info(
                        "tests generated",
                        cases=len(ctx.test_cases),
                        actions=len(ctx.actions),
                        duplicates_removed=generation.duplicates_removed,
                        impossible=generation.impossible_marked,
                    )
                # Impossible tests become BLOCKED results without execution
                for tc in ctx.test_cases:
                    if tc.status == TestCaseStatus.BLOCKED:
                        ctx.test_results[tc.test_id] = TestResult(
                            test_id=tc.test_id,
                            run_id=ctx.run_id,
                            status=TestStatus.BLOCKED,
                            expected=tc.expected_result,
                            actual="blocked: " + (tc.impossible_reason or "preconditions unmet"),
                        )
                esc = self.detect_escalation(ctx)
                if esc is not None:
                    ctx.escalation = esc
                    ctx.escalation_registry.escalate(
                        esc.reason,
                        what_was_attempted="Stopped before executing any action against the target.",
                        what_evidence_exists="Discovery profile and run manifest captured locally.",
                        what_human_input_is_required="Provide credentials or confirm scope/permissions, then re-run.",
                        halt=esc.halt,
                    )

            elif state == AgentState.EXECUTE:
                ctx.last_results = self.executor.execute(pending_actions, ctx)
                pending_actions = []

            elif state == AgentState.OBSERVE:
                self._observe(ctx, findings_manager, log)

            elif state == AgentState.ANALYZE:
                self._analyze_findings(ctx, findings_manager)

            elif state == AgentState.RETRY:
                retryable_ids = {
                    r.test_id
                    for r in ctx.last_results
                    if (not r.ok) and r.retryable and r.test_id
                }
                pending_actions = [a for a in ctx.actions if a.test_id in retryable_ids]
                for r in ctx.last_results:
                    if r.test_id in retryable_ids:
                        r.retry_count += 1
                if log:
                    log.warning("retrying transient failures", tests=len(pending_actions))

            elif state == AgentState.VERIFY:
                self._verify(ctx, log)

            elif state == AgentState.REPORT:
                self._write_reports(ctx)

            elif state == AgentState.ESCALATE:
                self._escalate(ctx, log)

            state = self.decision.next_state(state, ctx, self.analyzer)

        ctx.history.append(AgentState.DONE.value)
        ctx.findings = findings_manager.findings() if findings_manager._findings else ctx.findings

    # ------------------------------------------------------------------
    def _observe(self, ctx: RunContext, manager: FindingManager, log) -> None:
        new_findings: list[Finding] = []
        for result in ctx.last_results:
            # TestResult bookkeeping
            if result.test_id:
                status = self._status_from_result(result)
                prev = ctx.test_results.get(result.test_id)
                if prev is not None:
                    prev.status = status
                    prev.duration_ms = result.execution_time_ms
                    prev.error = result.error
                    prev.retries = result.retry_count
                    prev.evidence_ids = list(result.evidence_ids)
                else:
                    ctx.test_results[result.test_id] = TestResult(
                        test_id=result.test_id,
                        run_id=ctx.run_id,
                        status=status,
                        duration_ms=result.execution_time_ms,
                        expected="",
                        actual="",
                        error=result.error,
                        retries=result.retry_count,
                        evidence_ids=list(result.evidence_ids),
                    )
                self.analyzer.flaky.register_run(result.test_id, status.value.upper())
            for f in result.findings:
                f.run_id = ctx.run_id
                if result.test_id and not f.test_id:
                    f.test_id = result.test_id
                new_findings.append(f)
            if result.error and not result.ok:
                severity = Severity.MEDIUM if result.retryable else Severity.HIGH
                new_findings.append(
                    Finding(
                        category=FindingCategory.ENVIRONMENT,
                        severity=severity,
                        title=f"Executor error: {result.error[:120]}",
                        description=result.error,
                        source="executor",
                        status=FindingStatus.OPEN,
                        test_id=result.test_id or "",
                        run_id=ctx.run_id,
                    )
                )
        for f in new_findings:
            canonical, was_dup = manager.add(f)
            if was_dup:
                continue
            ctx.findings.append(canonical)
        if log:
            log.info("observations recorded", new=len(new_findings), total=len(ctx.findings))

    @staticmethod
    def _status_from_result(result: Result) -> TestStatus:
        if result.skipped:
            return TestStatus.SKIPPED
        if result.ok:
            return TestStatus.PASS
        if result.flaky_indicator:
            try:
                return TestStatus(str(result.flaky_indicator).lower())
            except ValueError:
                return TestStatus.ERROR
        return TestStatus.ERROR

    def _analyze_findings(self, ctx: RunContext, manager: FindingManager) -> None:
        for finding in ctx.findings:
            classification = self.analyzer.classify(finding)
            finding.metadata["failure_type"] = classification.failure_type.value
            finding.metadata["classification_confidence"] = round(classification.confidence, 3)
            if finding.status == FindingStatus.OPEN and finding.severity in {Severity.HIGH, Severity.CRITICAL}:
                conf = score_confidence(
                    finding,
                    reproducibility=0.5 if finding.reproduction else 0.3,
                    evidence_quality=0.8 if finding.evidence else 0.3,
                    deterministic=finding.metadata.get("flaky") is None,
                    failure_type=classification.failure_type.value,
                )
                finding.confidence = conf

    # ------------------------------------------------------------------
    def _verify(self, ctx: RunContext, log) -> None:
        execution_results: dict[str, str] = {}
        for tid, tr in ctx.test_results.items():
            execution_results[tid] = tr.status.value.upper()
        for item in (ctx.plan.items if ctx.plan else []):
            execution_results.setdefault(item.plan_id or f"planitem_{item.area}", item.status.upper())
        coverage = CoverageEngine().evaluate(
            plan_items=ctx.plan.items if ctx.plan else [],
            test_cases=ctx.test_cases,
            findings=ctx.findings,
            requirements_ids=[r.requirement_id for r in ctx.requirements],
            execution_results=execution_results,
        )
        ctx.coverage = coverage
        flaky_count = sum(1 for s in self.analyzer.flaky._runs.values() if len(set(s)) > 1)
        blocked = sum(1 for tr in ctx.test_results.values() if tr.status == TestStatus.BLOCKED)
        budget_reason = ctx.budget.exhausted_reason if ctx.budget.is_exhausted() else None
        escalations = len(ctx.escalation_registry)
        gate = self._gate_for(ctx)
        ctx.gate = gate.evaluate(
            ctx.findings,
            ctx.plan,
            coverage=coverage,
            escalations=escalations,
            flaky_count=flaky_count,
            blocked_tests=blocked,
            budget_exhausted_reason=budget_reason,
            scope_violations=ctx.scope_violations,
            credentials_missing=(ctx.session_public or {}).get("state") == "INVALID_CREDENTIALS",
        )
        if log:
            gate_floor = self._gate_for(ctx).min_requirements_coverage
            log.info(
                "quality gate evaluated",
                status=ctx.gate.status.value,
                coverage=coverage.ratio("requirements"),
                min_requirements_coverage=gate_floor,
            )

    # ------------------------------------------------------------------
    def detect_escalation(self, ctx: RunContext) -> Escalation | None:
        if ctx.risk_level == "high" and any(action.destructive for action in ctx.actions):
            return Escalation("destructive risk on high-risk run", True, "Refusing destructive actions")
        auth = ctx.profile.auth_mechanisms if ctx.profile is not None else []
        if "oauth" in auth and not Path(".env").exists() and ctx.risk_level == "high":
            return Escalation("missing credentials", True, "OAuth inferred but no local credentials file")
        if ctx.budget.is_exhausted() and ctx.budget.exhausted_reason == "runtime budget exhausted":
            return Escalation("environment/runtime exhausted", True, ctx.budget.exhausted_reason)
        return None

    def _escalate(self, ctx: RunContext, log) -> None:
        reason = ctx.escalation.reason if ctx.escalation else "halt"
        record, _created = ctx.escalation_registry.escalate(
            reason,
            what_was_attempted="Autonomous pipeline halted before further execution.",
            what_evidence_exists="Findings, evidence registry, and manifest captured locally.",
            what_human_input_is_required="Review the run report and provide the missing input, then re-run.",
            halt=True,
        )
        ctx.findings.append(
            Finding(
                category=FindingCategory.SECURITY,
                severity=Severity.HIGH,
                title="Human escalation required",
                description=record.why,
                evidence=record.what_evidence_exists,
                status=FindingStatus.NEEDS_HUMAN,
                recommendation=record.what_human_input_is_required,
                source="orchestrator",
                run_id=ctx.run_id,
            )
        )
        if log:
            log.warning("escalation fired", why=record.why, required=record.what_human_input_is_required)

    # ------------------------------------------------------------------
    def _manifest_payload(self, ctx: RunContext) -> dict:
        gate = {}
        if ctx.gate is not None:
            gate = ctx.gate.to_dict()
        return {
            "agent_version": "2.0.0",
            "target": ctx.target,
            "browser": ctx.browser,
            "python_version": sys.version.split()[0],
            "os": platform.platform(),
            "configuration": {
                "risk_level": ctx.risk_level,
                "browser": ctx.browser,
                "output_dir": str(ctx.output_dir),
                "gate_policy": (
                    {
                        "min_requirements_coverage": ctx.gate_policy.effective_floor(),
                        "floor_enabled": ctx.gate_policy.floor_enabled,
                    }
                    if ctx.gate_policy is not None
                    else None
                ),
            },
            "tests_planned": len(ctx.test_cases) or len(ctx.plan.items if ctx.plan else []),
            "tests_executed": len(ctx.test_results),
            "findings": {"total": len(ctx.findings)},
            "quality_gate": gate,
        }

    def _write_reports(self, ctx: RunContext) -> None:
        from core.atomic_write import atomic_write, atomic_write_json
        from core.report_builder import ReportBuilder

        output_dir = ctx.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        redaction = RedactionPolicy()

        if ctx.evidence.manifest is None:
            ctx.evidence.manifest = RunManifest(
                run_id=ctx.run_id,
                started_at=datetime.now(timezone.utc),
                target=ctx.target,
            )
        m = ctx.evidence.manifest
        m.agent_version = "2.0.0"
        m.python_version = sys.version.split()[0]
        m.os_name = platform.platform()
        m.browser = ctx.browser
        m.target = ctx.target
        if ctx.profile is not None:
            m.project_fingerprint = getattr(ctx.profile, "fingerprint", "") or ""
        m.scope = {
            "allowed_origin": ctx.budget.scope.allowed_origin,
            "allow_external": ctx.budget.scope.allow_external,
            "max_pages": ctx.budget.scope.max_pages,
            "max_requests": ctx.budget.scope.max_requests,
            "max_depth": ctx.budget.scope.max_depth,
        }
        m.budget = {k: v for k, v in (ctx.budget.remaining() or {}).items()}
        m.tests_planned = len(ctx.test_cases) or len(ctx.plan.items if ctx.plan else [])
        m.tests_executed = len([tr for tr in ctx.test_results.values() if tr.status != TestStatus.NOT_RUN])
        m.passed = sum(1 for tr in ctx.test_results.values() if tr.status == TestStatus.PASS)
        m.failed = sum(1 for tr in ctx.test_results.values() if tr.status in {TestStatus.FAIL, TestStatus.ERROR})
        m.blocked = sum(1 for tr in ctx.test_results.values() if tr.status == TestStatus.BLOCKED)
        m.flaky_count = sum(1 for s in self.analyzer.flaky._runs.values() if len(set(s)) > 1)
        m.retries = sum(tr.retries for tr in ctx.test_results.values())
        m.findings = {
            "total": len(ctx.findings),
            "critical": sum(1 for f in ctx.findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in ctx.findings if f.severity == Severity.HIGH),
        }
        m.escalations = [r.as_dict() for r in ctx.escalation_registry.records()]
        m.scope_limitations = [f"{o.reason}: {o.url[:120]}" for o in ctx.budget.scope.omits()[:50]]
        if ctx.gate is not None:
            m.quality_gate = ctx.gate.to_dict()
        if ctx.gate_policy is not None:
            # Reproducibility: record the exact policy the gate enforced.
            m.configuration["gate_policy"] = {
                "min_requirements_coverage": ctx.gate_policy.effective_floor(),
                "floor_enabled": ctx.gate_policy.floor_enabled,
                "max_critical": ctx.gate_policy.max_critical,
                "max_high": ctx.gate_policy.max_high,
            }

        evidence_payload = ctx.evidence.finalize(ctx.findings, output_dir, redaction=redaction)

        builder = ReportBuilder()
        markdown = builder.build(target=ctx.target, findings=ctx.findings)
        html = builder.build_html(target=ctx.target, findings=ctx.findings)
        jira = builder.build_jira(ctx.target, ctx.findings)
        payload = builder.build_json(target=ctx.target, findings=ctx.findings)
        payload["run_id"] = ctx.run_id
        if ctx.gate is not None:
            payload["quality_gate"] = ctx.gate.to_dict()
        if ctx.coverage is not None:
            payload["coverage"] = {
                "summary": ctx.coverage.summary(),
                "requirements_ratio": ctx.coverage.ratio("requirements"),
            }
        payload["escalations"] = [r.as_dict() for r in ctx.escalation_registry.records()]
        payload["limitations"] = m.scope_limitations
        payload["session"] = ctx.session_public
        payload["state_history"] = list(ctx.history)

        atomic_write(output_dir / "audit_report.md", markdown)
        atomic_write(output_dir / "audit_report.html", html)
        atomic_write(output_dir / "jira_export.md", jira)
        atomic_write_json(output_dir / "audit_report.json", payload)

    def _write_reports_legacy_name(self, ctx: RunContext) -> None:  # pragma: no cover
        self._write_reports(ctx)
