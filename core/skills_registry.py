# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Skill registry.

Dynamically binds named skills to the existing local engines without rewriting
those engines. Skills stay read-only/defensive.

Extended SkillContract declaration:
  name, version, purpose, description, inputs, outputs,
  required_tools, risk, timeout_seconds, resource_budget,
  supported_targets, idempotent, requires_browser, destructive_allowed,
  handler (callable)

Registry.register_defaults() — auto-binds:
  crawler, form_tester, a11y, api, scope, evidence, discovery
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.actions import Action, Result, now_ms
from core.models import (
    Finding,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    Severity,
    ConfidenceLevel,
)
from core.scope import Budget


SkillHandler = Callable[[Action, dict[str, Any]], Result]


# Backwards compat aliases
FindingSeverity = FindingSeverity
Severity = Severity


@dataclass
class SkillContract:
    """Declarative skill contract. Future skills register here without
    modifying the orchestrator.
    """

    name: str
    description: str
    handler: SkillHandler
    idempotent: bool = True
    requires_browser: bool = False
    # ---- enterprise extension ----
    version: str = "1.0.0"
    purpose: str = ""
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)
    risk: str = "low"
    timeout_seconds: int = 120
    resource_budget: dict[str, Any] = field(default_factory=dict)
    supported_targets: list[str] = field(default_factory=lambda: ["http", "file", "local-project"])
    destructive_allowed: bool = False


class SkillRegistry:
    def __init__(self) -> None:
        self._skills: dict[str, SkillContract] = {}
        self.register_defaults()

    def register(self, contract: SkillContract) -> None:
        self._skills[contract.name] = contract

    def get(self, name: str) -> SkillContract | None:
        return self._skills.get(name)

    def names(self) -> list[str]:
        return sorted(self._skills)

    def contracts(self) -> dict[str, SkillContract]:
        return dict(self._skills)

    def register_defaults(self) -> None:
        self.register(
            SkillContract(
                "crawler",
                "In-scope crawl using core.crawler",
                _run_crawler,
                True,
                True,
                version="1.0.0",
                purpose="Traverse same-origin HTML pages and collect URL/console/performance findings.",
                inputs=["target_url", "max_depth", "scope"],
                outputs=["CrawlFinding list", "ConsoleError list", "PerformanceMetrics list"],
                required_tools=["playwright/chromium"],
                risk="low",
                timeout_seconds=300,
                resource_budget={"max_browser_contexts": 1, "max_temp_files": 32, "max_screenshots": 32},
                supported_targets=["http", "https"],
            )
        )
        self.register(
            SkillContract(
                "form_tester",
                "Defensive form fuzz using core.form_tester",
                _run_form_tester,
                True,
                False,
                version="1.0.0",
                purpose="Submit synthetic, harmless, bounded payloads into detected forms.",
                inputs=["form_selector", "payload_list", "boundary_values"],
                outputs=["FormFinding list"],
                required_tools=[],
                risk="low",
                timeout_seconds=120,
                resource_budget={},
                supported_targets=["http", "https", "local-file"],
            )
        )
        self.register(
            SkillContract(
                "a11y",
                "Accessibility checks using core.a11y_auditor",
                _run_a11y,
                True,
                True,
                version="1.0.0",
                purpose="Partial heuristics: alt text, labels, headings, ARIA, duplicate IDs, semantics.",
                inputs=["page_html", "url"],
                outputs=["A11yFinding list"],
                required_tools=["playwright/chromium"],
                risk="low",
                timeout_seconds=60,
                resource_budget={"max_screenshots": 4},
                supported_targets=["http", "https", "local-file"],
            )
        )
        self.register(
            SkillContract(
                "api",
                "API intercept using core.api_auditor",
                _run_api,
                True,
                False,
                version="1.0.0",
                purpose="Intercept network responses; flag 4xx/5xx/invalid-content-type/slow/missing headers.",
                inputs=["network_request/response stream"],
                outputs=["ApiFinding list"],
                required_tools=["httpx/playwright-request-intercept"],
                risk="low",
                timeout_seconds=120,
                resource_budget={"max_response_size_bytes": 16 * 1024 * 1024},
                supported_targets=["http", "https"],
            )
        )
        self.register(
            SkillContract(
                "scope",
                "Scope and budget enforcement",
                _run_scope,
                True,
                False,
                version="1.0.0",
                purpose="Fail-closed DENY-UNKNOWN. No network; returns INFO finding only.",
                inputs=["Scope", "Budget"],
                outputs=["Info finding"],
                required_tools=[],
                risk="low",
                timeout_seconds=5,
                resource_budget={},
                supported_targets=["*"],
            )
        )
        self.register(
            SkillContract(
                "evidence",
                "Evidence and manifest checkpoint",
                _run_evidence,
                True,
                False,
                version="1.0.0",
                purpose="Verify temporary+final evidence dirs; checkpoint manifest to disk.",
                inputs=["EvidenceManager"],
                outputs=["Info finding"],
                required_tools=[],
                risk="low",
                timeout_seconds=15,
                resource_budget={},
                supported_targets=["*"],
            )
        )
        self.register(
            SkillContract(
                "discovery",
                "Read-only project discovery",
                _run_discovery,
                True,
                False,
                version="1.0.0",
                purpose="Inspect target directory; build ProjectProfile without writes.",
                inputs=["target_path"],
                outputs=["ProjectProfile"],
                required_tools=[],
                risk="low",
                timeout_seconds=60,
                resource_budget={},
                supported_targets=["local-project", "file"],
            )
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _info(
    finding_id: str,
    category: FindingCategory,
    title: str,
    description: str,
    source: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        category=category,
        severity=FindingSeverity.INFO,
        confidence=ConfidenceLevel.HIGH,
        title=title,
        description=description,
        location="",
        source_skill=source,
        status=FindingStatus.OPEN,
        recommendation="Continue within declared scope.",
    )


# ---------------------------------------------------------------------------
# Live-session plumbing (shared, bounded: one browser per run)
# ---------------------------------------------------------------------------


def _live_session(context: dict[str, Any], action: Action) -> Any:
    """Return the shared live browser session for this execute() pass.

    Created lazily on the first skill that needs it and stored in the context
    so every skill reuses the same audit memory (visited URLs, page HTML).
    Returns None when live execution is disabled (dry-run, non-HTTP target),
    the scope guard is missing, or the Playwright cycle cannot start; the
    caller then falls back to bind-level behavior. The executor closes the
    session after the pass (bookkeeping no-op in the current one-cycle
    design).
    """
    from core.live_session import LiveBrowserSession

    session = context.get("_session")
    if session is not None:
        return session
    if not context.get("live_enabled", False):
        return None

    scope = context.get("scope")
    budget = context.get("budget")
    target = str(action.params.get("target") or context.get("target") or "")
    if scope is None or budget is None or not str(target).startswith(("http://", "https://")):
        return None

    session = LiveBrowserSession(
        origin=target,
        scope=scope,
        budget=budget,
        evidence=context.get("evidence"),
        browser_name=str(context.get("browser") or "chromium"),
        headless=True,
        output_dir=Path(str(context.get("output_dir") or "reports")),
    )
    context["_session"] = session
    return session


def _run_crawler(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    from core import crawler as crawler_mod

    budget: Budget | None = context.get("budget")
    target = str(action.params.get("target") or context.get("target") or "")
    if not context.get("live_enabled", False):
        # Bind-level path (dry-run / local-project targets): announce + consume.
        if budget is not None and not budget.consume_request():
            return Result(ok=True, skipped=True, error=budget.exhausted_reason, findings=[], test_id=action.test_id, execution_time_ms=(now_ms() - started))
        return Result(
            ok=True,
            findings=[
                _info(
                    "skill-crawler-1",
                    FindingCategory.CRAWL,
                    "Crawler skill bound",
                    f"Bound to {getattr(crawler_mod, 'Crawler', 'Crawler').__name__} for target {target}",
                    "crawler",
                )
            ],
            metadata={"engine": "core.crawler", "mode": "bind"},
            test_id=action.test_id,
            execution_time_ms=(now_ms() - started),
        )

    session = _live_session(context, action)
    if session is not None:
        try:
            findings = session.crawl()
            return Result(
                ok=True,
                findings=findings,
                metadata={
                    "engine": "core.crawler",
                    "mode": "live",
                    "pages_visited": session.session_meta().pages_visited,
                    "scope_omits": session.session_meta().omits,
                },
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )
        except Exception as exc:  # noqa: BLE001 — live failure degrades to bind-level
            return Result(
                ok=True,
                findings=[
                    _info(
                        "skill-crawler-1",
                        FindingCategory.CRAWL,
                        "Live crawl failed — degraded to bind-level",
                        f"live session error: {exc}",
                        "crawler",
                    )
                ],
                metadata={"engine": "core.crawler", "mode": "bind", "error": str(exc)[:200]},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )

    return Result(
        ok=True,
        findings=[
            _info(
                "skill-crawler-1",
                FindingCategory.CRAWL,
                "Crawler skill bound",
                f"Bound to {getattr(crawler_mod, 'Crawler', 'Crawler').__name__} for target {target}",
                "crawler",
            )
        ],
        metadata={"engine": "core.crawler", "mode": "bind"},
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_form_tester(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    from core.form_tester import TestFormInjector, build_boundary_values, build_synthetic_payloads, BoundaryKind

    budget: Budget | None = context.get("budget")
    if not context.get("live_enabled", False):
        # Bind-level path (dry-run / local-project targets).
        if budget is not None and not budget.consume_request():
            return Result(ok=True, skipped=True, error=budget.exhausted_reason, test_id=action.test_id, execution_time_ms=(now_ms() - started))
        injector = TestFormInjector()
        finding = injector.inject_into(
            inputs=[],
            payloads=build_synthetic_payloads(),
            boundary_values=build_boundary_values(BoundaryKind.numeric, min_value=1, max_value=10),
            html_snapshot=None,
        )
        return Result(
            ok=True,
            findings=[
                _info(
                    "skill-form-1",
                    FindingCategory.FORM,
                    "Form tester skill bound",
                    finding.detail,
                    "form_tester",
                )
            ],
            metadata={"payloads_tested": finding.payloads_tested, "action": action.name, "mode": "bind"},
            test_id=action.test_id,
            execution_time_ms=(now_ms() - started),
        )

    session = _live_session(context, action)
    if session is not None:
        try:
            live_findings = session.exercise_forms()
            return Result(
                ok=True,
                findings=live_findings or [],
                metadata={
                    "payloads_tested": 0,
                    "action": action.name,
                    "mode": "live",
                    "forms_exercised": len(live_findings),
                },
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )
        except Exception as exc:  # noqa: BLE001 — live failure degrades to bind-level
            return Result(
                ok=True,
                findings=[
                    _info(
                        "skill-form-1",
                        FindingCategory.FORM,
                        "Form tester skill bound",
                        f"live form exercise failed: {exc}",
                        "form_tester",
                    )
                ],
                metadata={"payloads_tested": 0, "action": action.name, "mode": "bind"},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )

    injector = TestFormInjector()
    finding = injector.inject_into(
        inputs=[],
        payloads=build_synthetic_payloads(),
        boundary_values=build_boundary_values(BoundaryKind.numeric, min_value=1, max_value=10),
        html_snapshot=None,
    )
    return Result(
        ok=True,
        findings=[
            _info(
                "skill-form-1",
                FindingCategory.FORM,
                "Form tester skill bound",
                finding.detail,
                "form_tester",
            )
        ],
        metadata={"payloads_tested": finding.payloads_tested, "action": action.name, "mode": "bind"},
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_a11y(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    from core import a11y_auditor as a11y_mod

    if not context.get("live_enabled", False):
        # Bind-level path (dry-run / local-project targets).
        return Result(
            ok=True,
            findings=[
                _info(
                    "skill-a11y-1",
                    FindingCategory.ACCESSIBILITY,
                    "Accessibility skill bound",
                    f"Bound to {getattr(a11y_mod, 'A11yAuditor', 'A11yAuditor').__name__}",
                    "a11y_auditor",
                )
            ],
            metadata={"action": action.name, "mode": "bind"},
            test_id=action.test_id,
            execution_time_ms=(now_ms() - started),
        )

    session = _live_session(context, action)
    if session is not None:
        try:
            findings = session.a11y_sweep()
            return Result(
                ok=True,
                findings=findings,
                metadata={"action": action.name, "mode": "live", "pages_visited": session.session_meta().pages_visited},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )
        except Exception as exc:  # noqa: BLE001 — live failure degrades to bind-level
            return Result(
                ok=True,
                findings=[
                    _info(
                        "skill-a11y-1",
                        FindingCategory.ACCESSIBILITY,
                        "Live a11y sweep failed — degraded to bind-level",
                        f"live session error: {exc}",
                        "a11y_auditor",
                    )
                ],
                metadata={"action": action.name, "mode": "bind"},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )

    return Result(
        ok=True,
        findings=[
            _info(
                "skill-a11y-1",
                FindingCategory.ACCESSIBILITY,
                "Accessibility skill bound",
                f"Bound to {getattr(a11y_mod, 'A11yAuditor', 'A11yAuditor').__name__}",
                "a11y_auditor",
            )
        ],
        metadata={"action": action.name},
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_api(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    from core.api_auditor import ApiAuditor

    budget: Budget | None = context.get("budget")
    if not context.get("live_enabled", False):
        # Bind-level path (dry-run / local-project targets).
        if budget is not None and not budget.consume_request():
            return Result(ok=True, skipped=True, error=budget.exhausted_reason, test_id=action.test_id, execution_time_ms=(now_ms() - started))
        auditor = ApiAuditor()
        summary = auditor.summarize([])
        return Result(
            ok=True,
            findings=[
                _info(
                    "skill-api-1",
                    FindingCategory.API,
                    "API auditor skill bound",
                    f"Interceptor ready; observed {summary['total']} findings",
                    "api_auditor",
                )
            ],
            metadata={"mode": "bind"},
            test_id=action.test_id,
            execution_time_ms=(now_ms() - started),
        )

    session = _live_session(context, action)
    if session is not None:
        try:
            endpoints = list(context.get("api_endpoints") or [])
            findings = session.probe_apis(endpoints)
            return Result(
                ok=True,
                findings=findings,
                metadata={"mode": "live", "endpoints_probed": len(endpoints) or len(findings)},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )
        except Exception as exc:  # noqa: BLE001 — live failure degrades to bind-level
            return Result(
                ok=True,
                findings=[
                    _info(
                        "skill-api-1",
                        FindingCategory.API,
                        "Live API probe failed — degraded to bind-level",
                        f"live session error: {exc}",
                        "api_auditor",
                    )
                ],
                metadata={"mode": "bind"},
                test_id=action.test_id,
                execution_time_ms=(now_ms() - started),
            )

    auditor = ApiAuditor()
    summary = auditor.summarize([])
    return Result(
        ok=True,
        findings=[
            _info(
                "skill-api-1",
                FindingCategory.API,
                "API auditor skill bound",
                f"Interceptor ready; observed {summary['total']} findings",
                "api_auditor",
            )
        ],
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_scope(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    budget: Budget | None = context.get("budget")
    scope = budget.scope if budget is not None else None
    detail = "scope unavailable"
    if scope is not None:
        detail = (
            f"same-origin default allow_external={scope.allow_external} "
            f"max_pages={scope.max_pages} max_requests={scope.max_requests}"
        )
    return Result(
        ok=True,
        findings=[_info("skill-scope-1", FindingCategory.SECURITY, "Scope guard active", detail, "scope")],
        metadata={"action": action.name},
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_evidence(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    evidence = context.get("evidence")
    detail = "evidence manager bound"
    if evidence is not None:
        detail = f"temporary={evidence.temporary_dir} final={evidence.final_dir}"

    # Live mode: capture one redacted screenshot of the origin as concrete
    # evidence. Bounded (count cap + budget) and best-effort by design.
    captured = 0
    session = _live_session(context, action)
    if session is not None and context.get("live_enabled", False):
        try:
            session.capture_screenshot(str(context.get("target") or ""))
            captured = 1
        except Exception:  # noqa: BLE001 — screenshot evidence is best-effort
            captured = 0

    return Result(
        ok=True,
        findings=[_info("skill-evidence-1", FindingCategory.TEST, "Evidence checkpoint", detail, "evidence")],
        metadata={"action": action.name, "mode": "live" if captured else "bind", "screenshot_captured": captured},
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )


def _run_discovery(action: Action, context: dict[str, Any]) -> Result:
    started = now_ms()
    profile = context.get("profile")
    description = "discovery unavailable"
    if profile is not None:
        description = profile.summary()
    return Result(
        ok=True,
        findings=[_info("skill-discovery-1", FindingCategory.TEST, "Discovery complete", description, "discovery")],
        test_id=action.test_id,
        execution_time_ms=(now_ms() - started),
    )
