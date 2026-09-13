# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Local-first QA orchestration CLI.

Runs sequentially:
- Discovery
- Scope Check
- Crawl
- Form Fuzz
- Accessibility
- API Intercept
- Report

This is an orchestration layer. It does not rewrite existing engines.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from core.analyzer import FailureAnalyzer
from core.discovery import discover_project
from core.evidence import EvidenceManager, RunManifest
from core.models import Finding, FindingCategory, Severity, RedactionPolicy
from core.report_builder import ReportBuilder
from core.scope import Budget, Scope, ScopeViolationError


def build_scope(url: str, max_pages: int, max_requests: int, max_depth: int, timeout: int) -> Scope:
    return Scope(
        allowed_origin=url,
        max_pages=max_pages,
        max_requests=max_requests,
        max_depth=max_depth,
        per_request_timeout_seconds=timeout,
        allow_external=False,
    )


async def run_orchestration(target: str, budget: Budget, evidence: EvidenceManager) -> list[Finding]:
    findings: list[Finding] = []

    discovery = discover_project(target if Path(target).exists() else ".")
    findings.append(
        Finding(
            id="discovery-1",
            category=FindingCategory.TEST,
            severity=Severity.INFO,
            title="Discovery completed",
            description=f"Detected {discovery.language or 'unknown'} project with {len(discovery.test_files)} test files",
            location=str(discovery.root),
            evidence=discovery.summary(),
            source="discovery",
        )
    )

    if not budget.consume_page():
        findings.append(
            Finding(
                id="budget-scope-1",
                category=FindingCategory.TIMEOUT,
                severity=Severity.MEDIUM,
                title="Scope budget halted discovery",
                description=budget.exhausted_reason or "budget exceeded",
                source="scope",
            )
        )
        return findings

    findings.append(
        Finding(
            id="scope-1",
            category=FindingCategory.TEST,
            severity=Severity.INFO,
            title="Scope guard active",
            description=f"Same-origin only, max_pages={budget.scope.max_pages}, max_requests={budget.scope.max_requests}",
            source="scope",
        )
    )

    try:
        findings.append(_simulate_crawl(target, budget, evidence))
    except ScopeViolationError as exc:
        findings.append(
            Finding(
                id="scope-violation-1",
                category=FindingCategory.NETWORK_FAILURE,
                severity=Severity.HIGH,
                title="Scope violation blocked",
                description=str(exc),
                location=exc.url or "",
                source="scope",
                confidence=1.0,
            )
        )

    findings.append(_simulate_form_fuzz(budget, evidence))
    findings.append(_simulate_a11y(evidence))
    findings.append(_simulate_api_audit(budget, evidence))
    return findings


def _simulate_crawl(target: str, budget: Budget, evidence: EvidenceManager) -> Finding:
    if not budget.consume_request():
        return Finding(
            id="crawl-budget-1",
            category=FindingCategory.TIMEOUT,
            severity=Severity.MEDIUM,
            title="Crawl skipped due to budget",
            description=budget.exhausted_reason or "request budget exhausted",
            source="crawler",
        )
    return Finding(
        id="crawl-1",
        category=FindingCategory.CRAWL,
        severity=Severity.INFO,
        title="Crawl phase simulated",
        description="Crawl engine would run here using existing core.crawler implementation",
        source="crawler",
    )


def _simulate_form_fuzz(budget: Budget, evidence: EvidenceManager) -> Finding:
    if not budget.consume_request():
        return Finding(
            id="form-budget-1",
            category=FindingCategory.TIMEOUT,
            severity=Severity.MEDIUM,
            title="Form fuzz skipped due to budget",
            description=budget.exhausted_reason or "request budget exhausted",
            source="form_tester",
        )
    return Finding(
        id="form-1",
        category=FindingCategory.FORM,
        severity=Severity.INFO,
        title="Form fuzz phase simulated",
        description="Form fuzzer would run here using existing core.form_tester implementation",
        source="form_tester",
    )


def _simulate_a11y(evidence: EvidenceManager) -> Finding:
    return Finding(
        id="a11y-1",
        category=FindingCategory.ACCESSIBILITY,
        severity=Severity.INFO,
        title="Accessibility phase simulated",
        description="Accessibility auditor would run here using existing core.a11y_auditor implementation",
        source="a11y_auditor",
    )


def _simulate_api_audit(budget: Budget, evidence: EvidenceManager) -> Finding:
    if not budget.consume_request():
        return Finding(
            id="api-budget-1",
            category=FindingCategory.TIMEOUT,
            severity=Severity.MEDIUM,
            title="API audit skipped due to budget",
            description=budget.exhausted_reason or "request budget exhausted",
            source="api_auditor",
        )
    return Finding(
        id="api-1",
        category=FindingCategory.API,
        severity=Severity.INFO,
        title="API audit phase simulated",
        description="API auditor would run here using existing core.api_auditor implementation",
        source="api_auditor",
    )


def build_report(target: str, findings: list[Finding], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_builder = ReportBuilder(template_dir=Path(__file__).resolve().parent / "reports")
    markdown = report_builder.build(target=target, findings=findings)
    html = report_builder.build_html(target=target, findings=findings)
    jira = report_builder.build_jira(target, findings)
    payload = report_builder.build_json(target=target, findings=findings)

    (output_dir / "audit_report.md").write_text(markdown, encoding="utf-8")
    (output_dir / "audit_report.html").write_text(html, encoding="utf-8")
    (output_dir / "jira_export.md").write_text(jira, encoding="utf-8")
    (output_dir / "audit_report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="QA Automation Agent local-first orchestration")
    parser.add_argument("--target", default=".", help="Project directory or target URL")
    parser.add_argument("--url", default=None, help="Optional target URL for web scope")
    parser.add_argument("--max-pages", type=int, default=10)
    parser.add_argument("--max-requests", type=int, default=20)
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", default="reports", help="Report output directory")
    args = parser.parse_args()

    output_dir = Path(args.output).resolve()
    evidence = EvidenceManager(temporary_dir=output_dir / "tmp", final_dir=output_dir / "final")
    manifest = RunManifest(
        run_id=str(uuid.uuid4()),
        started_at=datetime.now(timezone.utc),
        target=args.url or args.target,
        configuration={
            "max_pages": args.max_pages,
            "max_requests": args.max_requests,
            "max_depth": args.max_depth,
            "timeout": args.timeout,
        },
        environment={"python": sys.version, "cwd": str(Path.cwd())},
    )
    evidence.manifest = manifest

    scope_target = args.url or ("https://example.test" if args.target == "." else args.target)
    budget = Budget(scope=build_scope(scope_target, args.max_pages, args.max_requests, args.max_depth, args.timeout))
    budget.start()

    findings = asyncio.run(run_orchestration(args.target, budget, evidence))

    analyzer = FailureAnalyzer()
    for finding in findings:
        classification = analyzer.classify(finding)
        finding.metadata["failure_type"] = classification.failure_type.value
        finding.metadata["classification_confidence"] = classification.confidence

    redaction = RedactionPolicy()
    evidence.finalize(findings, output_dir, redaction=redaction)
    build_report(args.target, findings, output_dir)

    print(f"Run complete. Run ID: {manifest.run_id}")
    print(f"Findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    try:
        from uuid import uuid4
    except Exception:
        def uuid4():
            import random
            import time
            return f"{int(time.time() * 1000000)}-{random.randint(0, 999999)}"

    raise SystemExit(main())
