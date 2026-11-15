# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unified command-line worker: ``python -m qa_agent <command>``.

Every command is also importable as a plain function so the pytest suite can
exercise it without a subprocess. Commands write artifacts under ``--out-dir``
and print a one-line JSON summary; exit code 0 means the gate passed, 1 means
findings breached the gate, and 2 means the command could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from qa_agent import __version__
from qa_agent.api_fuzzer import ApiFuzzer, Endpoint, endpoints_from_openapi, load_openapi
from qa_agent.crawler import CrawlConfig, Crawler
from qa_agent.db_qa import audit_ddl, audit_sqlite
from qa_agent.desktop_cli_qa import audit_desktop_source, default_cli_cases, run_cli_audit
from qa_agent.functional_qa import audit_rbac, audit_workflow
from qa_agent.llm_evals import (
    evaluate_context_precision,
    evaluate_context_recall,
    evaluate_safety,
    evaluate_semantic_groundedness,
)
from qa_agent.models import Finding, Severity
from qa_agent.mobile_qa import audit_pwa_dir, fetch_pwa, inspect_apk
from qa_agent.performance_qa import LoadConfig, run_load_test
from qa_agent.reporter import write_report
from qa_agent.security_checkout import SecurityAuditor
from qa_agent.test_generator import E2ETestGenerator
from qa_agent.test_management import build_rtm, discover_tests, generate_test_plan, parse_junit_file
from qa_agent.ux_a11y_perf import UXProfiler
from qa_agent.visual_regression import DiffConfig, compare_files, save_diff, save_side_by_side

__all__ = [
    "build_parser",
    "main",
    "run_audit",
    "run_audit_apk",
    "run_audit_db",
    "run_audit_pwa",
    "run_audit_rbac",
    "run_eval_rag",
    "run_fuzz_api",
    "run_gen_test_plan",
    "run_gen_tests",
    "run_load_test_command",
    "run_test_cli",
    "run_visual_diff",
]


def _parse_ignore(values: Sequence[str]) -> tuple[tuple[int, int, int, int], ...]:
    regions: list[tuple[int, int, int, int]] = []
    for value in values:
        parts = [part.strip() for part in str(value).split(",")]
        if len(parts) != 4:
            raise ValueError(f"ignore region must be x,y,width,height: {value!r}")
        left, top, width, height = (int(part) for part in parts)
        regions.append((left, top, left + width, top + height))
    return tuple(regions)


def _gate(findings: Sequence[Finding]) -> bool:
    return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in findings)


def run_audit(
    url: str,
    out_dir: str | Path,
    *,
    max_pages: int = 15,
    max_depth: int = 3,
    strategy: str = "bfs",
    auth_state: str | None = None,
    include_ux: bool = True,
    include_security: bool = True,
    sla_ms: float = 0.0,
) -> dict[str, Any]:
    """Crawl, profile, and security-audit one target, then write deliverables."""
    findings: list[Finding] = []
    crawl = Crawler(CrawlConfig(max_pages=max_pages, max_depth=max_depth, strategy=strategy, auth_state=auth_state)).crawl(url)
    findings.extend(crawl.findings)

    metadata: dict[str, Any] = {
        "pages_crawled": len(crawl.pages),
        "console_errors": crawl.console_error_count,
        "page_errors": crawl.page_error_count,
        "crawl_duration_ms": round(crawl.duration_ms, 1),
    }

    if include_ux:
        ux = UXProfiler().profile(url, auth_state=auth_state)
        findings.extend(ux.findings)
        if ux.vitals is not None:
            metadata["lcp_ms"] = round(ux.vitals.lcp_ms, 1)
            metadata["cls"] = round(ux.vitals.cls, 3)
            metadata["dom_nodes"] = ux.vitals.dom_nodes

    if include_security:
        security = SecurityAuditor().audit(url)
        findings.extend(security.findings)
        metadata["security_status"] = security.status

    bundle = write_report(
        findings,
        out_dir,
        title="QA Audit Report",
        target=url,
        metadata=metadata,
    )
    return {
        "command": "audit",
        "target": url,
        "passed": _gate(findings),
        "findings": len(findings),
        **bundle.to_dict(),
    }


def run_fuzz_api(
    target: str,
    out_dir: str | Path,
    *,
    base_url: str | None = None,
    endpoints: Sequence[str] = (),
    method: str = "POST",
    field: str = "input",
    auth_header: str | None = None,
    graphql_path: str | None = None,
    sla_ms: float = 500.0,
    max_cases: int = 120,
) -> dict[str, Any]:
    """Fuzz a base URL or an OpenAPI document and persist the report."""
    parsed_endpoints: list[Endpoint] = []
    resolved_base = base_url
    if Path(target).is_file():
        spec = load_openapi(target)
        parsed_endpoints = endpoints_from_openapi(spec)
        if not resolved_base:
            servers = spec.get("servers") or []
            resolved_base = str(servers[0].get("url", "")) if servers else ""
    if endpoints:
        parsed_endpoints.extend(Endpoint(method, path, field=field) for path in endpoints)
    if not parsed_endpoints:
        raise ValueError("provide an OpenAPI document or at least one --endpoint")
    base = (resolved_base or target).rstrip("/")

    header: tuple[str, str] | None = None
    if auth_header:
        name, _, value = auth_header.partition(":")
        header = (name.strip() or "Authorization", value.strip())

    report = ApiFuzzer(sla_ms=sla_ms, auth_header=header, max_cases=max_cases).run(
        base, parsed_endpoints, graphql_path=graphql_path
    )
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    payload = report.to_dict()
    (directory / "api_fuzz.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    bundle = write_report(
        [*report.findings, *report.graphql_findings],
        directory,
        title="API Contract Fuzz Report",
        target=base,
        metadata={"cases": len(report.results), "latency": report.latency.to_dict() if report.latency else None},
    )
    return {"command": "fuzz-api", "target": base, "passed": report.passed, **payload, **bundle.to_dict()}


def run_gen_tests(url: str, out_dir: str | Path, *, max_pages: int = 3, max_depth: int = 1, auth_state: str | None = None) -> dict[str, Any]:
    """Crawl a page and emit self-contained Playwright test modules."""
    report = Crawler(CrawlConfig(max_pages=max_pages, max_depth=max_depth, auth_state=auth_state)).crawl(url)
    written = E2ETestGenerator(output_dir=out_dir).write(report=report)
    return {
        "command": "gen-tests",
        "target": url,
        "passed": True,
        "generated": [str(path) for path in written],
    }


def run_visual_diff(
    baseline: str | Path,
    candidate: str | Path,
    out_path: str | Path,
    *,
    tolerance: int = 8,
    max_diff_ratio: float = 0.01,
    ignore: Sequence[str] = (),
) -> dict[str, Any]:
    config = DiffConfig(pixel_tolerance=tolerance, max_diff_ratio=max_diff_ratio, ignore_regions=_parse_ignore(ignore))
    result = compare_files(baseline, candidate, config)
    target = save_diff(result, out_path)
    side_by_side = Path(out_path).with_name(f"{Path(out_path).stem}_side_by_side.png")
    save_side_by_side(baseline, candidate, side_by_side, result)
    return {
        "command": "visual-diff",
        "passed": result.passed,
        "diff": str(target),
        "side_by_side": str(side_by_side),
        **result.to_dict(),
    }


def run_eval_rag(dataset: str | Path, *, min_score: float = 0.6, min_recall: float = 0.8) -> dict[str, Any]:
    payload = json.loads(Path(dataset).read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, Mapping) else payload
    if not isinstance(cases, list) or not cases:
        raise ValueError("dataset must contain a non-empty 'cases' list")

    results: list[dict[str, Any]] = []
    failures: list[str] = []
    for index, case in enumerate(cases):
        answer = str(case.get("answer", ""))
        contexts = [str(item) for item in case.get("contexts", [])]
        groundedness = evaluate_semantic_groundedness(answer, contexts, min_score=min_score)
        safety = evaluate_safety(answer)
        entry: dict[str, Any] = {
            "case": index,
            "groundedness": round(groundedness.score, 3),
            "groundedness_passed": groundedness.passed,
            "missing_numbers": list(groundedness.missing_numbers),
            "safety_passed": safety.passed,
            "safety": safety.to_dict(),
        }
        if "relevant_contexts" in case:
            precision = evaluate_context_precision(contexts, case["relevant_contexts"])
            recall = evaluate_context_recall(contexts, case["relevant_contexts"], min_recall=min_recall)
            entry.update(
                {
                    "precision": round(precision.precision, 3),
                    "recall": round(recall.recall, 3),
                    "retrieval_passed": precision.passed and recall.passed,
                }
            )
            if not (precision.passed and recall.passed):
                failures.append(f"case {index}: retrieval gate failed")
        if not groundedness.passed:
            failures.append(f"case {index}: groundedness {groundedness.score:.2f} < {min_score}")
        if not safety.passed:
            failures.append(f"case {index}: safety gate failed")
        results.append(entry)

    return {"command": "eval-rag", "passed": not failures, "cases": results, "failures": failures}


# ---------------------------------------------------------------------------
# Full-spectrum software QA commands
# ---------------------------------------------------------------------------


def run_audit_apk(path: str | Path, out_dir: str | Path, *, url: str = "") -> dict[str, Any]:
    """Statically audit an Android APK container."""
    report = inspect_apk(path, url=url)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "apk_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="Android APK Audit",
        target=report.package or report.path,
        metadata={
            "package": report.package,
            "version": report.version_name or report.version_code,
            "min_sdk": report.min_sdk,
            "target_sdk": report.target_sdk,
            "permissions": len(report.permissions),
            "signed": report.signed,
            "debuggable": report.debug_build,
        },
    )
    return {"command": "audit-apk", "target": report.path, "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_audit_pwa(target: str, out_dir: str | Path) -> dict[str, Any]:
    """Audit a built PWA directory or a live PWA URL."""
    report = audit_pwa_dir(target) if Path(target).is_dir() else fetch_pwa(target)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "pwa_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="PWA Installability Audit",
        target=report.url or target,
        metadata={
            "name": report.name,
            "display": report.display,
            "service_worker": report.service_worker,
            "installable": report.installable,
        },
    )
    return {"command": "audit-pwa", "target": report.url or target, "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_test_cli(
    command: Sequence[str],
    out_dir: str | Path,
    *,
    cwd: str | None = None,
    version_args: Sequence[str] = ("--version",),
    desktop_root: str | None = None,
) -> dict[str, Any]:
    """Run the bounded CLI contract probes and, optionally, the desktop AST audit."""
    report = run_cli_audit(command, default_cli_cases(version_args=tuple(version_args)), cwd=cwd)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cli_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    desktop = audit_desktop_source(desktop_root) if desktop_root else None
    findings = [*report.findings, *(desktop.findings if desktop else [])]
    bundle = write_report(
        findings,
        directory,
        title="Desktop / CLI Contract Audit",
        target=" ".join(report.command),
        metadata={"cases": len(report.runs), "frameworks": list(desktop.frameworks) if desktop else []},
    )
    return {
        "command": "test-cli",
        "target": " ".join(report.command),
        "passed": _gate(findings),
        "runs": [run.to_dict() for run in report.runs],
        "desktop": desktop.to_dict() if desktop else None,
        "findings": [finding.to_dict() for finding in findings],
        **bundle.to_dict(),
    }


def run_audit_rbac(matrix: str | Path, out_dir: str | Path) -> dict[str, Any]:
    """Audit a role/permission matrix for over-privilege and gaps."""
    report = audit_rbac(matrix)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "rbac_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="RBAC Matrix Audit",
        target=str(matrix),
        metadata={"roles": list(report.roles), "sensitive_permissions": list(report.sensitive_permissions)},
    )
    return {"command": "audit-rbac", "target": str(matrix), "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_audit_workflow(
    transitions: str | Path,
    out_dir: str | Path,
    *,
    initial: str = "",
    terminal: Sequence[str] = (),
) -> dict[str, Any]:
    """Audit a workflow transition graph loaded from JSON."""
    payload = json.loads(Path(transitions).read_text(encoding="utf-8"))
    graph = payload.get("transitions") if isinstance(payload, Mapping) else None
    if not isinstance(graph, Mapping):
        raise ValueError("workflow document must contain a 'transitions' object")
    report = audit_workflow(
        graph,
        initial=initial or str(payload.get("initial", "")),
        terminal=tuple(terminal) or tuple(payload.get("terminal") or ()),
        required=tuple(payload.get("required") or ()),
    )
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "workflow_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="Workflow Integrity Audit",
        target=str(transitions),
        metadata={"initial": report.initial, "terminal": list(report.terminal), "states": len(report.states)},
    )
    return {"command": "audit-workflow", "target": str(transitions), "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_audit_db(path: str | Path, out_dir: str | Path) -> dict[str, Any]:
    """Audit a SQLite database file or a SQL schema."""
    target = Path(path)
    if target.suffix.lower() in {".sql", ".ddl"}:
        report = audit_ddl(target.read_text(encoding="utf-8", errors="replace"), target=str(target))
    elif target.is_file():
        report = audit_sqlite(target)
    else:
        raise ValueError(f"database or schema not found: {target}")
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "db_audit.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="Database Integrity Audit",
        target=str(target),
        metadata={"engine": report.engine, "tables": len(report.tables), "schema_version": report.schema_version},
    )
    return {"command": "audit-db", "target": str(target), "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_load_test_command(
    url: str,
    out_dir: str | Path,
    *,
    requests: int = 20,
    concurrency: int = 4,
    sla_ms: float = 800.0,
    method: str = "GET",
    max_error_rate: float = 0.01,
    timeout_s: float = 10.0,
    preview: bool = False,
) -> dict[str, Any]:
    """Run a bounded load test and persist latency/error evidence."""
    config = LoadConfig(
        url=url,
        method=method,
        requests=requests,
        concurrency=concurrency,
        sla_ms=sla_ms,
        max_error_rate=max_error_rate,
        timeout_s=timeout_s,
    )
    report = run_load_test(config, preview=preview)
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "load_test.json").write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    bundle = write_report(
        report.findings,
        directory,
        title="Load Test Report",
        target=url,
        metadata={
            "method": report.method,
            "samples": len(report.samples),
            "error_rate": round(report.error_rate, 4),
            "latency": report.latency.to_dict() if report.latency else None,
        },
    )
    return {"command": "load-test", "target": url, "passed": report.passed, **report.to_dict(), **bundle.to_dict()}


def run_gen_test_plan(
    root: str | Path,
    out_dir: str | Path,
    *,
    requirements_path: str | Path | None = None,
    junit_path: str | Path | None = None,
    max_items: int = 40,
    min_coverage: float = 0.8,
) -> dict[str, Any]:
    """Inventory tests, build the RTM, and write a risk-based test plan."""
    inventory = discover_tests(root)
    test_ids = [test.name for test in inventory.tests]

    requirements: list[dict[str, Any]] = []
    if requirements_path:
        raw = json.loads(Path(requirements_path).read_text(encoding="utf-8"))
        entries = raw.get("requirements") if isinstance(raw, Mapping) else raw
        if not isinstance(entries, list) or not entries:
            raise ValueError("requirements document must contain a non-empty list")
        requirements = [dict(entry) if isinstance(entry, Mapping) else {"id": str(entry)} for entry in entries]
    else:
        grouped: dict[str, list[str]] = {}
        for test in inventory.tests:
            grouped.setdefault(test.suite or test.path, []).append(test.name)
        requirements = [
            {"id": f"SUITE-{index:02d}", "title": suite, "tests": names, "risk": 3.0}
            for index, (suite, names) in enumerate(sorted(grouped.items()), start=1)
        ]

    rtm = build_rtm(requirements, test_ids, min_coverage=min_coverage)
    plan = generate_test_plan(requirements, max_items=max_items, coverage_floor=0.0)
    junit = parse_junit_file(junit_path) if junit_path else None

    findings: list[Finding] = [*inventory.findings, *rtm.findings]
    findings.extend(Finding(**entry) for entry in plan["findings"])
    if junit is not None:
        findings.extend(junit.findings)

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    summary = {
        "inventory": inventory.to_dict(),
        "rtm": rtm.to_dict(),
        "plan": plan,
        "junit": junit.to_dict() if junit else None,
    }
    (directory / "test_plan.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    lines = [
        "# Risk-Based Test Plan",
        "",
        f"- Tests discovered: {inventory.count}",
        f"- Requirement coverage: {rtm.coverage:.0%}",
        f"- Planned items: {len(plan['items'])} (deferred {plan['deferred']})",
        "",
        "| Priority | Item | Risk | Tests |",
        "|---|---|---:|---|",
    ]
    lines += [
        f"| {item['priority']} | {item['title']} | {item['risk']} | {len(item['tests'])} |"
        for item in plan["items"]
    ]
    if rtm.uncovered:
        lines += ["", "## Uncovered requirements", ""] + [f"- {item}" for item in rtm.uncovered]
    (directory / "test_plan.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    bundle = write_report(
        findings,
        directory,
        title="Test Management Report",
        target=str(root),
        metadata={
            "tests": inventory.count,
            "coverage": round(rtm.coverage, 3),
            "planned": len(plan["items"]),
            "junit_tests": junit.tests if junit else 0,
        },
    )
    return {
        "command": "gen-test-plan",
        "target": str(root),
        "passed": _gate(findings),
        "inventory": {"count": inventory.count, "by_language": inventory.by_language, "files": inventory.files_scanned},
        "coverage": round(rtm.coverage, 4),
        "uncovered": list(rtm.uncovered),
        "orphan_tests": len(rtm.orphan_tests),
        "plan": plan,
        "junit": junit.to_dict() if junit else None,
        **bundle.to_dict(),
    }


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qa-agent", description="Local-first AI-SDET and client QA audit worker.")
    parser.add_argument("--version", action="version", version=f"qa_agent {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit = subparsers.add_parser("audit", help="crawl, profile accessibility/perf, and audit security")
    audit.add_argument("url")
    audit.add_argument("--out-dir", default="reports/audit")
    audit.add_argument("--auth-state")
    audit.add_argument("--max-pages", type=int, default=15)
    audit.add_argument("--max-depth", type=int, default=3)
    audit.add_argument("--strategy", choices=["bfs", "dfs"], default="bfs")
    audit.add_argument("--sla-ms", type=float, default=0.0)
    audit.add_argument("--no-ux", action="store_true", help="skip the multi-viewport profiler")
    audit.add_argument("--no-security", action="store_true", help="skip passive security checks")

    fuzz = subparsers.add_parser("fuzz-api", help="fuzz REST/GraphQL endpoints and measure latency")
    fuzz.add_argument("target", help="base URL or path to an OpenAPI JSON document")
    fuzz.add_argument("--out-dir", default="reports/api")
    fuzz.add_argument("--base-url")
    fuzz.add_argument("--endpoint", action="append", default=[], help="path to fuzz; repeatable")
    fuzz.add_argument("--method", default="POST")
    fuzz.add_argument("--field", default="input")
    fuzz.add_argument("--auth-header", help='header as "Name: value"')
    fuzz.add_argument("--graphql")
    fuzz.add_argument("--sla-ms", type=float, default=500.0)
    fuzz.add_argument("--max-cases", type=int, default=120)

    gen = subparsers.add_parser("gen-tests", help="generate Playwright tests from a live page")
    gen.add_argument("url")
    gen.add_argument("--out", default="generated_tests")
    gen.add_argument("--max-pages", type=int, default=3)
    gen.add_argument("--max-depth", type=int, default=1)
    gen.add_argument("--auth-state")

    visual = subparsers.add_parser("visual-diff", help="compare two screenshots with Pillow")
    visual.add_argument("baseline")
    visual.add_argument("current")
    visual.add_argument("--out", default="reports/visual/diff.png")
    visual.add_argument("--tolerance", type=int, default=8)
    visual.add_argument("--max-diff-ratio", type=float, default=0.01)
    visual.add_argument("--ignore", action="append", default=[], help="x,y,width,height; repeatable")

    rag = subparsers.add_parser("eval-rag", help="evaluate a RAG dataset offline")
    rag.add_argument("dataset")
    rag.add_argument("--min-score", type=float, default=0.6)
    rag.add_argument("--min-recall", type=float, default=0.8)

    apk = subparsers.add_parser("audit-apk", help="statically audit an Android APK container")
    apk.add_argument("path")
    apk.add_argument("--out-dir", default="reports/apk")
    apk.add_argument("--url", default="", help="target URL recorded in the evidence")

    pwa = subparsers.add_parser("audit-pwa", help="audit PWA installability (build directory or URL)")
    pwa.add_argument("target", help="built PWA directory or https:// URL")
    pwa.add_argument("--out-dir", default="reports/pwa")

    cli_audit = subparsers.add_parser("test-cli", help="probe a CLI contract and audit desktop source")
    cli_audit.add_argument("command", nargs=argparse.REMAINDER, help="command and base arguments to probe")
    cli_audit.add_argument("--out-dir", default="reports/cli")
    cli_audit.add_argument("--cwd")
    cli_audit.add_argument("--version-arg", default="--version")
    cli_audit.add_argument("--desktop-root", help="optional Python source tree for the static desktop audit")

    rbac = subparsers.add_parser("audit-rbac", help="audit a role/permission matrix")
    rbac.add_argument("matrix", help="JSON role matrix")
    rbac.add_argument("--out-dir", default="reports/rbac")

    workflow = subparsers.add_parser("audit-workflow", help="audit a workflow transition graph")
    workflow.add_argument("transitions", help="JSON workflow document")
    workflow.add_argument("--out-dir", default="reports/workflow")
    workflow.add_argument("--initial", default="")
    workflow.add_argument("--terminal", action="append", default=[])

    db = subparsers.add_parser("audit-db", help="audit SQLite schema/constraints or a SQL schema file")
    db.add_argument("path", help=".db/.sqlite file or .sql schema")
    db.add_argument("--out-dir", default="reports/db")

    load = subparsers.add_parser("load-test", help="bounded load test with latency and error-rate gates")
    load.add_argument("url")
    load.add_argument("--out-dir", default="reports/load")
    load.add_argument("--requests", type=int, default=20)
    load.add_argument("--concurrency", type=int, default=4)
    load.add_argument("--sla-ms", type=float, default=800.0)
    load.add_argument("--method", default="GET")
    load.add_argument("--timeout", type=float, default=10.0)
    load.add_argument("--max-error-rate", type=float, default=0.01)
    load.add_argument("--preview", action="store_true", help="send a single probe request")

    plan = subparsers.add_parser("gen-test-plan", help="inventory tests, build an RTM, and plan by risk")
    plan.add_argument("root", help="repository or suite root")
    plan.add_argument("--out-dir", default="reports/test-plan")
    plan.add_argument("--requirements", help="JSON list of requirements with linked tests")
    plan.add_argument("--junit", help="JUnit XML produced by the CI run")
    plan.add_argument("--max-items", type=int, default=40)
    plan.add_argument("--min-coverage", type=float, default=0.8)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            summary = run_audit(
                args.url,
                args.out_dir,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                strategy=args.strategy,
                auth_state=args.auth_state,
                include_ux=not args.no_ux,
                include_security=not args.no_security,
                sla_ms=args.sla_ms,
            )
        elif args.command == "fuzz-api":
            summary = run_fuzz_api(
                args.target,
                args.out_dir,
                base_url=args.base_url,
                endpoints=args.endpoint,
                method=args.method,
                field=args.field,
                auth_header=args.auth_header,
                graphql_path=args.graphql,
                sla_ms=args.sla_ms,
                max_cases=args.max_cases,
            )
        elif args.command == "gen-tests":
            summary = run_gen_tests(
                args.url,
                args.out,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                auth_state=args.auth_state,
            )
        elif args.command == "visual-diff":
            summary = run_visual_diff(
                args.baseline,
                args.current,
                args.out,
                tolerance=args.tolerance,
                max_diff_ratio=args.max_diff_ratio,
                ignore=args.ignore,
            )
        elif args.command == "eval-rag":
            summary = run_eval_rag(args.dataset, min_score=args.min_score, min_recall=args.min_recall)
        elif args.command == "audit-apk":
            summary = run_audit_apk(args.path, args.out_dir, url=args.url)
        elif args.command == "audit-pwa":
            summary = run_audit_pwa(args.target, args.out_dir)
        elif args.command == "test-cli":
            command = [part for part in args.command if part != "--"]
            if not command:
                raise ValueError("provide the command to probe, e.g. test-cli -- python -m mycli")
            summary = run_test_cli(
                command,
                args.out_dir,
                cwd=args.cwd,
                version_args=(args.version_arg,) if args.version_arg else (),
                desktop_root=args.desktop_root,
            )
        elif args.command == "audit-rbac":
            summary = run_audit_rbac(args.matrix, args.out_dir)
        elif args.command == "audit-workflow":
            summary = run_audit_workflow(args.transitions, args.out_dir, initial=args.initial, terminal=args.terminal)
        elif args.command == "audit-db":
            summary = run_audit_db(args.path, args.out_dir)
        elif args.command == "load-test":
            summary = run_load_test_command(
                args.url,
                args.out_dir,
                requests=args.requests,
                concurrency=args.concurrency,
                sla_ms=args.sla_ms,
                method=args.method,
                timeout_s=args.timeout,
                max_error_rate=args.max_error_rate,
                preview=args.preview,
            )
        elif args.command == "gen-test-plan":
            summary = run_gen_test_plan(
                args.root,
                args.out_dir,
                requirements_path=args.requirements,
                junit_path=args.junit,
                max_items=args.max_items,
                min_coverage=args.min_coverage,
            )
        else:  # pragma: no cover - argparse enforces the choices
            parser.error(f"unknown command {args.command}")
            return 2
    except (OSError, ValueError) as exc:
        print(json.dumps({"command": args.command, "error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 2

    print(json.dumps(summary, default=str))
    return 0 if summary.get("passed", True) else 1
