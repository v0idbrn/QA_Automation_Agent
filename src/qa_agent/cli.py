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
from qa_agent.llm_evals import (
    evaluate_context_precision,
    evaluate_context_recall,
    evaluate_safety,
    evaluate_semantic_groundedness,
)
from qa_agent.models import Finding, Severity
from qa_agent.reporter import write_report
from qa_agent.security_checkout import SecurityAuditor
from qa_agent.test_generator import E2ETestGenerator
from qa_agent.ux_a11y_perf import UXProfiler
from qa_agent.visual_regression import DiffConfig, compare_files, save_diff, save_side_by_side

__all__ = ["build_parser", "main", "run_audit", "run_eval_rag", "run_fuzz_api", "run_gen_tests", "run_visual_diff"]


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
        else:  # pragma: no cover - argparse enforces the choices
            parser.error(f"unknown command {args.command}")
            return 2
    except (OSError, ValueError) as exc:
        print(json.dumps({"command": args.command, "error": f"{type(exc).__name__}: {exc}"}), file=sys.stderr)
        return 2

    print(json.dumps(summary, default=str))
    return 0 if summary.get("passed", True) else 1
