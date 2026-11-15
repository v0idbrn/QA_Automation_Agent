# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""End-to-end tests against the seeded vulnerable SaaS fixture."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qa_agent.api_fuzzer import ApiFuzzer, Endpoint
from qa_agent.cli import main, run_audit
from qa_agent.crawler import CrawlConfig, Crawler
from qa_agent.security_checkout import SecurityAuditor
from qa_agent.test_generator import E2ETestGenerator
from qa_agent.ux_a11y_perf import UXProfiler


@pytest.fixture(scope="module")
def crawl(vulnerable_saas: str):
    return Crawler(CrawlConfig(max_pages=4, max_depth=1)).crawl(vulnerable_saas)


@pytest.fixture(scope="module")
def ux(vulnerable_saas: str):
    return UXProfiler().profile(vulnerable_saas)


def test_crawler_walks_linked_pages(crawl) -> None:
    urls = {page.url for page in crawl.pages}
    assert crawl.start_url in urls
    assert any(url.endswith("/checkout") for url in urls)
    assert len(crawl.pages) >= 2


def test_crawler_detects_console_error(crawl) -> None:
    assert crawl.console_error_count >= 1
    assert any(finding.category == "console-error" for finding in crawl.findings)


def test_crawler_detects_broken_asset(crawl) -> None:
    assert any(finding.category == "broken-asset" for finding in crawl.findings)


def test_crawler_detects_broken_link(crawl) -> None:
    assert any(finding.category == "broken-link" for finding in crawl.findings)


def test_crawler_report_serializes(crawl) -> None:
    payload = crawl.to_dict()
    assert payload["pages"]
    assert payload["passed"] is False
    json.dumps(payload)


def test_crawler_no_redirect_false_positive(crawl) -> None:
    home = next(page for page in crawl.pages if page.url.rstrip("/") == crawl.start_url.rstrip("/"))
    assert home.redirect_loop is False


def test_crawler_missing_auth_state_is_rejected(vulnerable_saas: str) -> None:
    with pytest.raises(FileNotFoundError):
        Crawler(CrawlConfig(auth_state="does-not-exist.json")).crawl(vulnerable_saas)


def test_crawler_rejects_invalid_url() -> None:
    with pytest.raises(ValueError):
        Crawler().crawl("not-a-url")


def test_ux_profiler_finds_mobile_overflow(ux) -> None:
    overflow = [finding for finding in ux.layout_findings if finding.category == "layout-overflow"]
    assert overflow
    assert any("390x844" in finding.evidence or "360x800" in finding.evidence for finding in overflow)


def test_ux_profiler_finds_low_contrast(ux) -> None:
    assert any(finding.category == "a11y-contrast" for finding in ux.accessibility.findings)


def test_ux_profiler_finds_unlabeled_input(ux) -> None:
    assert any(finding.category == "a11y-label" for finding in ux.accessibility.findings)


def test_ux_profiler_finds_missing_lang(ux) -> None:
    assert any(finding.category == "a11y-lang" for finding in ux.accessibility.findings)


def test_ux_profiler_collects_vitals(ux) -> None:
    assert ux.vitals is not None
    assert ux.vitals.dom_nodes > 0
    assert ux.to_dict()["vitals"]["dom_nodes"] > 0


def test_security_audit_flags_missing_headers(vulnerable_saas: str) -> None:
    report = SecurityAuditor().audit(vulnerable_saas + "/checkout")
    categories = {finding.category for finding in report.findings}
    assert {"security-csp", "security-hsts", "security-clickjacking"} <= categories
    assert report.passed is False


def test_api_fuzzer_detects_seeded_crash(vulnerable_saas: str) -> None:
    report = ApiFuzzer(sla_ms=1000, max_cases=24).run(vulnerable_saas, [Endpoint("POST", "/api/validate")])
    assert report.server_error_count >= 1
    assert report.passed is False
    assert report.latency is not None and report.latency.count > 0


def test_api_fuzzer_detects_graphql_issues(vulnerable_saas: str) -> None:
    report = ApiFuzzer(max_cases=1).run(vulnerable_saas, [Endpoint("POST", "/api/validate")], graphql_path="/graphql")
    categories = {finding.category for finding in report.graphql_findings}
    assert {"graphql-introspection", "graphql-error-leak"} <= categories


def test_gen_tests_writes_compilable_module(vulnerable_saas: str, tmp_path) -> None:
    report = Crawler(CrawlConfig(max_pages=1, max_depth=0)).crawl(vulnerable_saas)
    written = E2ETestGenerator(output_dir=tmp_path).write(report=report)
    assert written
    source = written[0].read_text(encoding="utf-8")
    compile(source, str(written[0]), "exec")
    assert "get_by_role" in source


def test_audit_cli_writes_client_deliverables(vulnerable_saas: str, tmp_path_factory) -> None:
    out = tmp_path_factory.mktemp("audit_run")
    summary = run_audit(vulnerable_saas, out, max_pages=2, max_depth=1, include_ux=False)
    assert summary["passed"] is False
    assert Path(summary["html"]).is_file()
    assert Path(summary["markdown"]).is_file()
    assert Path(summary["manifest"]).is_file()
    assert "Missing Content-Security-Policy" in Path(summary["markdown"]).read_text(encoding="utf-8")


def test_audit_cli_exit_code(vulnerable_saas: str, tmp_path, capsys) -> None:
    code = main(["audit", vulnerable_saas, "--out-dir", str(tmp_path), "--max-pages", "1", "--max-depth", "0", "--no-ux"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "audit"
    assert payload["findings"] > 0


def test_fuzz_cli_exit_code(vulnerable_saas: str, tmp_path, capsys) -> None:
    code = main(["fuzz-api", vulnerable_saas, "--endpoint", "/api/validate", "--out-dir", str(tmp_path), "--max-cases", "12"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "fuzz-api"
    assert payload["server_errors"] >= 1


def test_gen_tests_cli_exit_code(vulnerable_saas: str, tmp_path, capsys) -> None:
    code = main(["gen-tests", vulnerable_saas, "--out", str(tmp_path / "generated"), "--max-pages", "1", "--max-depth", "0"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["generated"]
    assert Path(payload["generated"][0]).is_file()


def test_module_entrypoint_is_runnable() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "qa_agent", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0
    assert "qa_agent" in completed.stdout
