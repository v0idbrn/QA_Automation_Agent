# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
GUI results-panel regressions.

The panel renders findings-by-severity from `audit_report.json`. These tests
lock the pure helpers (`summarize_findings`, `latest_report_data`) so a
malformed or corrupt report can never crash the GUI, and so the summarizer
stays in sync with the real report payload shape (lowercase severity values,
`quality_gate.status`, `run_id`).
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gui import SEVERITY_ORDER, latest_report_data, reports_dir_for, summarize_findings


# ---------------------------------------------------------------------------
# summarize_findings
# ---------------------------------------------------------------------------


def test_summarize_counts_all_severities() -> None:
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "info"},
    ]
    counts = summarize_findings(findings)
    assert counts == {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1}


def test_summarize_is_case_insensitive() -> None:
    counts = summarize_findings([{"severity": "HIGH"}, {"severity": "Critical"}])
    assert counts["high"] == 1
    assert counts["critical"] == 1


def test_summarize_skips_unknown_and_malformed_entries() -> None:
    findings = [
        {"severity": "galactic"},  # unknown severity — must not crash nor count
        "not-a-dict",
        42,
        None,
        {},  # missing severity
        {"severity": "low"},
    ]
    counts = summarize_findings(findings)
    assert counts["low"] == 1
    assert sum(counts.values()) == 1


def test_summarize_none_and_empty_inputs() -> None:
    empty = {s: 0 for s in SEVERITY_ORDER}
    assert summarize_findings(None) == empty
    assert summarize_findings([]) == empty


def test_summarize_severity_order_matches_report_enum_values() -> None:
    """Contract: SEVERITY_ORDER mirrors core.models.Severity values exactly."""
    from core.models import Severity

    assert set(SEVERITY_ORDER) == {s.value for s in Severity}
    assert list(SEVERITY_ORDER)[0] == Severity.CRITICAL.value


# ---------------------------------------------------------------------------
# latest_report_data
# ---------------------------------------------------------------------------


@pytest.fixture()
def reports_tmp(tmp_path: Path) -> Path:
    return tmp_path / "reports"


def _write_report(base: Path, run_id: str, severities: list[str], mtime_shift: float = 0.0) -> Path:
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "run_id": run_id,
        "findings": [{"severity": s} for s in severities],
        "quality_gate": {"status": "PASS", "passed": True, "reasons": []},
    }
    path = run_dir / "audit_report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    stamp = time.time() + mtime_shift
    path.touch()  # ensure mtime ordering is deterministic on coarse filesystems
    import os

    os.utime(path, (stamp, stamp))
    return path


def test_latest_report_picks_newest_run(reports_tmp: Path) -> None:
    _write_report(reports_tmp, "run-old", ["low"], mtime_shift=-100.0)
    _write_report(reports_tmp, "run-new", ["high", "high"], mtime_shift=0.0)
    data = latest_report_data(reports_tmp)
    assert data is not None
    assert data["run_id"] == "run-new"
    assert summarize_findings(data["findings"])["high"] == 2


def test_latest_report_skips_corrupt_file(reports_tmp: Path) -> None:
    _write_report(reports_tmp, "run-old", ["medium"], mtime_shift=-100.0)
    newest = _write_report(reports_tmp, "run-new", ["high"], mtime_shift=0.0)
    newest.write_text("{corrupt json", encoding="utf-8")
    data = latest_report_data(reports_tmp)
    # Falls back to the previous valid report instead of crashing or lying.
    assert data is not None
    assert data["run_id"] == "run-old"


def test_latest_report_missing_dir_returns_none(tmp_path: Path) -> None:
    assert latest_report_data(tmp_path / "does-not-exist") is None


def test_latest_report_empty_dir_returns_none(reports_tmp: Path) -> None:
    reports_tmp.mkdir(parents=True)
    assert latest_report_data(reports_tmp) is None


def test_latest_report_matches_orchestrator_payload_shape(reports_tmp: Path) -> None:
    """The shape the GUI reads must match what the orchestrator writes."""
    from core.report_builder import ReportBuilder
    from core.models import Finding, FindingCategory, Severity

    findings = [
        Finding(
            title="t1", description="d", severity=Severity.HIGH,
            confidence=0.9, category=FindingCategory.API, source="api",
        ),
        Finding(
            title="t2", description="d", severity=Severity.INFO,
            confidence=0.6, category=FindingCategory.CRAWL, source="crawler",
        ),
    ]
    out = reports_tmp / "shape-run" / "audit_report.json"
    ReportBuilder().build_json("t", findings, None, None)  # smoke: builder works
    payload = ReportBuilder().build_json("t", findings)
    payload["run_id"] = "shape-run"
    payload["quality_gate"] = {"status": "PASS"}
    out.parent.mkdir(parents=True)
    out.write_text(json.dumps(payload, default=str), encoding="utf-8")

    data = latest_report_data(reports_tmp)
    assert data is not None
    counts = summarize_findings(data["findings"])
    assert counts["high"] == 1 and counts["info"] == 1
    assert data["quality_gate"]["status"] == "PASS"
    assert data["run_id"] == "shape-run"


# ---------------------------------------------------------------------------
# reports_dir_for
# ---------------------------------------------------------------------------


def test_reports_dir_default() -> None:
    from gui import REPORTS

    assert reports_dir_for(None) == REPORTS


def test_reports_dir_relative_resolves_against_project_root(tmp_path: Path) -> None:
    resolved = reports_dir_for("out/runs")
    assert resolved.is_absolute()
    assert resolved.name == "runs"


def test_reports_dir_absolute_passthrough(tmp_path: Path) -> None:
    assert reports_dir_for(str(tmp_path)) == tmp_path
