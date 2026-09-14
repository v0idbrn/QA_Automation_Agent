# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
CLI robustness regressions.

Locks in the product-hardening fixes:
  * --budget/--scope string values fail fast with a clean ValidationError
    instead of an unhandled TypeError deep in validate_config;
  * `report` on a corrupt audit_report.json exits 2 with a clear message
    instead of crashing (a partially-written report must never wedge the CLI);
  * `report` re-renders missing MD/HTML artifacts atomically and leaves the
    authoritative JSON untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from main import ValidationError, _load_config, build_parser, cmd_report


def _args(argv: list[str]):
    return build_parser().parse_args(argv)


class TestBudgetOverrideCoercion:
    def test_string_value_fails_fast_cleanly(self):
        with pytest.raises(ValidationError) as excinfo:
            _load_config(_args(["plan", ".", "--budget", "max_pages=abc"]))
        assert "max_pages" in str(excinfo.value)
        assert "expects int" in str(excinfo.value)

    def test_numeric_string_is_coerced(self):
        cfg = _load_config(_args(["plan", ".", "--budget", "max_pages=7"]))
        assert cfg.budget.max_pages == 7

    def test_unknown_budget_key_still_rejected(self):
        with pytest.raises(ValidationError):
            _load_config(_args(["plan", ".", "--budget", "nope=1"]))

    def test_valid_overrides_still_work(self):
        cfg = _load_config(_args(["plan", ".", "--budget", "max_pages=5", "--max-requests", "9"]))
        assert cfg.budget.max_pages == 5
        assert cfg.budget.max_requests == 9


class TestReportCommand:
    def _write_report(self, run_dir: Path, findings: list[dict]) -> Path:
        run_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": "run_test",
            "target": "demo",
            "summary": {"total": len(findings), "high_severity": 0},
            "quality_gate": {"status": "PASS", "passed": True, "reasons": []},
            "findings": findings,
        }
        (run_dir / "audit_report.json").write_text(json.dumps(payload), encoding="utf-8")
        return run_dir

    def test_missing_directory_exits_2(self, capsys):
        assert cmd_report(str(Path("Z:/definitely/not/here"))) == 2

    def test_missing_json_exits_2(self, tmp_path: Path):
        (tmp_path / "empty_run").mkdir()
        assert cmd_report(str(tmp_path / "empty_run")) == 2

    def test_corrupt_json_exits_2_with_clear_message(self, tmp_path: Path, capsys):
        run_dir = tmp_path / "corrupt_run"
        run_dir.mkdir()
        (run_dir / "audit_report.json").write_bytes(b"{not valid json...")
        exit_code = cmd_report(str(run_dir))
        assert exit_code == 2
        assert "corrupt" in capsys.readouterr().err.lower()

    def test_renders_missing_artifacts_atomically(self, tmp_path: Path):
        run_dir = self._write_report(
            tmp_path / "run",
            [{"category": "crawl", "severity": "medium", "confidence": "high", "title": "Broken link: /missing", "description": "http 404"}],
        )
        exit_code = cmd_report(str(run_dir))
        assert exit_code == 0
        assert (run_dir / "audit_report.md").exists()
        html = (run_dir / "audit_report.html").read_text(encoding="utf-8")
        assert html.lstrip().lower().startswith("<!doctype html") or "<html" in html[:200].lower()
        # JSON stays authoritative and untouched
        data = json.loads((run_dir / "audit_report.json").read_text(encoding="utf-8"))
        assert data["run_id"] == "run_test"

    def test_does_not_rewrite_existing_artifacts(self, tmp_path: Path):
        run_dir = self._write_report(tmp_path / "run2", [])
        (run_dir / "audit_report.md").write_text("ORIGINAL", encoding="utf-8")
        (run_dir / "audit_report.html").write_text("<p>ORIGINAL</p>", encoding="utf-8")
        assert cmd_report(str(run_dir)) == 0
        assert (run_dir / "audit_report.md").read_text(encoding="utf-8") == "ORIGINAL"
        assert (run_dir / "audit_report.html").read_text(encoding="utf-8") == "<p>ORIGINAL</p>"
