# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
GUI command-builder regressions.

The GUI composes CLI argv through build_command(); these tests lock the
contract so a GUI click can never produce a malformed command line.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gui import build_command, reports_dir_for  # noqa: E402


class TestBuildCommand:
    def test_minimal_run_command(self):
        cmd = build_command("run", "samples/demo_site", "standard")
        assert cmd[2] == "run"
        assert cmd[3] == "samples/demo_site"
        assert cmd[4:6] == ["--profile", "standard"]
        # nothing else appended
        assert len(cmd) == 6

    def test_run_with_all_options(self):
        cmd = build_command(
            "run",
            "https://example.test",
            "deep",
            url="https://example.test",
            browser="firefox",
            headed=True,
            output_dir="reports/x",
            min_coverage=0.15,
            max_pages=7,
            max_requests=20,
            dry_run=True,
            allow_external=True,
        )
        for flag in ("--url", "--browser", "firefox", "--headed", "--output", "--min-coverage",
                     "0.15", "--max-pages", "7", "--max-requests", "20", "--dry-run", "--allow-external"):
            assert flag in cmd

    def test_chromium_default_is_omitted(self):
        cmd = build_command("run", ".", "standard", browser="chromium")
        assert "--browser" not in cmd

    def test_unknown_action_rejected(self):
        with pytest.raises(ValueError):
            build_command("destroy", ".", "safe")

    def test_zero_limits_are_omitted(self):
        cmd = build_command("run", ".", "safe", max_pages=0, max_requests=0)
        assert "--max-pages" not in cmd and "--max-requests" not in cmd

    def test_none_coverage_omitted(self):
        cmd = build_command("plan", ".", "safe", min_coverage=None)
        assert "--min-coverage" not in cmd

    def test_custom_python_exe(self):
        cmd = build_command("run", ".", "safe", python_exe="/custom/python")
        assert cmd[0] == "/custom/python"


class TestReportsDirFor:
    def test_default_reports_dir(self):
        assert reports_dir_for(None).name == "reports"

    def test_relative_output_resolved_against_root(self):
        resolved = reports_dir_for("out/run1")
        assert resolved.is_absolute()
        assert resolved.as_posix().endswith("out/run1")

    def test_absolute_output_kept(self):
        assert reports_dir_for(str(Path("Z:/tmp/abs"))) == Path("Z:/tmp/abs")
