from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.report_builder import (
    AuditFinding,
    ReportBuilder,
    render_audit_report,
    render_jira_export,
)


class TestReportBuilderMarkdown:
    def test_build_returns_string_with_target(self):
        builder = ReportBuilder(template_dir=Path(__file__).resolve().parent.parent / "reports")
        findings = [
            AuditFinding(
                source="crawler",
                kind="broken",
                url="https://example.test/404",
                detail="http 404",
                severity="medium",
            )
        ]
        text = builder.build(target="example.test", findings=findings)
        assert isinstance(text, str)
        assert "example.test" in text
        assert "QA Automation Audit Report" in text
        assert "broken" in text.lower()

    def test_summary_counts_high_severity(self):
        builder = ReportBuilder(template_dir=Path(__file__).resolve().parent.parent / "reports")
        findings = [
            AuditFinding(source="fuzzer", kind="failure", url="/", detail="xss-ish", severity="high"),
            AuditFinding(source="fuzzer", kind="failure", url="/", detail="long text", severity="low"),
        ]
        text = builder.build(target="example.test", findings=findings)
        assert "high_severity" in text.lower() or "1" in text


class TestRenderAuditReportFile:
    def test_render_audit_report_writes_file(self, tmp_path):
        findings = [
            AuditFinding(source="crawler", kind="broken", url="/", detail="broken link", severity="medium")
        ]
        output = tmp_path / "reports" / "audit_report.md"
        path = render_audit_report("example.test", findings, output)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "example.test" in content


class TestJiraExport:
    def test_jira_export_writes_file(self, tmp_path):
        findings = [
            AuditFinding(
                source="api",
                kind="500",
                url="https://example.test/api",
                detail="500 Internal Server Error",
                severity="high",
                steps_to_reproduce="1. Open page\n2. Trigger request",
                expected="200 OK",
                actual="500",
                screenshot="reports/screenshot.png",
            )
        ]
        output = tmp_path / "jira_export.md"
        path = render_jira_export(findings, "example.test", output)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Jira Export" in content
        assert "HIGH" in content
        assert "Steps to Reproduce:" in content
        assert "Expected Behavior:" in content
        assert "Actual Behavior:" in content
        assert "Screenshot:" in content

    def test_jira_export_empty_findings(self, tmp_path):
        output = tmp_path / "jira_export.md"
        path = render_jira_export([], "example.test", output)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Jira Export" in content
        assert content.count("## ") == 0
