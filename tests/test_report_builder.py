from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.models import Finding, FindingCategory, Severity
from core.report_builder import (
    ReportBuilder,
    render_audit_report,
    render_audit_report_json,
    render_jira_export,
)


class TestReportBuilderMarkdown:
    def test_build_returns_string_with_target(self):
        builder = ReportBuilder(template_dir=Path(__file__).resolve().parent.parent / "reports")
        findings = [
            Finding(
                id="f1",
                category=FindingCategory.CRAWL,
                severity=Severity.MEDIUM,
                title="broken link",
                description="http 404",
                location="https://example.test/404",
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
            Finding(id="f2", category=FindingCategory.FORM, severity=Severity.HIGH, title="xss-ish", description="xss-ish"),
            Finding(id="f3", category=FindingCategory.FORM, severity=Severity.LOW, title="long text", description="long text"),
        ]
        text = builder.build(target="example.test", findings=findings)
        assert "high_severity" in text.lower() or "1" in text


class TestRenderAuditReportFile:
    def test_render_audit_report_writes_file(self, tmp_path):
        findings = [
            Finding(id="f1", category=FindingCategory.CRAWL, severity=Severity.MEDIUM, title="broken link", description="broken link", location="/"),
        ]
        output = tmp_path / "reports" / "audit_report.md"
        path = render_audit_report("example.test", findings, output)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "example.test" in content


class TestJiraExport:
    def test_jira_export_writes_file(self, tmp_path):
        findings = [
            Finding(
                id="f4",
                category=FindingCategory.API,
                severity=Severity.HIGH,
                title="500 Internal Server Error",
                description="500 Internal Server Error",
                location="https://example.test/api",
                expected="200 OK",
                actual="500",
                reproduction="1. Open page\n2. Trigger request",
                evidence="reports/screenshot.png",
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
        assert "Evidence:" in content

    def test_jira_export_empty_findings(self, tmp_path):
        output = tmp_path / "jira_export.md"
        path = render_jira_export([], "example.test", output)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Jira Export" in content
        assert content.count("## ") == 0
