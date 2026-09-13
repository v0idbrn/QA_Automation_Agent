import pytest

from core.a11y_auditor import A11yAuditor, assess_accessibility, A11yFinding


class TestA11yAuditorStaticChecks:
    def test_missing_alt_count_detected(self):
        auditor = A11yAuditor()
        html = '<html><body><img src="a.png"><img src="b.png" alt="ok"></body></html>'
        issues = auditor._count_missing_alt(html)
        assert issues == 1

    def test_heading_hierarchy_no_h1(self):
        auditor = A11yAuditor()
        html = "<html><body><h2>No h1 here</h2></body></html>"
        result = auditor._check_heading_hierarchy(html)
        assert result == "no h1 found"

    def test_heading_hierarchy_multiple_h1(self):
        auditor = A11yAuditor()
        html = "<html><body><h1>One</h1><h1>Two</h1></body></html>"
        result = auditor._check_heading_hierarchy(html)
        assert result == "multiple h1 found"

    def test_aria_role_issue_flag(self):
        auditor = A11yAuditor()
        html = "<html><body><div role='button'>press</div></body></html>"
        issues = auditor._count_aria_role_issues(html)
        assert issues >= 1


class TestAssessAccessibility:
    def test_summary_counts_by_severity(self):
        findings = [
            A11yFinding(rule="alt", element="img", detail="missing", severity="medium"),
            A11yFinding(rule="aria", element="div", detail="bad", severity="high"),
            A11yFinding(rule="heading", element="h1", detail="ok", severity="low"),
        ]
        summary = assess_accessibility(findings)
        assert summary["total"] == 3
        assert summary["severe"] == 1
        assert summary["medium"] == 1
        assert summary["low"] == 1
        assert "aria" in summary["rules"]
