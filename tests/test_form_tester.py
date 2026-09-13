import pytest

from core.form_tester import (
    BoundaryKind,
    FormFinding,
    FormInput,
    TestFormInjector,
    build_boundary_values,
    build_synthetic_payloads,
)


class TestBoundaryValueGeneration:
    def test_numeric_boundary_includes_classic_edges(self):
        values = build_boundary_values(BoundaryKind.numeric, min_value=1, max_value=10)
        assert 0 in values
        assert 1 in values
        assert 10 in values
        assert 11 in values

    def test_text_boundary_includes_edges(self):
        values = build_boundary_values(BoundaryKind.text, max_length=5)
        assert "" in values
        assert "x" in values
        assert "xxxxx" in values
        assert "xxxxxx" in values
        assert "  " in values

    def test_date_boundary_includes_invalid_region(self):
        values = build_boundary_values(
            BoundaryKind.date,
            min_value="2024-01-01",
            max_value="2024-12-31",
        )
        assert "2024-01-01" in values
        assert "2024-12-31" in values
        assert "2023-12-31" in values
        assert "2025-01-01" in values


class TestSyntheticPayloadGeneration:
    def test_payloads_are_varied_and_non_null(self):
        payloads = build_synthetic_payloads()
        assert len(payloads) >= 10
        assert all(isinstance(p, str) for p in payloads)
        assert any("<script>" in p for p in payloads)
        assert any("' OR 1=1 --" in p for p in payloads)
        assert any("../.." in p for p in payloads)
        assert any("\x00" in p for p in payloads)


class TestFormInjector:
    def test_inject_into_keeps_html_snapshots(self):
        injector = TestFormInjector()
        finding = injector.inject_into(
            inputs=[
                FormInput(name="email", value_type="text", placeholder="email"),
                FormInput(name="age", value_type="number", placeholder="age"),
            ],
            payloads=build_synthetic_payloads(),
            boundary_values=build_boundary_values(BoundaryKind.numeric, min_value=1, max_value=100),
            html_snapshot="<form></form>",
        )
        assert isinstance(finding, FormFinding)
        assert finding.html_snapshot == "<form></form>"
        assert finding.payloads_tested > 0

    def test_summary_detail_includes_counts(self):
        injector = TestFormInjector()
        finding = injector.inject_into(
            inputs=[FormInput(name="q", value_type="text")],
            payloads=["a", "b"],
            boundary_values=[],
            html_snapshot=None,
        )
        assert "tested 2 payloads" in finding.detail


class TestFormFindingSeverity:
    def test_high_severity_is_flagged(self):
        finding = FormFinding(
            status="failure",
            field="search",
            input_value="<script>alert(1)</script>",
            input_type="text",
            detail="XSS-like payload reflected",
            severity="high",
        )
        assert finding.severity == "high"
        assert finding.status == "failure"

    def test_low_severity_default(self):
        finding = FormFinding(
            status="warning",
            field="bio",
            input_value="x" * 1000,
            input_type="textarea",
            detail="Long input accepted",
        )
        assert finding.status == "warning"
        assert finding.input_value == "x" * 1000
