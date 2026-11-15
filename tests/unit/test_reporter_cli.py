# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for the executive reporter and the unified CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from PIL import Image

from qa_agent.cli import build_parser, main, run_eval_rag, run_visual_diff
from qa_agent.models import Finding
from qa_agent.reporter import ReportBundle, build_manifest, render_html, render_markdown, sha256_file, write_report


def findings() -> list[Finding]:
    return [
        Finding(
            title="Missing CSP",
            severity="high",
            category="security-csp",
            description="No CSP header.",
            url="https://app.example.com/",
            evidence="content-security-policy absent",
            recommendation="Serve a restrictive CSP.",
        ),
        Finding(title="Tiny tap target", severity="low", category="layout-touch-target", description="20x20 button", url="https://app.example.com/checkout"),
        Finding(title="Unlabeled input", severity="medium", category="a11y-label", description="No label", url="https://app.example.com/"),
    ]


def test_render_markdown_contains_summary_and_findings() -> None:
    report = render_markdown(findings(), title="Client Audit", target="https://app.example.com/")
    assert "# Client Audit" in report
    assert "| Critical | 0 |" in report
    assert "| High | 1 |" in report
    assert "### 1. [HIGH] Missing CSP" in report
    assert "Serve a restrictive CSP." in report
    assert "```text" in report


def test_render_markdown_orders_by_severity() -> None:
    report = render_markdown(findings())
    assert report.index("Missing CSP") < report.index("Unlabeled input") < report.index("Tiny tap target")


def test_render_markdown_empty_findings() -> None:
    report = render_markdown([])
    assert "No findings were recorded" in report
    assert "Findings: 0" in report


def test_render_markdown_metadata_is_redacted() -> None:
    report = render_markdown([], metadata={"token": "password=secretvalue", "pages": 3})
    assert "secretvalue" not in report
    assert "**pages**: 3" in report


def test_render_markdown_falls_back_to_url_reproduction() -> None:
    report = render_markdown([Finding("x", "low", "c", url="https://app.example.com/x")])
    assert "Open https://app.example.com/x" in report


def test_render_html_is_standalone() -> None:
    document = render_html(findings(), title="Client Audit", target="https://app.example.com/")
    assert document.startswith("<!DOCTYPE html>")
    assert "<style>" in document
    assert "http://" not in document.split("<body>")[0]
    assert "data-filter" in document


def test_render_html_kpi_cards_count() -> None:
    document = render_html(findings())
    assert 'class="kpi-count">1</span>' in document
    assert "Executive summary" in document


def test_render_html_escapes_untrusted_text() -> None:
    hostile = Finding("<script>alert(1)</script>", "high", "x", description="<img src=x onerror=alert(1)>", evidence="<b>bold</b>")
    document = render_html([hostile])
    assert "<script>alert(1)</script>" not in document
    assert "&lt;script&gt;" in document
    assert "&lt;img src=x" in document


def test_render_html_escapes_title_and_target() -> None:
    document = render_html([], title="<b>Report</b>", target="https://app.example.com/?q=<script>")
    assert "<b>Report</b>" not in document
    assert "&lt;b&gt;Report" in document


def test_render_html_empty_findings() -> None:
    document = render_html([])
    assert "No findings were recorded" in document
    assert "Nothing to report" in document


def test_render_html_embeds_images() -> None:
    document = render_html([], images=[("Checkout page", "evidence/checkout.png")])
    assert 'src="evidence/checkout.png"' in document
    assert "Checkout page" in document


def test_render_html_embeds_manifest() -> None:
    manifest = {"generated_at": "2026-01-01T00:00:00+00:00", "files": {"audit_report.html": {"sha256": "abc", "bytes": 10}}}
    document = render_html([], manifest=manifest)
    assert "Evidence manifest (SHA-256)" in document
    assert "abc" in document


def test_sha256_file_stable(tmp_path) -> None:
    path = tmp_path / "x.txt"
    path.write_text("hello", encoding="utf-8")
    assert sha256_file(path) == sha256_file(path)
    assert len(sha256_file(path)) == 64


def test_build_manifest_skips_missing_files(tmp_path) -> None:
    path = tmp_path / "a.txt"
    path.write_text("a", encoding="utf-8")
    manifest = build_manifest([path, tmp_path / "missing.txt"], root=tmp_path)
    assert list(manifest["files"]) == ["a.txt"]
    assert manifest["files"]["a.txt"]["bytes"] == 1
    assert manifest["algorithm"] == "sha256"


def test_write_report_creates_deliverables(tmp_path) -> None:
    bundle = write_report(findings(), tmp_path / "run1", title="Audit", target="https://app.example.com/")
    assert bundle.html_path.is_file()
    assert bundle.markdown_path.is_file()
    assert bundle.manifest_path is not None and bundle.manifest_path.is_file()
    assert "audit_report.html" in bundle.manifest["files"]
    assert bundle.manifest["files"]["audit_report.html"]["sha256"] == sha256_file(bundle.html_path)


def test_write_report_copies_screenshots(tmp_path) -> None:
    screenshot = tmp_path / "checkout_page.png"
    Image.new("RGB", (4, 4), (255, 255, 255)).save(screenshot)
    bundle = write_report(findings(), tmp_path / "run", screenshots=[screenshot, tmp_path / "missing.png"])
    copied = bundle.out_dir / "evidence" / "checkout_page.png"
    assert copied.is_file()
    assert "evidence/checkout_page.png" in bundle.html_path.read_text(encoding="utf-8")


def test_report_bundle_serializes(tmp_path) -> None:
    bundle = write_report([], tmp_path / "run")
    payload = bundle.to_dict()
    assert payload["html"].endswith("audit_report.html")
    assert isinstance(payload["evidence"], dict)


def test_report_bundle_defaults() -> None:
    bundle = ReportBundle(Path("out"), Path("out/a.html"), Path("out/a.md"))
    assert bundle.manifest_path is None
    assert bundle.to_dict()["manifest"] is None


@pytest.mark.parametrize(
    ("argv", "command"),
    [
        (["audit", "https://app.example.com"], "audit"),
        (["fuzz-api", "https://api.example.com", "--endpoint", "/x"], "fuzz-api"),
        (["gen-tests", "https://app.example.com"], "gen-tests"),
        (["visual-diff", "a.png", "b.png"], "visual-diff"),
        (["eval-rag", "data.json"], "eval-rag"),
    ],
)
def test_parser_accepts_every_command(argv: list[str], command: str) -> None:
    args = build_parser().parse_args(argv)
    assert args.command == command


def test_parser_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_main_version_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "qa_agent" in capsys.readouterr().out


def test_main_rejects_unknown_command() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["nope"])
    assert excinfo.value.code == 2


def test_visual_diff_cli_passes(tmp_path, capsys) -> None:
    baseline = tmp_path / "a.png"
    candidate = tmp_path / "b.png"
    Image.new("RGB", (10, 10), (255, 255, 255)).save(baseline)
    Image.new("RGB", (10, 10), (255, 255, 255)).save(candidate)
    out = tmp_path / "diff.png"
    code = main(["visual-diff", str(baseline), str(candidate), "--out", str(out)])
    assert code == 0
    assert out.is_file()
    assert json.loads(capsys.readouterr().out)["passed"] is True


def test_visual_diff_cli_fails_on_regression(tmp_path) -> None:
    baseline = tmp_path / "a.png"
    candidate = tmp_path / "b.png"
    Image.new("RGB", (10, 10), (255, 255, 255)).save(baseline)
    Image.new("RGB", (10, 10), (0, 0, 0)).save(candidate)
    code = main(["visual-diff", str(baseline), str(candidate), "--out", str(tmp_path / "diff.png")])
    assert code == 1


def test_visual_diff_cli_ignores_region(tmp_path) -> None:
    baseline = tmp_path / "a.png"
    candidate = tmp_path / "b.png"
    Image.new("RGB", (10, 10), (255, 255, 255)).save(baseline)
    candidate_image = Image.new("RGB", (10, 10), (255, 255, 255))
    candidate_image.paste((0, 0, 0), (0, 0, 3, 3))
    candidate_image.save(candidate)
    result = run_visual_diff(baseline, candidate, tmp_path / "diff.png", ignore=["0,0,3,3"])
    assert result["passed"] is True


def test_visual_diff_invalid_ignore_region(tmp_path) -> None:
    with pytest.raises(ValueError):
        run_visual_diff(tmp_path / "a.png", tmp_path / "b.png", tmp_path / "d.png", ignore=["1,2,3"])


def test_eval_rag_passes(tmp_path) -> None:
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "answer": "The refund window is 30 days.",
                        "contexts": ["The refund window is 30 days."],
                        "relevant_contexts": ["The refund window is 30 days."],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    summary = run_eval_rag(dataset)
    assert summary["passed"] is True
    assert summary["cases"][0]["recall"] == 1.0


def test_eval_rag_detects_hallucination(tmp_path) -> None:
    dataset = tmp_path / "dataset.json"
    dataset.write_text(json.dumps({"cases": [{"answer": "Refunds take 90 days.", "contexts": ["Refunds take 30 days."]}]}), encoding="utf-8")
    summary = run_eval_rag(dataset)
    assert summary["passed"] is False
    assert "90" in summary["cases"][0]["missing_numbers"]


def test_eval_rag_detects_safety_violation(tmp_path) -> None:
    dataset = tmp_path / "dataset.json"
    dataset.write_text(json.dumps({"cases": [{"answer": "Email qa@example.com", "contexts": ["Contact support"]}]}), encoding="utf-8")
    assert run_eval_rag(dataset)["passed"] is False


def test_eval_rag_rejects_empty_dataset(tmp_path) -> None:
    dataset = tmp_path / "dataset.json"
    dataset.write_text(json.dumps({"cases": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        run_eval_rag(dataset)


def test_eval_rag_cli_exit_codes(tmp_path, capsys) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"cases": [{"answer": "Refunds take 30 days.", "contexts": ["Refunds take 30 days."]}]}), encoding="utf-8")
    assert main(["eval-rag", str(good)]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"cases": [{"answer": "Refunds take 90 days.", "contexts": ["Refunds take 30 days."]}]}), encoding="utf-8")
    assert main(["eval-rag", str(bad)]) == 1
    assert main(["eval-rag", str(tmp_path / "missing.json")]) == 2
    capsys.readouterr()
