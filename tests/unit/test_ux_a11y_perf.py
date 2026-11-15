# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Unit tests for layout, WCAG 2.1 AA, and Web Vitals analysis."""

from __future__ import annotations

import pytest

from qa_agent.ux_a11y_perf import (
    VIEWPORTS,
    Box,
    LayoutSnapshot,
    UXReport,
    Viewport,
    VitalsMetrics,
    analyze_layout,
    analyze_vitals,
    audit_accessibility,
    contrast_ratio,
    parse_color,
    relative_luminance,
)

MOBILE = Viewport("mobile", 390, 844)


def snapshot(*boxes: Box, scroll_width: float = 390, client_width: float = 390) -> LayoutSnapshot:
    return LayoutSnapshot(viewport=MOBILE, scroll_width=scroll_width, client_width=client_width, elements=tuple(boxes))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("#fff", (255, 255, 255)),
        ("#000000", (0, 0, 0)),
        ("#ff0000", (255, 0, 0)),
        ("#abc", (170, 187, 204)),
        ("rgb(1, 2, 3)", (1, 2, 3)),
        ("rgb(300, -5, 10)", (255, 0, 10)),
        ("rgba(10,20,30,0.5)", (10, 20, 30)),
        ("white", (255, 255, 255)),
        ("grey", (128, 128, 128)),
        ("transparent", None),
        ("not-a-color", None),
        ("", None),
        ("#12", None),
        ("rgb(bad)", None),
    ],
)
def test_parse_color(raw: str, expected: tuple[int, int, int] | None) -> None:
    assert parse_color(raw) == expected


def test_relative_luminance_white_and_black() -> None:
    assert relative_luminance((255, 255, 255)) == pytest.approx(1.0)
    assert relative_luminance((0, 0, 0)) == pytest.approx(0.0)


def test_contrast_ratio_max_and_min() -> None:
    assert contrast_ratio("#000", "#fff") == pytest.approx(21.0)
    assert contrast_ratio("#777", "#777") == pytest.approx(1.0)


def test_contrast_ratio_accepts_tuples() -> None:
    assert contrast_ratio((0, 0, 0), (255, 255, 255)) == pytest.approx(21.0)


def test_contrast_ratio_unknown_color_is_permissive() -> None:
    assert contrast_ratio("nope", "#fff") == 21.0


def test_viewport_matrix_is_fixed() -> None:
    assert [(item.width, item.height) for item in VIEWPORTS] == [(360, 800), (390, 844), (768, 1024), (1440, 900)]


def test_layout_snapshot_from_mapping() -> None:
    layout = LayoutSnapshot.from_mapping(MOBILE, {"scrollWidth": 500, "clientWidth": 390, "elements": [{"selector": "#a", "x": 0, "y": 0, "width": 10, "height": 10, "tag": "A"}]})
    assert layout.scroll_width == 500
    assert layout.elements[0].tag == "a"


def test_analyze_layout_detects_overflow() -> None:
    findings = analyze_layout(snapshot(scroll_width=480))
    assert [finding.category for finding in findings] == ["layout-overflow"]
    assert findings[0].severity.value == "high"


def test_analyze_layout_clean_page() -> None:
    assert analyze_layout(snapshot()) == []


def test_analyze_layout_touch_target() -> None:
    findings = analyze_layout(snapshot(Box("#buy", 0, 0, 20, 20, tag="button")))
    assert any(finding.category == "layout-touch-target" for finding in findings)


def test_analyze_layout_ignores_large_target() -> None:
    findings = analyze_layout(snapshot(Box("#buy", 0, 0, 80, 44, tag="button")))
    assert not any(finding.category == "layout-touch-target" for finding in findings)


def test_analyze_layout_ignores_non_interactive_small_box() -> None:
    findings = analyze_layout(snapshot(Box("p", 0, 0, 10, 10, tag="p")))
    assert findings == []


def test_analyze_layout_ignores_invisible_box() -> None:
    findings = analyze_layout(snapshot(Box("#hidden", 0, 0, 1, 1, tag="button", visible=False)))
    assert findings == []


def test_analyze_layout_clipped_control() -> None:
    findings = analyze_layout(snapshot(Box("#wide", 380, 0, 100, 50, tag="a")))
    assert any(finding.category == "layout-clipped" for finding in findings)


def test_analyze_layout_negative_offset_is_clipped() -> None:
    findings = analyze_layout(snapshot(Box("#off", -20, 0, 100, 50, tag="a")))
    assert any(finding.category == "layout-clipped" for finding in findings)


def test_analyze_layout_overlapping_controls() -> None:
    first = Box("#one", 0, 0, 100, 50, tag="button")
    second = Box("#two", 10, 10, 100, 50, tag="button")
    findings = analyze_layout(snapshot(first, second))
    assert any(finding.category == "layout-overlap" for finding in findings)


def test_analyze_layout_adjacent_controls_do_not_overlap() -> None:
    first = Box("#one", 0, 0, 100, 50, tag="button")
    second = Box("#two", 100, 0, 100, 50, tag="button")
    findings = analyze_layout(snapshot(first, second))
    assert not any(finding.category == "layout-overlap" for finding in findings)


def test_analyze_layout_sticky_overlay_coverage() -> None:
    overlay = Box("#wall", 0, 0, 390, 800, tag="div", position="fixed")
    findings = analyze_layout(snapshot(overlay))
    assert any(finding.category == "layout-sticky-overlay" and finding.severity.value == "high" for finding in findings)


def test_analyze_layout_sticky_overlay_intercepts_clicks() -> None:
    overlay = Box("#banner", 0, 0, 390, 50, tag="div", position="sticky")
    button = Box("#buy", 10, 10, 100, 50, tag="button")
    findings = analyze_layout(snapshot(overlay, button))
    assert any(finding.category == "layout-sticky-overlay" for finding in findings)


def test_analyze_layout_sticky_overlay_away_from_controls() -> None:
    overlay = Box("#banner", 0, 700, 390, 50, tag="div", position="fixed")
    button = Box("#buy", 10, 10, 100, 50, tag="button")
    findings = analyze_layout(snapshot(overlay, button))
    assert not any(finding.category == "layout-sticky-overlay" for finding in findings)


CLEAN_HTML = """<!DOCTYPE html><html lang="en"><head><title>t</title></head><body>
<h1>Title</h1><h2>Sub</h2>
<img src="/a.png" alt="A picture">
<label for="email">Email</label><input id="email" name="email">
<button>Submit</button>
</body></html>"""


def test_audit_accessibility_clean_page() -> None:
    report = audit_accessibility(CLEAN_HTML)
    assert report.passed is True
    assert report.findings == []


def test_audit_accessibility_missing_lang() -> None:
    report = audit_accessibility("<html><body><h1>Hi</h1></body></html>")
    assert any(finding.category == "a11y-lang" for finding in report.findings)


def test_audit_accessibility_missing_alt() -> None:
    report = audit_accessibility('<html lang="en"><img src="/x.png"></html>')
    assert any(finding.category == "a11y-img-alt" for finding in report.findings)


def test_audit_accessibility_decorative_image_allowed() -> None:
    report = audit_accessibility('<html lang="en"><img src="/x.png" alt=""></html>')
    assert not any(finding.category == "a11y-img-alt" for finding in report.findings)


def test_audit_accessibility_aria_hidden_image_allowed() -> None:
    report = audit_accessibility('<html lang="en"><img src="/x.png" aria-hidden="true"></html>')
    assert not any(finding.category == "a11y-img-alt" for finding in report.findings)


@pytest.mark.parametrize(
    "control",
    [
        '<input name="email">',
        '<select name="country"><option>US</option></select>',
        '<textarea name="notes"></textarea>',
    ],
)
def test_audit_accessibility_unlabeled_controls(control: str) -> None:
    report = audit_accessibility(f'<html lang="en">{control}</html>')
    assert any(finding.category == "a11y-label" for finding in report.findings)


@pytest.mark.parametrize(
    "control",
    [
        '<input name="email" aria-label="Email">',
        '<input name="email" title="Email">',
        '<label>Email <input name="email"></label>',
        '<span id="l">Email</span><input aria-labelledby="l">',
    ],
)
def test_audit_accessibility_labelled_controls(control: str) -> None:
    report = audit_accessibility(f'<html lang="en">{control}</html>')
    assert not any(finding.category == "a11y-label" for finding in report.findings)


def test_audit_accessibility_empty_button() -> None:
    report = audit_accessibility('<html lang="en"><button></button></html>')
    assert any(finding.category == "a11y-button-name" for finding in report.findings)


def test_audit_accessibility_aria_label_button_allowed() -> None:
    report = audit_accessibility('<html lang="en"><button aria-label="Close"></button></html>')
    assert not any(finding.category == "a11y-button-name" for finding in report.findings)


def test_audit_accessibility_heading_skip() -> None:
    report = audit_accessibility('<html lang="en"><h1>A</h1><h4>B</h4></html>')
    assert any(finding.category == "a11y-heading-skip" for finding in report.findings)


def test_audit_accessibility_sequential_headings_allowed() -> None:
    report = audit_accessibility('<html lang="en"><h1>A</h1><h2>B</h2><h3>C</h3></html>')
    assert not any(finding.category == "a11y-heading-skip" for finding in report.findings)


def test_audit_accessibility_invalid_role() -> None:
    report = audit_accessibility('<html lang="en"><div role="superbutton">x</div></html>')
    assert any(finding.category == "a11y-aria" for finding in report.findings)


def test_audit_accessibility_unknown_aria_attribute() -> None:
    report = audit_accessibility('<html lang="en"><div aria-not-real="1">x</div></html>')
    assert any(finding.category == "a11y-aria" for finding in report.findings)


def test_audit_accessibility_low_contrast_inline_style() -> None:
    report = audit_accessibility('<html lang="en"><p style="color:#999999;background-color:#aaaaaa">x</p></html>')
    assert any(finding.category == "a11y-contrast" for finding in report.findings)
    assert report.contrast_checks[0].passes_aa is False


def test_audit_accessibility_good_contrast_inline_style() -> None:
    report = audit_accessibility('<html lang="en"><p style="color:#000000;background-color:#ffffff">x</p></html>')
    assert not any(finding.category == "a11y-contrast" for finding in report.findings)


def test_audit_accessibility_attaches_redacted_url() -> None:
    report = audit_accessibility("<html></html>", "https://app.example.com/?token=abc")
    assert report.findings
    assert all("abc" not in finding.url for finding in report.findings)


def test_a11y_report_serializes() -> None:
    report = audit_accessibility("<html><input></html>")
    payload = report.to_dict()
    assert payload["passed"] is False
    assert payload["checks_run"] == 1
    assert isinstance(payload["findings"], list)


def test_audit_accessibility_empty_document_is_safe() -> None:
    assert audit_accessibility("").checks_run == 1


@pytest.mark.parametrize(
    ("metric", "category"),
    [
        ({"ttfb": 2000}, "vitals-ttfb"),
        ({"fcp": 3000}, "vitals-fcp"),
        ({"lcp": 4000}, "vitals-lcp"),
        ({"cls": 0.5}, "vitals-cls"),
        ({"domNodes": 5000}, "vitals-dom"),
        ({"jsBytes": 900_000}, "vitals-js-payload"),
        ({"imageBytes": 2_000_000}, "vitals-image-payload"),
    ],
)
def test_analyze_vitals_flags_each_budget(metric: dict, category: str) -> None:
    findings = analyze_vitals(VitalsMetrics.from_mapping(metric))
    assert [finding.category for finding in findings] == [category]


def test_analyze_vitals_clean_metrics() -> None:
    metrics = VitalsMetrics(ttfb_ms=100, fcp_ms=500, lcp_ms=1000, cls=0.01, dom_nodes=100, js_bytes=1000, image_bytes=1000)
    assert analyze_vitals(metrics) == []


def test_analyze_vitals_custom_thresholds() -> None:
    findings = analyze_vitals(VitalsMetrics(lcp_ms=1000), {"lcp_ms": 500})
    assert [finding.category for finding in findings] == ["vitals-lcp"]


def test_vitals_from_mapping_snake_case() -> None:
    metrics = VitalsMetrics.from_mapping({"ttfb_ms": 10, "dom_nodes": 5})
    assert metrics.ttfb_ms == 10
    assert metrics.dom_nodes == 5


def test_ux_report_serializes() -> None:
    report = UXReport(url="https://app.example.com/?token=secret")
    payload = report.to_dict()
    assert payload["passed"] is True
    assert "secret" not in payload["url"]
    assert payload["layout"] == []
