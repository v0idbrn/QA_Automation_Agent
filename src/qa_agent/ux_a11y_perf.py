# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Multi-viewport layout, WCAG 2.1 AA and Web Vitals profiler.

The pure helpers in this module take already-captured snapshots (HTML, element
boxes, performance metrics) so the entire accessibility and layout matrix is
unit-testable without a browser. :class:`UXProfiler` is the thin live layer
that captures those snapshots with Playwright.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from qa_agent.models import Finding, Severity
from qa_agent.redaction import redact_url

__all__ = [
    "A11yReport",
    "Box",
    "LayoutSnapshot",
    "ThemeContrast",
    "UXProfiler",
    "UXReport",
    "VIEWPORTS",
    "Viewport",
    "VitalsMetrics",
    "analyze_layout",
    "analyze_vitals",
    "audit_accessibility",
    "contrast_ratio",
    "parse_color",
    "relative_luminance",
]


@dataclass(frozen=True)
class Viewport:
    name: str
    width: int
    height: int


VIEWPORTS: tuple[Viewport, ...] = (
    Viewport("android", 360, 800),
    Viewport("ios", 390, 844),
    Viewport("tablet", 768, 1024),
    Viewport("desktop", 1440, 900),
)

_INTERACTIVE_TAGS = frozenset({"a", "button", "input", "select", "textarea", "summary"})
_MIN_TOUCH = 44.0


@dataclass(frozen=True)
class Box:
    selector: str
    x: float
    y: float
    width: float
    height: float
    tag: str = ""
    text: str = ""
    position: str = "static"
    z_index: int = 0
    visible: bool = True

    @property
    def right(self) -> float:
        return self.x + self.width

    @property
    def bottom(self) -> float:
        return self.y + self.height

    @property
    def area(self) -> float:
        return max(0.0, self.width) * max(0.0, self.height)


@dataclass(frozen=True)
class LayoutSnapshot:
    viewport: Viewport
    scroll_width: float
    client_width: float
    elements: tuple[Box, ...] = ()

    @classmethod
    def from_mapping(cls, viewport: Viewport, data: Mapping[str, Any]) -> "LayoutSnapshot":
        boxes = tuple(
            Box(
                selector=str(item.get("selector", "")),
                x=float(item.get("x", 0)),
                y=float(item.get("y", 0)),
                width=float(item.get("width", 0)),
                height=float(item.get("height", 0)),
                tag=str(item.get("tag", "")).lower(),
                text=str(item.get("text", "")),
                position=str(item.get("position", "static")),
                z_index=int(item.get("zIndex", 0)),
                visible=bool(item.get("visible", True)),
            )
            for item in data.get("elements", ())
        )
        return cls(
            viewport=viewport,
            scroll_width=float(data.get("scrollWidth", 0)),
            client_width=float(data.get("clientWidth", viewport.width)),
            elements=boxes,
        )


# ---------------------------------------------------------------------------
# Colour helpers (WCAG 2.1 relative luminance + contrast ratio)
# ---------------------------------------------------------------------------

_NAMED_COLORS = {
    "black": (0, 0, 0),
    "white": (255, 255, 255),
    "red": (255, 0, 0),
    "green": (0, 128, 0),
    "blue": (0, 0, 255),
    "grey": (128, 128, 128),
    "gray": (128, 128, 128),
    "transparent": None,
}


def parse_color(value: str) -> tuple[int, int, int] | None:
    """Parse ``#rgb``/``#rrggbb``/``rgb()``/``rgba()``/basic names to RGB."""
    if not value:
        return None
    text = str(value).strip().lower()
    if text in _NAMED_COLORS:
        return _NAMED_COLORS[text]
    if text.startswith("#"):
        digits = text[1:]
        if len(digits) == 3:
            return tuple(int(char * 2, 16) for char in digits)  # type: ignore[return-value]
        if len(digits) >= 6:
            try:
                return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16))
            except ValueError:
                return None
        return None
    if text.startswith("rgb"):
        start = text.find("(")
        end = text.find(")")
        if start == -1 or end == -1:
            return None
        parts = [part.strip() for part in text[start + 1 : end].split(",")]
        if len(parts) < 3:
            return None
        try:
            channels = [int(round(float(part))) for part in parts[:3]]
        except ValueError:
            return None
        return (max(0, min(255, channels[0])), max(0, min(255, channels[1])), max(0, min(255, channels[2])))
    return None


def _channel(lum: float) -> float:
    return lum / 12.92 if lum <= 0.03928 else ((lum + 0.055) / 1.055) ** 2.4


def relative_luminance(rgb: tuple[int, int, int]) -> float:
    red, green, blue = (channel / 255.0 for channel in rgb)
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def contrast_ratio(foreground: str | tuple[int, int, int], background: str | tuple[int, int, int]) -> float:
    fg = parse_color(foreground) if isinstance(foreground, str) else foreground
    bg = parse_color(background) if isinstance(background, str) else background
    if fg is None or bg is None:
        return 21.0
    first = relative_luminance(fg)
    second = relative_luminance(bg)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


@dataclass(frozen=True)
class ThemeContrast:
    selector: str
    foreground: str
    background: str
    ratio: float
    large_text: bool = False

    @property
    def passes_aa(self) -> bool:
        return self.ratio >= (3.0 if self.large_text else 4.5)


# ---------------------------------------------------------------------------
# Layout checks
# ---------------------------------------------------------------------------


def _layout_finding(
    title: str,
    severity: Severity,
    category: str,
    description: str,
    selector: str,
    viewport: Viewport,
    evidence: str = "",
    recommendation: str = "",
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        url=selector,
        evidence=redact_url(f"{viewport.name} {viewport.width}x{viewport.height} {evidence}".strip()),
        recommendation=recommendation,
    )


def analyze_layout(snapshot: LayoutSnapshot) -> list[Finding]:
    """Detect responsive layout defects for one viewport snapshot."""
    findings: list[Finding] = []
    viewport = snapshot.viewport

    if snapshot.scroll_width > snapshot.client_width + 1:
        delta = snapshot.scroll_width - snapshot.client_width
        findings.append(
            _layout_finding(
                title="Horizontal scroll overflow",
                severity=Severity.HIGH,
                category="layout-overflow",
                description="The page can be scrolled horizontally at this viewport.",
                selector="html",
                viewport=viewport,
                evidence=f"scrollWidth={snapshot.scroll_width} clientWidth={snapshot.client_width} (+{delta:.0f}px)",
                recommendation="Constrain wide media and long text; assert scrollWidth <= clientWidth in CI.",
            )
        )

    for box in snapshot.elements:
        if not box.visible:
            continue
        if box.tag in _INTERACTIVE_TAGS and (box.width < _MIN_TOUCH or box.height < _MIN_TOUCH):
            findings.append(
                _layout_finding(
                    title="Touch target below 44x44px",
                    severity=Severity.MEDIUM,
                    category="layout-touch-target",
                    description="A tappable control is smaller than the 44x44 CSS pixel guidance.",
                    selector=box.selector,
                    viewport=viewport,
                    evidence=f"{box.tag} {box.width:.0f}x{box.height:.0f}",
                    recommendation="Increase padding or min-width/min-height to 44x44px.",
                )
            )
        if box.x < -1 or box.right > snapshot.client_width + 1:
            findings.append(
                _layout_finding(
                    title="Interactive element clipped by viewport",
                    severity=Severity.MEDIUM,
                    category="layout-clipped",
                    description="A control extends outside the visible horizontal area.",
                    selector=box.selector,
                    viewport=viewport,
                    evidence=f"x={box.x:.0f} right={box.right:.0f} clientWidth={snapshot.client_width}",
                    recommendation="Use fluid widths or wrap the control so it stays reachable.",
                )
            )

    visible = [box for box in snapshot.elements if box.visible]
    for index, first in enumerate(visible):
        for second in visible[index + 1 :]:
            if first.tag not in _INTERACTIVE_TAGS or second.tag not in _INTERACTIVE_TAGS:
                continue
            overlap_w = min(first.right, second.right) - max(first.x, second.x)
            overlap_h = min(first.bottom, second.bottom) - max(first.y, second.y)
            if overlap_w <= 0 or overlap_h <= 0:
                continue
            overlap = overlap_w * overlap_h
            smaller = min(first.area, second.area) or 1.0
            if overlap / smaller >= 0.5:
                findings.append(
                    _layout_finding(
                        title="Overlapping interactive controls",
                        severity=Severity.MEDIUM,
                        category="layout-overlap",
                        description="Two controls occupy the same space, so one may be untappable.",
                        selector=f"{first.selector} + {second.selector}",
                        viewport=viewport,
                        evidence=f"overlap={overlap:.0f}px2 of {smaller:.0f}px2",
                        recommendation="Separate the controls in the layout and re-test at every viewport.",
                    )
                )

    for box in snapshot.elements:
        if not box.visible or box.position not in {"fixed", "sticky"}:
            continue
        covered = box.width * box.height
        viewport_area = float(viewport.width * viewport.height) or 1.0
        if covered / viewport_area >= 0.5:
            findings.append(
                _layout_finding(
                    title="Sticky overlay covers most of the viewport",
                    severity=Severity.HIGH,
                    category="layout-sticky-overlay",
                    description="A fixed/sticky layer blocks the content behind it.",
                    selector=box.selector,
                    viewport=viewport,
                    evidence=f"coverage={covered / viewport_area:.0%}",
                    recommendation="Reduce the overlay or provide a dismiss control.",
                )
            )
        elif any(
            other.selector != box.selector
            and other.tag in _INTERACTIVE_TAGS
            and min(box.right, other.right) > max(box.x, other.x)
            and min(box.bottom, other.bottom) > max(box.y, other.y)
            for other in visible
        ):
            findings.append(
                _layout_finding(
                    title="Sticky overlay intercepts clicks",
                    severity=Severity.MEDIUM,
                    category="layout-sticky-overlay",
                    description="A fixed/sticky element overlaps an interactive control.",
                    selector=box.selector,
                    viewport=viewport,
                    evidence="overlaps an interactive element",
                    recommendation="Reposition the overlay or add pointer-events handling.",
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Accessibility audit
# ---------------------------------------------------------------------------


@dataclass
class A11yReport:
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    contrast_checks: list[ThemeContrast] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks_run": self.checks_run,
            "findings": [finding.to_dict() for finding in self.findings],
            "contrast": [
                {"selector": item.selector, "ratio": round(item.ratio, 2), "passes": item.passes_aa}
                for item in self.contrast_checks
            ],
        }


def _a11y(title: str, severity: Severity, category: str, description: str, evidence: str, recommendation: str) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
    )


_ARIA_ATTRIBUTES = frozenset(
    {
        "aria-label", "aria-labelledby", "aria-describedby", "aria-hidden", "aria-expanded",
        "aria-controls", "aria-current", "aria-live", "aria-atomic", "aria-busy", "aria-checked",
        "aria-disabled", "aria-haspopup", "aria-invalid", "aria-level", "aria-modal",
        "aria-multiselectable", "aria-orientation", "aria-pressed", "aria-readonly",
        "aria-required", "aria-selected", "aria-sort", "aria-valuemax", "aria-valuemin",
        "aria-valuenow", "aria-valuetext", "aria-activedescendant", "aria-autocomplete",
        "aria-details", "aria-errormessage", "aria-flowto", "aria-keyshortcuts", "aria-roledescription",
    }
)

_ARIA_ROLES = frozenset(
    {
        "alert", "alertdialog", "application", "article", "banner", "button", "cell", "checkbox",
        "columnheader", "combobox", "complementary", "contentinfo", "definition", "dialog",
        "directory", "document", "feed", "figure", "form", "grid", "gridcell", "group",
        "heading", "img", "link", "list", "listbox", "listitem", "log", "main", "marquee",
        "math", "menu", "menubar", "menuitem", "menuitemcheckbox", "menuitemradio", "navigation",
        "none", "note", "option", "presentation", "progressbar", "radio", "radiogroup", "region",
        "row", "rowgroup", "rowheader", "scrollbar", "search", "searchbox", "separator", "slider",
        "spinbutton", "status", "switch", "tab", "table", "tablist", "tabpanel", "term", "textbox",
        "timer", "toolbar", "tooltip", "tree", "treegrid", "treeitem",
    }
)


def _labelled(control: Any, soup: Any) -> bool:
    if control.get("aria-label") or control.get("aria-labelledby") or control.get("title"):
        return True
    control_id = control.get("id")
    if control_id and soup.find("label", attrs={"for": control_id}):
        return True
    if control.find_parent("label") is not None:
        return True
    return False


def _accessible_text(node: Any) -> str:
    return " ".join(
        str(node.get(attribute) or "")
        for attribute in ("aria-label", "title", "alt")
    ).strip().strip() or " ".join(node.get_text(" ", strip=True).split())


def audit_accessibility(html: str, url: str = "") -> A11yReport:
    """Run WCAG 2.1 AA heuristics over a captured HTML document."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html or "", "html.parser")
    report = A11yReport()
    report.checks_run += 1

    if soup.find("html") is not None and not (soup.find("html").get("lang") or "").strip():
        report.findings.append(
            _a11y(
                "Missing document language",
                Severity.MEDIUM,
                "a11y-lang",
                "The <html> element has no lang attribute, so screen readers cannot pick a voice.",
                "<html> without lang",
                'Add lang="en" (or the correct locale) to <html>.',
            )
        )

    for index, image in enumerate(soup.select("img")):
        if image.get("alt") is None and image.get("aria-hidden") != "true" and image.get("role") != "presentation":
            report.findings.append(
                _a11y(
                    "Image missing alt text",
                    Severity.MEDIUM,
                    "a11y-img-alt",
                    "Images need an alt attribute so assistive tech can describe them.",
                    f"img #{index} src={image.get('src', '')}",
                    'Add descriptive alt text, or alt="" for decorative images.',
                )
            )

    for index, control in enumerate(soup.select("input:not([type=hidden]), select, textarea")):
        if not _labelled(control, soup):
            report.findings.append(
                _a11y(
                    "Form control without accessible label",
                    Severity.HIGH,
                    "a11y-label",
                    "A form control has no label, aria-label, aria-labelledby or title.",
                    f"{control.name} #{index} name={control.get('name', '')}",
                    "Associate a <label for> or add aria-label.",
                )
            )

    for index, button in enumerate(soup.select("button, [role=button]")):
        if not _accessible_text(button) and not button.get("aria-labelledby"):
            report.findings.append(
                _a11y(
                    "Button without accessible name",
                    Severity.HIGH,
                    "a11y-button-name",
                    "A button exposes no text or accessible name.",
                    f"button #{index}",
                    "Add visible text or aria-label to the button.",
                )
            )

    levels = [int(heading.name[1]) for heading in soup.select("h1, h2, h3, h4, h5, h6")]
    previous = 0
    for level in levels:
        if previous and level - previous > 1:
            report.findings.append(
                _a11y(
                    "Skipped heading level",
                    Severity.LOW,
                    "a11y-heading-skip",
                    "Headings jump more than one level, which breaks document outline navigation.",
                    f"h{previous} -> h{level}",
                    "Use sequential heading levels.",
                )
            )
            break
        previous = level

    for node in soup.select("[role]"):
        role = str(node.get("role", "")).strip().lower()
        if role and role not in _ARIA_ROLES:
            report.findings.append(
                _a11y(
                    "Invalid ARIA role",
                    Severity.LOW,
                    "a11y-aria",
                    "An element declares a role that is not part of the ARIA specification.",
                    f"role={role}",
                    "Use a valid ARIA role or native semantic element.",
                )
            )
    for node in soup.select("*"):
        for attribute in node.attrs:
            if attribute.startswith("aria-") and attribute not in _ARIA_ATTRIBUTES:
                report.findings.append(
                    _a11y(
                        "Unknown ARIA attribute",
                        Severity.LOW,
                        "a11y-aria",
                        "An element declares an unrecognized aria-* attribute.",
                        attribute,
                        "Remove the attribute or replace it with a supported one.",
                    )
                )

    for node in soup.select("[style]"):
        style = str(node.get("style", ""))
        declarations = dict(
            (key.strip(), value.strip()) for key, value in (part.split(":", 1) for part in style.split(";") if ":" in part)
        )
        foreground = declarations.get("color", "").strip()
        background = declarations.get("background-color", declarations.get("background", "")).strip()
        if not foreground or not background:
            continue
        ratio = contrast_ratio(foreground, background)
        large = node.name in {"h1", "h2", "h3"}
        theme = ThemeContrast(f"{node.name}:{node.get('class', '')}", foreground, background, ratio, large)
        report.contrast_checks.append(theme)
        if not theme.passes_aa:
            report.findings.append(
                _a11y(
                    "Insufficient colour contrast",
                    Severity.MEDIUM,
                    "a11y-contrast",
                    "Text contrast is below the WCAG 2.1 AA threshold.",
                    f"{foreground} on {background} = {ratio:.2f}:1",
                    "Raise contrast to at least 4.5:1 (3:1 for large text).",
                )
            )

    if url:
        report.findings = [
            Finding(
                title=finding.title,
                severity=finding.severity,
                category=finding.category,
                description=finding.description,
                url=redact_url(url),
                evidence=finding.evidence,
                recommendation=finding.recommendation,
            )
            for finding in report.findings
        ]

    return report


# ---------------------------------------------------------------------------
# Web Vitals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VitalsMetrics:
    ttfb_ms: float = 0.0
    fcp_ms: float = 0.0
    lcp_ms: float = 0.0
    cls: float = 0.0
    dom_nodes: int = 0
    js_bytes: int = 0
    image_bytes: int = 0
    requests: int = 0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "VitalsMetrics":
        return cls(
            ttfb_ms=float(data.get("ttfb", data.get("ttfb_ms", 0))),
            fcp_ms=float(data.get("fcp", data.get("fcp_ms", 0))),
            lcp_ms=float(data.get("lcp", data.get("lcp_ms", 0))),
            cls=float(data.get("cls", 0)),
            dom_nodes=int(data.get("domNodes", data.get("dom_nodes", 0))),
            js_bytes=int(data.get("jsBytes", data.get("js_bytes", 0))),
            image_bytes=int(data.get("imageBytes", data.get("image_bytes", 0))),
            requests=int(data.get("requests", 0)),
        )


_DEFAULT_VITALS = {
    "ttfb_ms": 800.0,
    "fcp_ms": 1800.0,
    "lcp_ms": 2500.0,
    "cls": 0.1,
    "dom_nodes": 1500,
    "js_bytes": 500_000,
    "image_bytes": 1_500_000,
}


def _vital(title: str, category: str, measured: str, limit: str, severity: Severity) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        description=f"Measured {measured} against the {limit} budget.",
        evidence=f"{measured} > {limit}",
        recommendation=f"Reduce {category} below {limit} or document the exception.",
    )


def analyze_vitals(metrics: VitalsMetrics, thresholds: Mapping[str, float] | None = None) -> list[Finding]:
    limits = {**_DEFAULT_VITALS, **(thresholds or {})}
    findings: list[Finding] = []
    if metrics.ttfb_ms > limits["ttfb_ms"]:
        findings.append(_vital("Slow TTFB", "vitals-ttfb", f"{metrics.ttfb_ms:.0f}ms", f"{limits['ttfb_ms']:.0f}ms", Severity.MEDIUM))
    if metrics.fcp_ms > limits["fcp_ms"]:
        findings.append(_vital("Slow First Contentful Paint", "vitals-fcp", f"{metrics.fcp_ms:.0f}ms", f"{limits['fcp_ms']:.0f}ms", Severity.MEDIUM))
    if metrics.lcp_ms > limits["lcp_ms"]:
        findings.append(_vital("Slow Largest Contentful Paint", "vitals-lcp", f"{metrics.lcp_ms:.0f}ms", f"{limits['lcp_ms']:.0f}ms", Severity.HIGH))
    if metrics.cls > limits["cls"]:
        findings.append(_vital("High layout shift (CLS)", "vitals-cls", f"{metrics.cls:.3f}", f"{limits['cls']:.3f}", Severity.HIGH))
    if metrics.dom_nodes > limits["dom_nodes"]:
        findings.append(_vital("DOM node bloat", "vitals-dom", f"{metrics.dom_nodes} nodes", f"{limits['dom_nodes']:.0f} nodes", Severity.MEDIUM))
    if metrics.js_bytes > limits["js_bytes"]:
        findings.append(_vital("Oversized JavaScript payload", "vitals-js-payload", f"{metrics.js_bytes} bytes", f"{limits['js_bytes']:.0f} bytes", Severity.MEDIUM))
    if metrics.image_bytes > limits["image_bytes"]:
        findings.append(_vital("Oversized image payload", "vitals-image-payload", f"{metrics.image_bytes} bytes", f"{limits['image_bytes']:.0f} bytes", Severity.LOW))
    return findings


# ---------------------------------------------------------------------------
# Live profiler
# ---------------------------------------------------------------------------

_LAYOUT_SCRIPT = """
() => ({
  scrollWidth: document.documentElement.scrollWidth,
  clientWidth: document.documentElement.clientWidth,
  elements: Array.from(document.querySelectorAll('a,button,input,select,textarea,summary,[role=button],[style*=fixed],[style*=sticky]'))
    .slice(0, 400)
    .map((el, index) => {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return {
        selector: el.id ? '#' + el.id : el.tagName.toLowerCase() + '[' + index + ']',
        x: rect.x, y: rect.y, width: rect.width, height: rect.height,
        tag: el.tagName.toLowerCase(),
        text: (el.innerText || el.value || '').slice(0, 80),
        position: style.position,
        zIndex: parseInt(style.zIndex || '0', 10) || 0,
        visible: style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0,
      };
    }),
})
"""

_VITALS_SCRIPT = """
() => {
  const nav = performance.getEntriesByType('navigation')[0] || {};
  const paint = performance.getEntriesByType('paint') || [];
  const fcp = paint.find(entry => entry.name === 'first-contentful-paint');
  const resources = performance.getEntriesByType('resource') || [];
  const sum = (type) => resources.filter(r => r.initiatorType === type)
    .reduce((total, r) => total + (r.transferSize || 0), 0);
  const lcpEntries = performance.getEntriesByType('largest-contentful-paint') || [];
  const layoutShifts = performance.getEntriesByType('layout-shift') || [];
  return {
    ttfb: nav.responseStart || 0,
    fcp: fcp ? fcp.startTime : 0,
    lcp: lcpEntries.length ? lcpEntries[lcpEntries.length - 1].startTime : 0,
    cls: layoutShifts.filter(entry => !entry.hadRecentInput).reduce((total, entry) => total + entry.value, 0),
    domNodes: document.getElementsByTagName('*').length,
    jsBytes: sum('script'),
    imageBytes: sum('img'),
    requests: resources.length,
  };
}
"""


@dataclass
class UXReport:
    url: str
    layout_findings: list[Finding] = field(default_factory=list)
    accessibility: A11yReport = field(default_factory=A11yReport)
    vitals: VitalsMetrics | None = None
    vital_findings: list[Finding] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def findings(self) -> list[Finding]:
        return [*self.layout_findings, *self.accessibility.findings, *self.vital_findings]

    @property
    def passed(self) -> bool:
        return not any(finding.severity in {Severity.CRITICAL, Severity.HIGH} for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": redact_url(self.url),
            "passed": self.passed,
            "layout": [finding.to_dict() for finding in self.layout_findings],
            "accessibility": self.accessibility.to_dict(),
            "vitals": None if self.vitals is None else self.vitals.__dict__,
            "vital_findings": [finding.to_dict() for finding in self.vital_findings],
            "duration_ms": round(self.duration_ms, 2),
        }


class UXProfiler:
    """Capture layout, accessibility, and vitals snapshots with Playwright."""

    def __init__(self, viewports: Sequence[Viewport] = VIEWPORTS, timeout_ms: float = 15_000) -> None:
        self.viewports = tuple(viewports)
        self.timeout_ms = timeout_ms

    def profile(self, url: str, auth_state: str | None = None) -> UXReport:
        from playwright.sync_api import sync_playwright

        started = time.perf_counter()
        report = UXReport(url=url)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for viewport in self.viewports:
                    context_options: dict[str, Any] = {"viewport": {"width": viewport.width, "height": viewport.height}}
                    if auth_state:
                        context_options["storage_state"] = auth_state
                    context = browser.new_context(**context_options)
                    page = context.new_page()
                    try:
                        page.goto(url, wait_until="load", timeout=self.timeout_ms)
                        page.wait_for_timeout(60)
                        snapshot = LayoutSnapshot.from_mapping(viewport, page.evaluate(_LAYOUT_SCRIPT))
                        report.layout_findings.extend(analyze_layout(snapshot))
                        if viewport is self.viewports[1] and not report.accessibility.findings:
                            report.accessibility = audit_accessibility(page.content(), url)
                        if viewport is self.viewports[-1]:
                            report.vitals = VitalsMetrics.from_mapping(page.evaluate(_VITALS_SCRIPT))
                    finally:
                        context.close()
            finally:
                browser.close()
        if report.vitals is not None:
            report.vital_findings = analyze_vitals(report.vitals)
        report.duration_ms = (time.perf_counter() - started) * 1000.0
        return report
