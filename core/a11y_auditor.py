# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Accessibility & Visual Auditor for autonomous QA.

Provides:
- Accessibility DOM checks (alt text, ARIA roles, heading hierarchy).
- Visual evidence capture on failures (high-resolution screenshots).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import Page


@dataclass(frozen=True)
class A11yFinding:
    rule: str
    element: str
    detail: str
    severity: str = "medium"
    screenshot: str | None = None


class A11yAuditor:
    def __init__(self, screenshot_dir: str | None = None) -> None:
        self.screenshot_dir = screenshot_dir or "reports"

    async def audit_page(self, page: Page, url: str) -> list[A11yFinding]:
        findings: list[A11yFinding] = []
        html = await self._safe_content(page)
        findings.extend(self._audit_from_html(html, url))
        if self._has_critical_a11y_issue(findings):
            await self._screenshot_high_res(page, url)
        return findings

    async def _safe_content(self, page: Page) -> str:
        try:
            return await page.content()
        except Exception:  # noqa: BLE001
            return ""

    def _audit_from_html(self, html: str, url: str) -> list[A11yFinding]:
        findings: list[A11yFinding] = []
        if not html:
            return findings

        missing_alt = self._count_missing_alt(html)
        if missing_alt:
            findings.append(
                A11yFinding(
                    rule="missing_alt_text",
                    element=f"{missing_alt} image(s) without alt",
                    detail=f"Found {missing_alt} <img> elements missing alt attributes on {url}",
                    severity="medium",
                )
            )

        aria_issues = self._count_aria_role_issues(html)
        if aria_issues:
            findings.append(
                A11yFinding(
                    rule="aria_role_issues",
                    element=f"{aria_issues} suspect ARIA usage",
                    detail=f"Detected {aria_issues} potential ARIA role issues on {url}",
                    severity="low",
                )
            )

        heading_issues = self._check_heading_hierarchy(html)
        if heading_issues:
            findings.append(
                A11yFinding(
                    rule="heading_hierarchy",
                    element=heading_issues,
                    detail=f"Possible heading hierarchy issue on {url}: {heading_issues}",
                    severity="low",
                )
            )

        return findings

    def _count_missing_alt(self, html: str) -> int:
        count = 0
        pos = 0
        lower = html.lower()
        while True:
            idx = lower.find("<img", pos)
            if idx == -1:
                break
            end = lower.find(">", idx)
            if end == -1:
                break
            tag = html[idx:end]
            if "alt=" not in tag.lower():
                count += 1
            pos = end + 1
        return count

    def _count_aria_role_issues(self, html: str) -> int:
        issues = 0
        if "role=" in html.lower():
            issues += 1
        return issues

    def _check_heading_hierarchy(self, html: str) -> str:
        h1_count = html.lower().count("<h1")
        if h1_count == 0:
            return "no h1 found"
        if h1_count > 1:
            return "multiple h1 found"
        return ""

    def _has_critical_a11y_issue(self, findings: list[A11yFinding]) -> bool:
        return any(f.severity in ("high", "critical") for f in findings)

    async def _screenshot_high_res(self, page: Page, url: str) -> str | None:
        try:
            path = f"{self.screenshot_dir}/a11y_{urlparse(url).path.strip('/') or 'index'}.png"
            await page.screenshot(path=path, full_page=True, width=1440, height=900)
            return path
        except Exception:  # noqa: BLE001
            return None


def assess_accessibility(findings: list[A11yFinding]) -> dict[str, Any]:
    """Summarize accessibility findings into a small report structure."""
    severe = sum(1 for f in findings if f.severity in ("high", "critical"))
    medium = sum(1 for f in findings if f.severity == "medium")
    low = sum(1 for f in findings if f.severity == "low")
    return {
        "total": len(findings),
        "severe": severe,
        "medium": medium,
        "low": low,
        "rules": sorted({f.rule for f in findings}),
    }
