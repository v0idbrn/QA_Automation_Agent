# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Executive & Bug-Tracking Reporter for autonomous QA.

Produces Markdown, HTML, Jira-ready Markdown, and JSON machine-readable reports
from the unified finding model.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import json

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.models import Finding, FindingCategory, Severity


def _default_template_dir() -> Path:
    """Locate the bundled Jinja2 templates.

    Works both from a source checkout (repo/reports) and inside a PyInstaller
    bundle, where data files land next to the executable and `__file__` points
    into a temporary one-file extraction dir.
    """
    candidates = []
    if getattr(sys, "frozen", False):  # PyInstaller (onefile: _MEIPASS2, onedir: exe dir)
        meipass = getattr(sys, "_MEIPASS2", None) or getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "reports")
        candidates.append(Path(sys.executable).resolve().parent / "reports")
    else:  # source checkout
        candidates.append(Path(__file__).resolve().parent.parent / "reports")
    for candidate in candidates:
        if (candidate / "audit_report.html.jinja").is_file():
            return candidate
    # Last resort (unchanged historical behavior) — get_template raises a
    # clear TemplateNotFound if truly absent.
    return candidates[-1] if candidates else Path("reports")


@dataclass
class AuditReport:
    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


class ReportBuilder:
    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            template_dir = _default_template_dir()
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.globals["now_utc"] = datetime.now(timezone.utc)

    def build(
        self,
        target: str,
        findings: list[Finding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> str:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)
        summary = self._summarize(findings)
        report = AuditReport(target=target, started_at=started_at, finished_at=finished_at, findings=findings, summary=summary)
        template = self._env.get_template("audit_report.md.jinja")
        return template.render(report=report, findings=findings, summary=summary)

    def build_html(
        self,
        target: str,
        findings: list[Finding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> str:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)
        summary = self._summarize(findings)
        report = AuditReport(target=target, started_at=started_at, finished_at=finished_at, findings=findings, summary=summary)
        template = self._env.get_template("audit_report.html.jinja")
        return template.render(report=report, findings=findings, summary=summary)

    def build_json(
        self,
        target: str,
        findings: list[Finding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> dict[str, Any]:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)
        summary = self._summarize(findings)
        return {
            "target": target,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "summary": summary,
            "findings": [f.model_dump() for f in findings],
        }

    def build_jira(
        self,
        target: str,
        findings: list[Finding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> str:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)
        lines: list[str] = []
        lines.append(f"# Jira Export - {target}")
        lines.append(f"Generated: {finished_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        for finding in findings:
            lines.append(f"## {finding.severity.value.upper()} - {finding.source} / {finding.category.value}")
            lines.append(f"- **URL/Location:** {finding.location or finding.title}")
            lines.append(f"- **Detail:** {finding.description}")
            lines.append(f"- **Severity:** {finding.severity.value}")
            lines.append(f"- **Confidence:** {finding.confidence}")
            if finding.expected:
                lines.append(f"- **Expected Behavior:** {finding.expected}")
            if finding.actual:
                lines.append(f"- **Actual Behavior:** {finding.actual}")
            if finding.reproduction:
                lines.append(f"- **Steps to Reproduce:** {finding.reproduction}")
            if finding.evidence:
                lines.append(f"- **Evidence:** {finding.evidence}")
            lines.append("")
        return "\n".join(lines)

    def _summarize(self, findings: list[Finding]) -> dict[str, int]:
        return {
            "total": len(findings),
            "broken": sum(1 for f in findings if f.category in (FindingCategory.CRAWL, FindingCategory.HTTP)),
            "console_errors": sum(1 for f in findings if f.category == FindingCategory.CONSOLE),
            "high_severity": sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)),
            "passed": sum(1 for f in findings if f.severity == Severity.INFO and f.actual is None),
            "failed": sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)),
            "skipped": 0,
            "blocked": 0,
            "errors": sum(1 for f in findings if f.severity == Severity.INFO and f.actual is None and f.evidence is None),
        }


def render_audit_report(
    target: str,
    findings: list[Finding],
    output_path: Path,
    template_dir: Path | None = None,
) -> Path:
    builder = ReportBuilder(template_dir=template_dir)
    markdown = builder.build(target=target, findings=findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return output_path


def render_audit_report_json(
    target: str,
    findings: list[Finding],
    output_path: Path,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> Path:
    builder = ReportBuilder(template_dir=None)
    payload = builder.build_json(target, findings, started_at, finished_at)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return output_path


def render_jira_export(
    findings: list[Finding],
    target: str,
    output_path: Path,
) -> Path:
    builder = ReportBuilder(template_dir=None)
    text = builder.build_jira(target, findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return output_path
