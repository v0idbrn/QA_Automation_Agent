# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""
Executive & Bug-Tracking Reporter for autonomous QA.

Provides:
- Jinja2 HTML and Markdown report generation.
- Jira-compatible bug ticket export with severity, steps, expected/actual behavior, and evidence paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


@dataclass(frozen=True)
class AuditFinding:
    source: str
    kind: str
    url: str
    detail: str
    severity: str = "info"
    screenshot: str | None = None
    html_snapshot: str | None = None
    steps_to_reproduce: str | None = None
    expected: str | None = None
    actual: str | None = None


@dataclass
class AuditReport:
    target: str
    started_at: datetime
    finished_at: datetime
    findings: list[AuditFinding] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


class ReportBuilder:
    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).resolve().parent.parent / "reports"
        self._env = Environment(
            loader=FileSystemLoader(template_dir or Path("reports")),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.globals["now_utc"] = datetime.now(timezone.utc)

    def build(
        self,
        target: str,
        findings: list[AuditFinding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> str:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)

        summary: dict[str, int] = {
            "total": len(findings),
            "broken": sum(1 for f in findings if f.kind == "broken"),
            "console_errors": sum(1 for f in findings if f.kind == "console_error"),
            "high_severity": sum(1 for f in findings if f.severity == "high"),
        }
        report = AuditReport(
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            findings=findings,
            summary=summary,
        )
        template = self._env.get_template("audit_report.md.jinja")
        return template.render(report=report, findings=findings, summary=summary)

    def build_html(
        self,
        target: str,
        findings: list[AuditFinding],
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> str:
        started_at = started_at or datetime.now(timezone.utc)
        finished_at = finished_at or datetime.now(timezone.utc)

        summary: dict[str, int] = {
            "total": len(findings),
            "broken": sum(1 for f in findings if f.kind == "broken"),
            "console_errors": sum(1 for f in findings if f.kind == "console_error"),
            "high_severity": sum(1 for f in findings if f.severity == "high"),
        }
        report = AuditReport(
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            findings=findings,
            summary=summary,
        )
        template = self._env.get_template("audit_report.html.jinja")
        return template.render(report=report, findings=findings, summary=summary)


def render_audit_report(
    target: str,
    findings: list[AuditFinding],
    output_path: Path,
    template_dir: Path | None = None,
) -> Path:
    builder = ReportBuilder(template_dir=template_dir)
    markdown = builder.build(target=target, findings=findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    return output_path


def render_jira_export(
    findings: list[AuditFinding],
    target: str,
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append(f"# Jira Export - {target}")
    lines.append(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append("")
    for finding in findings:
        lines.append(f"## {finding.severity.upper()} - {finding.source} / {finding.kind}")
        lines.append(f"- **URL:** {finding.url}")
        lines.append(f"- **Detail:** {finding.detail}")
        lines.append(f"- **Severity:** {finding.severity}")
        if finding.steps_to_reproduce:
            lines.append(f"- **Steps to Reproduce:** {finding.steps_to_reproduce}")
        if finding.expected:
            lines.append(f"- **Expected Behavior:** {finding.expected}")
        if finding.actual:
            lines.append(f"- **Actual Behavior:** {finding.actual}")
        if finding.screenshot:
            lines.append(f"- **Screenshot:** {finding.screenshot}")
        if finding.html_snapshot:
            lines.append("- **HTML Snapshot:** attached")
        lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
