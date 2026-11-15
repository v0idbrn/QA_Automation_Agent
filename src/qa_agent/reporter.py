# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Client-ready deliverables: standalone HTML executive report and Markdown bug report.

No template engine and no CDN are required: the HTML carries inline CSS and a
few lines of vanilla JS for severity filtering, so it can be attached to an
email or an Upwork delivery without network access.
"""

from __future__ import annotations

import hashlib
import html
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from qa_agent.models import Finding, Severity, severity_counts, sort_findings
from qa_agent.redaction import redact_text, redact_url

__all__ = [
    "ReportBundle",
    "build_manifest",
    "render_html",
    "render_markdown",
    "sha256_file",
    "write_report",
]

_SEVERITY_COLORS = {
    "critical": "#b3261e",
    "high": "#d9480f",
    "medium": "#b8860b",
    "low": "#2b6cb0",
    "info": "#4a5568",
}


@dataclass
class ReportBundle:
    out_dir: Path
    html_path: Path
    markdown_path: Path
    manifest_path: Path | None = None
    manifest: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "out_dir": str(self.out_dir),
            "html": str(self.html_path),
            "markdown": str(self.markdown_path),
            "manifest": None if self.manifest_path is None else str(self.manifest_path),
            "evidence": self.manifest,
        }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(paths: Iterable[str | Path], root: str | Path | None = None) -> dict[str, Any]:
    base = Path(root) if root is not None else None
    entries: dict[str, Any] = {}
    for raw in paths:
        path = Path(raw)
        if not path.is_file():
            continue
        key = str(path.relative_to(base)) if base and base in path.parents else path.name
        entries[key] = {"sha256": sha256_file(path), "bytes": path.stat().st_size}
    return {"algorithm": "sha256", "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "files": entries}


def _finding_sort(findings: Sequence[Finding]) -> list[Finding]:
    return sort_findings(list(findings))


def _reproduction(finding: Finding) -> str:
    if finding.reproduction:
        return finding.reproduction
    if finding.url:
        return f"Open {finding.url} and follow the steps in the evidence section."
    return "Reproduce on the audited target using the evidence below."


def render_markdown(
    findings: Sequence[Finding],
    *,
    title: str = "QA Audit Report",
    target: str = "",
    metadata: Mapping[str, Any] | None = None,
) -> str:
    ordered = _finding_sort(findings)
    counts = severity_counts(ordered)
    lines = [
        f"# {title}",
        "",
        f"- Target: {redact_url(target) if target else 'n/a'}",
        f"- Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- Findings: {len(ordered)} "
        + " · ".join(f"{severity}: {count}" for severity, count in counts.items() if count) if ordered else "- Findings: 0",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    lines += [f"| {severity.title()} | {count} |" for severity, count in counts.items()]
    if metadata:
        lines += ["", "## Engagement metadata", ""]
        for key, value in metadata.items():
            lines.append(f"- **{key}**: {redact_text(str(value))}")
    if not ordered:
        lines += ["", "No findings were recorded for this run.", ""]
        return "\n".join(lines) + "\n"

    lines += ["", "## Findings", ""]
    for index, finding in enumerate(ordered, start=1):
        lines += [
            f"### {index}. [{finding.severity.value.upper()}] {finding.title}",
            "",
            f"- **Category**: {finding.category}",
            f"- **URL**: {finding.url or 'n/a'}",
            f"- **Confidence**: {finding.confidence}",
            "",
            finding.description or "No description captured.",
            "",
            "**Steps to reproduce**",
            "",
            _reproduction(finding),
            "",
        ]
        if finding.evidence:
            lines += ["**Evidence**", "", "```text", finding.evidence, "```", ""]
        if finding.recommendation:
            lines += [f"**Recommendation**: {finding.recommendation}", ""]
    return "\n".join(lines).rstrip() + "\n"


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _kpi_cards(counts: Mapping[str, int]) -> str:
    cards = []
    for severity in ("critical", "high", "medium", "low", "info"):
        cards.append(
            f'<div class="kpi" style="border-top:4px solid {_SEVERITY_COLORS[severity]}">'
            f'<span class="kpi-count">{counts.get(severity, 0)}</span>'
            f'<span class="kpi-label">{severity.title()}</span></div>'
        )
    return "".join(cards)


def _evidence_images(images: Sequence[tuple[str, str]]) -> str:
    if not images:
        return ""
    cards = "".join(
        f'<figure><img src="{_escape(src)}" alt="{_escape(caption)}"/>'
        f"<figcaption>{_escape(caption)}</figcaption></figure>"
        for caption, src in images
    )
    return f'<section><h2>Evidence</h2><div class="gallery">{cards}</div></section>'


def render_html(
    findings: Sequence[Finding],
    *,
    title: str = "QA Audit Report",
    target: str = "",
    metadata: Mapping[str, Any] | None = None,
    images: Sequence[tuple[str, str]] = (),
    manifest: Mapping[str, Any] | None = None,
) -> str:
    ordered = _finding_sort(findings)
    counts = severity_counts(ordered)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    details = []
    for index, finding in enumerate(ordered, start=1):
        color = _SEVERITY_COLORS[finding.severity.value]
        rows.append(
            "<tr>"
            f'<td class="sev" data-sev="{finding.severity.value}" style="color:{color}">{_escape(finding.severity.value.upper())}</td>'
            f"<td>{_escape(finding.title)}</td>"
            f"<td>{_escape(finding.category)}</td>"
            f"<td class=\"url\">{_escape(finding.url)}</td>"
            f'<td><a href="#f{index}">details</a></td>'
            "</tr>"
        )
        details.append(
            f'<article id="f{index}" class="finding" data-sev="{finding.severity.value}">'
            f'<h3><span class="sev" style="color:{color}">{_escape(finding.severity.value.upper())}</span> {_escape(finding.title)}</h3>'
            f"<p>{_escape(finding.description)}</p>"
            f"<p class=\"meta\"><strong>Category:</strong> {_escape(finding.category)} · "
            f"<strong>Confidence:</strong> {_escape(finding.confidence)} · "
            f"<strong>URL:</strong> {_escape(finding.url)}</p>"
            f"<h4>Steps to reproduce</h4><pre>{_escape(_reproduction(finding))}</pre>"
            + (f"<h4>Evidence</h4><pre>{_escape(finding.evidence)}</pre>" if finding.evidence else "")
            + (f"<h4>Recommendation</h4><p>{_escape(finding.recommendation)}</p>" if finding.recommendation else "")
            + "</article>"
        )

    metadata_html = ""
    if metadata:
        items = "".join(f"<li><strong>{_escape(key)}</strong>: {_escape(redact_text(str(value)))}</li>" for key, value in metadata.items())
        metadata_html = f'<section><h2>Engagement metadata</h2><ul class="meta-list">{items}</ul></section>'

    manifest_html = ""
    if manifest:
        files = manifest.get("files", {})
        entries = "".join(
            f"<tr><td>{_escape(name)}</td><td><code>{_escape(data.get('sha256', ''))}</code></td><td>{_escape(data.get('bytes', ''))}</td></tr>"
            for name, data in files.items()
        )
        manifest_html = (
            "<section><h2>Evidence manifest (SHA-256)</h2>"
            '<table class="manifest"><thead><tr><th>File</th><th>SHA-256</th><th>Bytes</th></tr></thead>'
            f"<tbody>{entries}</tbody></table>"
            f"<p class=\"meta\">Generated {_escape(manifest.get('generated_at', ''))}</p></section>"
        )

    table = (
        '<section><h2>Findings</h2>'
        '<div class="filters">'
        '<button data-filter="all" class="active">All</button>'
        + "".join(f'<button data-filter="{severity}">{severity.title()}</button>' for severity in ("critical", "high", "medium", "low", "info"))
        + "</div>"
        '<table id="findings"><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>URL</th><th></th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></section>"
        if ordered
        else '<section><h2>Findings</h2><p class="empty">No findings were recorded for this run.</p></section>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_escape(title)}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1a202c; background: #f7fafc; }}
header {{ background: #101828; color: #fff; padding: 32px 40px; }}
header h1 {{ margin: 0 0 8px; font-size: 26px; }}
header p {{ margin: 4px 0; color: #cbd5e0; }}
main {{ max-width: 1100px; margin: 0 auto; padding: 24px 40px 60px; }}
section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px 24px; margin: 20px 0; }}
section h2 {{ margin-top: 0; font-size: 18px; }}
.kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }}
.kpi {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 14px; text-align: center; }}
.kpi-count {{ display: block; font-size: 30px; font-weight: 700; }}
.kpi-label {{ color: #4a5568; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid #edf2f7; vertical-align: top; }}
th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #4a5568; }}
tr:hover td {{ background: #f7fafc; }}
td.url {{ max-width: 320px; word-break: break-all; color: #4a5568; }}
.sev {{ font-weight: 700; white-space: nowrap; }}
.finding {{ border-left: 4px solid #cbd5e0; padding: 4px 0 4px 18px; margin: 18px 0; }}
.finding h3 {{ margin: 0 0 8px; font-size: 16px; }}
.finding h4 {{ margin: 14px 0 4px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #4a5568; }}
pre {{ white-space: pre-wrap; word-break: break-word; background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; font-size: 13px; }}
.meta {{ color: #4a5568; font-size: 13px; }}
.filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }}
.filters button {{ border: 1px solid #cbd5e0; background: #fff; padding: 6px 12px; border-radius: 999px; cursor: pointer; font-size: 13px; }}
.filters button.active {{ background: #101828; color: #fff; border-color: #101828; }}
.gallery {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
.gallery img {{ max-width: 100%; border: 1px solid #e2e8f0; border-radius: 8px; }}
.gallery figcaption {{ font-size: 12px; color: #4a5568; margin-top: 6px; }}
.empty {{ color: #38a169; font-weight: 600; }}
footer {{ text-align: center; color: #718096; font-size: 12px; padding: 24px; }}
@media print {{ body {{ background: #fff; }} section {{ border: none; padding: 0; }} .filters {{ display: none; }} }}
</style>
</head>
<body>
<header>
  <h1>{_escape(title)}</h1>
  <p>Target: {_escape(redact_url(target)) if target else "n/a"}</p>
  <p>Generated {_escape(generated)} · {len(ordered)} findings</p>
</header>
<main>
  <section><h2>Executive summary</h2><div class="kpis">{_kpi_cards(counts)}</div></section>
  {metadata_html}
  {table}
  {_evidence_images(images)}
  <section><h2>Detailed findings</h2>{''.join(details) if details else '<p class="empty">Nothing to report.</p>'}</section>
  {manifest_html}
</main>
<footer>Generated locally by QA Automation Agent · zero-SaaS · redacted evidence</footer>
<script>
document.querySelectorAll('.filters button').forEach(function (button) {{
  button.addEventListener('click', function () {{
    var filter = button.getAttribute('data-filter');
    document.querySelectorAll('.filters button').forEach(function (item) {{ item.classList.remove('active'); }});
    button.classList.add('active');
    document.querySelectorAll('#findings tbody tr').forEach(function (row) {{
      row.style.display = filter === 'all' || row.getAttribute('data-sev') === filter ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>
"""


def write_report(
    findings: Sequence[Finding],
    out_dir: str | Path,
    *,
    title: str = "QA Audit Report",
    target: str = "",
    metadata: Mapping[str, Any] | None = None,
    screenshots: Sequence[str | Path] = (),
) -> ReportBundle:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    evidence_dir = directory / "evidence"
    images: list[tuple[str, str]] = []
    for raw in screenshots:
        source = Path(raw)
        if not source.is_file():
            continue
        evidence_dir.mkdir(parents=True, exist_ok=True)
        destination = evidence_dir / source.name
        shutil.copyfile(source, destination)
        images.append((destination.stem.replace("_", " "), f"evidence/{destination.name}"))

    markdown_path = directory / "bug_report.md"
    markdown_path.write_text(render_markdown(findings, title=title, target=target, metadata=metadata), encoding="utf-8")
    html_path = directory / "audit_report.html"

    copied = [path for path in evidence_dir.glob("*") if path.is_file()] if evidence_dir.is_dir() else []
    manifest = build_manifest([markdown_path, *copied], root=directory)
    html_path.write_text(
        render_html(findings, title=title, target=target, metadata=metadata, images=images, manifest=manifest),
        encoding="utf-8",
    )
    # The HTML hash is added after rendering so the manifest covers the deliverable itself.
    manifest = build_manifest([html_path, markdown_path, *copied], root=directory)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return ReportBundle(directory, html_path, markdown_path, manifest_path, manifest)
