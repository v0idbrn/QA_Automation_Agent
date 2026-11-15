# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""CLI entrypoint for the workspace-aware ATS CV & Proposal builder.

Commands:
  python -m tools.cv_builder --preset all --workspace-dir ..
  python -m tools.cv_builder --preset ai-sdet-en --jd job.txt --ai --workspace-dir ..
  python -m tools.cv_builder --scan-only --workspace-dir ..
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.cv_builder.jd_tailor import ATSMatchResult, extract_keywords, generate_proposal, load_jd, match_keywords, rerank_bullets, rerank_projects, tailor_with_llm
from tools.cv_builder.presets import ContactInfo, Preset, build_presets, list_presets, load_private_profile
from tools.cv_builder.renderers import RenderConfig, render_both, render_docx, render_pdf
from tools.cv_builder.workspace_scanner import WorkspaceSnapshot, sanitize_snapshot, scan_workspace, write_snapshot

__all__ = ["build_parser", "main"]


def _load_snapshot(path: str | Path) -> dict[str, Any] | None:
    p = Path(path)
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
    return None


def _save_proposal(proposal: str, preset_name: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    slug = preset_name.replace("-", "_")
    path = output_dir / f"{slug}_proposal.md"
    path.write_text(proposal, encoding="utf-8")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cv-builder",
        description="Workspace-aware ATS CV & Proposal builder (privacy-first, deterministic).",
    )
    parser.add_argument("--version", action="version", version="cv-builder 1.0.0")

    # Preset selection
    parser.add_argument(
        "--preset",
        choices=list_presets() + ["all"],
        default="ai-sdet-en",
        help="Preset to render (default: ai-sdet-en). Use 'all' for all 5 presets.",
    )

    # Workspace scanning
    parser.add_argument(
        "--workspace-dir",
        default="..",
        help="Root directory containing sibling repos to scan (default: ..)",
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only scan workspace and write workspace_snapshot.json, then exit.",
    )
    parser.add_argument(
        "--snapshot",
        help="Path to existing workspace_snapshot.json to reuse (skips live scan).",
    )
    parser.add_argument(
        "--include",
        help="Regex filter for repo names during scan.",
    )

    # Job description & ATS matching
    parser.add_argument("--jd", help="Path to job description text file.")
    parser.add_argument("--jd-stdin", action="store_true", help="Read job description from stdin.")
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable optional LLM tailoring (auto-discovers key from env/keyfiles).",
    )
    parser.add_argument(
        "--llm-base-url",
        default="https://api.openai.com/v1",
        help="OpenAI-compatible base URL for --ai.",
    )
    parser.add_argument(
        "--llm-model",
        default="gpt-4o-mini",
        help="Model name for --ai.",
    )

    # Output options
    parser.add_argument(
        "--output-dir",
        default="output_cvs",
        help="Output directory for generated CVs and proposals (default: output_cvs).",
    )
    parser.add_argument(
        "--one-page",
        action="store_true",
        help="Compact one-page mode (default).",
    )
    parser.add_argument(
        "--detailed",
        action="store_true",
        help="Two-page detailed mode.",
    )
    parser.add_argument(
        "--format",
        choices=["pdf", "docx", "both"],
        default="both",
        help="Output format (default: both).",
    )
    parser.add_argument(
        "--page-size",
        choices=["A4", "letter"],
        default="A4",
        help="Page size (default: A4).",
    )

    # Private profile
    parser.add_argument(
        "--private-profile",
        help="Path to .cv_private.json (default: .cv_private.json in cwd).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Determine one-page vs detailed
    one_page = not args.detailed

    # Load or scan workspace snapshot
    if args.snapshot:
        snapshot = _load_snapshot(args.snapshot)
        print(f"Loaded snapshot from {args.snapshot}")
    else:
        print(f"Scanning workspace: {args.workspace_dir}")
        ws_snapshot = scan_workspace(args.workspace_dir, include_pattern=args.include)
        ws_snapshot = sanitize_snapshot(ws_snapshot)
        snapshot = ws_snapshot.to_dict()
        snap_path = Path("tools/cv_builder/workspace_snapshot.json")
        write_snapshot(ws_snapshot, snap_path)
        print(f"Snapshot written to {snap_path} ({len(snapshot.get('repos', []))} repos)")

    if args.scan_only:
        print("Scan complete.")
        return 0

    # Load private profile (PII)
    private = load_private_profile(args.private_profile)
    contact = ContactInfo(
        email=private.email,
        phone=private.phone,
        location=private.location,
        linkedin=private.linkedin,
        github=private.github,
        portfolio=private.portfolio,
    )

    # Load job description if provided
    jd_text = ""
    jd_keywords = None
    match_result = None
    if args.jd or args.jd_stdin:
        jd_text = load_jd(args.jd, args.jd_stdin)
        jd_keywords = extract_keywords(jd_text)
        print(f"JD loaded: {len(jd_keywords.expanded)} technical keywords extracted")

    # Build presets
    presets = build_presets(snapshot, contact)
    target_presets = list_presets() if args.preset == "all" else [args.preset]

    render_config = RenderConfig(
        one_page=one_page,
        page_size=args.page_size,
        margins_cm=2.0,
        font_name="Helvetica",
        font_size=10,
        leading=13,
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for preset_name in target_presets:
        preset = presets.get(preset_name)
        if not preset:
            print(f"Warning: preset '{preset_name}' not found", file=sys.stderr)
            continue

        # ATS matching & re-ranking
        if jd_keywords:
            # Collect resume keywords from preset
            resume_kw = set()
            resume_kw.update(preset.core_skills)
            for bullet in preset.experience_bullets:
                resume_kw.update(extract_keywords(bullet).expanded)
            for proj in preset.project_highlights:
                resume_kw.update(extract_keywords(proj).expanded)

            match_result = match_keywords(jd_keywords, resume_kw)
            print(f"[{preset_name}] ATS Match: {match_result.score:.1f}% ({len(match_result.matched)}/{match_result.total_keywords})")
            if match_result.matched:
                print(f"  Matched: {', '.join(match_result.matched[:15])}")
            if match_result.missing:
                print(f"  Missing: {', '.join(match_result.missing[:10])}")

            # Re-rank bullets and projects
            preset.experience_bullets = rerank_bullets(preset.experience_bullets, jd_keywords)
            preset.project_highlights = [p["desc"] if isinstance(p, dict) else p for p in rerank_projects(
                [{"name": "proj", "desc": h, "tech": []} for h in preset.project_highlights], jd_keywords
            )]

        # Optional LLM tailoring
        llm_result = None
        if args.ai and jd_text:
            print(f"[{preset_name}] Tailoring with LLM (--ai)...")
            llm_result = tailor_with_llm(
                preset_name,
                jd_text,
                match_result or ATSMatchResult(0, [], [], 0),
                preset,
                snapshot,
                base_url=args.llm_base_url,
                model=args.llm_model,
            )
            if llm_result:
                if llm_result.get("professional_summary"):
                    preset.professional_summary = llm_result["professional_summary"]
                if llm_result.get("top_bullets"):
                    preset.experience_bullets = llm_result["top_bullets"]
                print(f"  LLM tailored summary and top bullets")
            else:
                print(f"  LLM tailoring unavailable (no key or API error), using deterministic fallback")

        # Generate proposal if JD provided
        if jd_text:
            proposal = generate_proposal(preset_name, jd_text, match_result or ATSMatchResult(0, [], [], 0), preset, snapshot, llm_result)
            proposal_path = _save_proposal(proposal, preset_name, output_dir)
            print(f"  Proposal: {proposal_path}")

        # Render CV
        base_name = f"{preset_name}"
        if args.format in ("pdf", "both"):
            try:
                pdf_path = render_pdf(preset, contact, render_config, output_dir / f"{base_name}.pdf")
                print(f"  PDF: {pdf_path}")
            except Exception as e:
                print(f"  PDF render failed: {e}", file=sys.stderr)
        if args.format in ("docx", "both"):
            try:
                docx_path = render_docx(preset, contact, render_config, output_dir / f"{base_name}.docx")
                print(f"  DOCX: {docx_path}")
            except Exception as e:
                print(f"  DOCX render failed: {e}", file=sys.stderr)

    print(f"\nDone. Outputs in {output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())