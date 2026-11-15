# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""tools.cv_builder — Workspace-aware ATS CV & Proposal builder.

Privacy-first, deterministic, zero-hallucination career automation.
"""

from __future__ import annotations

from tools.cv_builder.cli import main
from tools.cv_builder.jd_tailor import ATSMatchResult, extract_keywords, generate_proposal, load_jd, match_keywords, rerank_bullets, rerank_projects, tailor_with_llm
from tools.cv_builder.presets import ContactInfo, Preset, build_presets, list_presets, load_private_profile
from tools.cv_builder.renderers import RenderConfig, render_both, render_docx, render_pdf
from tools.cv_builder.workspace_scanner import (
    RepoFacts,
    WorkspaceSnapshot,
    sanitize_snapshot,
    scan_repo,
    scan_workspace,
    write_snapshot,
)

__all__ = [
    "main",
    "ATSMatchResult",
    "ContactInfo",
    "Preset",
    "RepoFacts",
    "WorkspaceSnapshot",
    "RenderConfig",
    "build_presets",
    "extract_keywords",
    "generate_proposal",
    "load_jd",
    "load_private_profile",
    "list_presets",
    "match_keywords",
    "render_both",
    "render_docx",
    "render_pdf",
    "rerank_bullets",
    "rerank_projects",
    "sanitize_snapshot",
    "scan_repo",
    "scan_workspace",
    "tailor_with_llm",
    "write_snapshot",
]

__version__ = "1.0.0"