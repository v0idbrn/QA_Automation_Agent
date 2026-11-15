# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Deterministic tests for tools/cv_builder (30+ tests).

Covers: workspace scanner, presets, ATS keyword matching, PII/secret non-leakage,
mocked LLM tailoring, PDF/DOCX rendering validity.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tools.cv_builder.jd_tailor import (
    ATSMatchResult,
    extract_keywords,
    generate_proposal,
    load_jd,
    match_keywords,
    rerank_bullets,
    rerank_projects,
    tailor_with_llm,
)
from tools.cv_builder.presets import ContactInfo, Preset, build_presets, list_presets, load_private_profile
from tools.cv_builder.renderers import RenderConfig, render_both, render_docx, render_pdf
from tools.cv_builder.workspace_scanner import (
    RepoFacts,
    WorkspaceSnapshot,
    extract_js_tests,
    extract_python_tests,
    load_cv_metrics,
    load_package_json,
    load_pyproject,
    load_readme,
    load_requirements,
    sanitize_snapshot,
    scan_repo,
    scan_workspace,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Create a mini workspace with two sibling repos."""
    ws = tmp_path / "workspace"
    ws.mkdir()

    # Repo 1: Python project with tests
    repo1 = ws / "QA_Automation_Agent"
    repo1.mkdir()
    (repo1 / "pyproject.toml").write_text("""
[project]
name = "qa-automation-agent"
version = "2.0.0"
dependencies = ["pytest>=8.0.0", "playwright>=1.40.0", "pydantic>=2.0.0", "httpx>=0.27.0"]
[project.optional-dependencies]
test = ["pytest-asyncio>=0.23.0"]
""", encoding="utf-8")
    (repo1 / "requirements.txt").write_text("pytest>=8.0.0\nplaywright>=1.40.0\npydantic>=2.0.0\nhttpx>=0.27.0\n", encoding="utf-8")
    (repo1 / "cv_metrics.json").write_text(json.dumps({"total_tests": 726, "modules": ["api_fuzzer", "crawler"]}), encoding="utf-8")
    (repo1 / "README.md").write_text("# QA Automation Agent\n\nLocal-first AI-SDET framework with 726 tests.\n", encoding="utf-8")
    (repo1 / ".github" / "workflows").mkdir(parents=True)
    (repo1 / ".github" / "workflows" / "ci.yml").write_text("""
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - run: pytest
""", encoding="utf-8")
    tests_dir = repo1 / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sample.py").write_text("""
def test_one():
    assert True

async def test_two():
    assert True

class TestGroup:
    def test_three(self):
        assert True
""", encoding="utf-8")

    # Repo 2: JS/TS project
    repo2 = ws / "ApexFOSS"
    repo2.mkdir()
    (repo2 / "package.json").write_text(json.dumps({
        "name": "apex-foss",
        "version": "1.0.0",
        "dependencies": {"react": "^18", "react-native": "^0.72"},
        "devDependencies": {"jest": "^29", "detox": "^20", "typescript": "^5"}
    }), encoding="utf-8")
    (repo2 / "README.md").write_text("# ApexFOSS\n\nReact Native app with Detox E2E tests.\n", encoding="utf-8")
    (repo2 / ".github" / "workflows").mkdir(parents=True)
    (repo2 / ".github" / "workflows" / "ci.yml").write_text("""
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: ["18", "20"]
    steps:
      - run: npm test
""", encoding="utf-8")
    src_dir = repo2 / "src"
    src_dir.mkdir()
    (src_dir / "App.test.tsx").write_text("""
import { render } from '@testing-library/react-native';
it('renders correctly', () => {});
test('handles press', () => {});
""", encoding="utf-8")

    return ws


@pytest.fixture
def sample_jd() -> str:
    return """
We are looking for an AI-SDET with strong Python and Playwright experience.
Required: pytest, Playwright, API testing, GraphQL, CI/CD (GitHub Actions),
LLM evaluation (RAG, groundedness), MCP security, OWASP LLM Top 10.
Nice to have: FastAPI, Pydantic, visual regression, load testing.
"""


@pytest.fixture
def sample_preset() -> Preset:
    return Preset(
        name="ai-sdet-en",
        language="en",
        title="AI-SDET & Quality Engineering Specialist",
        professional_summary="Test summary",
        core_skills=["pytest", "Playwright", "FastAPI", "LLM Evaluation"],
        experience_bullets=[
            "Built QA_Automation_Agent with 726 tests and 7 audit engines",
            "Implemented LLM/RAG evaluation suite with groundedness and precision/recall",
            "Delivered MCP tool validator mapped to OWASP LLM Top 10",
        ],
        project_highlights=[
            "QA_Automation_Agent: 726 tests, 7 engines, CI gates",
            "ConciliaPDF: Financial PDF reconciliation",
        ],
        certifications=["Google LLM Certification", "Google Responsible AI Certification"],
        education=["Engineering in AI & Data Science, UNSa"],
    )


@pytest.fixture
def sample_snapshot() -> dict:
    return {
        "root": "/tmp/workspace",
        "repos": [
            {
                "name": "QA_Automation_Agent",
                "path": "QA_Automation_Agent",
                "languages": ["Python"],
                "frameworks": ["Pytest", "Playwright", "Pydantic", "FastAPI", "HTTPX"],
                "test_count": 726,
                "python_tests": 726,
                "js_tests": 0,
                "ci_matrix": ["python-version: 3.11", "python-version: 3.12"],
                "has_cv_metrics": True,
                "has_pyproject": True,
                "has_requirements": True,
                "has_package_json": False,
                "has_github_workflows": True,
                "readme_preview": "# QA Automation Agent\n\nLocal-first AI-SDET...",
                "security_features": ["MCP tool validation", "LLM/RAG evaluations", "SHA-256 evidence logging"],
            },
            {
                "name": "ApexFOSS",
                "path": "ApexFOSS",
                "languages": ["TypeScript"],
                "frameworks": ["React Native", "Expo", "Detox", "Jest", "TypeScript"],
                "test_count": 42,
                "python_tests": 0,
                "js_tests": 42,
                "ci_matrix": ["node-version: 18", "node-version: 20"],
                "has_cv_metrics": False,
                "has_pyproject": False,
                "has_requirements": False,
                "has_package_json": True,
                "has_github_workflows": True,
                "readme_preview": "# ApexFOSS\n\nReact Native app...",
                "security_features": [],
            },
        ],
        "generated_at": "2026-11-15T10:00:00Z",
    }


# ---------------------------------------------------------------------------
# Workspace Scanner Tests
# ---------------------------------------------------------------------------


def test_load_cv_metrics(tmp_path: Path) -> None:
    p = tmp_path / "cv_metrics.json"
    p.write_text(json.dumps({"total_tests": 100}), encoding="utf-8")
    assert load_cv_metrics(p) == {"total_tests": 100}
    assert load_cv_metrics(tmp_path / "missing.json") == {}


def test_load_pyproject(tmp_path: Path) -> None:
    p = tmp_path / "pyproject.toml"
    p.write_text('[project]\nname = "test"\ndependencies = ["pytest"]\n', encoding="utf-8")
    data = load_pyproject(p)
    assert data["project"]["name"] == "test"
    assert "pytest" in data["project"]["dependencies"]
    assert load_pyproject(tmp_path / "missing.toml") == {}


def test_load_requirements(tmp_path: Path) -> None:
    p = tmp_path / "requirements.txt"
    p.write_text("pytest>=8.0.0\nplaywright>=1.40.0\n# comment\n", encoding="utf-8")
    assert load_requirements(p) == ["pytest>=8.0.0", "playwright>=1.40.0"]
    assert load_requirements(tmp_path / "missing.txt") == []


def test_load_package_json(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"name": "test", "dependencies": {"react": "^18"}}), encoding="utf-8")
    data = load_package_json(p)
    assert data["name"] == "test"
    assert "react" in data["dependencies"]
    assert load_package_json(tmp_path / "missing.json") == {}


def test_load_readme(tmp_path: Path) -> None:
    p = tmp_path / "README.md"
    p.write_text("# Hello\n\nWorld", encoding="utf-8")
    assert load_readme(p) == "# Hello\n\nWorld"
    assert load_readme(tmp_path / "missing.md") == ""


def test_extract_python_tests(tmp_path: Path) -> None:
    (tmp_path / "test_a.py").write_text("def test_one():\n    assert True\n", encoding="utf-8")
    (tmp_path / "test_b.py").write_text("async def test_two():\n    assert True\nclass TestX:\n    def test_three(self):\n        pass\n", encoding="utf-8")
    count, names = extract_python_tests(tmp_path)
    assert count == 3
    assert any("test_one" in n for n in names)
    assert any("test_two" in n for n in names)
    assert any("test_three" in n for n in names)  # Class method found


def test_extract_js_tests(tmp_path: Path) -> None:
    (tmp_path / "app.test.ts").write_text("it('renders', () => {});\ntest('clicks', () => {});\n", encoding="utf-8")
    (tmp_path / "other.spec.js").write_text("it.only('focused', () => {});\n", encoding="utf-8")
    count, names = extract_js_tests(tmp_path)
    assert count == 3
    assert any("renders" in n for n in names)
    assert any("clicks" in n for n in names)
    assert any("focused" in n for n in names)


def test_scan_repo(tmp_workspace: Path) -> None:
    repo = tmp_workspace / "QA_Automation_Agent"
    facts = scan_repo(repo)
    assert isinstance(facts, RepoFacts)
    assert facts.name == "QA_Automation_Agent"
    assert facts.test_count >= 3
    assert facts.python_tests >= 3
    assert "Pytest" in facts.frameworks
    assert "Playwright" in facts.frameworks
    assert facts.has_cv_metrics is True
    assert facts.has_pyproject is True
    assert facts.has_github_workflows is True
    assert "python-version: 3.11" in facts.ci_matrix


def test_scan_workspace(tmp_workspace: Path) -> None:
    snapshot = scan_workspace(tmp_workspace)
    assert isinstance(snapshot, WorkspaceSnapshot)
    assert len(snapshot.repos) == 2
    repo_names = {r.name for r in snapshot.repos}
    assert repo_names == {"QA_Automation_Agent", "ApexFOSS"}

    # Check ApexFOSS facts
    apex = next(r for r in snapshot.repos if r.name == "ApexFOSS")
    assert apex.js_tests >= 2
    assert "React Native" in apex.frameworks
    assert "Detox" in apex.frameworks
    assert "node-version: 18" in apex.ci_matrix


def test_sanitize_snapshot(tmp_workspace: Path) -> None:
    snapshot = scan_workspace(tmp_workspace)
    sanitized = sanitize_snapshot(snapshot)
    for repo in sanitized.repos:
        assert repo.path == repo.name  # Path replaced with name only
        assert "/" not in repo.path and "\\" not in repo.path


# ---------------------------------------------------------------------------
# Presets Tests
# ---------------------------------------------------------------------------


def test_list_presets() -> None:
    presets = list_presets()
    assert presets == ["ai-sdet-en", "qa-ia-es", "qa-software-en", "qa-software-es", "python-automation-en"]


def test_load_private_profile_env(monkeypatch) -> None:
    monkeypatch.setenv("CV_EMAIL", "test@example.com")
    monkeypatch.setenv("CV_GITHUB", "https://github.com/test")
    profile = load_private_profile(None)
    assert profile.email == "test@example.com"
    assert profile.github == "https://github.com/test"


def test_load_private_profile_file(tmp_path: Path) -> None:
    p = tmp_path / ".cv_private.json"
    p.write_text(json.dumps({"email": "file@example.com", "phone": "+123"}), encoding="utf-8")
    profile = load_private_profile(p)
    assert profile.email == "file@example.com"
    assert profile.phone == "+123"


def test_build_presets_all(sample_snapshot: dict) -> None:
    presets = build_presets(sample_snapshot)
    assert len(presets) == 5
    for name in list_presets():
        preset = presets[name]
        assert isinstance(preset, Preset)
        assert preset.name == name
        assert preset.professional_summary
        assert len(preset.core_skills) > 0
        assert len(preset.experience_bullets) > 0
        assert len(preset.project_highlights) > 0
        assert len(preset.certifications) > 0
        assert len(preset.education) > 0


def test_build_presets_enriches_with_snapshot(sample_snapshot: dict) -> None:
    presets = build_presets(sample_snapshot)
    # Check that frameworks from snapshot appear in core_skills
    ai_sdet = presets["ai-sdet-en"]
    all_skills = " ".join(ai_sdet.core_skills).lower()
    assert "detox" in all_skills or "jest" in all_skills  # from ApexFOSS


def test_preset_language_detection() -> None:
    presets = build_presets({})
    assert presets["ai-sdet-en"].language == "en"
    assert presets["qa-ia-es"].language == "es"
    assert presets["qa-software-en"].language == "en"
    assert presets["qa-software-es"].language == "es"
    assert presets["python-automation-en"].language == "en"


# ---------------------------------------------------------------------------
# JD Tailor / ATS Matching Tests
# ---------------------------------------------------------------------------


def test_extract_keywords(sample_jd: str) -> None:
    kw = extract_keywords(sample_jd)
    from tools.cv_builder.jd_tailor import JDKeywords
    assert isinstance(kw, JDKeywords)
    assert len(kw.expanded) > 0
    assert "playwright" in kw.expanded or "pytest" in kw.expanded


def test_match_keywords_perfect(sample_jd: str, sample_preset: Preset) -> None:
    jd_kw = extract_keywords(sample_jd)
    resume_kw = set(sample_preset.core_skills)
    for bullet in sample_preset.experience_bullets:
        resume_kw.update(extract_keywords(bullet).expanded)
    result = match_keywords(jd_kw, resume_kw)
    assert isinstance(result, ATSMatchResult)
    assert 0 <= result.score <= 100
    assert result.total_keywords == len(jd_kw.expanded)


def test_match_keywords_empty_jd() -> None:
    from tools.cv_builder.jd_tailor import JDKeywords
    empty_jd = JDKeywords(raw=[], normalized=set(), expanded=set())
    result = match_keywords(empty_jd, {"pytest"})
    assert result.score == 100.0
    assert result.matched == []
    assert result.missing == []


def test_rerank_bullets(sample_jd: str, sample_preset: Preset) -> None:
    jd_kw = extract_keywords(sample_jd)
    reranked = rerank_bullets(sample_preset.experience_bullets, jd_kw)
    assert len(reranked) == len(sample_preset.experience_bullets)
    # All bullets should be present
    assert set(reranked) == set(sample_preset.experience_bullets)


def test_rerank_projects(sample_jd: str, sample_preset: Preset) -> None:
    jd_kw = extract_keywords(sample_jd)
    projects = [{"name": "p1", "desc": d, "tech": []} for d in sample_preset.project_highlights]
    reranked = rerank_projects(projects, jd_kw)
    assert len(reranked) == len(projects)
    # QA_Automation_Agent should rank higher (mentions tests, engines, CI)
    assert "QA_Automation_Agent" in reranked[0]["desc"]


def test_generate_proposal_deterministic(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    jd_kw = extract_keywords(sample_jd)
    resume_kw = set(sample_preset.core_skills)
    match_result = match_keywords(jd_kw, resume_kw)
    proposal = generate_proposal("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, None)
    assert isinstance(proposal, str)
    assert "ATS Match" in proposal
    assert "QA_Automation_Agent" in proposal
    assert "726" in proposal or "7 engines" in proposal


def test_generate_proposal_with_llm_result(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    jd_kw = extract_keywords(sample_jd)
    resume_kw = set(sample_preset.core_skills)
    match_result = match_keywords(jd_kw, resume_kw)
    llm_result = {
        "professional_summary": "LLM tailored summary",
        "top_bullets": ["LLM bullet 1", "LLM bullet 2"],
        "cover_letter": "LLM generated cover letter",
    }
    proposal = generate_proposal("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, llm_result)
    assert "LLM generated cover letter" in proposal


def test_load_jd_file(tmp_path: Path) -> None:
    p = tmp_path / "job.txt"
    p.write_text("Python developer needed with pytest and Playwright.", encoding="utf-8")
    assert "Python developer" in load_jd(p)


def test_load_jd_stdin(monkeypatch) -> None:
    import sys
    from io import StringIO
    monkeypatch.setattr(sys, "stdin", StringIO("Stdin JD content"))
    assert "Stdin JD" in load_jd(stdin=True)


# ---------------------------------------------------------------------------
# LLM Tailoring Tests (Mocked)
# ---------------------------------------------------------------------------


def test_tailor_with_llm_success(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    import tools.cv_builder.jd_tailor as jd_tailor_module
    original_post = jd_tailor_module.httpx.post
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "choices": [{"message": {"content": json.dumps({
            "professional_summary": "AI tailored summary",
            "top_bullets": ["AI bullet 1", "AI bullet 2"],
            "cover_letter": "AI cover letter",
        })}}]
    }
    mock_response.raise_for_status = lambda: None
    jd_tailor_module.httpx.post = MagicMock(return_value=mock_response)

    try:
        from tools.cv_builder.jd_tailor import ATSMatchResult
        match_result = ATSMatchResult(score=80.0, matched=["pytest"], missing=["kubernetes"], total_keywords=2)
        result = tailor_with_llm("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, api_key="test-key")

        assert result is not None
        assert result["professional_summary"] == "AI tailored summary"
        assert result["top_bullets"] == ["AI bullet 1", "AI bullet 2"]
    finally:
        jd_tailor_module.httpx.post = original_post


def test_tailor_with_llm_failure(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    import tools.cv_builder.jd_tailor as jd_tailor_module
    original_post = jd_tailor_module.httpx.post
    jd_tailor_module.httpx.post = MagicMock(side_effect=Exception("API error"))

    try:
        from tools.cv_builder.jd_tailor import ATSMatchResult
        match_result = ATSMatchResult(score=80.0, matched=["pytest"], missing=["kubernetes"], total_keywords=2)
        result = tailor_with_llm("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, api_key="test-key")
        assert result is None
    finally:
        jd_tailor_module.httpx.post = original_post


def test_tailor_with_llm_no_key(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    from tools.cv_builder.jd_tailor import ATSMatchResult
    match_result = ATSMatchResult(score=80.0, matched=["pytest"], missing=["kubernetes"], total_keywords=2)
    with patch.dict(os.environ, {}, clear=True):
        result = tailor_with_llm("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, api_key=None)
    assert result is None


# ---------------------------------------------------------------------------
# Renderer Tests
# ---------------------------------------------------------------------------


def test_render_pdf_creates_file(tmp_path: Path, sample_preset: Preset) -> None:
    contact = ContactInfo(email="test@example.com", github="https://github.com/test")
    config = RenderConfig(one_page=True, page_size="A4")
    output = tmp_path / "test_cv.pdf"
    result = render_pdf(sample_preset, contact, config, output)
    assert result == output
    assert output.is_file()
    assert output.stat().st_size > 1000  # Non-trivial PDF


def test_render_docx_creates_file(tmp_path: Path, sample_preset: Preset) -> None:
    contact = ContactInfo(email="test@example.com", github="https://github.com/test")
    config = RenderConfig(one_page=True, page_size="A4")
    output = tmp_path / "test_cv.docx"
    result = render_docx(sample_preset, contact, config, output)
    assert result == output
    assert output.is_file()
    assert output.stat().st_size > 1000


def test_render_both(tmp_path: Path, sample_preset: Preset) -> None:
    contact = ContactInfo(email="test@example.com", github="https://github.com/test")
    config = RenderConfig(one_page=True)
    pdf_path, docx_path = render_both(sample_preset, contact, config, tmp_path, "test_cv")
    assert pdf_path.is_file()
    assert docx_path.is_file()
    assert pdf_path.suffix == ".pdf"
    assert docx_path.suffix == ".docx"


def test_render_config_defaults() -> None:
    config = RenderConfig()
    assert config.one_page is True
    assert config.page_size == "A4"
    assert config.margins_cm == 2.0
    assert config.font_name == "Helvetica"


# ---------------------------------------------------------------------------
# PII / Secret Non-Leakage Tests
# ---------------------------------------------------------------------------


def test_private_profile_not_in_snapshot(tmp_workspace: Path) -> None:
    # Create a .cv_private.json in one repo (should be ignored by scanner)
    private_file = tmp_workspace / "QA_Automation_Agent" / ".cv_private.json"
    private_file.write_text(json.dumps({"email": "secret@test.com", "api_key": "sk-1234567890"}), encoding="utf-8")

    snapshot = scan_workspace(tmp_workspace)
    # The scanner only looks at manifest files, not .cv_private.json
    # Verify no secret appears in the snapshot
    snapshot_json = json.dumps(snapshot.to_dict())
    assert "secret@test.com" not in snapshot_json
    assert "sk-1234567890" not in snapshot_json


def test_env_keys_not_logged(sample_jd: str, sample_preset: Preset, sample_snapshot: dict) -> None:
    # Ensure tailor_with_llm doesn't log or return the API key
    import tools.cv_builder.jd_tailor as jd_tailor_module
    original_post = jd_tailor_module.httpx.post
    mock_response = MagicMock()
    mock_response.json.return_value = {"choices": [{"message": {"content": '{"professional_summary": "x"}'}}]}
    mock_response.raise_for_status = lambda: None
    jd_tailor_module.httpx.post = MagicMock(return_value=mock_response)

    try:
        from tools.cv_builder.jd_tailor import ATSMatchResult
        match_result = ATSMatchResult(score=80.0, matched=["pytest"], missing=["k8s"], total_keywords=2)
        result = tailor_with_llm("ai-sdet-en", sample_jd, match_result, sample_preset, sample_snapshot, api_key="sk-secret-key")

        # Verify the key was passed to httpx but not in result
        call_args = jd_tailor_module.httpx.post.call_args
        assert call_args is not None
        headers = call_args.kwargs.get("headers", {})
        assert "sk-secret-key" in headers.get("Authorization", "")
        assert result is not None
        # Result should not contain the key
        assert "sk-secret-key" not in json.dumps(result)
    finally:
        jd_tailor_module.httpx.post = original_post


def test_snapshot_sanitization_removes_paths(tmp_workspace: Path) -> None:
    snapshot = scan_workspace(tmp_workspace)
    sanitized = sanitize_snapshot(snapshot)
    for repo in sanitized.repos:
        # Path should be just the repo name, not absolute path
        assert repo.path == repo.name
        assert not repo.path.startswith("/")
        assert not repo.path.startswith("C:\\")
        assert not repo.path.startswith("..")


# ---------------------------------------------------------------------------
# Integration Test: Full Pipeline
# ---------------------------------------------------------------------------


def test_full_pipeline_scan_to_pdf(tmp_workspace: Path, tmp_path: Path) -> None:
    """End-to-end: scan workspace -> build presets -> render PDF."""
    # Scan
    snapshot = scan_workspace(tmp_workspace)
    sanitized = sanitize_snapshot(snapshot)

    # Build presets
    presets = build_presets(sanitized.to_dict())

    # Render one preset
    preset = presets["ai-sdet-en"]
    contact = ContactInfo(email="test@example.com", github="https://github.com/test")
    config = RenderConfig(one_page=True)

    pdf_path = tmp_path / "output" / "ai-sdet-en.pdf"
    result = render_pdf(preset, contact, config, pdf_path)

    assert result.is_file()
    assert result.stat().st_size > 2000


def test_full_pipeline_with_jd_rerank(tmp_workspace: Path, sample_jd: str, tmp_path: Path) -> None:
    """End-to-end: scan -> JD match -> rerank -> render."""
    snapshot = scan_workspace(tmp_workspace)
    sanitized = sanitize_snapshot(snapshot)
    presets = build_presets(sanitized.to_dict())
    preset = presets["qa-software-en"]

    # JD matching
    jd_kw = extract_keywords(sample_jd)
    resume_kw = set(preset.core_skills)
    for b in preset.experience_bullets:
        resume_kw.update(extract_keywords(b).expanded)
    match = match_keywords(jd_kw, resume_kw)

    # Rerank
    original_bullets = list(preset.experience_bullets)
    preset.experience_bullets = rerank_bullets(preset.experience_bullets, jd_kw)
    assert preset.experience_bullets != original_bullets  # Should be reordered

    # Render
    contact = ContactInfo(email="test@example.com")
    config = RenderConfig(one_page=True)
    pdf_path = tmp_path / "output" / "qa-software-en.pdf"
    render_pdf(preset, contact, config, pdf_path)
    assert pdf_path.is_file()


# ---------------------------------------------------------------------------
# CLI Smoke Test
# ---------------------------------------------------------------------------


def test_cli_scan_only(tmp_workspace: Path, tmp_path: Path, monkeypatch) -> None:
    from tools.cv_builder.cli import main
    monkeypatch.setattr("sys.argv", [
        "cv-builder", "--scan-only", "--workspace-dir", str(tmp_workspace)
    ])
    exit_code = main()
    assert exit_code == 0
    output = Path("tools/cv_builder/workspace_snapshot.json")
    assert output.is_file()
    data = json.loads(output.read_text())
    assert "repos" in data
    assert len(data["repos"]) == 2


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------


def test_scan_workspace_empty_dir(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    snapshot = scan_workspace(empty)
    assert len(snapshot.repos) == 0


def test_scan_workspace_ignores_dot_dirs(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".hidden").mkdir()
    (ws / ".hidden" / "pyproject.toml").write_text('[project]\nname="hidden"\n', encoding="utf-8")
    (ws / "visible").mkdir()
    (ws / "visible" / "pyproject.toml").write_text('[project]\nname="visible"\n', encoding="utf-8")
    snapshot = scan_workspace(ws)
    assert len(snapshot.repos) == 1
    assert snapshot.repos[0].name == "visible"


def test_rerank_bullets_empty_jd(sample_preset: Preset) -> None:
    from tools.cv_builder.jd_tailor import JDKeywords
    empty_jd = JDKeywords(raw=[], normalized=set(), expanded=set())
    reranked = rerank_bullets(sample_preset.experience_bullets, empty_jd)
    assert len(reranked) == len(sample_preset.experience_bullets)
    # All bullets have 0 relevance, so order may vary by length; just check all present
    assert set(reranked) == set(sample_preset.experience_bullets)


def test_rerank_projects_empty_jd(sample_preset: Preset) -> None:
    from tools.cv_builder.jd_tailor import JDKeywords
    empty_jd = JDKeywords(raw=[], normalized=set(), expanded=set())
    projects = [{"name": "p1", "desc": d, "tech": []} for d in sample_preset.project_highlights]
    reranked = rerank_projects(projects, empty_jd)
    assert reranked == projects  # No change


def test_preset_to_dict(sample_preset: Preset) -> None:
    d = sample_preset.to_dict()
    assert d["name"] == "ai-sdet-en"
    assert "professional_summary" in d
    assert "core_skills" in d
    assert isinstance(d["core_skills"], list)


def test_repo_facts_to_dict(tmp_workspace: Path) -> None:
    facts = scan_repo(tmp_workspace / "QA_Automation_Agent")
    d = facts.to_dict()
    assert d["name"] == "QA_Automation_Agent"
    assert "frameworks" in d
    assert isinstance(d["frameworks"], list)


def test_workspace_snapshot_to_dict(tmp_workspace: Path) -> None:
    snapshot = scan_workspace(tmp_workspace)
    d = snapshot.to_dict()
    assert "root" in d
    assert "repos" in d
    assert "generated_at" in d
    assert len(d["repos"]) == 2