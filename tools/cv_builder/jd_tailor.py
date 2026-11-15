# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Job Description ATS Matcher, Bullet Re-Ranker & Optional LLM Tailor.

- Exact keyword match % against a curated technical dictionary
- Re-ranks experience bullets and project highlights by relevance
- Optional LLM tailoring (OpenAI-compatible) with key auto-discovery
- Deterministic fallback when --ai is omitted or offline
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

__all__ = [
    "ATSMatchResult",
    "JDKeywords",
    "extract_keywords",
    "match_keywords",
    "rerank_bullets",
    "rerank_projects",
    "discover_llm_key",
    "tailor_with_llm",
    "generate_proposal",
    "load_jd",
]

# Curated technical keyword dictionary (extendable)
TECH_KEYWORDS = {
    # Languages
    "python", "typescript", "javascript", "java", "kotlin", "c#", "go", "rust", "dart", "swift",
    # Frameworks
    "pytest", "playwright", "fastapi", "django", "flask", "react", "next.js", "vue", "svelte",
    "angular", "expo", "react native", "jetpack compose", "wpf", "winforms", "tkinter", "pyside",
    "pyqt", "wxpython", "kivy", "spring", "quarkus", "express", "nestjs",
    # Testing
    "unit testing", "integration testing", "e2e testing", "test automation", "tdd", "bdd",
    "selenium", "cypress", "detox", "jest", "vitest", "mocha", "supertest",
    # QA Specific
    "qa", "quality assurance", "test management", "test plan", "rtm", "traceability",
    "risk-based testing", "exploratory testing", "regression testing", "smoke testing",
    "api testing", "contract testing", "fuzzing", "load testing", "performance testing",
    "accessibility testing", "wcag", "a11y", "visual regression", "self-healing",
    "defect triage", "release gating", "ci/cd", "github actions", "gitlab ci", "jenkins",
    # AI/LLM
    "llm", "rag", "groundedness", "hallucination", "prompt engineering", "fine-tuning",
    "mcp", "owasp llm", "llm01", "llm02", "llm05", "llm06", "semantic evaluation",
    "context precision", "context recall", "agent trace", "safety evaluation",
    # Data
    "pandas", "numpy", "sqlalchemy", "postgresql", "mysql", "sqlite", "prisma",
    "etl", "data pipeline", "data validation", "schema validation", "pii detection",
    # Cloud/DevOps
    "docker", "kubernetes", "aws", "gcp", "azure", "terraform", "ansible",
    "github actions", "gitlab ci", "circleci", "vercel", "netlify",
    # Mobile
    "android", "ios", "apk", "aab", "gradle", "fastlane", "fdroid", "app store",
    # Desktop
    "electron", "tauri", "pyinstaller", "nsis", "msix",
    # Security
    "security testing", "sast", "dast", "codeql", "bandit", "semgrep", "dependency scanning",
    "csp", "hsts", "xfo", "cors", "csrf", "jwt", "oauth", "openid connect",
    # Soft/Process
    "agile", "scrum", "kanban", "jira", "confluence", "requirements analysis",
    "stakeholder management", "mentoring", "code review", "documentation",
}

# Common variations/aliases
KEYWORD_ALIASES = {
    "playwright": ["playwright", "playwright python", "playwright typescript"],
    "pytest": ["pytest", "pytest-asyncio", "py.test"],
    "ci/cd": ["ci/cd", "ci cd", "continuous integration", "continuous deployment"],
    "github actions": ["github actions", "gh actions", "actions"],
    "wcag": ["wcag", "wcag 2.1", "wcag 2.1 aa", "accessibility"],
    "a11y": ["a11y", "accessibility"],
    "rtm": ["rtm", "requirements traceability matrix", "traceability matrix"],
    "etl": ["etl", "extract transform load"],
    "pii": ["pii", "personally identifiable information", "data privacy"],
    "llm": ["llm", "large language model", "language model"],
    "rag": ["rag", "retrieval augmented generation", "retrieval-augmented generation"],
    "mcp": ["mcp", "model context protocol"],
    "owasp llm": ["owasp llm", "owasp top 10 llm", "llm01", "llm02", "llm05", "llm06"],
    "groundedness": ["groundedness", "semantic groundedness", "faithfulness"],
    "context precision": ["context precision", "precision"],
    "context recall": ["context recall", "recall"],
    "apk": ["apk", "android apk", "android package"],
    "fastapi": ["fastapi", "fast api"],
    "pydantic": ["pydantic", "pydantic v2"],
    "sql": ["sql", "sqlite", "postgresql", "mysql", "database"],
    "load testing": ["load testing", "performance testing", "stress testing", "k6", "locust", "jmeter"],
    "visual regression": ["visual regression", "visual diff", "screenshot testing", "pixel diff"],
    "self-healing": ["self-healing", "self healing", "auto-healing", "locator recovery"],
}


def _normalize(text: str) -> str:
    return re.sub(r"[^\w\s\-\.\+#]", " ", text.lower())


def _expand_keywords(keywords: set[str]) -> set[str]:
    expanded = set(keywords)
    for kw in list(keywords):
        for alias in KEYWORD_ALIASES.get(kw, []):
            expanded.add(alias)
    return expanded


@dataclass
class JDKeywords:
    raw: list[str]
    normalized: set[str]
    expanded: set[str]

    @classmethod
    def from_text(cls, text: str) -> "JDKeywords":
        normalized = set()
        # Extract words and phrases (1-3 grams)
        words = _normalize(text).split()
        for n in range(1, 4):
            for i in range(len(words) - n + 1):
                gram = " ".join(words[i : i + n])
                if len(gram) >= 3:
                    normalized.add(gram)
        # Match against known tech keywords
        matched = {kw for kw in TECH_KEYWORDS if kw in text.lower()}
        expanded = _expand_keywords(matched)
        return cls(raw=list(normalized), normalized=matched, expanded=expanded)


@dataclass
class ATSMatchResult:
    score: float
    matched: list[str]
    missing: list[str]
    total_keywords: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "matched": self.matched,
            "missing": self.missing,
            "total_keywords": self.total_keywords,
        }


def extract_keywords(text: str) -> JDKeywords:
    return JDKeywords.from_text(text)


def match_keywords(jd_keywords: JDKeywords, resume_keywords: set[str]) -> ATSMatchResult:
    """Compute exact ATS keyword match percentage."""
    if not jd_keywords.expanded:
        return ATSMatchResult(score=100.0, matched=[], missing=[], total_keywords=0)
    resume_expanded = _expand_keywords(resume_keywords)
    matched = sorted(jd_keywords.expanded & resume_expanded)
    missing = sorted(jd_keywords.expanded - resume_expanded)
    score = (len(matched) / len(jd_keywords.expanded)) * 100 if jd_keywords.expanded else 100.0
    return ATSMatchResult(score=score, matched=matched, missing=missing, total_keywords=len(jd_keywords.expanded))


def _bullet_relevance(bullet: str, jd_keywords: JDKeywords) -> float:
    text = bullet.lower()
    hits = sum(1 for kw in jd_keywords.expanded if kw in text)
    return hits / max(1, len(jd_keywords.expanded)) if jd_keywords.expanded else 0.0


def rerank_bullets(bullets: list[str], jd_keywords: JDKeywords) -> list[str]:
    """Re-rank experience bullets by JD keyword relevance (highest first)."""
    scored = [(bullet, _bullet_relevance(bullet, jd_keywords)) for bullet in bullets]
    scored.sort(key=lambda x: (-x[1], len(x[0])))
    return [bullet for bullet, _ in scored]


def _project_relevance(project: dict[str, Any], jd_keywords: JDKeywords) -> float:
    text = " ".join([
        project.get("name", ""),
        project.get("desc", ""),
        " ".join(project.get("tech", [])),
    ]).lower()
    hits = sum(1 for kw in jd_keywords.expanded if kw in text)
    return hits / max(1, len(jd_keywords.expanded)) if jd_keywords.expanded else 0.0


def rerank_projects(projects: list[dict[str, Any]], jd_keywords: JDKeywords) -> list[dict[str, Any]]:
    """Re-rank project highlights by JD keyword relevance."""
    scored = [(proj, _project_relevance(proj, jd_keywords)) for proj in projects]
    scored.sort(key=lambda x: (-x[1], x[0].get("name", "")))
    return [proj for proj, _ in scored]


# ---------------------------------------------------------------------------
# Optional LLM Tailoring
# ---------------------------------------------------------------------------

KEY_FILES = [
    Path("../.jarvis_7keys.json"),
    Path(".jarvis_7keys.json"),
    Path(".env"),
]

ENV_KEYS = ["GROQ_KEY", "NVIDIA_KEY", "MISTRAL_KEY", "CEREBRAS_KEY", "OPENROUTER_KEY"]


def discover_llm_key() -> str | None:
    """Auto-discover an OpenAI-compatible API key from env or local keyfiles."""
    for env_key in ENV_KEYS:
        if value := os.environ.get(env_key):
            return value
    for key_file in KEY_FILES:
        if key_file.is_file():
            try:
                data = json.loads(key_file.read_text(encoding="utf-8"))
                for env_key in ENV_KEYS:
                    if value := data.get(env_key):
                        return value
                if value := data.get("api_key"):
                    return value
            except (json.JSONDecodeError, OSError):
                pass
    return None


def _build_llm_prompt(
    preset_name: str,
    jd_text: str,
    match_result: ATSMatchResult,
    preset: Any,
    snapshot: dict[str, Any] | None,
) -> str:
    matched_skills = ", ".join(match_result.matched[:20])
    missing_skills = ", ".join(match_result.missing[:10])
    projects = snapshot.get("repos", []) if snapshot else []
    project_names = ", ".join(p["name"] for p in projects[:5])
    project_details = "\n".join(
        f"- {p['name']}: {p.get('desc', p.get('readme_preview', 'No description'))}" for p in projects[:3]
    )

    return f"""You are a senior technical resume writer. Tailor a 3-4 line Professional Summary and reorder the top 6 experience bullets for a {preset_name} resume targeting this job description.

JOB DESCRIPTION:
{jd_text[:3000]}

ATS MATCH: {match_result.score:.0f}%
MATCHED KEYWORDS: {matched_skills}
MISSING KEYWORDS: {missing_skills}
AVAILABLE PROJECTS: {project_names}

CANDIDATE FACTS (use ONLY these, zero hallucination):
- Role: {preset.title}
- Current Summary: {preset.professional_summary}
- Experience: {chr(10).join(f"- {b}" for b in preset.experience_bullets[:6])}
- Projects: {project_details}
- Certifications: {", ".join(preset.certifications)}
- Education: {", ".join(preset.education)}

OUTPUT FORMAT (JSON only):
{{
  "professional_summary": "3-4 lines, tight to JD, truthful facts only",
  "top_bullets": ["bullet 1", "bullet 2", "bullet 3", "bullet 4", "bullet 5", "bullet 6"],
  "cover_letter": "150-200 word tailored cover letter / Upwork proposal referencing exact matching repos and metrics"
}}"""


def tailor_with_llm(
    preset_name: str,
    jd_text: str,
    match_result: ATSMatchResult,
    preset: Any,
    snapshot: dict[str, Any] | None,
    api_key: str | None = None,
    base_url: str = "https://api.openai.com/v1",
    model: str = "gpt-4o-mini",
) -> dict[str, Any] | None:
    """Call an OpenAI-compatible LLM to tailor the summary and bullets. Returns None on failure."""
    if not api_key:
        api_key = discover_llm_key()
    if not api_key:
        return None
    try:
        prompt = _build_llm_prompt(preset_name, jd_text, match_result, preset, snapshot)
        response = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": "You are a precise technical resume writer. Output valid JSON only."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 800,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return json.loads(content)
    except Exception:
        return None


def load_jd(path: str | Path | None = None, stdin: bool = False) -> str:
    if stdin:
        import sys

        return sys.stdin.read()
    if path:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    return ""


def generate_proposal(
    preset_name: str,
    jd_text: str,
    match_result: ATSMatchResult,
    preset: Any,
    snapshot: dict[str, Any] | None,
    llm_result: dict[str, Any] | None,
) -> str:
    """Generate a tailored cover letter / Upwork proposal (Markdown)."""
    if llm_result and llm_result.get("cover_letter"):
        return llm_result["cover_letter"]

    # Deterministic fallback
    matched = match_result.matched[:10]
    projects = snapshot.get("repos", []) if snapshot else []
    top_projects = projects[:3]

    lines = [
        f"# Tailored Proposal for {preset.title}",
        "",
        f"**ATS Match:** {match_result.score:.0f}% ({len(match_result.matched)}/{match_result.total_keywords} keywords)",
        "",
        "## Why I'm a Strong Fit",
        "",
        f"I've built production-grade {preset_name.replace('-', ' ')} systems that directly address your requirements:",
        "",
    ]
    for kw in matched:
        lines.append(f"- **{kw}**: demonstrated in QA_Automation_Agent and related repos")
    lines.extend([
        "",
        "## Relevant Projects & Metrics",
        "",
    ])
    for proj in top_projects:
        lines.append(f"- **{proj['name']}**: {proj.get('test_count', 0)} tests, frameworks: {', '.join(proj.get('frameworks', [])[:5]) or 'N/A'}")
    lines.extend([
        "",
        "## Core Competencies",
        "",
        ", ".join(preset.core_skills[:8]),
        "",
        "## Certifications",
        "",
        ", ".join(preset.certifications),
        "",
        "---",
        "",
        "*Generated by QA_Automation_Agent CV Builder — deterministic, privacy-first, zero-hallucination.*",
    ])
    return "\n".join(lines)